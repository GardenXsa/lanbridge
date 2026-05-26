"""
LanBridge Relay Server for NAT/VPN Traversal.

When both players are behind VPN or NAT (no public IP),
the relay server helps establish a connection.

Architecture:
  Peer A <---> Relay Server <---> Peer B

The relay simply forwards encrypted packets between peers.
It CANNOT read the traffic - everything is end-to-end encrypted.

Protocol:
  All packets: [8 bytes session_id] + [payload]
  payload = raw tunnel packet (AUTH, DATA, PING, etc.)

  Special relay control messages (from peer to relay):
    RELAY_REGISTER + session_id (8 bytes) [+ password_hash] - host registers a room
    RELAY_JOIN + session_id (8 bytes) - client joins a room  
    RELAY_PING - keepalive ping to relay

  Special relay responses (from relay to peer):
    RELAY_OK + session_id - registration/join successful
    RELAY_WAIT + session_id - waiting for second peer
    RELAY_FULL + session_id - room already has 2 peers
    RELAY_BYE - peer disconnected
    RELAY_ERROR + message - error
    RELAY_PONG - keepalive pong
"""

import asyncio
import struct
import time
import logging
import os
import hashlib
import secrets
from typing import Dict, Tuple, Optional, Set

logger = logging.getLogger("lanbridge.relay")

# Relay control message prefixes (all 9 bytes for consistency)
RELAY_REGISTER = b'RELAY_REG'
RELAY_OK       = b'RELAY_OK\x00'
RELAY_WAIT     = b'RELAY_WAIT'
RELAY_FULL     = b'RELAY_FULL'
RELAY_ERROR    = b'RELAY_ERR\x00'
RELAY_PING     = b'RELAY_PING'
RELAY_PONG     = b'RELAY_PONG'
RELAY_BYE      = b'RELAY_BYE\x00'

SESSION_ID_SIZE = 8  # 8 ASCII chars


class RelayDatagramTransport:
    """
    Transparent wrapper around asyncio.DatagramTransport that
    adds relay session_id header on send and strips it on receive.

    This makes the relay completely invisible to the tunnel protocol:
    - Tunnel calls transport.sendto(data, addr) -> we add session_id + send to relay
    - Relay responses come with session_id -> we strip it before passing to tunnel
    """

    def __init__(self, real_transport: asyncio.DatagramTransport,
                 relay_addr: Tuple[str, int], session_id: str):
        self._real_transport = real_transport
        self._relay_addr = relay_addr
        self._session_id = session_id[:SESSION_ID_SIZE].ljust(SESSION_ID_SIZE, '0')
        self._session_id_bytes = self._session_id.encode('ascii')

    def sendto(self, data: bytes, addr: Tuple[str, int] = None):
        """Send data through relay (adds session_id header, always sends to relay)."""
        relay_data = self._session_id_bytes + data
        self._real_transport.sendto(relay_data, self._relay_addr)

    def close(self):
        """Close the underlying transport."""
        self._real_transport.close()

    def get_extra_info(self, name, default=None):
        """Pass through to real transport."""
        return self._real_transport.get_extra_info(name, default)

    @property
    def session_id(self) -> str:
        return self._session_id

    @staticmethod
    def is_relay_control(data: bytes) -> bool:
        """Check if data is a relay control message (not tunnel data)."""
        return (data.startswith(RELAY_OK) or
                data.startswith(RELAY_WAIT) or
                data.startswith(RELAY_FULL) or
                data.startswith(RELAY_ERROR) or
                data.startswith(RELAY_PONG) or
                data.startswith(RELAY_BYE))

    @staticmethod
    def strip_header(data: bytes) -> Optional[bytes]:
        """Strip session_id header from relay data. Returns None for control msgs."""
        if RelayDatagramTransport.is_relay_control(data):
            return None
        if len(data) > SESSION_ID_SIZE:
            return data[SESSION_ID_SIZE:]
        return None


class RelaySession:
    """Session between two peers on the relay server."""

    def __init__(self, session_id: str, password_hash: str, created_at: float):
        self.session_id = session_id
        self.password_hash = password_hash
        self.created_at = created_at
        self.host_addr: Optional[Tuple[str, int]] = None
        self.client_addr: Optional[Tuple[str, int]] = None
        self.host_last_seen = 0.0
        self.client_last_seen = 0.0
        self.bytes_relayed = 0

    @property
    def is_complete(self) -> bool:
        return self.host_addr is not None and self.client_addr is not None

    def get_other_peer(self, addr: Tuple[str, int]) -> Optional[Tuple[str, int]]:
        """Returns the address of the other peer."""
        if addr == self.host_addr:
            return self.client_addr
        elif addr == self.client_addr:
            return self.host_addr
        return None

    def register_host(self, addr: Tuple[str, int]):
        """Register the host peer."""
        self.host_addr = addr
        self.host_last_seen = time.time()

    def register_client(self, addr: Tuple[str, int]):
        """Register the client peer."""
        self.client_addr = addr
        self.client_last_seen = time.time()

    def update_peer(self, addr: Tuple[str, int]):
        """Update peer address (NAT may change port) and last seen time."""
        now = time.time()
        # Match by IP address (NAT can change port)
        if self.host_addr and addr[0] == self.host_addr[0]:
            self.host_addr = addr
            self.host_last_seen = now
        elif self.client_addr and addr[0] == self.client_addr[0]:
            self.client_addr = addr
            self.client_last_seen = now
        # Exact match fallback
        elif self.host_addr and addr == self.host_addr:
            self.host_last_seen = now
        elif self.client_addr and addr == self.client_addr:
            self.client_last_seen = now


class RelayServerProtocol(asyncio.DatagramProtocol):
    """UDP relay server for NAT/VPN traversal."""

    MAX_SESSION_TIME = 3600 * 8   # 8 hours max
    CLEANUP_INTERVAL = 30         # cleanup every 30 seconds
    PEER_TIMEOUT = 180            # 3 minutes inactivity = peer gone
    MAX_SESSIONS = 1000           # max concurrent sessions

    def __init__(self):
        self.sessions: Dict[str, RelaySession] = {}
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._addr_to_session: Dict[Tuple[str, int], str] = {}

    def connection_made(self, transport: asyncio.DatagramTransport):
        self._transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        now = time.time()

        # Handle relay control messages
        if data.startswith(RELAY_PING):
            self._transport.sendto(RELAY_PONG, addr)
            return

        if data.startswith(RELAY_REGISTER):
            self._handle_register(data, addr, now)
            return

        if data.startswith(RELAY_BYE):
            self._handle_bye(data, addr)
            return

        # Minimum packet: session_id (8 bytes) + some payload
        if len(data) < SESSION_ID_SIZE + 1:
            return

        # Extract session_id
        session_id = data[:SESSION_ID_SIZE].decode('ascii', errors='replace')
        payload = data[SESSION_ID_SIZE:]

        # Find session
        if session_id not in self.sessions:
            self._transport.sendto(
                RELAY_ERROR + b'unknown_session',
                addr
            )
            return

        session = self.sessions[session_id]

        # Update peer
        session.update_peer(addr)
        self._addr_to_session[addr] = session_id

        # Relay to other peer
        if session.is_complete:
            other = session.get_other_peer(addr)
            if other:
                # Forward the entire packet (with session_id) to the other peer
                self._transport.sendto(data, other)
                session.bytes_relayed += len(payload)
        else:
            # Waiting for second peer
            self._transport.sendto(
                RELAY_WAIT + session_id.encode('ascii'),
                addr
            )

    def _handle_register(self, data: bytes, addr: Tuple[str, int], now: float):
        """Handle RELAY_REGISTER: creates a new session."""
        # Format: RELAY_REGISTER (9) + session_id (8) [+ password_hash]
        if len(data) < 9 + SESSION_ID_SIZE:
            self._transport.sendto(RELAY_ERROR + b'bad_register', addr)
            return

        session_id = data[9:9 + SESSION_ID_SIZE].decode('ascii', errors='replace')
        password_hash = data[9 + SESSION_ID_SIZE:].decode('ascii', errors='replace') if len(data) > 9 + SESSION_ID_SIZE else ''

        if len(self.sessions) >= self.MAX_SESSIONS:
            self._transport.sendto(RELAY_ERROR + b'server_full', addr)
            return

        if session_id in self.sessions:
            session = self.sessions[session_id]
            # Host reconnecting (same IP)?
            if session.host_addr and addr[0] == session.host_addr[0]:
                session.host_addr = addr
                session.host_last_seen = now
                self._addr_to_session[addr] = session_id
                self._transport.sendto(RELAY_OK + session_id.encode('ascii'), addr)
                return
            self._transport.sendto(RELAY_FULL + session_id.encode('ascii'), addr)
            return

        # Create new session
        session = RelaySession(session_id, password_hash, now)
        session.register_host(addr)
        self.sessions[session_id] = session
        self._addr_to_session[addr] = session_id

        logger.info(f"New session: {session_id} from {addr[0]}:{addr[1]}")
        self._transport.sendto(RELAY_OK + session_id.encode('ascii'), addr)

    def _handle_bye(self, data: bytes, addr: Tuple[str, int]):
        """Handle RELAY_BYE: peer disconnecting gracefully."""
        if addr not in self._addr_to_session:
            return

        session_id = self._addr_to_session[addr]
        if session_id not in self.sessions:
            return

        session = self.sessions[session_id]

        # Notify the other peer
        other = session.get_other_peer(addr)
        if other:
            self._transport.sendto(RELAY_BYE, other)

        # Remove peer from session
        if session.host_addr and addr[0] == session.host_addr[0]:
            session.host_addr = None
        elif session.client_addr and addr[0] == session.client_addr[0]:
            session.client_addr = None

        del self._addr_to_session[addr]

        if not session.host_addr and not session.client_addr:
            del self.sessions[session_id]
            logger.info(f"Session {session_id} removed (both peers gone)")

    def cleanup_sessions(self):
        """Remove expired sessions and timed-out peers."""
        now = time.time()
        to_remove = []

        for sid, session in self.sessions.items():
            if now - session.created_at > self.MAX_SESSION_TIME:
                to_remove.append(sid)
                continue

            if session.host_addr and (now - session.host_last_seen) > self.PEER_TIMEOUT:
                if session.client_addr:
                    self._transport.sendto(RELAY_BYE, session.client_addr)
                session.host_addr = None

            if session.client_addr and (now - session.client_last_seen) > self.PEER_TIMEOUT:
                if session.host_addr:
                    self._transport.sendto(RELAY_BYE, session.host_addr)
                session.client_addr = None

            if not session.host_addr and not session.client_addr:
                to_remove.append(sid)

        for sid in to_remove:
            addrs_to_remove = [
                addr for addr, s in self._addr_to_session.items() if s == sid
            ]
            for addr in addrs_to_remove:
                del self._addr_to_session[addr]
            del self.sessions[sid]
            logger.info(f"Session {sid} cleaned up")

    def get_stats(self) -> dict:
        """Get relay server statistics."""
        active = sum(1 for s in self.sessions.values() if s.is_complete)
        waiting = sum(1 for s in self.sessions.values() if not s.is_complete)
        return {
            'total_sessions': len(self.sessions),
            'active_sessions': active,
            'waiting_sessions': waiting,
        }


def generate_session_id() -> str:
    """Generate a random 8-character session ID."""
    alphabet = 'abcdefghijkmnopqrstuvwxyz23456789'
    return ''.join(secrets.choice(alphabet) for _ in range(SESSION_ID_SIZE))


async def run_relay_server(host: str = '0.0.0.0', port: int = 9876):
    """Start the relay server."""
    logger.info(f"Starting relay server on {host}:{port}")

    loop = asyncio.get_event_loop()
    protocol = RelayServerProtocol()

    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol,
        local_addr=(host, port)
    )

    print(f"  LanBridge Relay Server running on {host}:{port}")
    print(f"  Max sessions: {RelayServerProtocol.MAX_SESSIONS}")
    print(f"  Session timeout: {RelayServerProtocol.MAX_SESSION_TIME // 3600}h")
    print()

    async def cleanup_loop():
        while True:
            await asyncio.sleep(RelayServerProtocol.CLEANUP_INTERVAL)
            protocol.cleanup_sessions()
            stats = protocol.get_stats()
            logger.info(
                f"Sessions: {stats['active_sessions']} active, "
                f"{stats['waiting_sessions']} waiting"
            )

    cleanup_task = asyncio.ensure_future(cleanup_loop())

    try:
        await asyncio.Future()
    except asyncio.CancelledError:
        pass
    finally:
        cleanup_task.cancel()
        transport.close()
        logger.info("Relay server stopped")
