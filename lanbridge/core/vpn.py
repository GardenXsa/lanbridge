"""
LanBridge VPN Engine.

Binds TUN device and encrypted UDP tunnel:
  TUN (IP packets) <-> Crypto <-> UDP <-> Crypto <-> TUN (IP packets)

Both computers see each other at IP 10.13.37.x
as if on the same LAN.

Supports two modes:
  1. Direct P2P: Peer A <----UDP----> Peer B
  2. Via Relay:   Peer A <----UDP----> Relay <----UDP----> Peer B
     (for VPN/NAT traversal where direct connection is impossible)

Relay mode is transparent - the tunnel protocol doesn't change.
The RelayDatagramTransport wrapper adds/strips the session_id header
automatically, making the relay invisible to the tunnel layer.
"""

import asyncio
import struct
import time
import logging
import hashlib
from typing import Optional, Callable, Tuple

from .crypto import create_crypto
from .tunnel import (
    TunnelProtocol, TunnelServerProtocol, TunnelClientProtocol,
    TunnelPacket, PacketType
)
from ..platform.tun_device import TUNDevice, create_tun_device, HOST_IP, CLIENT_IP, MTU
from ..relay import (
    RelayDatagramTransport, generate_session_id,
    RELAY_REGISTER, RELAY_OK, RELAY_WAIT,
    RELAY_BYE, RELAY_PONG, SESSION_ID_SIZE
)

logger = logging.getLogger("lanbridge.vpn")

PACKET_TYPE_RAW_IP = 0x50


class VPNEngine:
    """
    VPN Engine - the heart of LanBridge.

    Binds two data flows:
    1. TUN -> encrypt -> UDP (outgoing packets)
    2. UDP -> decrypt -> TUN (incoming packets)
    """

    def __init__(self, is_host: bool, tunnel: TunnelProtocol, tun: TUNDevice):
        self.is_host = is_host
        self.tunnel = tunnel
        self.tun = tun
        self._running = False
        self._tun_read_task: Optional[asyncio.Task] = None
        self._stats = {
            'tun_read': 0,
            'tun_written': 0,
            'tunnel_sent': 0,
            'tunnel_recv': 0,
            'bytes_sent': 0,
            'bytes_recv': 0,
        }

    @property
    def stats(self) -> dict:
        return self._stats.copy()

    def start(self):
        """Start TUN <-> Tunnel forwarding."""
        self._running = True
        self.tun.start()
        self.tunnel.on_packet = self._on_tunnel_packet
        self._tun_read_task = asyncio.ensure_future(self._tun_to_tunnel_loop())
        logger.info(f"VPN started: {self.tun.address} <-> tunnel")

    def stop(self):
        """Stop VPN."""
        self._running = False
        if self._tun_read_task:
            self._tun_read_task.cancel()

    async def _tun_to_tunnel_loop(self):
        """Read from TUN and send to tunnel."""
        try:
            while self._running:
                try:
                    packet = await asyncio.wait_for(
                        self.tun.read_packet(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                except Exception as e:
                    if self._running:
                        logger.debug(f"TUN read error: {e}")
                    await asyncio.sleep(0.1)
                    continue

                if not packet or len(packet) < 20:
                    continue

                tunnel_pkt = TunnelPacket(
                    PacketType.DATA_TCP,
                    port=0,
                    conn_id=0,
                    payload=packet,
                )
                await self.tunnel.send_packet(tunnel_pkt)

                self._stats['tun_read'] += 1
                self._stats['bytes_sent'] += len(packet)

        except asyncio.CancelledError:
            pass
        except Exception as e:
            logger.error(f"TUN->tunnel error: {e}")

    def _on_tunnel_packet(self, packet: TunnelPacket):
        """Handle incoming packet from tunnel -> write to TUN."""
        if packet.ptype == PacketType.DATA_TCP and packet.port == 0:
            asyncio.ensure_future(self._write_to_tun(packet.payload))

    async def _write_to_tun(self, ip_packet: bytes):
        """Write IP packet to TUN."""
        if not ip_packet or len(ip_packet) < 20:
            return
        try:
            await self.tun.write_packet(ip_packet)
            self._stats['tun_written'] += 1
            self._stats['bytes_recv'] += len(ip_packet)
        except Exception as e:
            logger.debug(f"TUN write error: {e}")


# ================================================================
# Direct P2P mode
# ================================================================

async def run_vpn_host(
    password: str,
    port: int = 9876,
    on_connected: Optional[Callable] = None,
    bind_ip: str = '0.0.0.0',
) -> tuple:
    """Start VPN in host mode (direct P2P)."""
    tun = create_tun_device(is_host=True)
    await tun.create()

    crypto = create_crypto(password)
    tunnel = TunnelProtocol(crypto)
    vpn = VPNEngine(is_host=True, tunnel=tunnel, tun=tun)
    connected_event = asyncio.Event()

    def on_client_connected():
        connected_event.set()
        vpn.start()
        if on_connected:
            on_connected()

    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: TunnelServerProtocol(tunnel, password, on_client_connected),
        local_addr=(bind_ip, port)
    )

    return tunnel, vpn, tun, transport, connected_event


async def run_vpn_client(
    password: str,
    server_addr: tuple,
    on_connected: Optional[Callable] = None,
    bind_ip: str = '0.0.0.0',
) -> tuple:
    """Start VPN in client mode (direct P2P)."""
    tun = create_tun_device(is_host=False)
    await tun.create()

    crypto = create_crypto(password)
    tunnel = TunnelProtocol(crypto)
    vpn = VPNEngine(is_host=False, tunnel=tunnel, tun=tun)
    connected_event = asyncio.Event()

    def on_server_connected():
        connected_event.set()
        vpn.start()
        if on_connected:
            on_connected()

    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: TunnelClientProtocol(
            tunnel, password, server_addr, on_server_connected
        ),
        local_addr=(bind_ip, 0)
    )

    return tunnel, vpn, tun, transport, connected_event


# ================================================================
# Relay mode (for VPN/NAT traversal)
# ================================================================

DEFAULT_RELAY_HOST = '8.212.10.159'
DEFAULT_RELAY_PORT = 9876


class _RelayHostDatagramProtocol(asyncio.DatagramProtocol):
    """
    DatagramProtocol for the HOST side using relay.

    Handles:
    1. Registration with relay server
    2. Receiving relay control messages
    3. Passing tunnel data to TunnelServerProtocol (with relay header stripped)
    """

    def __init__(self, tunnel_server: TunnelServerProtocol,
                 password: str, relay_addr: tuple, session_id: str,
                 on_registered: Callable = None):
        self.tunnel_server = tunnel_server
        self.password = password
        self.relay_addr = relay_addr
        self.session_id = session_id
        self.on_registered = on_registered
        self._transport = None
        self._registered = False
        self._retry_task = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self._transport = transport

        # Wire tunnel server to use relay transport (adds session_id header)
        relay_transport = RelayDatagramTransport(
            transport, self.relay_addr, self.session_id
        )
        self.tunnel_server.tunnel.attach_transport(relay_transport)
        self.tunnel_server.tunnel.set_remote(self.relay_addr)

        # Start registration
        asyncio.ensure_future(self._register())

    async def _register(self):
        """Register with relay server."""
        pw_hash = hashlib.sha256(self.password.encode()).hexdigest()[:16]
        register_data = (
            RELAY_REGISTER +
            self.session_id.encode('ascii') +
            pw_hash.encode('ascii')
        )
        self._transport.sendto(register_data, self.relay_addr)
        self._retry_task = asyncio.ensure_future(self._register_retry())

    async def _register_retry(self):
        """Retry registration until confirmed."""
        try:
            for _ in range(30):
                await asyncio.sleep(2.0)
                if self._registered:
                    return
                pw_hash = hashlib.sha256(self.password.encode()).hexdigest()[:16]
                register_data = (
                    RELAY_REGISTER +
                    self.session_id.encode('ascii') +
                    pw_hash.encode('ascii')
                )
                self._transport.sendto(register_data, self.relay_addr)
        except asyncio.CancelledError:
            pass

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        # Handle relay control messages
        if data.startswith(RELAY_OK):
            self._registered = True
            if self.on_registered:
                self.on_registered()
            return

        if data.startswith(RELAY_WAIT):
            return  # Waiting for peer

        if data.startswith(RELAY_BYE):
            # Peer disconnected
            self.tunnel_server.tunnel._connected = False
            return

        if data.startswith(RELAY_ERROR):
            logger.error(f"Relay error: {data[9:]}")
            return

        if data.startswith(RELAY_PONG):
            return

        # Tunnel data: strip relay header and pass to tunnel server
        payload = RelayDatagramTransport.strip_header(data)
        if payload is not None:
            self.tunnel_server.datagram_received(payload, addr)


class _RelayClientDatagramProtocol(asyncio.DatagramProtocol):
    """
    DatagramProtocol for the CLIENT side using relay.

    Handles:
    1. Receiving relay control messages
    2. Passing tunnel data to TunnelClientProtocol (with relay header stripped)
    3. Sending AUTH through relay
    """

    def __init__(self, tunnel_client: TunnelClientProtocol,
                 password: str, relay_addr: tuple, session_id: str,
                 on_connected: Callable = None):
        self.tunnel_client = tunnel_client
        self.password = password
        self.relay_addr = relay_addr
        self.session_id = session_id
        self.on_connected = on_connected
        self._transport = None
        self._relay_transport = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self._transport = transport

        # Create relay transport wrapper (adds session_id header on send)
        self._relay_transport = RelayDatagramTransport(
            transport, self.relay_addr, self.session_id
        )

        # Wire tunnel client to use relay transport
        self.tunnel_client.tunnel.attach_transport(self._relay_transport)
        self.tunnel_client.tunnel.set_remote(self.relay_addr)

        # Manually trigger AUTH through relay
        asyncio.ensure_future(self._send_auth())

    async def _send_auth(self):
        """Send AUTH packet through relay."""
        client_salt = self.tunnel_client.tunnel.crypto.get_salt()
        payload = client_salt + self.password.encode('utf-8')
        auth_packet = TunnelPacket(PacketType.AUTH, payload=payload)
        raw = auth_packet.pack()
        # Send through relay (adds session_id header automatically)
        self._relay_transport.sendto(raw)

        # Start retry loop
        asyncio.ensure_future(self._auth_retry())

    async def _auth_retry(self):
        """Retry AUTH through relay."""
        try:
            for _ in range(60):
                await asyncio.sleep(2.0)
                if self.tunnel_client.tunnel.is_connected:
                    return
                client_salt = self.tunnel_client.tunnel.crypto.get_salt()
                payload = client_salt + self.password.encode('utf-8')
                auth_packet = TunnelPacket(PacketType.AUTH, payload=payload)
                raw = auth_packet.pack()
                self._relay_transport.sendto(raw)
        except asyncio.CancelledError:
            pass

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        # Handle relay control messages
        if data.startswith(RELAY_WAIT):
            return
        if data.startswith(RELAY_OK):
            return
        if data.startswith(RELAY_ERROR):
            logger.error(f"Relay error: {data[9:]}")
            return
        if data.startswith(RELAY_PONG):
            return
        if data.startswith(RELAY_BYE):
            self.tunnel_client.tunnel._connected = False
            return

        # Tunnel data: strip relay header and pass to tunnel client
        payload = RelayDatagramTransport.strip_header(data)
        if payload is not None:
            self.tunnel_client.datagram_received(payload, self.relay_addr)



async def run_vpn_host_relay(
    password: str,
    relay_addr: tuple,
    session_id: str,
    on_connected: Optional[Callable] = None,
    on_registered: Optional[Callable] = None,
) -> tuple:
    """
    Start VPN in host mode via relay server.

    Both peers connect outbound to the relay, so NAT/VPN
    is not a problem - no port forwarding needed.

    Returns: (tunnel, vpn_engine, tun_device, transport, connected_event, registered_event)
    """
    tun = create_tun_device(is_host=True)
    await tun.create()

    crypto = create_crypto(password)
    tunnel = TunnelProtocol(crypto)
    vpn = VPNEngine(is_host=True, tunnel=tunnel, tun=tun)

    connected_event = asyncio.Event()
    registered_event = asyncio.Event()

    def on_client_connected():
        connected_event.set()
        vpn.start()
        if on_connected:
            on_connected()

    def on_registered_cb():
        registered_event.set()
        if on_registered:
            on_registered()

    # Create tunnel server (handles AUTH, DATA, etc.)
    tunnel_server = TunnelServerProtocol(tunnel, password, on_client_connected)

    # Create relay host protocol
    relay_protocol = _RelayHostDatagramProtocol(
        tunnel_server, password,
        relay_addr, session_id,
        on_registered=on_registered_cb,
    )

    # Connect to relay server
    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: relay_protocol,
        local_addr=('0.0.0.0', 0)
    )

    return tunnel, vpn, tun, transport, connected_event, registered_event


async def run_vpn_client_relay(
    password: str,
    relay_addr: tuple,
    session_id: str,
    on_connected: Optional[Callable] = None,
) -> tuple:
    """
    Start VPN in client mode via relay server.

    Both peers connect outbound to the relay, so NAT/VPN
    is not a problem - no port forwarding needed.

    Returns: (tunnel, vpn_engine, tun_device, transport, connected_event)
    """
    tun = create_tun_device(is_host=False)
    await tun.create()

    crypto = create_crypto(password)
    tunnel = TunnelProtocol(crypto)
    vpn = VPNEngine(is_host=False, tunnel=tunnel, tun=tun)

    connected_event = asyncio.Event()

    def on_server_connected():
        connected_event.set()
        vpn.start()
        if on_connected:
            on_connected()

    # Create tunnel client (handles AUTH, DATA, etc.)
    tunnel_client = TunnelClientProtocol(
        tunnel, password, relay_addr, on_server_connected
    )

    # Create relay client protocol
    relay_protocol = _RelayClientDatagramProtocol(
        tunnel_client, password,
        relay_addr, session_id,
        on_connected=on_server_connected,
    )

    # Connect to relay server
    loop = asyncio.get_event_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: relay_protocol,
        local_addr=('0.0.0.0', 0)
    )

    return tunnel, vpn, tun, transport, connected_event
