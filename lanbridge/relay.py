"""
Relay-сервер LanBridge для NAT traversal.

Когда оба игрока за NAT (без белого IP),
relay-сервер помогает установить соединение.

Архитектура:
  Peer A <---> Relay Server <---> Peer B

Relay просто пересылает зашифрованные пакеты между пирами.
Он НЕ может прочитать трафик — всё зашифровано.
"""

import asyncio
import struct
import time
import logging
from typing import Dict, Tuple, Optional

logger = logging.getLogger("lanbridge.relay")


class RelaySession:
    """Сессия между двумя пирами на relay-сервере."""

    def __init__(self, session_id: str, created_at: float):
        self.session_id = session_id
        self.created_at = created_at
        self.peer_a: Optional[Tuple[str, int]] = None
        self.peer_b: Optional[Tuple[str, int]] = None
        self.peer_a_last_seen = 0.0
        self.peer_b_last_seen = 0.0
        self.bytes_relayed = 0

    @property
    def is_complete(self) -> bool:
        return self.peer_a is not None and self.peer_b is not None

    def get_other_peer(self, addr: Tuple[str, int]) -> Optional[Tuple[str, int]]:
        """Возвращает адрес другого пира."""
        if addr == self.peer_a:
            return self.peer_b
        elif addr == self.peer_b:
            return self.peer_a
        return None

    def register_peer(self, addr: Tuple[str, int]) -> str:
        """Регистрирует пира в сессии. Возвращает 'A' или 'B'."""
        if self.peer_a is None:
            self.peer_a = addr
            self.peer_a_last_seen = time.time()
            return 'A'
        elif self.peer_b is None:
            self.peer_b = addr
            self.peer_b_last_seen = time.time()
            return 'B'
        else:
            # Обновляем существующего
            if addr[0] == self.peer_a[0]:
                self.peer_a = addr
                self.peer_a_last_seen = time.time()
                return 'A'
            else:
                self.peer_b = addr
                self.peer_b_last_seen = time.time()
                return 'B'


class RelayServerProtocol(asyncio.DatagramProtocol):
    """UDP relay-сервер для NAT traversal."""

    MAX_SESSION_TIME = 3600 * 4  # 4 часа максимум
    CLEANUP_INTERVAL = 60         # чистка каждую минуту
    PEER_TIMEOUT = 120            # 2 минуты бездействия = отключение

    def __init__(self):
        self.sessions: Dict[str, RelaySession] = {}
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._addr_to_session: Dict[Tuple[str, int], str] = {}

    def connection_made(self, transport: asyncio.DatagramTransport):
        self._transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        now = time.time()

        # Минимальный пакет: session_id (8 байт) + данные
        if len(data) < 8:
            return

        # Первые 8 байт — ID сессии (hex string как bytes)
        session_id = data[:8].decode('ascii', errors='replace')
        payload = data[8:]

        # Получаем или создаём сессию
        if session_id not in self.sessions:
            session = RelaySession(session_id, now)
            self.sessions[session_id] = session
            logger.info(f"Новая сессия: {session_id} от {addr[0]}:{addr[1]}")
        else:
            session = self.sessions[session_id]

        # Регистрируем пира
        peer_label = session.register_peer(addr)
        self._addr_to_session[addr] = session_id

        # Обновляем время активности
        if peer_label == 'A':
            session.peer_a_last_seen = now
        else:
            session.peer_b_last_seen = now

        # Если сессия полная — пересылаем другому пиру
        if session.is_complete:
            other = session.get_other_peer(addr)
            if other:
                # Пересылаем payload (без session_id) другому пиру
                self._transport.sendto(data, other)
                session.bytes_relayed += len(payload)
        else:
            # Ждём второго пира — отправляем подтверждение
            self._transport.sendto(
                b'RELAY_WAIT:' + session_id.encode(),
                addr
            )

    def cleanup_sessions(self):
        """Удаляет устаревшие сессии."""
        now = time.time()
        to_remove = []

        for sid, session in self.sessions.items():
            age = now - session.created_at
            if age > self.MAX_SESSION_TIME:
                to_remove.append(sid)
                continue

            # Удаляем пир, если он неактивен
            if session.peer_a and (now - session.peer_a_last_seen) > self.PEER_TIMEOUT:
                session.peer_a = None
            if session.peer_b and (now - session.peer_b_last_seen) > self.PEER_TIMEOUT:
                session.peer_b = None

            # Если оба пира ушли — удаляем сессию
            if not session.peer_a and not session.peer_b:
                to_remove.append(sid)

        for sid in to_remove:
            logger.info(f"Удаление сессии {sid}")
            # Чистим адресный маппинг
            addrs_to_remove = [
                addr for addr, s in self._addr_to_session.items() if s == sid
            ]
            for addr in addrs_to_remove:
                del self._addr_to_session[addr]
            del self.sessions[sid]


class RelayClient:
    """
    Клиент relay-сервера.
    Используется, когда оба пира за NAT.
    """

    RELAY_HEADER_SIZE = 8  # session_id как 8-символьный hex

    def __init__(self, relay_addr: Tuple[str, int], session_id: str):
        self.relay_addr = relay_addr
        self.session_id = session_id[:8].ljust(8, '0')  # Ровно 8 символов
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._ready = False

    def attach_transport(self, transport: asyncio.DatagramTransport):
        self._transport = transport
        self._ready = True

    def send_to_relay(self, data: bytes):
        """Оборачивает данные в relay-протокол и отправляет."""
        if not self._transport:
            return
        relay_data = self.session_id.encode('ascii') + data
        self._transport.sendto(relay_data, self.relay_addr)

    def extract_payload(self, data: bytes) -> Optional[bytes]:
        """Извлекает payload из relay-пакета."""
        # Ответ от relay приходит в формате session_id + data
        # или RELAY_WAIT:session_id
        if data.startswith(b'RELAY_WAIT:'):
            logger.info("Ожидание второго пира на relay...")
            return None
        if len(data) > self.RELAY_HEADER_SIZE:
            return data[self.RELAY_HEADER_SIZE:]
        return data


async def run_relay_server(host: str = '0.0.0.0', port: int = 9876):
    """Запускает relay-сервер."""
    logger.info(f"Запуск relay-сервера на {host}:{port}")

    loop = asyncio.get_event_loop()
    protocol = RelayServerProtocol()

    transport, _ = await loop.create_datagram_endpoint(
        lambda: protocol,
        local_addr=(host, port)
    )

    # Периодическая чистка сессий
    async def cleanup_loop():
        while True:
            await asyncio.sleep(RelayServerProtocol.CLEANUP_INTERVAL)
            protocol.cleanup_sessions()
            active = len(protocol.sessions)
            logger.info(f"Активных сессий: {active}")

    cleanup_task = asyncio.ensure_future(cleanup_loop())

    try:
        await asyncio.Future()  # Бесконечное ожидание
    except asyncio.CancelledError:
        pass
    finally:
        cleanup_task.cancel()
        transport.close()
        logger.info("Relay-сервер остановлен")
