"""
Модуль туннеля LanBridge.
Реализует протокол UDP-туннеля между двумя пирами.

Протокол соединения:
  1. Клиент отправляет AUTH пакет в ОТКРЫТОМ виде (с salt)
  2. Сервер проверяет пароль, принимает salt клиента
  3. Сервер отправляет AUTH_OK зашифрованный с salt клиента
  4. Далее все пакеты зашифрованы с общим salt
"""

import asyncio
import struct
import time
import os
import logging
from enum import IntEnum
from typing import Optional, Callable, Dict, Tuple

logger = logging.getLogger("lanbridge.tunnel")


class PacketType(IntEnum):
    """Типы пакетов туннеля."""
    AUTH = 0x01           # Аутентификация (открытый текст)
    AUTH_OK = 0x02        # Успешная аутентификация
    DATA_TCP = 0x10       # Данные TCP
    DATA_UDP = 0x11       # Данные UDP
    OPEN_PORT = 0x20      # Запрос на открытие порта
    CLOSE_PORT = 0x21     # Закрытие порта
    PING = 0x30           # Keepalive ping
    PONG = 0x31           # Keepalive pong
    DISCONNECT = 0x40     # Отключение
    ERROR = 0xFF          # Ошибка


class TunnelPacket:
    """Представление пакета туннеля."""

    HEADER_FORMAT = '!BHI'  # type(1) + port(2) + conn_id(4)
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def __init__(self, ptype: PacketType, port: int = 0,
                 conn_id: int = 0, payload: bytes = b''):
        self.ptype = ptype
        self.port = port
        self.conn_id = conn_id
        self.payload = payload

    def pack(self) -> bytes:
        """Сериализует пакет в байты."""
        header = struct.pack(
            self.HEADER_FORMAT,
            self.ptype, self.port, self.conn_id
        )
        return header + self.payload

    @classmethod
    def unpack(cls, data: bytes) -> 'TunnelPacket':
        """Десериализует пакет из байтов."""
        if len(data) < cls.HEADER_SIZE:
            raise ValueError(f"Пакет слишком короткий: {len(data)} байт")
        ptype, port, conn_id = struct.unpack(
            cls.HEADER_FORMAT, data[:cls.HEADER_SIZE]
        )
        payload = data[cls.HEADER_SIZE:]
        return cls(PacketType(ptype), port, conn_id, payload)

    def __repr__(self):
        return (f"TunnelPacket(type={self.ptype.name}, port={self.port}, "
                f"conn_id={self.conn_id}, payload_len={len(self.payload)})")


class TunnelProtocol:
    """
    Протокол туннеля поверх UDP.
    Обеспечивает отправку/приём зашифрованных пакетов,
    keepalive и повторную отправку при потере.
    """

    KEEPALIVE_INTERVAL = 5.0       # секунд между ping
    KEEPALIVE_TIMEOUT = 15.0       # секунд до признания соединения мёртвым
    MTU = 1400                     # макс. размер пакета (с учётом заголовков)

    def __init__(self, crypto, on_packet: Callable = None):
        self.crypto = crypto
        self.on_packet = on_packet
        self._transport: Optional[asyncio.DatagramTransport] = None
        self._remote_addr: Optional[Tuple[str, int]] = None
        self._connected = False
        self._last_recv_time = 0.0
        self._last_send_time = 0.0
        self._keepalive_task: Optional[asyncio.Task] = None
        self._timeout_task: Optional[asyncio.Task] = None
        self._stats = {
            'sent': 0, 'recv': 0,
            'sent_bytes': 0, 'recv_bytes': 0,
        }

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def stats(self) -> dict:
        return self._stats.copy()

    def set_remote(self, addr: Tuple[str, int]):
        """Устанавливает адрес удалённого пира."""
        self._remote_addr = addr

    def attach_transport(self, transport: asyncio.DatagramTransport):
        """Привязывает UDP-транспорт."""
        self._transport = transport

    def send_raw(self, data: bytes, addr: Tuple[str, int] = None):
        """Отправляет сырые данные без шифрования (для AUTH)."""
        if not self._transport:
            logger.warning("Попытка отправки без транспорта")
            return
        target = addr or self._remote_addr
        if not target:
            logger.warning("Попытка отправки без адреса")
            return
        self._transport.sendto(data, target)
        self._stats['sent'] += 1
        self._stats['sent_bytes'] += len(data)
        self._last_send_time = time.time()

    async def send_packet(self, packet: TunnelPacket):
        """Отправляет зашифрованный пакет удалённому пиру."""
        if not self._transport or not self._remote_addr:
            logger.warning("Попытка отправки без транспорта или адреса")
            return

        raw = packet.pack()
        encrypted = self.crypto.encrypt(raw)

        # Фрагментация если пакет слишком большой
        if len(encrypted) > self.MTU:
            await self._send_fragmented(encrypted)
            return

        self._transport.sendto(encrypted, self._remote_addr)
        self._stats['sent'] += 1
        self._stats['sent_bytes'] += len(encrypted)
        self._last_send_time = time.time()

    async def _send_fragmented(self, data: bytes):
        """Отправляет данные фрагментами."""
        offset = 0
        frag_id = int(time.time() * 1000) & 0xFFFF
        total_frags = (len(data) + self.MTU - 1) // self.MTU

        while offset < len(data):
            chunk = data[offset:offset + self.MTU]
            frag_header = struct.pack('!HBB', frag_id,
                                      offset // self.MTU, total_frags)
            frag_packet = TunnelPacket(
                PacketType.DATA_TCP, 0, 0,
                frag_header + chunk
            )
            raw = frag_packet.pack()
            enc = self.crypto.encrypt(raw)
            self._transport.sendto(enc, self._remote_addr)
            offset += self.MTU

        self._stats['sent'] += total_frags
        self._stats['sent_bytes'] += len(data)

    def handle_datagram(self, data: bytes, addr: Tuple[str, int]):
        """Обрабатывает входящую зашифрованную UDP-датаграмму."""
        try:
            decrypted = self.crypto.decrypt(data)
            packet = TunnelPacket.unpack(decrypted)
        except Exception as e:
            logger.debug(f"Ошибка расшифровки/парсинга от {addr}: {e}")
            return

        self._stats['recv'] += 1
        self._stats['recv_bytes'] += len(data)
        self._last_recv_time = time.time()

        # Обработка системных пакетов
        if packet.ptype == PacketType.PING:
            asyncio.ensure_future(self._send_pong())
            return
        elif packet.ptype == PacketType.PONG:
            return
        elif packet.ptype == PacketType.DISCONNECT:
            self._connected = False
            logger.info("Удалённый пир отключился")
            return

        # Передаём пакет обработчику
        if self.on_packet:
            self.on_packet(packet)

    async def _send_pong(self):
        await self.send_packet(TunnelPacket(PacketType.PONG))

    async def send_ping(self):
        await self.send_packet(TunnelPacket(PacketType.PING))

    async def start_keepalive(self):
        """Запускает цикл keepalive."""
        self._connected = True
        self._last_recv_time = time.time()
        self._keepalive_task = asyncio.ensure_future(self._keepalive_loop())
        self._timeout_task = asyncio.ensure_future(self._timeout_loop())

    async def _keepalive_loop(self):
        try:
            while self._connected:
                if time.time() - self._last_send_time > self.KEEPALIVE_INTERVAL:
                    await self.send_ping()
                await asyncio.sleep(1.0)
        except asyncio.CancelledError:
            pass

    async def _timeout_loop(self):
        try:
            while self._connected:
                if self._last_recv_time > 0:
                    elapsed = time.time() - self._last_recv_time
                    if elapsed > self.KEEPALIVE_TIMEOUT:
                        logger.error(
                            f"Таймаут соединения: нет ответа {elapsed:.1f}с"
                        )
                        self._connected = False
                        return
                await asyncio.sleep(2.0)
        except asyncio.CancelledError:
            pass

    async def stop(self):
        """Останавливает туннель."""
        if self._connected:
            try:
                await self.send_packet(TunnelPacket(PacketType.DISCONNECT))
            except Exception:
                pass
        self._connected = False
        if self._keepalive_task:
            self._keepalive_task.cancel()
        if self._timeout_task:
            self._timeout_task.cancel()
        if self._transport:
            self._transport.close()


class TunnelServerProtocol(asyncio.DatagramProtocol):
    """
    UDP-протокол для серверной стороны туннеля.

    Процесс аутентификации:
      1. Получаем AUTH-пакет в открытом виде (с salt клиента)
      2. Проверяем пароль
      3. Пересоздаём свой crypto с salt клиента
      4. Отправляем AUTH_OK зашифрованно
    """

    def __init__(self, tunnel: TunnelProtocol, password: str,
                 on_client_connected: Callable = None):
        self.tunnel = tunnel
        self.password = password
        self.on_client_connected = on_client_connected
        self._authenticated = False
        self._client_addr = None
        self._transport = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.tunnel.attach_transport(transport)
        self._transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        if not self._authenticated:
            self._handle_auth(data, addr)
            return

        # После аутентификации — обычная обработка
        if addr == self._client_addr:
            self.tunnel.handle_datagram(data, addr)

    def _handle_auth(self, data: bytes, addr: Tuple[str, int]):
        """Обрабатывает AUTH-пакет (открытый текст)."""
        try:
            # AUTH-пакет отправляется без шифрования
            packet = TunnelPacket.unpack(data)
            if packet.ptype != PacketType.AUTH:
                logger.debug(f"Пакет без аутентификации от {addr}")
                return

            # Формат payload: salt(16) + password_utf8
            if len(packet.payload) < 16:
                logger.debug(f"AUTH payload слишком короткий от {addr}")
                return

            client_salt = packet.payload[:16]
            auth_password = packet.payload[16:].decode('utf-8', errors='replace')

            if auth_password != self.password:
                logger.warning(f"Неверный пароль от {addr}")
                return

            # Аутентификация успешна — пересоздаём crypto с salt клиента
            from .crypto import create_crypto
            self.tunnel.crypto = create_crypto(self.password, client_salt)

            self._authenticated = True
            self._client_addr = addr
            self.tunnel.set_remote(addr)

            logger.info(f"Клиент аутентифицирован: {addr[0]}:{addr[1]}")

            # Отправляем AUTH_OK (уже зашифрованный)
            asyncio.ensure_future(self._send_auth_ok())

            self.tunnel._last_recv_time = time.time()
            if self.on_client_connected:
                self.on_client_connected()

            # Запускаем keepalive
            asyncio.ensure_future(self.tunnel.start_keepalive())

        except Exception as e:
            logger.debug(f"Ошибка при аутентификации от {addr}: {e}")

    async def _send_auth_ok(self):
        packet = TunnelPacket(PacketType.AUTH_OK, payload=b'OK')
        await self.tunnel.send_packet(packet)


class TunnelClientProtocol(asyncio.DatagramProtocol):
    """
    UDP-протокол для клиентской стороны туннеля.

    Процесс аутентификации:
      1. Отправляем AUTH в открытом виде (свой salt + пароль)
      2. Ждём AUTH_OK (зашифрованный с нашим salt)
      3. Туннель установлен
    """

    def __init__(self, tunnel: TunnelProtocol, password: str,
                 server_addr: Tuple[str, int],
                 on_connected: Callable = None):
        self.tunnel = tunnel
        self.password = password
        self.server_addr = server_addr
        self.on_connected = on_connected
        self._auth_retry_task = None
        self._client_salt = None

    def connection_made(self, transport: asyncio.DatagramTransport):
        self.tunnel.attach_transport(transport)
        self.tunnel.set_remote(self.server_addr)
        self._transport = transport
        asyncio.ensure_future(self._send_auth())

    async def _send_auth(self):
        """Отправляет AUTH-пакет в открытом виде с salt."""
        # Получаем salt нашего crypto-движка
        self._client_salt = self.tunnel.crypto.get_salt()

        # Формируем payload: salt(16) + password_utf8
        payload = self._client_salt + self.password.encode('utf-8')
        auth_packet = TunnelPacket(PacketType.AUTH, payload=payload)

        # Отправляем без шифрования!
        raw = auth_packet.pack()
        self.tunnel.send_raw(raw, self.server_addr)

        logger.info(f"AUTH отправлен на {self.server_addr[0]}:{self.server_addr[1]}")
        self._auth_retry_task = asyncio.ensure_future(self._auth_retry_loop())

    async def _auth_retry_loop(self):
        """Периодически повторяет AUTH."""
        try:
            for _ in range(30):
                await asyncio.sleep(2.0)
                if self.tunnel.is_connected:
                    return
                payload = self._client_salt + self.password.encode('utf-8')
                auth_packet = TunnelPacket(PacketType.AUTH, payload=payload)
                raw = auth_packet.pack()
                self.tunnel.send_raw(raw, self.server_addr)
                logger.debug("Повторная отправка AUTH...")
            logger.error("Таймаут аутентификации — сервер не ответил")
        except asyncio.CancelledError:
            pass

    def datagram_received(self, data: bytes, addr: Tuple[str, int]):
        if addr != self.server_addr:
            return

        # Пробуем расшифровать — сервер уже использует наш salt
        try:
            decrypted = self.tunnel.crypto.decrypt(data)
            packet = TunnelPacket.unpack(decrypted)
        except Exception as e:
            logger.debug(f"Ошибка расшифровки от {addr}: {e}")
            return

        if packet.ptype == PacketType.AUTH_OK:
            self.tunnel._last_recv_time = time.time()
            asyncio.ensure_future(self.tunnel.start_keepalive())
            if self._auth_retry_task:
                self._auth_retry_task.cancel()
            logger.info("Соединение установлено!")
            if self.on_connected:
                self.on_connected()
            return

        # Обычные пакеты
        self.tunnel.handle_datagram(data, addr)
