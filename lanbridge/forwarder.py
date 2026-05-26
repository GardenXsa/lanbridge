"""
Модуль проброса портов LanBridge.
Перенаправляет TCP и UDP трафик через туннель.

Архитектура:
  ┌─────────────── Клиент ───────────────┐
  │                                       │
  │  Game Client → TCP :local_port        │
  │       │                              │
  │  TCPPortForwarder._local_servers     │
  │       │ (conn_id = X)                │
  │  TCPPortForwarder._connections[X]    │
  │       │                              │
  │  tunnel.send(OPEN_PORT/DATA_TCP)     │
  │       │                              │
  └───────┼──────────────────────────────┘
          │ UDP tunnel
  ┌───────┼──────────────────────────────┐
  │       ▼                              │
  │  tunnel.recv(OPEN_PORT/DATA_TCP)     │
  │       │                              │
  │  TCPPortForwarder._connections[X]    │
  │       │ (то же conn_id = X)         │
  │  TCP → 127.0.0.1:remote_port        │
  │       │                              │
  │  Game Server                         │
  └──────────────────────────────────────┘
"""

import asyncio
import struct
import logging
from typing import Dict, Optional, Tuple, Set
from .core.tunnel import TunnelProtocol, TunnelPacket, PacketType

logger = logging.getLogger("lanbridge.forwarder")


class Connection:
    """Представление одного TCP-соединения через туннель."""

    def __init__(self, conn_id: int, writer: asyncio.StreamWriter,
                 direction: str, remote_port: int = 0):
        self.conn_id = conn_id
        self.writer = writer
        self.direction = direction  # 'local' или 'remote'
        self.remote_port = remote_port
        self._read_task: Optional[asyncio.Task] = None

    def cancel_read(self):
        if self._read_task:
            self._read_task.cancel()


class TCPPortForwarder:
    """
    Проброс TCP-портов через туннель.

    Каждая сторона использует ЕДИНЫЙ _connections dict,
    где conn_id → Connection. Направление (direction) указывает,
    кто инициировал соединение:
      - 'local': локальный TCP-клиент подключился к нашему серверру
      - 'remote': мы подключились к локальному сервису по запросу из туннеля
    """

    def __init__(self, tunnel: TunnelProtocol):
        self.tunnel = tunnel
        self._servers: Dict[int, asyncio.AbstractServer] = {}
        self._connections: Dict[int, Connection] = {}
        self._pending: Dict[int, list] = {}  # conn_id → буфер данных
        self._ready_events: Dict[int, asyncio.Event] = {}  # conn_id → событие готовности
        self._next_id = 1
        self._forward_map: Dict[int, int] = {}  # local_port → remote_port

    def _allocate_id(self) -> int:
        conn_id = self._next_id
        self._next_id = (self._next_id + 1) & 0xFFFFFFFF
        if self._next_id == 0:
            self._next_id = 1
        return conn_id

    async def add_local_port(self, local_port: int, remote_port: int):
        """
        Настраивает проброс: local_port -> remote_port через туннель.
        Открывает TCP-сервер на local_port.
        """
        if local_port in self._servers:
            logger.warning(f"Порт {local_port} уже пробрасывается")
            return

        self._forward_map[local_port] = remote_port

        async def handle_client(reader: asyncio.StreamReader,
                                writer: asyncio.StreamWriter):
            conn_id = self._allocate_id()
            conn = Connection(conn_id, writer, 'local', remote_port)
            self._connections[conn_id] = conn
            peer = writer.get_extra_info('peername')
            logger.info(f"[TCP] Локальное подключение на :{local_port} "
                        f"от {peer}, conn_id={conn_id}")

            # Уведомляем удалённую сторону: открой подключение к remote_port
            await self.tunnel.send_packet(TunnelPacket(
                PacketType.OPEN_PORT,
                port=remote_port,
                conn_id=conn_id,
            ))

            # Читаем данные от локального клиента и шлём в туннель
            try:
                while True:
                    data = await reader.read(65536)
                    if not data:
                        break
                    await self.tunnel.send_packet(TunnelPacket(
                        PacketType.DATA_TCP,
                        port=remote_port,
                        conn_id=conn_id,
                        payload=data,
                    ))
            except (ConnectionResetError, BrokenPipeError, asyncio.CancelledError):
                pass
            finally:
                logger.info(f"[TCP] Локальное подключение закрыто, conn_id={conn_id}")
                self._connections.pop(conn_id, None)
                try:
                    await self.tunnel.send_packet(TunnelPacket(
                        PacketType.CLOSE_PORT,
                        port=remote_port,
                        conn_id=conn_id,
                    ))
                except Exception:
                    pass
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

        server = await asyncio.start_server(handle_client, '0.0.0.0', local_port)
        self._servers[local_port] = server
        logger.info(f"[TCP] Проброс :{local_port} -> remote:{remote_port}")

    async def handle_tunnel_packet(self, packet: TunnelPacket):
        """Обрабатывает пакет из туннеля."""
        if packet.ptype == PacketType.OPEN_PORT:
            await self._on_open_port(packet)
        elif packet.ptype == PacketType.DATA_TCP:
            self._on_data_tcp(packet)
        elif packet.ptype == PacketType.CLOSE_PORT:
            self._on_close_port(packet)

    async def _on_open_port(self, packet: TunnelPacket):
        """Удалённая сторона просит подключиться к локальному порту."""
        target_port = packet.port
        conn_id = packet.conn_id
        logger.info(f"[TCP] Удалённый запрос подключения к :{target_port}, "
                     f"conn_id={conn_id}")

        # Создаём событие готовности и буфер
        ready = asyncio.Event()
        self._ready_events[conn_id] = ready
        self._pending[conn_id] = []

        try:
            reader, writer = await asyncio.open_connection(
                '127.0.0.1', target_port
            )
            conn = Connection(conn_id, writer, 'remote', target_port)
            self._connections[conn_id] = conn

            # Сбрасываем буфер
            buffered = self._pending.pop(conn_id, [])
            for data in buffered:
                try:
                    writer.write(data)
                    await writer.drain()
                except Exception:
                    pass

            # Сигнализируем готовность
            ready.set()

            # Читаем данные от локального сервиса и отправляем обратно в туннель
            conn._read_task = asyncio.ensure_future(
                self._relay_back(conn_id, reader)
            )
        except ConnectionRefusedError:
            logger.error(f"[TCP] Не удалось подключиться к :{target_port}")
            self._pending.pop(conn_id, None)
            ready.set()  # Разблокируем ожидание
            await self.tunnel.send_packet(TunnelPacket(
                PacketType.CLOSE_PORT,
                port=target_port,
                conn_id=conn_id,
            ))

    def _on_data_tcp(self, packet: TunnelPacket):
        """Данные от удалённой стороны — записываем в локальное подключение."""
        conn_id = packet.conn_id

        # Если подключение ещё устанавливается — буферизуем
        if conn_id in self._pending:
            self._pending[conn_id].append(packet.payload)
            return

        conn = self._connections.get(conn_id)
        if conn and conn.writer and not conn.writer.is_closing():
            try:
                conn.writer.write(packet.payload)
                asyncio.ensure_future(conn.writer.drain())
            except (ConnectionResetError, BrokenPipeError):
                self._close_connection(conn_id)

    def _on_close_port(self, packet: TunnelPacket):
        """Удалённая сторона закрыла соединение."""
        self._close_connection(packet.conn_id)

    async def _relay_back(self, conn_id: int, reader: asyncio.StreamReader):
        """Читает данные от локального сервиса и отправляет в туннель."""
        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                await self.tunnel.send_packet(TunnelPacket(
                    PacketType.DATA_TCP,
                    port=0,
                    conn_id=conn_id,
                    payload=data,
                ))
        except (ConnectionResetError, asyncio.CancelledError):
            pass
        finally:
            self._close_connection(conn_id)
            await self.tunnel.send_packet(TunnelPacket(
                PacketType.CLOSE_PORT,
                port=0,
                conn_id=conn_id,
            ))

    def _close_connection(self, conn_id: int):
        """Закрывает соединение по conn_id."""
        conn = self._connections.pop(conn_id, None)
        if conn:
            conn.cancel_read()
            try:
                conn.writer.close()
                asyncio.ensure_future(conn.writer.wait_closed())
            except Exception:
                pass

    async def stop(self):
        """Останавливает все серверы и закрывает подключения."""
        for port, server in self._servers.items():
            server.close()
            await server.wait_closed()
        self._servers.clear()

        for conn_id, conn in list(self._connections.items()):
            conn.cancel_read()
            try:
                conn.writer.close()
                await conn.writer.wait_closed()
            except Exception:
                pass
        self._connections.clear()


class UDPPortForwarder:
    """
    Проброс UDP-портов через туннель.
    """

    def __init__(self, tunnel: TunnelProtocol):
        self.tunnel = tunnel
        self._local_sockets: Dict[int, asyncio.DatagramTransport] = {}
        self._remote_sockets: Dict[int, asyncio.DatagramTransport] = {}
        self._client_addrs: Dict[int, Tuple[str, int]] = {}
        self._remote_client_addrs: Dict[int, Tuple[str, int]] = {}

    async def add_local_port(self, local_port: int, remote_port: int):
        """Настраивает проброс UDP порта."""
        if local_port in self._local_sockets:
            logger.warning(f"UDP порт {local_port} уже пробрасывается")
            return

        class UDPForwardProtocol(asyncio.DatagramProtocol):
            def __init__(self, forwarder, lport, rport):
                self.forwarder = forwarder
                self.local_port = lport
                self.remote_port = rport
                self.transport = None

            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                self.forwarder._client_addrs[self.local_port] = addr
                asyncio.ensure_future(self.forwarder.tunnel.send_packet(
                    TunnelPacket(
                        PacketType.DATA_UDP,
                        port=self.remote_port,
                        conn_id=self.local_port,
                        payload=data,
                    )
                ))

        loop = asyncio.get_event_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: UDPForwardProtocol(self, local_port, remote_port),
            local_addr=('0.0.0.0', local_port)
        )
        self._local_sockets[local_port] = transport
        logger.info(f"[UDP] Проброс :{local_port} -> remote:{remote_port}")

    async def handle_tunnel_packet(self, packet: TunnelPacket):
        """Обрабатывает UDP-пакет из туннеля."""
        if packet.ptype == PacketType.DATA_UDP:
            target_port = packet.port
            source_port = packet.conn_id

            # Создаём UDP-сокет для пересылки если нужно
            if target_port not in self._remote_sockets and target_port > 0:
                await self._create_remote_udp_socket(target_port)

            if target_port > 0:
                transport = self._remote_sockets.get(target_port)
                if transport:
                    transport.sendto(packet.payload, ('127.0.0.1', target_port))
                    self._remote_client_addrs[target_port] = source_port
            else:
                # Ответ от удалённого сервиса — отправляем локальному клиенту
                transport = self._local_sockets.get(source_port)
                if transport and source_port in self._client_addrs:
                    addr = self._client_addrs[source_port]
                    transport.sendto(packet.payload, addr)

    async def _create_remote_udp_socket(self, port: int):
        """Создаёт UDP-сокет для пересылки на локальный порт."""

        class UDPRelayProtocol(asyncio.DatagramProtocol):
            def __init__(self, forwarder, p):
                self.forwarder = forwarder
                self.port = p
                self.transport = None

            def connection_made(self, transport):
                self.transport = transport

            def datagram_received(self, data, addr):
                source_port = self.forwarder._remote_client_addrs.get(
                    self.port, 0
                )
                asyncio.ensure_future(self.forwarder.tunnel.send_packet(
                    TunnelPacket(
                        PacketType.DATA_UDP,
                        port=0,  # признак ответа
                        conn_id=source_port,
                        payload=data,
                    )
                ))

        loop = asyncio.get_event_loop()
        transport, _ = await loop.create_datagram_endpoint(
            lambda: UDPRelayProtocol(self, port),
            local_addr=('0.0.0.0', 0)
        )
        self._remote_sockets[port] = transport

    async def stop(self):
        for transport in self._local_sockets.values():
            transport.close()
        self._local_sockets.clear()

        for transport in self._remote_sockets.values():
            transport.close()
        self._remote_sockets.clear()

        self._client_addrs.clear()
        self._remote_client_addrs.clear()


class PortForwarder:
    """
    Единый интерфейс для проброса TCP и UDP портов.
    """

    def __init__(self, tunnel: TunnelProtocol):
        self.tunnel = tunnel
        self.tcp = TCPPortForwarder(tunnel)
        self.udp = UDPPortForwarder(tunnel)

    def parse_port_specs(self, specs: list) -> list:
        """
        Парсит спецификации портов.
        Формат: ['7777/tcp', '7778/udp', '25565']  (по умолчанию tcp)
        Возвращает: [(local_port, remote_port, protocol), ...]
        """
        result = []
        for spec in specs:
            parts = spec.split('/')
            port_part = parts[0]
            proto = parts[1].strip().lower() if len(parts) > 1 else 'tcp'

            if ':' in port_part:
                local_str, remote_str = port_part.split(':', 1)
                local_port = int(local_str)
                remote_port = int(remote_str)
            else:
                local_port = int(port_part)
                remote_port = local_port

            if proto not in ('tcp', 'udp'):
                raise ValueError(f"Неизвестный протокол: {proto}")
            result.append((local_port, remote_port, proto))
        return result

    async def setup_ports(self, port_specs: list):
        """Настраивает проброс всех указанных портов."""
        ports = self.parse_port_specs(port_specs)
        for local_port, remote_port, proto in ports:
            if proto == 'tcp':
                await self.tcp.add_local_port(local_port, remote_port)
            elif proto == 'udp':
                await self.udp.add_local_port(local_port, remote_port)

    def handle_packet(self, packet: TunnelPacket):
        """Обрабатывает входящий пакет туннеля."""
        if packet.ptype in (PacketType.OPEN_PORT, PacketType.DATA_TCP,
                            PacketType.CLOSE_PORT):
            asyncio.ensure_future(self.tcp.handle_tunnel_packet(packet))
        elif packet.ptype == PacketType.DATA_UDP:
            asyncio.ensure_future(self.udp.handle_tunnel_packet(packet))

    async def stop(self):
        await self.tcp.stop()
        await self.udp.stop()
