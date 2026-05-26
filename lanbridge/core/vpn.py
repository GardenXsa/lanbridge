"""
VPN движок LanBridge.

Связывает TUN-устройство и зашифрованный UDP-туннель:
  TUN (IP-пакеты) ↔ Crypto ↔ UDP ↔ Crypto ↔ TUN (IP-пакеты)

Оба компьютера видят друг друга по IP 10.13.37.x
как в обычной локальной сети.
"""

import asyncio
import struct
import time
import logging
from typing import Optional, Callable

from .crypto import create_crypto
from .tunnel import (
    TunnelProtocol, TunnelServerProtocol, TunnelClientProtocol,
    TunnelPacket, PacketType
)
from ..platform.tun_device import TUNDevice, create_tun_device, HOST_IP, CLIENT_IP, MTU

logger = logging.getLogger("lanbridge.vpn")

# Типы пакетов для VPN
PACKET_TYPE_RAW_IP = 0x50  # Сырой IP-пакет


class VPNEngine:
    """
    VPN движок — сердце LanBridge.

    Связывает два потока данных:
    1. TUN → зашифровать → UDP (исходящие пакеты)
    2. UDP → расшифровать → TUN (входящие пакеты)
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
        """Запускает пересылку TUN ↔ Tunnel."""
        self._running = True
        self.tun.start()

        # Настраиваем обработчик входящих пакетов из туннеля
        self.tunnel.on_packet = self._on_tunnel_packet

        # Запускаем чтение из TUN
        self._tun_read_task = asyncio.ensure_future(self._tun_to_tunnel_loop())

        logger.info(f"VPN запущен: {self.tun.address} ↔ tunnel")

    def stop(self):
        """Останавливает VPN."""
        self._running = False
        if self._tun_read_task:
            self._tun_read_task.cancel()

    async def _tun_to_tunnel_loop(self):
        """Читает из TUN и отправляет в туннель."""
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
                    continue  # Слишком короткий для IP

                # Отправляем в туннель как DATA_TCP с port=0, conn_id=0
                # payload = сырой IP-пакет
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
            logger.error(f"TUN→tunnel error: {e}")

    def _on_tunnel_packet(self, packet: TunnelPacket):
        """Обрабатывает входящий пакет из туннеля → пишет в TUN."""
        if packet.ptype == PacketType.DATA_TCP and packet.port == 0:
            # Сырой IP-пакет из туннеля
            asyncio.ensure_future(self._write_to_tun(packet.payload))

    async def _write_to_tun(self, ip_packet: bytes):
        """Записывает IP-пакет в TUN."""
        if not ip_packet or len(ip_packet) < 20:
            return
        try:
            await self.tun.write_packet(ip_packet)
            self._stats['tun_written'] += 1
            self._stats['bytes_recv'] += len(ip_packet)
        except Exception as e:
            logger.debug(f"TUN write error: {e}")


async def run_vpn_host(
    password: str,
    port: int = 9876,
    on_connected: Optional[Callable] = None,
    on_stats: Optional[Callable] = None,
) -> tuple:
    """
    Запускает VPN в режиме хоста.

    Возвращает: (tunnel, vpn_engine, tun_device, transport)
    """
    # Создаём TUN
    tun = create_tun_device(is_host=True)
    await tun.create()

    # Создаём туннель
    crypto = create_crypto(password)
    tunnel = TunnelProtocol(crypto)

    # VPN движок
    vpn = VPNEngine(is_host=True, tunnel=tunnel, tun=tun)

    connected_event = asyncio.Event()

    def on_client_connected():
        connected_event.set()
        vpn.start()  # Запускаем пересылку после подключения
        if on_connected:
            on_connected()

    # Запускаем UDP сервер
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: TunnelServerProtocol(tunnel, password, on_client_connected),
        local_addr=('0.0.0.0', port)
    )

    return tunnel, vpn, tun, transport, connected_event


async def run_vpn_client(
    password: str,
    server_addr: tuple,
    on_connected: Optional[Callable] = None,
) -> tuple:
    """
    Запускает VPN в режиме клиента.

    Возвращает: (tunnel, vpn_engine, tun_device, transport)
    """
    # Создаём TUN
    tun = create_tun_device(is_host=False)
    await tun.create()

    # Создаём туннель
    crypto = create_crypto(password)
    tunnel = TunnelProtocol(crypto)

    # VPN движок
    vpn = VPNEngine(is_host=False, tunnel=tunnel, tun=tun)

    connected_event = asyncio.Event()

    def on_server_connected():
        connected_event.set()
        vpn.start()  # Запускаем пересылку после подключения
        if on_connected:
            on_connected()

    # Подключаемся к серверу
    loop = asyncio.get_event_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: TunnelClientProtocol(
            tunnel, password, server_addr, on_server_connected
        ),
        local_addr=('0.0.0.0', 0)
    )

    return tunnel, vpn, tun, transport, connected_event
