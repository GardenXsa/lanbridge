"""
TUN-устройство для LanBridge VPN.

Создаёт виртуальный сетевой интерфейс:
  - Linux: /dev/net/tun
  - Windows: wintun.dll (автозагрузка если нет)

Оба компьютера получают IP в сети 10.13.37.0/24:
  - Хост:    10.13.37.1
  - Клиент:  10.13.37.2

Игры видят друг друга как в локалке — никаких портов настраивать не нужно.
"""

import os
import sys
import struct
import subprocess
import logging
import asyncio
import platform
from typing import Optional

logger = logging.getLogger("lanbridge.tun")

# ─── Конфигурация виртуальной сети ───
VPN_NETWORK = "10.13.37"
VPN_MASK = "255.255.255.0"
VPN_PREFIX = 24
HOST_IP = f"{VPN_NETWORK}.1"
CLIENT_IP = f"{VPN_NETWORK}.2"
MTU = 1400


class TUNDevice:
    """
    Виртуальное TUN-устройство.

    Читает/пишет IP-пакеты напрямую —
    любой протокол, любой порт, любая игра.
    """

    def __init__(self, address: str, peer_address: str):
        self.address = address
        self.peer_address = peer_address
        self.name = ""
        self._fd = None          # Linux: файловый дескриптор
        self._read_queue = None  # asyncio.Queue для пакетов
        self._write_queue = None
        self._running = False
        self._read_task = None
        self._write_task = None
        # Windows
        self._wintun = None
        self._adapter = None
        self._session = None
        self._read_thread = None

    @property
    def is_open(self) -> bool:
        return self._fd is not None or self._session is not None

    async def create(self):
        """Создаёт TUN-устройство."""
        if sys.platform == 'linux':
            await self._create_linux()
        elif sys.platform == 'win32':
            await self._create_windows()
        else:
            raise RuntimeError(
                f"Платформа '{sys.platform}' не поддерживается.\n"
                f"Поддерживаются: Linux, Windows"
            )

    # ═══════════════════════════════════════════════
    # Linux: /dev/net/tun
    # ═══════════════════════════════════════════════

    async def _create_linux(self):
        """Создаёт TUN через /dev/net/tun."""
        import fcntl

        TUNSETIFF = 0x400454ca
        IFF_TUN = 0x0001
        IFF_NO_PI = 0x1000

        try:
            self._fd = os.open('/dev/net/tun', os.O_RDWR | os.O_NONBLOCK)
        except FileNotFoundError:
            raise RuntimeError(
                "/dev/net/tun не найден. Нужно:\n"
                "  sudo modprobe tun\n"
                "  sudo mkdir -p /dev/net\n"
                "  sudo mknod /dev/net/tun c 10 200"
            )
        except PermissionError:
            raise RuntimeError(
                "Нет доступа к /dev/net/tun. Запусти через sudo:\n"
                "  sudo lanbridge host minecraft"
            )

        # Создаём интерфейс
        ifr = struct.pack('16sH', b'lanbridge%d', IFF_TUN | IFF_NO_PI)
        try:
            ifr = fcntl.ioctl(self._fd, TUNSETIFF, ifr)
        except OSError as e:
            os.close(self._fd)
            self._fd = None
            raise RuntimeError(f"Не удалось создать TUN: {e}")

        self.name = ifr[:16].decode().rstrip('\x00')

        # Настраиваем IP-адрес
        try:
            subprocess.run(
                ['ip', 'addr', 'add', f'{self.address}/{VPN_PREFIX}', 'dev', self.name],
                check=True, capture_output=True, text=True
            )
        except subprocess.CalledProcessError as e:
            # Адрес уже может быть назначен — это ок
            if 'File exists' not in (e.stderr or ''):
                logger.warning(f"ip addr add: {e.stderr}")

        # Поднимаем интерфейс
        subprocess.run(
            ['ip', 'link', 'set', self.name, 'up'],
            check=True, capture_output=True
        )

        # MTU
        subprocess.run(
            ['ip', 'link', 'set', self.name, 'mtu', str(MTU)],
            check=False, capture_output=True
        )

        logger.info(f"TUN {self.name} создан: {self.address}/{VPN_PREFIX}")

    # ═══════════════════════════════════════════════
    # Windows: wintun.dll
    # ═══════════════════════════════════════════════

    async def _create_windows(self):
        """Создаёт TUN через wintun.dll (от WireGuard)."""
        import ctypes
        from ctypes import wintypes
        import urllib.request
        import zipfile
        import io

        # Ищем wintun.dll
        wintun_path = self._find_wintun()
        if not wintun_path:
            # Пробуем скачать
            print("  Скачиваю wintun.dll...")
            wintun_path = await self._download_wintun()
            if not wintun_path:
                raise RuntimeError(
                    "Не удалось найти wintun.dll.\n"
                    "Скачай с https://www.wintun.net/ и положи рядом с lanbridge"
                )

        # Загружаем библиотеку
        try:
            self._wintun = ctypes.WinDLL(wintun_path)
        except OSError as e:
            raise RuntimeError(f"Не удалось загрузить wintun.dll: {e}")

        # Определяем типы
        WINTUN_ADAPTER_HANDLE = ctypes.c_void_p
        WINTUN_SESSION_HANDLE = ctypes.c_void_p
        GUID = ctypes.c_byte * 16

        # WintunCreateAdapter
        self._wintun.WintunCreateAdapter.restype = WINTUN_ADAPTER_HANDLE
        self._wintun.WintunCreateAdapter.argtypes = [
            ctypes.c_wchar_p,  # name
            ctypes.c_wchar_p,  # tunnel type
            ctypes.POINTER(GUID)  # GUID
        ]

        # WintunStartSession
        self._wintun.WintunStartSession.restype = WINTUN_SESSION_HANDLE
        self._wintun.WintunStartSession.argtypes = [
            WINTUN_ADAPTER_HANDLE,  # adapter
            wintypes.DWORD  # capacity
        ]

        # WintunReceivePacket
        self._wintun.WintunReceivePacket.restype = ctypes.c_void_p
        self._wintun.WintunReceivePacket.argtypes = [
            WINTUN_SESSION_HANDLE,
            ctypes.POINTER(wintypes.DWORD)
        ]

        # WintunSendPacket
        self._wintun.WintunSendPacket.restype = None
        self._wintun.WintunSendPacket.argtypes = [
            WINTUN_SESSION_HANDLE,
            wintypes.LPCVOID,
            wintypes.DWORD
        ]

        # WintunReleaseReceivePacket
        self._wintun.WintunReleaseReceivePacket.restype = None
        self._wintun.WintunReleaseReceivePacket.argtypes = [
            WINTUN_SESSION_HANDLE,
            ctypes.c_void_p
        ]

        # WintunGetReadWaitEvent
        self._wintun.WintunGetReadWaitEvent.restype = wintypes.HANDLE
        self._wintun.WintunGetReadWaitEvent.argtypes = [
            WINTUN_SESSION_HANDLE
        ]

        # Создаём адаптер
        self._adapter = self._wintun.WintunCreateAdapter(
            "LanBridge", "LanBridge", None
        )
        if not self._adapter:
            raise RuntimeError("Не удалось создать wintun адаптер. Запусти от имени администратора.")

        # Стартуем сессию
        self._session = self._wintun.WintunStartSession(self._adapter, 0x400000)
        if not self._session:
            raise RuntimeError("Не удалось запустить wintun сессию")

        self.name = "LanBridge"

        # Настраиваем IP через netsh
        subprocess.run(
            ['netsh', 'interface', 'ip', 'set', 'address',
             self.name, 'static', self.address, VPN_MASK],
            check=False, capture_output=True
        )

        logger.info(f"wintun создан: {self.address}/{VPN_PREFIX}")

    def _find_wintun(self) -> Optional[str]:
        """Ищет wintun.dll в пути."""
        # Текущая директория
        if os.path.exists('wintun.dll'):
            return 'wintun.dll'
        # Рядом с исполняемым файлом
        exe_dir = os.path.dirname(sys.executable)
        path = os.path.join(exe_dir, 'wintun.dll')
        if os.path.exists(path):
            return path
        # В PATH
        for dir_path in os.environ.get('PATH', '').split(';'):
            path = os.path.join(dir_path, 'wintun.dll')
            if os.path.exists(path):
                return path
        return None

    async def _download_wintun(self) -> Optional[str]:
        """Скачивает wintun.dll."""
        import urllib.request
        import zipfile
        import io
        import tempfile

        try:
            url = "https://www.wintun.net/builds/wintun-0.14.1.zip"
            req = urllib.request.Request(url, headers={'User-Agent': 'LanBridge'})
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = resp.read()

            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                # Ищем нужную архитектуру
                arch = platform.machine().lower()
                if arch in ('amd64', 'x86_64'):
                    dll_path = 'wintun/bin/amd64/wintun.dll'
                elif arch in ('x86', 'i386', 'i686'):
                    dll_path = 'wintun/bin/x86/wintun.dll'
                elif arch in ('arm64', 'aarch64'):
                    dll_path = 'wintun/bin/arm64/wintun.dll'
                else:
                    dll_path = 'wintun/bin/amd64/wintun.dll'

                dll_data = zf.read(dll_path)
                target = os.path.join(os.path.dirname(sys.executable), 'wintun.dll')
                with open(target, 'wb') as f:
                    f.write(dll_data)
                return target
        except Exception as e:
            logger.error(f"Не удалось скачать wintun: {e}")
            return None

    # ═══════════════════════════════════════════════
    # Чтение/запись пакетов
    # ═══════════════════════════════════════════════

    async def read_packet(self) -> bytes:
        """Читает один IP-пакет из TUN."""
        if sys.platform == 'linux':
            return await self._read_linux()
        elif sys.platform == 'win32':
            return await self._read_windows()

    async def _read_linux(self) -> bytes:
        """Читает пакет из /dev/net/tun."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._read_linux_blocking)

    def _read_linux_blocking(self) -> bytes:
        """Блокирующее чтение из TUN fd."""
        while self._running:
            try:
                data = os.read(self._fd, 65535)
                return data
            except BlockingIOError:
                import time
                time.sleep(0.001)
                continue
            except OSError:
                return b''
        return b''

    async def _read_windows(self) -> bytes:
        """Читает пакет из wintun."""
        import ctypes
        from ctypes import wintypes

        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._read_windows_blocking)

    def _read_windows_blocking(self) -> bytes:
        """Блокирующее чтение из wintun."""
        import ctypes
        from ctypes import wintypes

        size = wintypes.DWORD()
        while self._running:
            ptr = self._wintun.WintunReceivePacket(self._session, ctypes.byref(size))
            if ptr:
                data = ctypes.string_at(ptr, size.value)
                self._wintun.WintunReleaseReceivePacket(self._session, ptr)
                return data

            # Ждём события
            event = self._wintun.WintunGetReadWaitEvent(self._session)
            if event:
                import time
                time.sleep(0.001)
            else:
                import time
                time.sleep(0.01)

        return b''

    async def write_packet(self, packet: bytes):
        """Записывает IP-пакет в TUN."""
        if not packet:
            return

        if sys.platform == 'linux':
            await self._write_linux(packet)
        elif sys.platform == 'win32':
            await self._write_windows(packet)

    async def _write_linux(self, packet: bytes):
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, os.write, self._fd, packet)

    async def _write_windows(self, packet: bytes):
        import ctypes
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._write_windows_blocking, packet)

    def _write_windows_blocking(self, packet: bytes):
        import ctypes
        from ctypes import wintypes

        buf = ctypes.create_string_buffer(packet, len(packet))
        self._wintun.WintunAllocateSendPacket.restype = ctypes.c_void_p
        self._wintun.WintunAllocateSendPacket.argtypes = [
            ctypes.c_void_p, wintypes.DWORD
        ]

        ptr = self._wintun.WintunAllocateSendPacket(self._session, len(packet))
        if ptr:
            ctypes.memmove(ptr, buf, len(packet))
            self._wintun.WintunSendPacket(self._session, ptr, len(packet))

    # ═══════════════════════════════════════════════
    # Жизненный цикл
    # ═══════════════════════════════════════════════

    def start(self):
        """Запускает чтение."""
        self._running = True

    def stop(self):
        """Останавливает и закрывает устройство."""
        self._running = False

        if sys.platform == 'linux' and self._fd is not None:
            try:
                os.close(self._fd)
            except Exception:
                pass
            self._fd = None

            # Удаляем интерфейс
            subprocess.run(
                ['ip', 'link', 'del', self.name],
                check=False, capture_output=True
            )

        elif sys.platform == 'win32':
            if self._session and self._wintun:
                try:
                    self._wintun.WintunEndSession(self._session)
                except Exception:
                    pass
                self._session = None

            if self._adapter and self._wintun:
                try:
                    self._wintun.WintunCloseAdapter(self._adapter)
                except Exception:
                    pass
                self._adapter = None


def create_tun_device(is_host: bool) -> TUNDevice:
    """
    Создаёт TUN-устройство с правильным IP.

    Хост:    10.13.37.1
    Клиент:  10.13.37.2
    """
    if is_host:
        return TUNDevice(HOST_IP, CLIENT_IP)
    else:
        return TUNDevice(CLIENT_IP, HOST_IP)
