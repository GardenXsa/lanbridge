"""
LanBridge VPN -- CLI interface.

Creates a virtual LAN between two computers over an encrypted UDP tunnel.
Both computers receive IPs in the 10.13.37.0/24 subnet and can communicate
as if on a physical LAN.

Usage:
  lanbridge host          -> create room, get 10.13.37.1
  lanbridge connect CODE  -> join room, get 10.13.37.2
  lanbridge games         -> game connection hints
"""

import argparse
import asyncio
import logging
import sys
import os
import secrets
import signal
import time
import socket
import urllib.request
import json
from typing import Optional

from .platform.tun_device import HOST_IP, CLIENT_IP, VPN_NETWORK

logger = logging.getLogger("lanbridge")

_shutdown_event: Optional[asyncio.Event] = None


def _has_admin() -> bool:
    """Check if running with admin/root privileges."""
    if sys.platform == 'win32':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.getuid() == 0


def _wait_on_windows():
    """Pause before exit on Windows so the window does not close instantly."""
    if sys.platform == 'win32':
        print()
        try:
            input("  Press Enter to exit...")
        except EOFError:
            pass


# ═══════════════════════════════════════════════════════════
# UTILITIES
# ═══════════════════════════════════════════════════════════

def generate_password(length: int = 16) -> str:
    alphabet = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def get_external_ip() -> Optional[str]:
    for url in ['https://api.ipify.org?format=json',
                'https://ifconfig.me/ip',
                'https://icanhazip.com']:
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'LanBridge/1.0'})
            with urllib.request.urlopen(req, timeout=5) as resp:
                text = resp.read().decode('utf-8').strip()
                if text.startswith('{'):
                    return json.loads(text).get('ip')
                parts = text.split('.')
                if len(parts) == 4 and all(p.isdigit() for p in parts):
                    return text
        except Exception:
            continue
    return None


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return '127.0.0.1'


def build_code(ip: str, port: int, password: str) -> str:
    return f"{ip}:{port}:{password}"


def parse_code(code: str):
    """Парсит: IP:PORT:ПАРОЛЬ"""
    parts = code.strip().split(':')
    if len(parts) < 3:
        raise ValueError(
            f"Неверный код: {code}\n"
            f"Формат: IP:ПОРТ:ПАРОЛЬ"
        )
    ip = parts[0]
    try:
        port = int(parts[1])
    except ValueError:
        raise ValueError(f"Порт — число, а не '{parts[1]}'")
    password = parts[2]
    return ip, port, password


# ═══════════════════════════════════════════════════════════
# ПОДСКАЗКИ ПО ИГРАМ
# ═══════════════════════════════════════════════════════════

GAME_HINTS = {
    'minecraft': 'Multiplayer → Direct Connect → 10.13.37.1:25565',
    'terraria': 'Multiplayer → Join via IP → 10.13.37.1:7777',
    'valheim': 'Join Game → Join IP → 10.13.37.1:2456',
    'left4dead2': 'Console → connect 10.13.37.1:27015',
    'dont-starve': 'Browse Games → 10.13.37.1:10999',
    'raft': 'Join via IP → 10.13.37.1:7777',
    'palworld': 'Connect → 10.13.37.1:8211',
    'project-zomboid': 'Join Server → 10.13.37.1:16261',
    'satisfactory': 'Server Manager → 10.13.37.1:15777',
    'ark': 'Join via IP → 10.13.37.1:7777',
    'rust': 'Console → connect 10.13.37.1:28015',
    'core-keeper': 'Join via IP → 10.13.37.1:1234',
    'starbound': 'Multiplayer → 10.13.37.1:21025',
    'unturned': 'Connect → 10.13.37.1:27015',
    '7dtd': 'Connect → 10.13.37.1:26900',
}


# ═══════════════════════════════════════════════════════════
# КОМАНДЫ
# ═══════════════════════════════════════════════════════════

async def cmd_host(args):
    """Создаёт VPN комнату."""
    password = args.password or generate_password()
    port = args.port or 9876

    # Определяем IP
    print("  Detecting IP...")
    ext_ip = get_external_ip()
    local_ip = get_local_ip()
    display_ip = args.ip or ext_ip or local_ip

    # Проверяем права
    if not _has_admin():
        print()
        if sys.platform == 'win32':
            print("  [!] Administrator rights required to create virtual network adapter.")
            print("  [!] Right-click the executable -> Run as administrator")
        else:
            print("  [!] Root required to create virtual network adapter.")
            print("  [!] Run with sudo:")
            print("  [!]   sudo lanbridge host")
        print()
        _wait_on_windows()
        return

    print()
    print("  +=====================================================+")
    print("  |            LanBridge VPN -- HOST                    |")
    print("  +=====================================================+")
    print(f"  |  Your IP:       {display_ip:<39}|")
    print(f"  |  Port:          {port:<39}|")
    print(f"  |  Password:      {password:<39}|")
    print("  |                                                     |")
    print(f"  |  Your virtual IP:   {HOST_IP:<32}|")
    print("  |                                                      |")
    print("  +=====================================================+")
    print("  |  Send to friend:                                    |")
    print("  |                                                      |")
    exe = 'lanbridge' if sys.platform != 'win32' else 'lanbridge-windows-amd64.exe'
    code = build_code(display_ip, port, password)
    print(f"  |  {exe} connect {code}")
    print("  |                                                      |")
    print("  +=====================================================+")
    print()

    if ext_ip and ext_ip != local_ip:
        print(f"  Local IP: {local_ip} (if friend is on the same WiFi)")
        print()

    # Создаём VPN
    from .core.vpn import run_vpn_host

    connected = asyncio.Event()

    def on_connected():
        print()
        print("  ===================================================")
        print(f"    Friend connected! Their IP: {CLIENT_IP}")
        print("    You are in the same virtual LAN!")
        print("  ===================================================")
        print()
        print("  Connect in game to: 10.13.37.1  (or 10.13.37.2)")
        print("  (like a regular LAN -- any ports, any protocols)")
        print()

    try:
        tunnel, vpn, tun, transport, conn_event = await run_vpn_host(
            password=password,
            port=port,
            on_connected=on_connected,
        )
    except RuntimeError as e:
        print(f"\n  [!] {e}\n")
        _wait_on_windows()
        return

    print(f"  Virtual interface: {tun.name}")
    print(f"  IP: {HOST_IP}")
    print(f"  Waiting for friend... (Ctrl+C to stop)")
    print()

    global _shutdown_event
    _shutdown_event = asyncio.Event()

    stats_task = asyncio.ensure_future(_print_stats(vpn, tunnel))

    try:
        await _shutdown_event.wait()
    except asyncio.CancelledError:
        pass
    finally:
        stats_task.cancel()
        vpn.stop()
        await tunnel.stop()
        tun.stop()
        transport.close()
        print("\n  VPN stopped.")
        _wait_on_windows()


async def cmd_connect(args):
    """Подключается к VPN комнате."""
    try:
        ip, port, password = parse_code(args.code)
    except ValueError as e:
        print(f"\n  {e}\n")
        return

    # Проверяем права
    if not _has_admin():
        print()
        if sys.platform == 'win32':
            print("  [!] Administrator rights required to create virtual network adapter.")
            print("  [!] Right-click the executable -> Run as administrator")
        else:
            print("  [!] Root required to create virtual network adapter.")
            print("  [!] Run with sudo:")
            print(f"  [!]   sudo lanbridge connect {args.code}")
        print()
        _wait_on_windows()
        return

    print()
    print("  +=====================================================+")
    print("  |            LanBridge VPN -- CLIENT                  |")
    print("  +=====================================================+")
    print(f"  |  Server:      {ip}:{port:<36}|")
    print(f"  |  Password:    {password:<39}|")
    print("  |                                                      |")
    print(f"  |  Your virtual IP:   {CLIENT_IP:<32}|")
    print("  +=====================================================+")
    print()

    # Создаём VPN
    from .core.vpn import run_vpn_client

    def on_connected():
        print()
        print("  ===================================================")
        print("    Connected! You are in the same virtual LAN!")
        print("  ===================================================")
        print()
        print("  Host IP: 10.13.37.1")
        print("  Your IP: 10.13.37.2")
        print()
        print("  Connect in game to: 10.13.37.1")
        print("  (like a regular LAN -- any ports, any protocols)")
        print()

    try:
        tunnel, vpn, tun, transport, conn_event = await run_vpn_client(
            password=password,
            server_addr=(ip, port),
            on_connected=on_connected,
        )
    except RuntimeError as e:
        print(f"\n  [!] {e}\n")
        _wait_on_windows()
        return

    print(f"  Virtual interface: {tun.name}")
    print(f"  IP: {CLIENT_IP}")
    print(f"  Connecting to {ip}:{port}...")
    print(f"  (Ctrl+C to disconnect)")
    print()

    global _shutdown_event
    _shutdown_event = asyncio.Event()

    stats_task = asyncio.ensure_future(_print_stats(vpn, tunnel))

    try:
        await _shutdown_event.wait()
    except asyncio.CancelledError:
        pass
    finally:
        stats_task.cancel()
        vpn.stop()
        await tunnel.stop()
        tun.stop()
        transport.close()
        print("\n  VPN stopped.")
        _wait_on_windows()


def cmd_games(args=None):
    """Game connection hints."""
    print()
    print("  +=====================================================+")
    print("  |  Connect to host in any game:                       |")
    print("  |  Use IP: 10.13.37.1                                 |")
    print("  +=====================================================+")
    print()

    for game, hint in sorted(GAME_HINTS.items()):
        name = game.replace('-', ' ').title()
        print(f"    {name:<22} {hint}")

    print()
    print("    Any other game -- just connect to 10.13.37.1")
    print("    on the required port. VPN forwards everything.")
    print()
    _wait_on_windows()


async def cmd_relay(args):
    """Relay-сервер для NAT."""
    from .relay import run_relay_server
    port = args.port or 9876

    print()
    print("  LanBridge Relay Server")
    print(f"  Port: {port}")
    print("  Forwarding encrypted packets between peers.")
    print()

    await run_relay_server(args.bind, port)


async def _print_stats(vpn, tunnel):
    """Периодически печатает статистику."""
    try:
        while True:
            await asyncio.sleep(15)
            if tunnel.is_connected:
                s = vpn.stats
                sent_mb = s['bytes_sent'] / (1024 * 1024)
                recv_mb = s['bytes_recv'] / (1024 * 1024)
                print(f"  [стат] ↑ {sent_mb:.1f} МБ | ↓ {recv_mb:.1f} МБ")
    except asyncio.CancelledError:
        pass


# ═══════════════════════════════════════════════════════════
# ТОЧКА ВХОДА
# ═══════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        prog='lanbridge',
        description='LanBridge VPN — виртуальная локальная сеть для игр',
    )

    parser.add_argument('-v', '--verbose', action='store_true')

    sub = parser.add_subparsers(dest='command')

    # host
    hp = sub.add_parser('host', help='Создать VPN комнату')
    hp.add_argument('-p', '--password', type=str, default=None,
                    help='Пароль (автогенерация)')
    hp.add_argument('--port', type=int, default=9876,
                    help='UDP порт (по умолчанию 9876)')
    hp.add_argument('--ip', type=str, default=None,
                    help='Внешний IP (авто)')

    # connect
    cp = sub.add_parser('connect', help='Подключиться к комнате')
    cp.add_argument('code', type=str,
                    help='Код от хоста: IP:ПОРТ:ПАРОЛЬ')

    # games
    sub.add_parser('games', help='Подсказки по играм')

    # relay
    rp = sub.add_parser('relay', help='Relay-сервер (для VPS)')
    rp.add_argument('--port', type=int, default=9876)
    rp.add_argument('--bind', type=str, default='0.0.0.0')

    args = parser.parse_args()

    if not args.command:
        print()
        print("  LanBridge VPN -- virtual LAN for gaming")
        print()
        if sys.platform == 'win32':
            print("  1. Create a room:       lanbridge host")
            print("  2. Send friend:         lanbridge connect IP:PORT:PASSWORD")
        else:
            print("  1. Create a room:       sudo lanbridge host")
            print("  2. Send friend:         sudo lanbridge connect IP:PORT:PASSWORD")
        print("  3. Play! Both see each other at IP 10.13.37.x")
        print()
        print("  Game hints:  lanbridge games")
        print()
        _wait_on_windows()
        return

    # Настройка логирования
    level = logging.DEBUG if getattr(args, 'verbose', False) else logging.WARNING
    logging.basicConfig(level=level, format='')

    def signal_handler(sig, frame):
        global _shutdown_event
        if _shutdown_event:
            _shutdown_event.set()

    signal.signal(signal.SIGINT, signal_handler)

    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    if args.command == 'host':
        asyncio.run(cmd_host(args))
    elif args.command == 'connect':
        asyncio.run(cmd_connect(args))
    elif args.command == 'games':
        cmd_games(args)
        # it's not async
    elif args.command == 'relay':
        asyncio.run(cmd_relay(args))
