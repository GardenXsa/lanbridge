"""
LanBridge VPN - Virtual LAN for gaming.

Like Radmin VPN, but yours.
Both computers get IPs in virtual network 10.13.37.x
and see each other as if on the same LAN.

Usage:
  lanbridge host          -> create a room, get 10.13.37.1
  lanbridge connect CODE  -> connect to room, get 10.13.37.2
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
import subprocess
import ctypes
from typing import Optional

from .platform.tun_device import HOST_IP, CLIENT_IP, VPN_NETWORK

logger = logging.getLogger("lanbridge")

_shutdown_event: Optional[asyncio.Event] = None


# ================================================================
# UTILITIES
# ================================================================

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
    """Parse connection code: IP:PORT:PASSWORD"""
    parts = code.strip().split(':')
    if len(parts) < 3:
        raise ValueError(
            f"Invalid code: {code}\n"
            f"Format: IP:PORT:PASSWORD"
        )
    ip = parts[0]
    try:
        port = int(parts[1])
    except ValueError:
        raise ValueError(f"Port must be a number, not '{parts[1]}'")
    password = parts[2]
    return ip, port, password


def is_admin() -> bool:
    """Check if running with admin/root privileges."""
    if sys.platform == 'win32':
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    else:
        return os.getuid() == 0


def open_windows_firewall(port: int, protocol: str = 'UDP') -> bool:
    """Add a Windows Firewall rule to allow incoming traffic."""
    if sys.platform != 'win32':
        return True
    try:
        # Check if rule already exists
        check = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'show', 'rule',
             f'name=LanBridge VPN {protocol} {port}'],
            capture_output=True, text=True
        )
        if check.returncode == 0:
            # Rule exists
            return True

        # Add the rule
        result = subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
             f'name=LanBridge VPN {protocol} {port}',
             f'dir=in', f'action=allow', f'protocol={protocol}',
             f'localport={port}', 'enable=yes',
             f'description=LanBridge VPN virtual LAN'],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            print(f"  [+] Firewall rule added: {protocol} port {port}")
            return True
        else:
            print(f"  [!] Could not add firewall rule: {result.stderr.strip()}")
            return False
    except Exception as e:
        print(f"  [!] Firewall rule error: {e}")
        return False


def remove_windows_firewall(port: int, protocol: str = 'UDP') -> bool:
    """Remove the Windows Firewall rule."""
    if sys.platform != 'win32':
        return True
    try:
        subprocess.run(
            ['netsh', 'advfirewall', 'firewall', 'delete', 'rule',
             f'name=LanBridge VPN {protocol} {port}'],
            capture_output=True, text=True
        )
        return True
    except Exception:
        return False


# ================================================================
# GAME HINTS
# ================================================================

GAME_HINTS = {
    'minecraft': 'Multiplayer -> Direct Connect -> 10.13.37.1:25565',
    'terraria': 'Multiplayer -> Join via IP -> 10.13.37.1:7777',
    'valheim': 'Join Game -> Join IP -> 10.13.37.1:2456',
    'left4dead2': 'Console -> connect 10.13.37.1:27015',
    'dont-starve': 'Browse Games -> 10.13.37.1:10999',
    'raft': 'Join via IP -> 10.13.37.1:7777',
    'palworld': 'Connect -> 10.13.37.1:8211',
    'project-zomboid': 'Join Server -> 10.13.37.1:16261',
    'satisfactory': 'Server Manager -> 10.13.37.1:15777',
    'ark': 'Join via IP -> 10.13.37.1:7777',
    'rust': 'Console -> connect 10.13.37.1:28015',
    'core-keeper': 'Join via IP -> 10.13.37.1:1234',
    'starbound': 'Multiplayer -> 10.13.37.1:21025',
    'unturned': 'Connect -> 10.13.37.1:27015',
    '7dtd': 'Connect -> 10.13.37.1:26900',
}


# ================================================================
# COMMANDS
# ================================================================

async def cmd_host(args):
    """Create a VPN room."""
    password = args.password or generate_password()
    port = args.port or 9876
    upnp_handler = None

    # Detect IP
    print("  Detecting IP...")
    ext_ip = get_external_ip()
    local_ip = get_local_ip()
    display_ip = args.ip or ext_ip or local_ip

    # Check admin rights
    if not is_admin():
        print()
        if sys.platform == 'win32':
            print("  [!] Admin privileges required to create virtual network adapter.")
            print("  [!] Right-click lanbridge.exe -> Run as Administrator")
        else:
            print("  [!] Root required to create virtual network adapter.")
            print("  [!] Run with sudo:")
            print(f"  [!]   sudo lanbridge host")
        print()
        return False

    # Open Windows Firewall
    if sys.platform == 'win32':
        print("  Opening Windows Firewall...")
        fw_result = open_windows_firewall(port, 'UDP')
        if fw_result:
            print(f"  [+] Windows Firewall: UDP {port} allowed")
        else:
            print(f"  [!] Windows Firewall: could not add rule (may need admin)")

    # UPnP port forwarding (auto port forward on router)
    behind_nat = ext_ip and ext_ip != local_ip
    if behind_nat:
        print(f"  You are behind NAT (local: {local_ip}, external: {ext_ip})")
        print("  Trying UPnP port forwarding...")
        try:
            from .upnp import setup_upnp
            upnp_handler = setup_upnp(port, 'UDP')
        except Exception as e:
            print(f"  [!] UPnP failed: {e}")

    print()
    print("  +=====================================================+")
    print("  |            LanBridge VPN -- HOST                    |")
    print("  +=====================================================+")
    print(f"  |  Your IP:       {display_ip:<37}|")
    print(f"  |  Port:          {port:<37}|")
    print(f"  |  Password:      {password:<37}|")
    print("  |                                                     |")
    print(f"  |  Your virtual IP:   {HOST_IP:<30}|")
    print("  |                                                     |")
    print("  +=====================================================+")
    print("  |  Send to friend:                                    |")
    print("  |                                                     |")

    if sys.platform == 'win32':
        exe_name = 'lanbridge-windows-amd64.exe'
    else:
        exe_name = 'lanbridge'

    code = build_code(display_ip, port, password)
    print(f"  |  {exe_name} connect {code}")
    print("  |                                                     |")
    print("  +=====================================================+")
    print()

    if behind_nat:
        if upnp_handler:
            print(f"  [+] UPnP: UDP {port} forwarded on your router")
        else:
            print(f"  [!] BEHIND NAT - friend may not be able to connect!")
            print(f"  [!] Solutions:")
            print(f"  [!]   1. Enable UPnP in your router settings")
            print(f"  [!]   2. Or manually forward UDP {port} -> {local_ip}:{port}")
            print(f"  [!]      (router admin page usually at 192.168.1.1)")
        print()
    elif ext_ip and ext_ip == local_ip:
        print(f"  [+] You have a public IP - friends can connect directly!")
        print()

    # Create VPN
    from .core.vpn import run_vpn_host

    connected = asyncio.Event()

    def on_connected():
        print()
        print("  ========================================================")
        print(f"    Friend connected! Virtual IP: {CLIENT_IP}")
        print("    You are on the same virtual LAN!")
        print("  ========================================================")
        print()
        print("  Connect in game to: 10.13.37.1  (or 10.13.37.2)")
        print("  (works like real LAN - any port, any protocol)")
        print()

    try:
        tunnel, vpn, tun, transport, conn_event = await run_vpn_host(
            password=password,
            port=port,
            on_connected=on_connected,
        )
    except Exception as e:
        print(f"\n  [!] Failed to create VPN: {e}")
        print()
        _print_troubleshooting('host', port)
        if upnp_handler:
            upnp_handler.cleanup()
        return False

    print(f"  Virtual interface created: {tun.name}")
    print(f"  IP: {HOST_IP}")
    print(f"  Waiting for friend... (Ctrl+C to stop)")
    print()

    global _shutdown_event
    _shutdown_event = asyncio.Event()

    # Set up signal handlers
    loop = asyncio.get_event_loop()

    def on_disconnect():
        """Called when the remote peer disconnects."""
        print()
        print("  [!] Friend disconnected.")
        if _shutdown_event:
            _shutdown_event.set()

    # Monitor tunnel connection
    stats_task = asyncio.ensure_future(_print_stats(vpn, tunnel))
    monitor_task = asyncio.ensure_future(_monitor_connection(tunnel, on_disconnect))

    try:
        await _shutdown_event.wait()
    except asyncio.CancelledError:
        pass
    finally:
        stats_task.cancel()
        monitor_task.cancel()
        vpn.stop()
        await tunnel.stop()
        tun.stop()
        transport.close()
        # Clean up firewall rule
        if sys.platform == 'win32':
            remove_windows_firewall(port, 'UDP')
        # Clean up UPnP port mapping
        if upnp_handler:
            upnp_handler.cleanup()
            print("  UPnP port mapping removed.")
        print("\n  VPN stopped.")

    return True


async def cmd_connect(args):
    """Connect to a VPN room."""
    try:
        ip, port, password = parse_code(args.code)
    except ValueError as e:
        print(f"\n  {e}\n")
        return False

    # Check admin rights
    if not is_admin():
        print()
        if sys.platform == 'win32':
            print("  [!] Admin privileges required to create virtual network adapter.")
            print("  [!] Right-click lanbridge.exe -> Run as Administrator")
        else:
            print("  [!] Root required to create virtual network adapter.")
            print("  [!] Run with sudo:")
            print(f"  [!]   sudo lanbridge connect {args.code}")
        print()
        return False

    print()
    print("  +=====================================================+")
    print("  |            LanBridge VPN -- CLIENT                  |")
    print("  +=====================================================+")
    print(f"  |  Server:     {ip}:{port:<33}|")
    print(f"  |  Password:   {password:<40}|")
    print("  |                                                     |")
    print(f"  |  Your virtual IP:  {CLIENT_IP:<30}|")
    print("  +=====================================================+")
    print()

    # Create VPN
    from .core.vpn import run_vpn_client

    def on_connected():
        print()
        print("  ========================================================")
        print("    Connected! You are on the same virtual LAN!")
        print("  ========================================================")
        print()
        print("  Host IP:  10.13.37.1")
        print("  Your IP:  10.13.37.2")
        print()
        print("  Connect in game to: 10.13.37.1")
        print("  (like real LAN - any port, any protocol)")
        print()

    try:
        tunnel, vpn, tun, transport, conn_event = await run_vpn_client(
            password=password,
            server_addr=(ip, port),
            on_connected=on_connected,
        )
    except Exception as e:
        print(f"\n  [!] Failed to create VPN: {e}")
        print()
        _print_troubleshooting('connect', port, ip)
        return False

    print(f"  Virtual interface: {tun.name}")
    print(f"  IP: {CLIENT_IP}")
    print(f"  Connecting to {ip}:{port}...")
    print(f"  (Ctrl+C to disconnect)")
    print()

    global _shutdown_event
    _shutdown_event = asyncio.Event()

    # Monitor tunnel connection
    stats_task = asyncio.ensure_future(_print_stats(vpn, tunnel))

    def on_disconnect():
        print()
        print("  [!] Disconnected from host.")
        if _shutdown_event:
            _shutdown_event.set()

    monitor_task = asyncio.ensure_future(_monitor_connection(tunnel, on_disconnect))

    try:
        await _shutdown_event.wait()
    except asyncio.CancelledError:
        pass
    finally:
        stats_task.cancel()
        monitor_task.cancel()
        vpn.stop()
        await tunnel.stop()
        tun.stop()
        transport.close()
        print("\n  VPN stopped.")

    return True


def cmd_games(args=None):
    """Game connection hints."""
    print()
    print("  +=====================================================+")
    print("  |  Connect to host in any game using:                 |")
    print("  |  IP: 10.13.37.1                                     |")
    print("  +=====================================================+")
    print("  |                                                     |")

    for game, hint in sorted(GAME_HINTS.items()):
        name = game.replace('-', ' ').title()
        print(f"  |  {name:<22} {hint[:35]:<35}|")

    print("  |                                                     |")
    print("  |  Any other game - just connect to 10.13.37.1       |")
    print("  |  on the required port. VPN tunnels EVERYTHING.     |")
    print("  +=====================================================+")
    print()


async def cmd_relay(args):
    """Relay server for NAT traversal."""
    from .relay import run_relay_server
    port = args.port or 9876

    print()
    print("  LanBridge Relay Server")
    print(f"  Port: {port}")
    print(f"  Relays encrypted packets between peers.")
    print()

    await run_relay_server(args.bind, port)


async def _print_stats(vpn, tunnel):
    """Periodically print statistics."""
    try:
        while True:
            await asyncio.sleep(15)
            if tunnel.is_connected:
                s = vpn.stats
                sent_mb = s['bytes_sent'] / (1024 * 1024)
                recv_mb = s['bytes_recv'] / (1024 * 1024)
                print(f"  [stats] up {sent_mb:.1f} MB | down {recv_mb:.1f} MB")
    except asyncio.CancelledError:
        pass


async def _monitor_connection(tunnel, on_disconnect):
    """Monitor tunnel connection and notify on disconnect."""
    try:
        # Wait until connection is established first
        while not tunnel.is_connected:
            await asyncio.sleep(1.0)
        # Now monitor for disconnection
        while tunnel.is_connected:
            await asyncio.sleep(2.0)
        # Disconnected
        on_disconnect()
    except asyncio.CancelledError:
        pass


def _print_troubleshooting(mode: str, port: int, ip: str = None):
    """Print troubleshooting tips."""
    print("  --- Troubleshooting ---")
    if mode == 'host':
        print(f"  1. Make sure UDP port {port} is open in your firewall")
        if sys.platform == 'win32':
            print(f"     Run: netsh advfirewall firewall add rule name=\"LanBridge\" dir=in action=allow protocol=UDP localport={port}")
        print(f"  2. If you're behind a router, forward UDP port {port}")
        print(f"     (port forwarding / NAT / DMZ in router settings)")
        print(f"  3. Your external IP must be reachable from the internet")
        print(f"     (check with your ISP if you have a public IP)")
    else:
        print(f"  1. Make sure the host is running and accessible")
        print(f"  2. Check if IP {ip} is correct and reachable")
        print(f"  3. The host must have UDP port {port} open")
        print(f"  4. Both you and the host may need to disable VPN/proxy")
    print()


# ================================================================
# INTERACTIVE MENU (when launched without args)
# ================================================================

def _interactive_menu():
    """Show interactive menu when launched without arguments."""
    while True:
        print()
        print("  +=====================================================+")
        print("  |            LanBridge VPN                            |")
        print("  |            Virtual LAN for Gaming                   |")
        print("  +=====================================================+")
        print("  |                                                     |")
        print("  |  1. Create a room (host)                            |")
        print("  |  2. Connect to a room                               |")
        print("  |  3. Game connection hints                           |")
        print("  |  0. Exit                                            |")
        print("  |                                                     |")
        print("  +=====================================================+")
        print()

        try:
            choice = input("  Choose [0-3]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return

        if choice == '1':
            _run_host_interactive()
        elif choice == '2':
            _run_connect_interactive()
        elif choice == '3':
            cmd_games()
        elif choice == '0':
            print()
            return
        else:
            print("  Invalid choice. Enter 0-3.")


def _run_host_interactive():
    """Run host command from interactive menu."""
    print()

    # Check admin first
    if not is_admin():
        if sys.platform == 'win32':
            print("  [!] Admin privileges required!")
            print("  [!] Right-click lanbridge.exe -> Run as Administrator")
        else:
            print("  [!] Root required!")
            print("  [!] Run with: sudo lanbridge host")
        print()
        input("  Press Enter to continue...")
        return

    args = argparse.Namespace(
        password=None, port=9876, ip=None, verbose=False
    )

    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        asyncio.run(cmd_host(args))
    except KeyboardInterrupt:
        print("\n  VPN stopped by user.")
    except Exception as e:
        print(f"\n  [!] Error: {e}")


def _run_connect_interactive():
    """Run connect command from interactive menu."""
    print()
    print("  Enter the connection code from the host.")
    print("  Format: IP:PORT:PASSWORD")
    print("  Example: 192.168.1.5:9876:MyPassword123")
    print()

    try:
        code = input("  Code: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return

    if not code or ':' not in code:
        print("  [!] Invalid code format. Must be IP:PORT:PASSWORD")
        print()
        input("  Press Enter to continue...")
        return

    # Check admin first
    if not is_admin():
        if sys.platform == 'win32':
            print("  [!] Admin privileges required!")
            print("  [!] Right-click lanbridge.exe -> Run as Administrator")
        else:
            print("  [!] Root required!")
            print("  [!] Run with: sudo lanbridge connect CODE")
        print()
        input("  Press Enter to continue...")
        return

    args = argparse.Namespace(code=code, verbose=False)

    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        asyncio.run(cmd_connect(args))
    except KeyboardInterrupt:
        print("\n  VPN stopped by user.")
    except Exception as e:
        print(f"\n  [!] Error: {e}")


# ================================================================
# ENTRY POINT
# ================================================================

def main():
    parser = argparse.ArgumentParser(
        prog='lanbridge',
        description='LanBridge VPN - Virtual LAN for gaming',
    )

    parser.add_argument('-v', '--verbose', action='store_true')

    sub = parser.add_subparsers(dest='command')

    # host
    hp = sub.add_parser('host', help='Create a VPN room')
    hp.add_argument('-p', '--password', type=str, default=None,
                    help='Password (auto-generated)')
    hp.add_argument('--port', type=int, default=9876,
                    help='UDP port (default: 9876)')
    hp.add_argument('--ip', type=str, default=None,
                    help='External IP (auto-detected)')

    # connect
    cp = sub.add_parser('connect', help='Connect to a VPN room')
    cp.add_argument('code', type=str,
                    help='Connection code: IP:PORT:PASSWORD')

    # games
    sub.add_parser('games', help='Game connection hints')

    # relay
    rp = sub.add_parser('relay', help='Relay server (for VPS)')
    rp.add_argument('--port', type=int, default=9876)
    rp.add_argument('--bind', type=str, default='0.0.0.0')

    args = parser.parse_args()

    # No command -> interactive menu
    if not args.command:
        _interactive_menu()
        return

    # Setup logging
    level = logging.DEBUG if getattr(args, 'verbose', False) else logging.WARNING
    logging.basicConfig(level=level, format='')

    def signal_handler(sig, frame):
        global _shutdown_event
        if _shutdown_event:
            _shutdown_event.set()

    signal.signal(signal.SIGINT, signal_handler)

    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

    try:
        if args.command == 'host':
            asyncio.run(cmd_host(args))
        elif args.command == 'connect':
            asyncio.run(cmd_connect(args))
        elif args.command == 'games':
            cmd_games(args)
        elif args.command == 'relay':
            asyncio.run(cmd_relay(args))
    except KeyboardInterrupt:
        print("\n  Stopped by user.")
    except Exception as e:
        print(f"\n  [!] Unexpected error: {e}")
        if getattr(args, 'verbose', False):
            import traceback
            traceback.print_exc()
    finally:
        # On Windows, keep console open so user can read output
        if sys.platform == 'win32':
            print()
            input("  Press Enter to exit...")
