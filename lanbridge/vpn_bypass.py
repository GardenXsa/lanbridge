"""
VPN bypass for LanBridge.

When the user is behind a VPN (e.g. Bebra VPN, NordVPN, etc.),
their "external IP" belongs to the VPN server, not their ISP.
Incoming UDP packets to that IP are dropped by the VPN server.

This module:
1. Detects VPN network interfaces
2. Finds the real (non-VPN) network interface and gateway
3. Gets the real external IP (from ISP, not VPN)
4. Adds a route so LanBridge UDP traffic bypasses the VPN tunnel

Result: Discord works through VPN, LanBridge works through real ISP.
"""

import socket
import subprocess
import sys
import os
import json
import re
import logging
from typing import Optional, Tuple, List, Dict

logger = logging.getLogger("lanbridge.vpn_bypass")

# Use utf-8 with error handling for subprocess on Russian Windows
# This fixes the UnicodeDecodeError: 'charmap' codec can't decode byte 0x98
SUBPROCESS_ENCODING = 'utf-8'
SUBPROCESS_ERRORS = 'replace'


def _run_subprocess(args: list, **kwargs) -> subprocess.CompletedProcess:
    """Run subprocess with proper encoding for Russian Windows."""
    defaults = {
        'capture_output': True,
        'timeout': 10,
        'encoding': SUBPROCESS_ENCODING,
        'errors': SUBPROCESS_ERRORS,
    }
    defaults.update(kwargs)
    return subprocess.run(args, **defaults)


def is_vpn_active() -> bool:
    """Check if a VPN interface exists on the system."""
    vpn_interfaces = _find_vpn_interfaces()
    return len(vpn_interfaces) > 0


def get_vpn_info() -> Dict:
    """Get information about VPN and real network interfaces."""
    info = {
        'vpn_active': False,
        'vpn_interfaces': [],
        'real_interface': None,
        'real_local_ip': None,
        'real_gateway': None,
        'vpn_local_ip': None,
    }

    if sys.platform == 'win32':
        info.update(_get_network_info_windows())
    else:
        info.update(_get_network_info_linux())

    info['vpn_active'] = len(info['vpn_interfaces']) > 0
    return info


def get_real_external_ip(real_local_ip: str) -> Optional[str]:
    """
    Get the real external IP (from ISP) by binding the request
    to the real network interface, bypassing VPN.
    """
    for host, path in [
        ('api.ipify.org', '/?format=json'),
        ('ifconfig.me', '/ip'),
        ('icanhazip.com', '/'),
    ]:
        try:
            # Create a socket bound to the real interface
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(8)
            s.bind((real_local_ip, 0))
            s.connect((host, 80))

            request = (
                f'GET {path} HTTP/1.1\r\n'
                f'Host: {host}\r\n'
                f'User-Agent: LanBridge/1.0\r\n'
                f'Connection: close\r\n'
                f'\r\n'
            ).encode()
            s.sendall(request)

            response = b''
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()

            # Parse HTTP response body
            parts = response.split(b'\r\n\r\n', 1)
            if len(parts) < 2:
                continue
            body = parts[1].decode('utf-8', errors='replace').strip()

            # Handle chunked transfer encoding
            if body.startswith(('0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f')):
                lines = body.split('\r\n')
                for line in lines:
                    line = line.strip()
                    if '.' in line and len(line.split('.')) == 4:
                        if all(p.isdigit() and 0 <= int(p) <= 255 for p in line.split('.')):
                            return line

            if body.startswith('{'):
                ip = json.loads(body).get('ip')
                if ip:
                    return ip
            else:
                parts = body.strip().split('.')
                if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                    return body.strip()

        except Exception as e:
            logger.debug(f"Failed to get real IP via {host}: {e}")
            continue

    return None


def add_bypass_route(port: int, target_ip: str = None) -> bool:
    """
    Add a route that ensures LanBridge UDP traffic bypasses VPN.
    """
    info = get_vpn_info()

    if not info['vpn_active']:
        return True  # No VPN, no bypass needed

    if sys.platform == 'win32':
        return _add_bypass_route_windows(info, port, target_ip)
    else:
        return _add_bypass_route_linux(info, port, target_ip)


def remove_bypass_route(port: int, target_ip: str = None) -> bool:
    """Remove the bypass route."""
    info = get_vpn_info()

    if not info['vpn_active']:
        return True

    if sys.platform == 'win32':
        return _remove_bypass_route_windows(info, port, target_ip)
    else:
        return _remove_bypass_route_linux(info, port, target_ip)


# ================================================================
# VPN Interface Detection
# ================================================================

# Known VPN interface name patterns (case-insensitive)
VPN_PATTERNS = [
    'vpn', 'wireguard', 'wg', 'wintun', 'tunnel', 'tap',
    'openvpn', 'nordvpn', 'mullvad', 'proton', 'express',
    'cyberghost', 'surfshark', 'pia', 'bebra', 'v2ray',
    'shadowsocks', 'trojan', 'xray', 'hysteria', 'sing-box',
    'outline', 'psiphon', 'lantern', 'cloudflare warp', 'warp',
    'tun', 'ppp', 'utun', 'ipsec', 'l2tp', 'sstp',
]

# Interfaces to always exclude (virtual but NOT VPN)
EXCLUDE_PATTERNS = [
    'loopback', 'lo', 'docker', 'veth', 'br-',
    'virbr', 'vnet', 'vmnet', 'hyper-v',
]


def _find_vpn_interfaces() -> List[str]:
    """Find VPN network interfaces."""
    if sys.platform == 'win32':
        return _find_vpn_windows()
    else:
        return _find_vpn_linux()


def _find_vpn_windows() -> List[str]:
    """Find VPN interfaces on Windows."""
    vpn_ifaces = []
    try:
        result = _run_subprocess(
            ['netsh', 'interface', 'show', 'interface']
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                # Skip excluded patterns
                if any(ex in line_lower for ex in EXCLUDE_PATTERNS):
                    continue
                for pattern in VPN_PATTERNS:
                    if pattern in line_lower and 'connected' in line_lower:
                        parts = line.split()
                        if len(parts) >= 4:
                            name = ' '.join(parts[3:]).strip()
                            if name and name not in vpn_ifaces:
                                vpn_ifaces.append(name)
                        break
    except Exception as e:
        logger.debug(f"Error finding VPN interfaces: {e}")

    # Also check via ipconfig
    try:
        result = _run_subprocess(['ipconfig', '/all'])
        if result.returncode == 0:
            current_adapter = None
            for line in result.stdout.split('\n'):
                if 'adapter' in line.lower():
                    current_adapter = line.split('adapter')[-1].strip().rstrip(':')
                if current_adapter:
                    # Skip excluded
                    if any(ex in current_adapter.lower() for ex in EXCLUDE_PATTERNS):
                        current_adapter = None
                        continue
                    for pattern in VPN_PATTERNS:
                        if pattern in current_adapter.lower() and current_adapter not in vpn_ifaces:
                            vpn_ifaces.append(current_adapter)
                            break
    except Exception:
        pass

    return vpn_ifaces


def _find_vpn_linux() -> List[str]:
    """Find VPN interfaces on Linux."""
    vpn_ifaces = []
    try:
        result = _run_subprocess(['ip', 'link', 'show'])
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                for pattern in VPN_PATTERNS:
                    if pattern in line.lower():
                        match = re.search(r'\d+:\s*(\w+):', line)
                        if match:
                            name = match.group(1)
                            if name != 'lo' and name not in vpn_ifaces:
                                if not any(ex in name.lower() for ex in EXCLUDE_PATTERNS):
                                    vpn_ifaces.append(name)
                        break
    except Exception:
        pass
    return vpn_ifaces


# ================================================================
# Network Info
# ================================================================

def _get_network_info_windows() -> Dict:
    """Get network info on Windows."""
    info = {
        'vpn_interfaces': [],
        'real_interface': None,
        'real_local_ip': None,
        'real_gateway': None,
        'vpn_local_ip': None,
    }

    try:
        # Get routing table
        result = _run_subprocess(['route', 'print', '0.0.0.0'])
        if result.returncode == 0:
            gateways = []
            for line in result.stdout.split('\n'):
                if '0.0.0.0' in line and '0.0.0.0' in line.split()[0:2]:
                    parts = line.split()
                    if len(parts) >= 3:
                        gateway = parts[2]
                        iface_idx = parts[3] if len(parts) > 3 else None
                        try:
                            metric = int(parts[4]) if len(parts) > 4 else 9999
                        except (ValueError, IndexError):
                            metric = 9999
                        gateways.append({
                            'gateway': gateway,
                            'iface_idx': iface_idx,
                            'metric': metric,
                        })

            # Sort by metric - lowest metric is the default route
            gateways.sort(key=lambda g: g['metric'])

            vpn_ifaces = _find_vpn_windows()
            info['vpn_interfaces'] = vpn_ifaces

            for gw in gateways:
                iface_name = _get_iface_name_from_idx(gw.get('iface_idx'))
                is_vpn = any(vp.lower() in (iface_name or '').lower() for vp in VPN_PATTERNS) if iface_name else False

                # First gateway with lowest metric is usually VPN (it hijacks default route)
                is_first = (gw == gateways[0])

                if is_vpn or (is_first and vpn_ifaces):
                    # This is the VPN gateway
                    if not info['vpn_local_ip']:
                        info['vpn_local_ip'] = _get_ip_for_iface(iface_name)
                else:
                    # This is the real gateway
                    if not info['real_gateway']:
                        info['real_gateway'] = gw['gateway']
                        info['real_interface'] = iface_name
                        info['real_local_ip'] = _get_ip_for_iface(iface_name)

    except Exception as e:
        logger.debug(f"Error getting network info: {e}")

    # Fallback: use ipconfig
    if not info['real_local_ip']:
        info.update(_parse_ipconfig())

    return info


def _get_iface_name_from_idx(idx: str) -> Optional[str]:
    """Get interface name from interface index on Windows."""
    if not idx:
        return None
    try:
        result = _run_subprocess(
            ['netsh', 'interface', 'ipv4', 'show', 'interface', f'index={idx}']
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and not line.startswith(('Admin', '---', 'Enabled', 'Disabled')):
                    parts = line.split()
                    if len(parts) >= 5:
                        return ' '.join(parts[4:]).strip()
    except Exception:
        pass
    return None


def _get_ip_for_iface(iface_name: str) -> Optional[str]:
    """Get the IP address assigned to an interface."""
    if not iface_name:
        return None
    try:
        result = _run_subprocess(
            ['netsh', 'interface', 'ipv4', 'show', 'address', f'name={iface_name}']
        )
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'IP Address' in line or 'IP-' in line:
                    ip = line.split(':')[-1].strip()
                    if '.' in ip:
                        return ip
    except Exception:
        pass
    return None


def _parse_ipconfig() -> Dict:
    """Parse ipconfig output as fallback."""
    result_info = {
        'real_interface': None,
        'real_local_ip': None,
        'real_gateway': None,
        'vpn_local_ip': None,
    }

    try:
        result = _run_subprocess(['ipconfig'])
        if result.returncode == 0:
            current_adapter = None
            current_ip = None
            current_gw = None
            is_vpn = False

            for line in result.stdout.split('\n'):
                line_stripped = line.strip()

                # New adapter section
                if 'adapter' in line.lower() or 'Ethernet' in line or 'Wireless' in line or 'Wi-Fi' in line:
                    # Save previous adapter info
                    if current_adapter:
                        if is_vpn:
                            if not result_info['vpn_local_ip'] and current_ip:
                                result_info['vpn_local_ip'] = current_ip
                        else:
                            if not result_info['real_interface']:
                                result_info['real_interface'] = current_adapter
                                result_info['real_local_ip'] = current_ip
                                result_info['real_gateway'] = current_gw

                    # Start new adapter
                    if 'adapter' in line.lower():
                        current_adapter = line.split('adapter')[-1].strip().rstrip(':')
                    else:
                        current_adapter = line.strip().rstrip(':')
                    current_ip = None
                    current_gw = None
                    is_vpn = any(p in current_adapter.lower() for p in VPN_PATTERNS)

                elif 'IPv4' in line or 'IPv4-' in line or 'IP Address' in line or 'IP-' in line:
                    ip = line.split(':')[-1].strip()
                    if '(' in ip:  # Remove "(Preferred)" etc
                        ip = ip.split('(')[0].strip()
                    current_ip = ip

                elif 'Default Gateway' in line or 'Default Gateway' in line or 'Gateway' in line:
                    gw = line.split(':')[-1].strip()
                    if '.' in gw:
                        current_gw = gw

            # Don't forget last adapter
            if current_adapter and not is_vpn:
                if not result_info['real_interface']:
                    result_info['real_interface'] = current_adapter
                    result_info['real_local_ip'] = current_ip
                    result_info['real_gateway'] = current_gw

    except Exception:
        pass

    return result_info


def _get_network_info_linux() -> Dict:
    """Get network info on Linux."""
    info = {
        'vpn_interfaces': [],
        'real_interface': None,
        'real_local_ip': None,
        'real_gateway': None,
        'vpn_local_ip': None,
    }

    vpn_ifaces = _find_vpn_linux()
    info['vpn_interfaces'] = vpn_ifaces

    try:
        result = _run_subprocess(['ip', 'route', 'show', 'default'])
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'via' in line:
                    parts = line.split()
                    gw_idx = parts.index('via') + 1 if 'via' in parts else -1
                    dev_idx = parts.index('dev') + 1 if 'dev' in parts else -1
                    if gw_idx > 0 and dev_idx > 0:
                        gateway = parts[gw_idx]
                        iface = parts[dev_idx]
                        if iface in vpn_ifaces:
                            info['vpn_local_ip'] = _get_ip_linux(iface)
                        else:
                            info['real_gateway'] = gateway
                            info['real_interface'] = iface
                            info['real_local_ip'] = _get_ip_linux(iface)
    except Exception:
        pass

    return info


def _get_ip_linux(iface: str) -> Optional[str]:
    """Get IP address for a Linux interface."""
    try:
        result = _run_subprocess(['ip', 'addr', 'show', iface])
        if result.returncode == 0:
            for line in result.stdout.split('\n'):
                if 'inet ' in line:
                    return line.strip().split()[1].split('/')[0]
    except Exception:
        pass
    return None


# ================================================================
# Route Management
# ================================================================

def _add_bypass_route_windows(info: Dict, port: int, target_ip: str = None) -> bool:
    """Add bypass route on Windows."""
    real_gw = info.get('real_gateway')
    real_iface = info.get('real_interface')

    if not real_gw:
        logger.warning("Cannot add bypass route: no real gateway found")
        return False

    success = False

    if target_ip:
        try:
            result = _run_subprocess(
                ['route', 'add', target_ip, 'mask', '255.255.255.255', real_gw, 'metric', '1']
            )
            if result.returncode == 0 or 'OK' in result.stdout:
                logger.info(f"Bypass route added: {target_ip} -> {real_gw}")
                success = True
        except Exception as e:
            logger.debug(f"Failed to add route: {e}")

    return success


def _remove_bypass_route_windows(info: Dict, port: int, target_ip: str = None) -> bool:
    """Remove bypass route on Windows."""
    if target_ip:
        try:
            _run_subprocess(['route', 'delete', target_ip])
            return True
        except Exception:
            return False
    return True


def _add_bypass_route_linux(info: Dict, port: int, target_ip: str = None) -> bool:
    """Add bypass route on Linux."""
    real_gw = info.get('real_gateway')
    real_iface = info.get('real_interface')

    if not real_gw or not real_iface:
        return False

    if target_ip:
        try:
            _run_subprocess(
                ['ip', 'route', 'add', target_ip, 'via', real_gw, 'dev', real_iface]
            )
            return True
        except Exception:
            return False
    return True


def _remove_bypass_route_linux(info: Dict, port: int, target_ip: str = None) -> bool:
    """Remove bypass route on Linux."""
    if target_ip:
        try:
            _run_subprocess(['ip', 'route', 'del', target_ip])
            return True
        except Exception:
            return False
    return True
