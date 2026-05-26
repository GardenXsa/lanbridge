"""
UPnP port forwarding for LanBridge VPN.

Automatically opens UDP port on the router so that
incoming connections can reach the host even behind NAT.

Uses only Python standard library -- no extra dependencies.
"""

import socket
import urllib.request
import xml.etree.ElementTree as ET
import logging
import time
from typing import Optional, Tuple

logger = logging.getLogger("lanbridge.upnp")

# SSDP constants
SSDP_ADDR = '239.255.255.250'
SSDP_PORT = 1900
SSDP_TIMEOUT = 5.0


def _ssdp_discover() -> Optional[str]:
    """Discover UPnP Internet Gateway Device via SSDP. Returns location URL."""
    search_types = [
        'urn:schemas-upnp-org:device:InternetGatewayDevice:1',
        'urn:schemas-upnp-org:service:WANIPConnection:1',
        'urn:schemas-upnp-org:service:WANPPPConnection:1',
    ]

    for st in search_types:
        msg = (
            'M-SEARCH * HTTP/1.1\r\n'
            f'HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n'
            'MAN: "ssdp:discover"\r\n'
            'MX: 3\r\n'
            f'ST: {st}\r\n'
            '\r\n'
        )

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(SSDP_TIMEOUT)
        try:
            sock.sendto(msg.encode(), (SSDP_ADDR, SSDP_PORT))
            data, addr = sock.recvfrom(4096)
            response = data.decode('utf-8', errors='replace')

            # Extract LOCATION header
            for line in response.split('\r\n'):
                if line.lower().startswith('location:'):
                    location = line.split(':', 1)[1].strip()
                    logger.info(f"UPnP device found: {location}")
                    return location
        except socket.timeout:
            continue
        except Exception as e:
            logger.debug(f"SSDP error: {e}")
            continue
        finally:
            sock.close()

    return None


def _get_wan_ip_connection_url(location_url: str) -> Optional[str]:
    """Parse device description XML to find WANIPConnection control URL."""
    try:
        req = urllib.request.Request(location_url, headers={'User-Agent': 'LanBridge/1.0'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            xml_data = resp.read()
    except Exception as e:
        logger.debug(f"Failed to fetch device description: {e}")
        return None

    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError as e:
        logger.debug(f"Failed to parse device XML: {e}")
        return None

    # Namespace handling
    ns = ''
    if root.tag.startswith('{'):
        ns = root.tag.split('}')[0] + '}'

    # Search for WANIPConnection service
    search_tags = [
        f'.//{ns}serviceType',
    ]

    for elem in root.iter():
        if elem.text and 'WANIPConnection' in elem.text:
            # Found the service, now get the controlURL
            parent = elem.getparent() if hasattr(elem, 'getparent') else None
            if parent is not None:
                for child in parent:
                    tag = child.tag.replace(ns, '')
                    if tag == 'controlURL' and child.text:
                        # Combine with base URL
                        base = location_url.rsplit('/', 1)[0]
                        if child.text.startswith('/'):
                            return base + child.text
                        return base + '/' + child.text

    # Fallback: try common paths
    base = location_url.rsplit('/', 1)[0]
    for path in ['/upnp/control/WANIPConn1', '/ctl/IPConn', '/WANIPConnCtrl']:
        try:
            req = urllib.request.Request(base + path, headers={'User-Agent': 'LanBridge/1.0'})
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            # 404 or 500 means the endpoint exists but we need proper SOAP
            pass

    return None


def _soap_request(control_url: str, action: str, fields: dict) -> Optional[dict]:
    """Send a SOAP request to the UPnP control URL."""
    body_parts = ['<?xml version="1.0"?>',
                  '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">',
                  '  <s:Body>',
                  f'  <u:{action} xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">']

    for key, value in fields.items():
        body_parts.append(f'    <{key}>{value}</{key}>')
    body_parts.append(f'  </u:{action}>')
    body_parts.append('  </s:Body>')
    body_parts.append('</s:Envelope>')

    body = '\r\n'.join(body_parts)

    headers = {
        'Content-Type': 'text/xml; charset="utf-8"',
        'SOAPAction': f'"urn:schemas-upnp-org:service:WANIPConnection:1#{action}"',
        'User-Agent': 'LanBridge/1.0',
        'Content-Length': str(len(body)),
        'Connection': 'close',
    }

    req = urllib.request.Request(control_url, data=body.encode('utf-8'), headers=headers)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return {'status': resp.status, 'data': resp.read().decode('utf-8', errors='replace')}
    except urllib.error.HTTPError as e:
        # SOAP errors come as HTTP 500
        error_body = e.read().decode('utf-8', errors='replace')
        if 'Conflict' in error_body or '718' in error_body:
            # Port already mapped - this is OK
            return {'status': 'already_mapped'}
        logger.debug(f"SOAP error {e.code}: {error_body[:200]}")
        return None
    except Exception as e:
        logger.debug(f"SOAP request failed: {e}")
        return None


class UPnPPortForward:
    """Manages UPnP port forwarding for LanBridge VPN."""

    def __init__(self):
        self._control_url: Optional[str] = None
        self._location_url: Optional[str] = None
        self._mapped_ports: list = []

    def discover(self) -> bool:
        """Discover UPnP router on the network."""
        self._location_url = _ssdp_discover()
        if not self._location_url:
            return False

        self._control_url = _get_wan_ip_connection_url(self._location_url)
        if not self._control_url:
            # Try common paths as fallback
            base = self._location_url.rsplit('/', 1)[0]
            self._control_url = base + '/upnp/control/WANIPConn1'

        return True

    def add_port_mapping(self, external_port: int, internal_port: int,
                         protocol: str = 'UDP',
                         description: str = 'LanBridge VPN') -> bool:
        """Add a port mapping on the router."""
        if not self._control_url:
            return False

        # Get local IP
        local_ip = self._get_local_ip()

        fields = {
            'NewRemoteHost': '',
            'NewExternalPort': str(external_port),
            'NewProtocol': protocol,
            'NewInternalPort': str(internal_port),
            'NewInternalClient': local_ip,
            'NewEnabled': '1',
            'NewPortMappingDescription': description,
            'NewLeaseDuration': '0',  # 0 = permanent
        }

        result = _soap_request(self._control_url, 'AddPortMapping', fields)

        if result is None:
            return False

        if result.get('status') == 'already_mapped':
            logger.info(f"Port {external_port}/{protocol} already mapped")
            return True

        if result.get('status') in (200, '200'):
            self._mapped_ports.append((external_port, internal_port, protocol))
            logger.info(f"UPnP: Mapped {protocol} {external_port} -> {local_ip}:{internal_port}")
            return True

        # Check if it was actually successful (some routers return weird status codes)
        if result.get('data') and 'AddPortMappingResponse' in result.get('data', ''):
            self._mapped_ports.append((external_port, internal_port, protocol))
            return True

        return True  # Assume success if no error

    def remove_port_mapping(self, external_port: int, protocol: str = 'UDP') -> bool:
        """Remove a port mapping from the router."""
        if not self._control_url:
            return False

        fields = {
            'NewRemoteHost': '',
            'NewExternalPort': str(external_port),
            'NewProtocol': protocol,
        }

        result = _soap_request(self._control_url, 'DeletePortMapping', fields)
        return result is not None

    def get_external_ip(self) -> Optional[str]:
        """Get the external IP via UPnP."""
        if not self._control_url:
            return None

        result = _soap_request(self._control_url, 'GetExternalIPAddress', {})
        if result and result.get('data'):
            # Parse IP from response
            import re
            match = re.search(r'<NewExternalIPAddress>(.*?)</NewExternalIPAddress>',
                              result['data'])
            if match:
                return match.group(1)
        return None

    def cleanup(self):
        """Remove all port mappings created by this instance."""
        for external_port, internal_port, protocol in self._mapped_ports:
            self.remove_port_mapping(external_port, protocol)
        self._mapped_ports.clear()

    @staticmethod
    def _get_local_ip() -> str:
        """Get the local IP address."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'


def setup_upnp(port: int, protocol: str = 'UDP') -> Optional[UPnPPortForward]:
    """
    Convenience function: discover UPnP router and add port mapping.

    Returns the UPnPPortForward object (for cleanup later), or None on failure.
    """
    upnp = UPnPPortForward()

    print("  Discovering UPnP router...")
    if not upnp.discover():
        print("  [!] No UPnP router found.")
        print("  [!] You may need to enable UPnP in your router settings,")
        print("  [!] or manually forward UDP port on your router.")
        return None

    print(f"  UPnP router found!")

    # Try to get external IP
    ext_ip = upnp.get_external_ip()
    if ext_ip:
        print(f"  Router external IP: {ext_ip}")

    # Add port mapping
    local_ip = upnp._get_local_ip()
    print(f"  Mapping UDP {port} -> {local_ip}:{port}...")

    if upnp.add_port_mapping(port, port, protocol, 'LanBridge VPN'):
        print(f"  [+] UPnP port mapping added: UDP {port}")
        return upnp
    else:
        print(f"  [!] UPnP port mapping failed.")
        print(f"  [!] Try enabling UPnP on your router,")
        print(f"  [!] or manually forward UDP port {port}.")
        return None
