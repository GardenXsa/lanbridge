<div align="center">

# LanBridge

Peer-to-peer VPN for LAN emulation

[![Version](https://img.shields.io/badge/version-1.0.3-blue.svg)](https://github.com/GardenXsa/lanbridge)
[![Python](https://img.shields.io/badge/python-3.7+-3776AB.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey.svg)]()

</div>

---

LanBridge creates an encrypted UDP tunnel between two computers and brings up virtual network interfaces on each side. The result is two hosts in a shared `10.13.37.0/24` subnet that see each other exactly as they would on a physical LAN. Any protocol, any port, no port forwarding required.

The working principle is similar to Radmin VPN and ZeroTier, but implemented from scratch: custom tunneling protocol, custom authentication, custom TUN device management. The only external dependency is the `cryptography` library for encryption.

---

## Table of Contents

- [Architecture](#architecture)
- [Protocol](#protocol)
- [Encryption](#encryption)
- [Installation](#installation)
- [Usage](#usage)
- [Requirements](#requirements)
- [Game Compatibility](#game-compatibility)
- [NAT Traversal](#nat-traversal)
- [Project Structure](#project-structure)
- [Security](#security)
- [License](#license)

---

## Architecture

```
  HOST (10.13.37.1)                           CLIENT (10.13.37.2)
  +--------------------+                      +--------------------+
  |   Game Server      |                      |   Game Client      |
  |   0.0.0.0:25565    |                      |                    |
  +--------+-----------+                      +--------+-----------+
           | TCP/UDP to 10.13.37.1                     |
  +--------v-----------+                      +--------v-----------+
  |  TUN: lanbridge0   |                      |  TUN: lanbridge0   |
  |  10.13.37.1/24     |                      |  10.13.37.2/24     |
  +--------+-----------+                      +--------+-----------+
           | IP packets                                  | IP packets
  +--------v-----------+                      +--------v-----------+
  |   VPNEngine        |                      |   VPNEngine        |
  |   TUN <-> Tunnel   |                      |   TUN <-> Tunnel   |
  +--------+-----------+                      +--------v-----------+
           | ChaCha20-Poly1305                            |
  +--------v----------------------------------------------v-----------+
  |                     Encrypted UDP Tunnel                           |
  |                     (port 9876 by default)                        |
  +-------------------------------------------------------------------+
```

Data flow:

1. Game client sends a TCP/UDP packet to `10.13.37.1`
2. Kernel routes the packet into the TUN device `lanbridge0`
3. `VPNEngine` reads the IP packet from TUN, wraps it in the tunnel protocol, encrypts with ChaCha20-Poly1305
4. Encrypted datagram is sent via UDP to the remote host
5. Remote side decrypts, extracts the IP packet, writes it to its TUN device
6. Kernel delivers the packet to the game server

Return path is symmetric. There is no binding to specific ports or protocols -- at the TUN level, all IP traffic passes through.

---

## Protocol

The tunnel protocol operates over UDP. Each packet has a 7-byte header:

```
 0      1      2      3      4      5      6
+------+------+------+------+------+------+------+
| TYPE |     PORT      |        CONN_ID         |
+------+------+------+------+------+------+------+
|                     PAYLOAD                     |
+-------------------------------------------------+
```

| Field    | Size   | Description                                                        |
|----------|--------|--------------------------------------------------------------------|
| TYPE     | 1 byte | Packet type (AUTH, DATA, PING, etc.)                               |
| PORT     | 2 bytes| Port (for TCP/UDP forwarding mode)                                 |
| CONN_ID  | 4 bytes| Connection identifier                                              |
| PAYLOAD  | N bytes| Data (IP packet in VPN mode, port data in forwarding mode)         |

Packet types:

| Code  | Name        | Description                               |
|-------|-------------|-------------------------------------------|
| 0x01  | AUTH        | Authentication (plaintext)                |
| 0x02  | AUTH_OK     | Authentication confirmed                  |
| 0x10  | DATA_TCP    | TCP connection data / IP packet           |
| 0x11  | DATA_UDP    | UDP connection data                       |
| 0x20  | OPEN_PORT   | Port open request                         |
| 0x21  | CLOSE_PORT  | Port close                                |
| 0x30  | PING        | Keepalive                                 |
| 0x31  | PONG        | Keepalive response                        |
| 0x40  | DISCONNECT  | Disconnect                                |

### Connection Establishment

```
  CLIENT                                SERVER
     |                                     |
     |  AUTH (plaintext)                   |
     |  [salt(16) + password]              |
     |------------------------------------>|
     |                                     |  Verify password
     |                                     |  Recreate crypto with client salt
     |  AUTH_OK (encrypted)                |
     |<------------------------------------|
     |                                     |
     |  Encrypted traffic                  |
     |<----------------------------------->|
```

The AUTH packet is sent in plaintext and contains the client's salt. The server verifies the password, recreates its cryptographic context with the received salt, and sends AUTH_OK already encrypted. All subsequent traffic is encrypted.

---

## Encryption

| Parameter       | Value                          |
|-----------------|--------------------------------|
| Algorithm       | ChaCha20-Poly1305              |
| Key length      | 256 bit                        |
| Key derivation  | PBKDF2-SHA256, 100 000 rounds  |
| Salt            | 128 bit, generated by client   |
| Nonce           | 96 bit, incremental counter    |

---

## Installation

### From source

```bash
git clone https://github.com/GardenXsa/lanbridge.git
cd lanbridge
pip install cryptography
pip install -e .
```

### Without installation

```bash
git clone https://github.com/GardenXsa/lanbridge.git
cd lanbridge
pip install cryptography
python -m lanbridge host
```

### Prebuilt binaries

Download the latest release for your platform from the [Releases](https://github.com/GardenXsa/lanbridge/releases) page.

---

## Usage

### Create a room

```bash
sudo lanbridge host
```

Output:

```
  +=======================================================+
  |            LanBridge VPN -- HOST                       |
  +=======================================================+
  |  Your IP:      203.0.113.42                           |
  |  Port:         9876                                    |
  |  Password:     kX7mR2vNpB4qL9wE                        |
  |  Virtual IP:   10.13.37.1                              |
  +=======================================================+
  |  Send to friend:                                      |
  |  lanbridge connect 203.0.113.42:9876:kX7mR2vNpB4qL9wE |
  +=======================================================+
```

### Connect

```bash
sudo lanbridge connect 203.0.113.42:9876:kX7mR2vNpB4qL9wE
```

Once connected, both hosts are in the `10.13.37.0/24` subnet:

| Role   | IP           |
|--------|-------------|
| Host   | 10.13.37.1  |
| Client | 10.13.37.2  |

To connect to a game server on the host, simply use IP `10.13.37.1` on the required port.

### Additional commands

```bash
sudo lanbridge host --ip 1.2.3.4      # Specify external IP manually
sudo lanbridge host --port 12345       # Specify tunnel port
lanbridge games                        # Game connection hints
lanbridge relay                        # Start relay server
```

---

## Requirements

| Component   | Requirement                                        |
|-------------|-----------------------------------------------------|
| Python      | 3.7+                                                |
| OS          | Linux (with /dev/net/tun) or Windows (with wintun)  |
| Privileges  | root / Administrator (required for TUN creation)    |
| Dependencies| cryptography (pip install cryptography)              |
| Network     | UDP reachability between hosts, or a relay server   |

Windows: wintun.dll is downloaded automatically on first run. If automatic download fails, the file can be obtained from [wintun.net](https://www.wintun.net/) and placed next to the executable.

---

## Game Compatibility

LanBridge operates at the IP layer (TUN device), making it compatible with any application that uses TCP or UDP. Since it creates a full virtual network interface, it works identically to being on the same physical LAN.

**Confirmed working** -- these games have been verified to work correctly over LanBridge:

| Game                     | Connection                            |
|--------------------------|---------------------------------------|
| Minecraft (Java)         | Direct Connect: `10.13.37.1:25565`   |
| Minecraft (Bedrock)      | Add Server: `10.13.37.1:19132`       |
| Terraria                | Join via IP: `10.13.37.1:7777`       |
| Valheim                 | Join IP: `10.13.37.1:2456`           |
| Left 4 Dead 2           | Console: `connect 10.13.37.1:27015`  |
| Don't Starve Together   | `10.13.37.1:10999`                    |
| Palworld                | `10.13.37.1:8211`                     |
| Raft                    | `10.13.37.1:7777`                     |
| Project Zomboid         | `10.13.37.1:16261`                    |
| Satisfactory            | `10.13.37.1:15777`                    |
| ARK: Survival Evolved   | `10.13.37.1:7777`                     |
| Rust                    | Console: `connect 10.13.37.1:28015`  |
| Core Keeper             | `10.13.37.1:1234`                     |
| Starbound               | `10.13.37.1:21025`                    |
| Unturned                | `10.13.37.1:27015`                    |
| 7 Days to Die           | `10.13.37.1:26900`                    |

Any other application that supports connecting by IP address will work the same way. The only limitation is with applications that rely on broadcast for host discovery (some games auto-discover servers without entering an IP). In such cases, manual entry of the address `10.13.37.1` is required.

---

## NAT Traversal

If both hosts are behind NAT without the ability to forward ports, the connection is established through a relay server with a public IP:

```
  HOST <--- UDP ---> RELAY <--- UDP ---> CLIENT
```

The relay forwards encrypted packets between peers but cannot decrypt the traffic -- keys are only known to the host and client.

Running a relay on a VPS:

```bash
lanbridge relay --port 9876
```

Connecting through relay:

```bash
sudo lanbridge host --relay relay.example.com:9876
sudo lanbridge connect --relay relay.example.com:9876 CODE
```

---

## Project Structure

```
lanbridge/
  __init__.py               # Package
  __main__.py               # Entry point (python -m lanbridge)
  cli.py                    # CLI interface
  core/
    __init__.py
    crypto.py               # Encryption (ChaCha20-Poly1305 / XOR fallback)
    tunnel.py               # UDP tunnel protocol
    vpn.py                  # VPN engine (TUN <-> Tunnel)
  platform/
    __init__.py
    tun_device.py           # TUN device (Linux / Windows wintun)
  forwarder.py              # TCP/UDP port forwarder (alternative mode)
  relay.py                  # Relay server for NAT traversal
```

| Module                   | Responsibility                                       |
|--------------------------|------------------------------------------------------|
| `core/crypto.py`         | Key generation, packet encryption/decryption         |
| `core/tunnel.py`         | Packet serialization, keepalive, authentication       |
| `core/vpn.py`            | Bridging TUN device and tunnel                        |
| `platform/tun_device.py` | Virtual network interface creation and management     |
| `forwarder.py`           | Specific TCP/UDP port forwarding (without TUN)        |
| `relay.py`               | Packet transport between NAT-trapped peers            |

---

## Security

- Traffic is encrypted with ChaCha20-Poly1305 -- an AEAD cipher with authentication
- Keys are derived from the password via PBKDF2-SHA256 (100 000 iterations, 128-bit salt)
- Nonce is an incremental counter, unique for each packet
- Relay server has no access to keys and cannot decrypt traffic
- AUTH packet is sent in plaintext (contains salt and password) -- when using over public networks, it is recommended to connect through a relay with TLS or use a VPN on top of LanBridge

---

## License

[MIT](LICENSE)
