#!/bin/bash
# ================================================================
# LanBridge Relay Server - Deploy Script
# ================================================================
#
# This script deploys the LanBridge relay server.
# The relay is needed so two peers behind VPN/NAT can connect.
#
# Options:
#   1. Docker (recommended) - works on any VPS with Docker
#   2. Direct Python - works on any Linux with Python 3.8+
#   3. Systemd service - auto-restart on crash/reboot
#
# Requirements:
#   - A VPS with a public IP
#   - UDP port 9876 open in firewall
#
# Free VPS options:
#   - Oracle Cloud Free Tier (always-free ARM, 1GB RAM)
#   - Google Cloud e2-micro (always-free)
#   - Fly.io free tier
#   - Cheap VPS: RuVDS, Timeweb, Aeza ($3-5/month)
#
# ================================================================

set -e

RELAY_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PORT=${1:-9876}

echo "=============================================="
echo "  LanBridge Relay Server Deploy"
echo "=============================================="
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "[!] Run as root for system-wide install"
    echo "    sudo $0"
    exit 1
fi

# Open firewall
echo "[+] Opening UDP port $PORT..."
if command -v ufw &> /dev/null; then
    ufw allow $PORT/udp
elif command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=$PORT/udp
    firewall-cmd --reload
elif command -v iptables &> /dev/null; then
    iptables -I INPUT -p udp --dport $PORT -j ACCEPT
    # Save rule
    if command -v iptables-save &> /dev/null; then
        iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
    fi
fi

# Install as systemd service
echo "[+] Installing systemd service..."

cat > /etc/systemd/system/lanbridge-relay.service << EOF
[Unit]
Description=LanBridge Relay Server
After=network.target

[Service]
Type=simple
WorkingDirectory=$RELAY_DIR
ExecStart=/usr/bin/python3 -c "import asyncio; from lanbridge.relay import run_relay_server; asyncio.run(run_relay_server('0.0.0.0', $PORT))"
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable lanbridge-relay
systemctl start lanbridge-relay

echo ""
echo "[+] Relay server started!"
echo "[+] UDP port: $PORT"
echo "[+] Service: lanbridge-relay"
echo ""
echo "Commands:"
echo "  systemctl status lanbridge-relay   - check status"
echo "  journalctl -u lanbridge-relay -f   - view logs"
echo "  systemctl restart lanbridge-relay   - restart"
echo "  systemctl stop lanbridge-relay      - stop"
echo ""

# Get public IP
PUB_IP=$(curl -s https://api.ipify.org 2>/dev/null || curl -s https://ifconfig.me/ip 2>/dev/null || echo "YOUR_VPS_IP")
echo "Your relay server: $PUB_IP:$PORT"
echo ""
echo "LanBridge clients should use:"
echo "  Host:   lanbridge host --relay $PUB_IP --relay-port $PORT"
echo "  Code:   R:$PUB_IP:$PORT:SESSION:PASSWORD"
