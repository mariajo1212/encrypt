#!/bin/bash

# ============================================================
# CaaS Firewall Setup Script (UFW)
# ============================================================

set -e

echo "======================================"
echo "Setting up firewall (UFW)"
echo "======================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

echo "[1/5] Installing UFW..."
apt-get install -y ufw

echo "[2/5] Setting default policies..."
ufw default deny incoming
ufw default allow outgoing

echo "[3/5] Allowing SSH (port 22)..."
ufw allow 22/tcp

echo "[4/5] Allowing HTTP and HTTPS (ports 80, 443)..."
ufw allow 80/tcp
ufw allow 443/tcp

echo "[5/5] Enabling firewall..."
ufw --force enable

echo ""
echo "======================================"
echo "Firewall setup completed!"
echo "======================================"
echo ""
echo "Firewall status:"
ufw status verbose
echo ""
echo "Useful commands:"
echo "  - Check status: sudo ufw status"
echo "  - Disable firewall: sudo ufw disable"
echo "  - Enable firewall: sudo ufw enable"
echo "  - Allow port: sudo ufw allow PORT/tcp"
echo "  - Deny port: sudo ufw deny PORT/tcp"
echo ""
