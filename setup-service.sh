#!/bin/bash

# ============================================================
# CaaS Systemd Service Setup Script
# ============================================================

set -e

echo "======================================"
echo "Setting up CaaS as a systemd service"
echo "======================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

APP_DIR="/opt/caas"

if [ ! -d "$APP_DIR" ]; then
    echo "Error: Application directory not found at $APP_DIR"
    echo "Please run install.sh first"
    exit 1
fi

echo "[1/4] Creating systemd service file..."
cat > /etc/systemd/system/caas.service <<EOF
[Unit]
Description=CaaS (Crypto as a Service) API
After=network.target

[Service]
Type=simple
User=$SUDO_USER
WorkingDirectory=$APP_DIR
Environment="PATH=$APP_DIR/venv/bin"
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/run.py
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=true
PrivateTmp=true

# Logging
StandardOutput=append:/var/log/caas/access.log
StandardError=append:/var/log/caas/error.log

[Install]
WantedBy=multi-user.target
EOF

echo "[2/4] Creating log directory..."
mkdir -p /var/log/caas
chown -R $SUDO_USER:$SUDO_USER /var/log/caas

echo "[3/4] Reloading systemd daemon..."
systemctl daemon-reload

echo "[4/4] Enabling and starting CaaS service..."
systemctl enable caas
systemctl start caas

# Wait a moment for service to start
sleep 3

echo ""
echo "======================================"
echo "Service setup completed!"
echo "======================================"
echo ""
echo "Service status:"
systemctl status caas --no-pager -l
echo ""
echo "Useful commands:"
echo "  - Check status: sudo systemctl status caas"
echo "  - Stop service: sudo systemctl stop caas"
echo "  - Start service: sudo systemctl start caas"
echo "  - Restart service: sudo systemctl restart caas"
echo "  - View logs: sudo journalctl -u caas -f"
echo "  - View access logs: sudo tail -f /var/log/caas/access.log"
echo "  - View error logs: sudo tail -f /var/log/caas/error.log"
echo ""
