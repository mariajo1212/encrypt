#!/bin/bash

# ============================================================
# CaaS Complete Deployment Script
# Installs and configures CaaS on Ubuntu 20.04/22.04
# ============================================================

set -e

echo ""
echo "============================================================"
echo "  CaaS (Crypto as a Service) - Complete Deployment"
echo "============================================================"
echo ""
echo "This script will:"
echo "  1. Install system dependencies"
echo "  2. Setup Python virtual environment"
echo "  3. Configure the application"
echo "  4. Create systemd service"
echo "  5. Setup firewall"
echo "  6. Configure Nginx reverse proxy (optional)"
echo ""
read -p "Continue? (y/n): " CONFIRM

if [[ $CONFIRM != "y" && $CONFIRM != "Y" ]]; then
    echo "Deployment cancelled"
    exit 0
fi

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

echo ""
echo "Starting deployment..."
echo ""

# Run installation
echo "========================================"
echo "Step 1/4: Installing application..."
echo "========================================"
bash install.sh

# Setup service
echo ""
echo "========================================"
echo "Step 2/4: Setting up systemd service..."
echo "========================================"
bash setup-service.sh

# Setup firewall
echo ""
echo "========================================"
echo "Step 3/4: Configuring firewall..."
echo "========================================"
bash setup-firewall.sh

# Ask about nginx
echo ""
echo "========================================"
echo "Step 4/4: Nginx reverse proxy (optional)"
echo "========================================"
read -p "Do you want to setup Nginx reverse proxy? (y/n): " SETUP_NGINX

if [[ $SETUP_NGINX == "y" || $SETUP_NGINX == "Y" ]]; then
    bash setup-nginx.sh
else
    echo "Skipping Nginx setup"
    echo "Note: Application is running on port 8000"
    echo "You may need to allow port 8000 in firewall:"
    echo "  sudo ufw allow 8000/tcp"
fi

echo ""
echo "============================================================"
echo "  Deployment Completed Successfully!"
echo "============================================================"
echo ""
echo "Service Information:"
echo "  - Service name: caas"
echo "  - Status: sudo systemctl status caas"
echo "  - Logs: sudo journalctl -u caas -f"
echo ""
echo "Default Users:"
echo "  Username: admin    Password: Admin123!"
echo "  Username: testuser Password: Test123!"
echo ""
if [[ $SETUP_NGINX == "y" || $SETUP_NGINX == "Y" ]]; then
    echo "Access your application via the domain you configured"
else
    echo "Access your application at:"
    echo "  http://YOUR_SERVER_IP:8000/web"
    echo "  http://YOUR_SERVER_IP:8000/api/docs"
fi
echo ""
echo "IMPORTANT SECURITY NOTES:"
echo "  1. Change default user passwords immediately"
echo "  2. Keep your .env file secure (contains secrets)"
echo "  3. Enable HTTPS in production (setup-nginx.sh with SSL)"
echo "  4. Regularly update the system: sudo apt update && sudo apt upgrade"
echo ""
