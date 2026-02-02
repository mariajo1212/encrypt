#!/bin/bash

# ============================================================
# CaaS Installation Script for Ubuntu 20.04/22.04
# ============================================================

set -e  # Exit on error

echo "======================================"
echo "CaaS Installation Script"
echo "======================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Get the actual user (not root)
ACTUAL_USER=${SUDO_USER:-$USER}
ACTUAL_HOME=$(eval echo ~$ACTUAL_USER)

echo "[1/9] Updating system packages..."
apt-get update
apt-get upgrade -y

echo "[2/9] Installing Python 3.10+ and dependencies..."
apt-get install -y python3 python3-pip python3-venv git nginx ufw

# Verify Python version
PYTHON_VERSION=$(python3 --version | cut -d' ' -f2 | cut -d'.' -f1,2)
echo "Python version: $PYTHON_VERSION"

echo "[3/9] Detecting application files..."
# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Check if we're in the application directory
if [ ! -f "$SCRIPT_DIR/run.py" ] || [ ! -d "$SCRIPT_DIR/app" ]; then
    echo "Error: Cannot find application files"
    echo "Make sure run.py and app/ directory exist in: $SCRIPT_DIR"
    echo ""
    echo "Current directory structure:"
    ls -la "$SCRIPT_DIR"
    exit 1
fi

echo "Found application files in: $SCRIPT_DIR"

echo "[4/9] Creating application directory..."
APP_DIR="/opt/caas"
mkdir -p $APP_DIR

echo "[5/9] Copying application files..."
# Copy all files from script directory to /opt/caas
cp -r "$SCRIPT_DIR"/* $APP_DIR/
# Remove the tar file if it exists
rm -f $APP_DIR/caas.tar.gz 2>/dev/null || true

# Change to application directory
cd $APP_DIR

echo "[6/9] Creating Python virtual environment..."
python3 -m venv venv
source venv/bin/activate

echo "[7/9] Installing Python dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[8/9] Setting up production environment..."
# Generate secure secrets
JWT_SECRET=$(openssl rand -hex 32)
MASTER_KEY_SECRET=$(openssl rand -hex 32)
MASTER_KEY_SALT=$(openssl rand -hex 16)

# Create production .env file
cat > .env <<EOF
# Production Environment Configuration
APP_NAME=CaaS-Prototype
ENVIRONMENT=production
DEBUG=False
APP_VERSION=1.0.0

# Server
HOST=0.0.0.0
PORT=8000

# Security - CHANGE THESE IN PRODUCTION
JWT_SECRET=$JWT_SECRET
JWT_ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30
REFRESH_TOKEN_EXPIRE_DAYS=7

# Master Key (for encrypting stored keys)
MASTER_KEY_SECRET=$MASTER_KEY_SECRET
MASTER_KEY_SALT=$MASTER_KEY_SALT

# Database
DATABASE_URL=sqlite:///./data/caas.db

# Rate Limiting
RATE_LIMIT_ENABLED=True
RATE_LIMIT_PER_MINUTE=100

# Logging
LOG_LEVEL=INFO
LOG_FILE=./logs/app.log

# SSL/TLS (configured by nginx)
SSL_ENABLED=False
SSL_KEYFILE=
SSL_CERTFILE=
EOF

echo "[9/9] Initializing database and creating test users..."
mkdir -p data logs
python3 -c "from app.db.session import init_db; init_db()"
python3 -c "from app.db.seed import seed_database; seed_database()"

# Set correct permissions
chown -R $ACTUAL_USER:$ACTUAL_USER $APP_DIR
chmod 600 .env

echo ""
echo "======================================"
echo "Installation completed successfully!"
echo "======================================"
echo ""
echo "Next steps:"
echo "1. Run: sudo bash setup-service.sh"
echo "2. Configure nginx (optional): sudo bash setup-nginx.sh"
echo ""
