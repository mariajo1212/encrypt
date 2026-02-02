#!/bin/bash

# ============================================================
# CaaS Nginx Reverse Proxy Setup Script
# ============================================================

set -e

echo "======================================"
echo "Setting up Nginx reverse proxy"
echo "======================================"
echo ""

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Ask for domain name
read -p "Enter your domain name (e.g., caas.example.com) or press Enter to use IP: " DOMAIN_NAME

if [ -z "$DOMAIN_NAME" ]; then
    DOMAIN_NAME="your-server-ip"
    USE_SSL=false
    echo "Using IP address - SSL will not be configured"
else
    read -p "Do you want to setup SSL with Let's Encrypt? (y/n): " SETUP_SSL
    if [[ $SETUP_SSL == "y" || $SETUP_SSL == "Y" ]]; then
        USE_SSL=true
    else
        USE_SSL=false
    fi
fi

echo ""
echo "[1/5] Installing Nginx..."
apt-get install -y nginx

if [ "$USE_SSL" = true ]; then
    echo "[2/5] Installing Certbot for Let's Encrypt..."
    apt-get install -y certbot python3-certbot-nginx
else
    echo "[2/5] Skipping SSL setup..."
fi

echo "[3/5] Creating Nginx configuration..."
cat > /etc/nginx/sites-available/caas <<EOF
server {
    listen 80;
    server_name $DOMAIN_NAME;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Increase max body size for file uploads
    client_max_body_size 10M;

    # API endpoints
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # Logs
    access_log /var/log/nginx/caas_access.log;
    error_log /var/log/nginx/caas_error.log;
}
EOF

echo "[4/5] Enabling site configuration..."
ln -sf /etc/nginx/sites-available/caas /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test nginx configuration
nginx -t

echo "[5/5] Restarting Nginx..."
systemctl restart nginx
systemctl enable nginx

if [ "$USE_SSL" = true ]; then
    echo ""
    echo "Setting up SSL certificate with Let's Encrypt..."
    read -p "Enter email address for Let's Encrypt: " EMAIL
    certbot --nginx -d $DOMAIN_NAME --non-interactive --agree-tos --email $EMAIL --redirect
fi

echo ""
echo "======================================"
echo "Nginx setup completed!"
echo "======================================"
echo ""
if [ "$USE_SSL" = true ]; then
    echo "Your API is now available at: https://$DOMAIN_NAME"
    echo "Web interface: https://$DOMAIN_NAME/web"
    echo "API Docs: https://$DOMAIN_NAME/api/docs"
else
    echo "Your API is now available at: http://$DOMAIN_NAME"
    echo "Web interface: http://$DOMAIN_NAME/web"
    echo "API Docs: http://$DOMAIN_NAME/api/docs"
fi
echo ""
echo "Note: Make sure your firewall allows HTTP (80) and HTTPS (443)"
echo ""
