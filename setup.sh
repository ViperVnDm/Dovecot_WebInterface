#!/bin/bash
# Dovecot Web Admin Console - Installation Script
# Run as root or with sudo

set -e

INSTALL_DIR="/opt/dovecot-webadmin"
VENV_DIR="$INSTALL_DIR/venv"
DATA_DIR="$INSTALL_DIR/data"
SERVICE_USER="www-data"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

echo_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

echo_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo_error "Please run as root or with sudo"
    exit 1
fi

# Check for Python 3.10+
PYTHON_VERSION=$(python3 --version 2>&1 | grep -oP '(?<=Python )\d+\.\d+')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 10 ]); then
    echo_error "Python 3.10 or higher is required (found $PYTHON_VERSION)"
    exit 1
fi

echo_info "Installing Dovecot Web Admin Console..."

# Create installation directory
echo_info "Creating installation directory..."
mkdir -p "$INSTALL_DIR"
mkdir -p "$DATA_DIR"

# Copy application files
echo_info "Copying application files..."
cp -r app "$INSTALL_DIR/"
cp -r privileged "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"
cp manage.py "$INSTALL_DIR/"
cp .env.example "$INSTALL_DIR/.env"

# Create Python virtual environment
echo_info "Creating Python virtual environment..."
python3 -m venv "$VENV_DIR"

# Install dependencies
echo_info "Installing Python dependencies..."
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt"

# Generate secret key
echo_info "Generating secret key..."
SECRET_KEY=$("$VENV_DIR/bin/python" -c "import secrets; print(secrets.token_urlsafe(32))")
sed -i "s/SECRET_KEY=.*/SECRET_KEY=$SECRET_KEY/" "$INSTALL_DIR/.env"

# Set permissions
echo_info "Setting file permissions..."
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
chmod 600 "$INSTALL_DIR/.env"

# Privileged helper needs root ownership
chown root:root "$INSTALL_DIR/privileged" -R

# Install systemd services
echo_info "Installing systemd services..."
cp systemd/dovecot-webadmin.service /etc/systemd/system/
cp systemd/dovecot-webadmin-helper.service /etc/systemd/system/
systemctl daemon-reload

# Create initial admin user
echo_info "Creating initial admin user..."
read -p "Admin username: " ADMIN_USER
read -s -p "Admin password: " ADMIN_PASS
echo ""

# Pass credentials via environment to avoid shell-injection through quotes
# in the username or password (CVE-style: a password containing ' would
# break out of the Python string literal).
ADMIN_USER="$ADMIN_USER" ADMIN_PASS="$ADMIN_PASS" INSTALL_DIR="$INSTALL_DIR" \
"$VENV_DIR/bin/python" -c "
import asyncio
import os
import sys
sys.path.insert(0, os.environ['INSTALL_DIR'])
from app.database import create_initial_admin, init_db

async def main():
    await init_db()
    await create_initial_admin(os.environ['ADMIN_USER'], os.environ['ADMIN_PASS'])
    print('Admin user created successfully')

asyncio.run(main())
"

# Scrub the password from this shell's memory
unset ADMIN_PASS

# Enable and start services
echo_info "Enabling and starting services..."
systemctl enable dovecot-webadmin-helper
systemctl enable dovecot-webadmin
systemctl start dovecot-webadmin-helper
systemctl start dovecot-webadmin

echo ""
echo_info "Installation complete!"
echo ""
echo "The admin console is now running at http://127.0.0.1:8000"
echo ""
echo_warn "Next steps:"
echo "  1. Edit /opt/dovecot-webadmin/.env and set SMTP_FROM to a real address"
echo "     on your domain (e.g. alerts@yourdomain.com) to enable email alerts."
echo "  2. Configure nginx as a reverse proxy with HTTPS."
echo "     See README.md for a sample nginx configuration."
echo ""
echo "Service commands:"
echo "  systemctl status dovecot-webadmin"
echo "  systemctl restart dovecot-webadmin"
echo "  journalctl -u dovecot-webadmin -f"
echo "  journalctl -u dovecot-webadmin-helper -f"
