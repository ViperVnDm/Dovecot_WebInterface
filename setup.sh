#!/bin/bash
# Dovecot Web Admin Console - Installation Script
# Run as root or with sudo from inside a fresh git clone of this repo.
#
# Installs by git-cloning into /opt/dovecot-webadmin, so subsequent updates
# are just `sudo dovecot-webadmin-update` (which calls git pull + restart).
# See update.sh.

set -e

INSTALL_DIR="/opt/dovecot-webadmin"
VENV_DIR="$INSTALL_DIR/venv"
DATA_DIR="$INSTALL_DIR/data"
SERVICE_USER="www-data"
UPDATE_SYMLINK="/usr/local/sbin/dovecot-webadmin-update"

SCRIPT_DIR="$(cd "$(dirname "$(realpath "$0")")" && pwd)"

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

# Check for git
if ! command -v git >/dev/null 2>&1; then
    echo_error "git is required (sudo apt install git)"
    exit 1
fi

# Determine the repo URL to clone from — derived from the directory this
# script is being run from, so the install matches whatever fork/branch
# the operator already trusts.
if [ ! -d "$SCRIPT_DIR/.git" ]; then
    echo_error "setup.sh must be run from a git checkout of the source repo."
    echo_error "Try: git clone <repo-url> /tmp/dovecot-webadmin-src && sudo /tmp/dovecot-webadmin-src/setup.sh"
    exit 1
fi

REPO_URL=$(git -C "$SCRIPT_DIR" remote get-url origin 2>/dev/null || echo "")
if [ -z "$REPO_URL" ]; then
    echo_error "Could not determine origin remote from $SCRIPT_DIR — is 'origin' configured?"
    exit 1
fi

# Refuse to clobber an existing install. Migration from the old
# copy-based layout is documented in the README.
if [ -e "$INSTALL_DIR" ]; then
    if [ -d "$INSTALL_DIR/.git" ]; then
        echo_error "$INSTALL_DIR already exists and is git-managed."
        echo_error "Use 'sudo dovecot-webadmin-update' (or 'sudo $INSTALL_DIR/update.sh') to update."
    else
        echo_error "$INSTALL_DIR exists but is not a git checkout (legacy copy-based install)."
        echo_error "To migrate: back up .env and data/, remove $INSTALL_DIR, then re-run this script."
        echo_error "  sudo cp $INSTALL_DIR/.env /tmp/dwa.env.bak"
        echo_error "  sudo cp -r $INSTALL_DIR/data /tmp/dwa-data.bak"
        echo_error "  sudo systemctl stop dovecot-webadmin dovecot-webadmin-helper"
        echo_error "  sudo rm -rf $INSTALL_DIR"
        echo_error "  sudo $0           # re-run setup"
        echo_error "  sudo cp /tmp/dwa.env.bak $INSTALL_DIR/.env"
        echo_error "  sudo cp -r /tmp/dwa-data.bak/* $INSTALL_DIR/data/"
        echo_error "  sudo chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR/data $INSTALL_DIR/.env"
    fi
    exit 1
fi

echo_info "Installing Dovecot Web Admin Console from $REPO_URL"

# Clone the repo in-place. Subsequent updates pull into this same directory.
echo_info "Cloning repository to $INSTALL_DIR..."
git clone "$REPO_URL" "$INSTALL_DIR"
mkdir -p "$DATA_DIR"

# Seed .env from the example (this path lives inside the clone now)
if [ ! -f "$INSTALL_DIR/.env" ]; then
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
fi

# Create Python virtual environment (gitignored: venv/)
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

# Keep .git owned by root so future `sudo git pull` works without tripping
# git's "dubious ownership" safety check (CVE-2022-24765).
chown -R root:root "$INSTALL_DIR/.git"

# Install systemd services
echo_info "Installing systemd services..."
cp "$INSTALL_DIR/systemd/dovecot-webadmin.service" /etc/systemd/system/
cp "$INSTALL_DIR/systemd/dovecot-webadmin-helper.service" /etc/systemd/system/
systemctl daemon-reload

# Install the update helper as a system command
echo_info "Installing update helper at $UPDATE_SYMLINK..."
chmod 750 "$INSTALL_DIR/update.sh"
ln -sf "$INSTALL_DIR/update.sh" "$UPDATE_SYMLINK"

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
echo "  1. Edit $INSTALL_DIR/.env and set SMTP_FROM to a real address"
echo "     on your domain (e.g. alerts@yourdomain.com) to enable email alerts."
echo "  2. Configure nginx as a reverse proxy with HTTPS."
echo "     See README.md for a sample nginx configuration."
echo ""
echo "To update later:"
echo "  sudo dovecot-webadmin-update"
echo ""
echo "Service commands:"
echo "  systemctl status dovecot-webadmin"
echo "  systemctl restart dovecot-webadmin"
echo "  journalctl -u dovecot-webadmin -f"
echo "  journalctl -u dovecot-webadmin-helper -f"
