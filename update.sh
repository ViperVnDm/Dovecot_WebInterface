#!/bin/bash
# Dovecot Web Admin Console - Update Script
# Run as root or with sudo. Pulls the latest changes, re-installs Python
# dependencies if requirements.txt changed, refreshes systemd units if
# they changed, and restarts both services.
#
# Usage:
#   sudo dovecot-webadmin-update         # via the /usr/local/sbin symlink
#   sudo /opt/dovecot-webadmin/update.sh # direct
#
# The entire body runs inside main() so bash loads it before `git pull`
# can modify this file on disk — safe across self-modification.

set -e

INSTALL_DIR="/opt/dovecot-webadmin"
VENV_DIR="$INSTALL_DIR/venv"
SYSTEMD_DIR="/etc/systemd/system"
SERVICE_USER="www-data"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }

main() {
    if [ "$EUID" -ne 0 ]; then
        echo_error "Please run as root or with sudo"
        exit 1
    fi

    if [ ! -d "$INSTALL_DIR/.git" ]; then
        echo_error "$INSTALL_DIR is not a git checkout."
        echo_error "This script only works with the git-managed install layout."
        echo_error "See README.md → 'Migrating an existing copy-based install'."
        exit 1
    fi

    cd "$INSTALL_DIR"

    # Refuse to merge over local edits — operators occasionally hand-patch
    # files in /opt and would lose those changes silently otherwise.
    if [ -n "$(git status --porcelain)" ]; then
        echo_error "Local changes detected in $INSTALL_DIR:"
        git status --short
        echo_error "Commit, stash, or revert them before updating."
        exit 1
    fi

    local before_req before_units current_branch
    before_req=$(sha256sum requirements.txt | awk '{print $1}')
    before_units=$(sha256sum systemd/*.service | sha256sum | awk '{print $1}')
    current_branch=$(git rev-parse --abbrev-ref HEAD)

    echo_info "Fetching latest from origin/$current_branch..."
    git fetch --quiet origin "$current_branch"

    local local_sha remote_sha
    local_sha=$(git rev-parse HEAD)
    remote_sha=$(git rev-parse "origin/$current_branch")

    if [ "$local_sha" = "$remote_sha" ]; then
        echo_info "Already up to date ($local_sha)."
        exit 0
    fi

    echo_info "Updating $local_sha → $remote_sha"
    git pull --ff-only --quiet origin "$current_branch"

    # Re-install deps only if requirements.txt actually changed (most
    # updates don't touch deps, so this saves ~10s per run).
    local after_req
    after_req=$(sha256sum requirements.txt | awk '{print $1}')
    if [ "$before_req" != "$after_req" ]; then
        echo_info "requirements.txt changed — reinstalling Python dependencies..."
        "$VENV_DIR/bin/pip" install --quiet --upgrade pip
        "$VENV_DIR/bin/pip" install --quiet -r "$INSTALL_DIR/requirements.txt"
    else
        echo_info "requirements.txt unchanged — skipping pip install."
    fi

    # Refresh systemd units only if they changed.
    local after_units
    after_units=$(sha256sum systemd/*.service | sha256sum | awk '{print $1}')
    if [ "$before_units" != "$after_units" ]; then
        echo_info "Systemd units changed — copying to $SYSTEMD_DIR and reloading..."
        cp "$INSTALL_DIR/systemd/dovecot-webadmin.service" "$SYSTEMD_DIR/"
        cp "$INSTALL_DIR/systemd/dovecot-webadmin-helper.service" "$SYSTEMD_DIR/"
        systemctl daemon-reload
    else
        echo_info "Systemd units unchanged — skipping daemon-reload."
    fi

    # File ownership: git pull writes as root (since we run as root). Reset
    # ownership so the web service can read its own files.
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chown -R root:root "$INSTALL_DIR/privileged"
    chmod 600 "$INSTALL_DIR/.env" 2>/dev/null || true
    chmod 750 "$INSTALL_DIR/update.sh"

    echo_info "Restarting services..."
    systemctl restart dovecot-webadmin-helper
    systemctl restart dovecot-webadmin

    echo_info "Update complete. Showing recent log entries:"
    sleep 1
    journalctl -u dovecot-webadmin -u dovecot-webadmin-helper -n 10 --no-pager || true
}

main "$@"
