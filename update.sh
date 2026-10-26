#!/bin/bash
# Dovecot Web Admin Console - Update Script
# Run as root or with sudo. Pulls the latest changes, re-installs Python
# dependencies if requirements.txt changed, refreshes systemd units if
# they differ from the installed copies, re-applies file ownership, and
# restarts both services if anything changed.
#
# The ownership/account steps run even when there is nothing to pull, so
# re-running this script also repairs a drifted install. That is also how an
# install that predates the dwa-web account migrates: the first update after
# that change still executes the *old* script (bash loaded it before the
# pull), so run `sudo dovecot-webadmin-update` a second time.
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
# Keep in sync with setup.sh (see the comment there on why not www-data).
SERVICE_USER="dwa-web"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
echo_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
echo_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Keep in sync with apply_ownership() in setup.sh.
apply_ownership() {
    chown -R root:root "$INSTALL_DIR"
    chmod -R u=rwX,go=rX "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/data"
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/data"
    chmod 700 "$INSTALL_DIR/data"
    if [ -f "$INSTALL_DIR/.env" ]; then
        chown "root:$SERVICE_USER" "$INSTALL_DIR/.env"
        chmod 640 "$INSTALL_DIR/.env"
    fi
    chmod 750 "$INSTALL_DIR/update.sh"
}

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

    local needs_restart=false
    if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
        echo_info "Creating service account $SERVICE_USER..."
        useradd --system --user-group --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE_USER"
        needs_restart=true
    fi

    # Refuse to merge over local edits — operators occasionally hand-patch
    # files in /opt and would lose those changes silently otherwise.
    if [ -n "$(git status --porcelain)" ]; then
        echo_error "Local changes detected in $INSTALL_DIR:"
        git status --short
        echo_error "Commit, stash, or revert them before updating."
        exit 1
    fi

    local before_req current_branch
    before_req=$(sha256sum requirements.txt | awk '{print $1}')
    current_branch=$(git rev-parse --abbrev-ref HEAD)

    echo_info "Fetching latest from origin/$current_branch..."
    git fetch --quiet origin "$current_branch"

    local local_sha remote_sha
    local_sha=$(git rev-parse HEAD)
    remote_sha=$(git rev-parse "origin/$current_branch")

    if [ "$local_sha" = "$remote_sha" ]; then
        echo_info "Already up to date ($local_sha)."
    else
        echo_info "Updating $local_sha → $remote_sha"
        git pull --ff-only --quiet origin "$current_branch"
        needs_restart=true
    fi

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

    # Refresh systemd units if the installed copies differ from the repo —
    # compared against /etc rather than before/after the pull, so a unit
    # that was never copied (or was hand-edited) is also corrected.
    local units_changed=false unit
    for unit in dovecot-webadmin.service dovecot-webadmin-helper.service; do
        if ! cmp -s "$INSTALL_DIR/systemd/$unit" "$SYSTEMD_DIR/$unit"; then
            cp "$INSTALL_DIR/systemd/$unit" "$SYSTEMD_DIR/"
            units_changed=true
        fi
    done
    if [ "$units_changed" = true ]; then
        echo_info "Systemd units changed — reloading..."
        systemctl daemon-reload
        needs_restart=true
    else
        echo_info "Systemd units unchanged — skipping daemon-reload."
    fi

    # The tree must stay root-owned (see apply_ownership). Precompile as root
    # because the service can't write __pycache__ into a root-owned tree.
    apply_ownership
    "$VENV_DIR/bin/python" -m compileall -q "$INSTALL_DIR/app" >/dev/null || true

    if [ "$needs_restart" != true ]; then
        echo_info "Nothing changed — services left running."
        exit 0
    fi

    echo_info "Restarting services..."
    systemctl restart dovecot-webadmin-helper
    systemctl restart dovecot-webadmin

    echo_info "Update complete. Showing recent log entries:"
    sleep 1
    journalctl -u dovecot-webadmin -u dovecot-webadmin-helper -n 10 --no-pager || true
}

main "$@"
