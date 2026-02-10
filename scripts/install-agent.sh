#!/usr/bin/env bash
# BİGR Discovery Agent — Quick Install Script
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/okanyucel2/genesis-bigr-discovery/main/scripts/install-agent.sh | bash
#
# Or locally:
#   bash scripts/install-agent.sh
#
# Prerequisites:
#   - Python 3.12+
#   - pip
#   - (optional) nmap for active scanning
#   - (optional) root/sudo for ARP sweeps

set -euo pipefail

REPO_URL="https://github.com/okanyucel2/genesis-bigr-discovery.git"
INSTALL_DIR="${BIGR_INSTALL_DIR:-$HOME/.bigr-agent}"
VENV_DIR="$INSTALL_DIR/venv"

echo "============================================"
echo "  BİGR Discovery Agent — Installer"
echo "============================================"
echo ""

# ── Check Python ──────────────────────────────────────────────────────────────
PYTHON=""
for cmd in python3.12 python3 python; do
    if command -v "$cmd" &>/dev/null; then
        ver=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null || echo "0.0")
        major=$(echo "$ver" | cut -d. -f1)
        minor=$(echo "$ver" | cut -d. -f2)
        if [ "$major" -ge 3 ] && [ "$minor" -ge 12 ]; then
            PYTHON="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON" ]; then
    echo "ERROR: Python 3.12+ is required but not found."
    echo "Install it from https://www.python.org/downloads/"
    exit 1
fi
echo "[OK] Python: $($PYTHON --version)"

# ── Check nmap (optional) ────────────────────────────────────────────────────
if command -v nmap &>/dev/null; then
    echo "[OK] nmap: $(nmap --version | head -1)"
else
    echo "[WARN] nmap not found — active scanning will be limited."
    echo "       Install: sudo apt install nmap  (or brew install nmap)"
fi

echo ""

# ── Clone or update repo ─────────────────────────────────────────────────────
if [ -d "$INSTALL_DIR/.git" ]; then
    echo "Updating existing installation..."
    git -C "$INSTALL_DIR" pull --ff-only
else
    echo "Installing to $INSTALL_DIR ..."
    git clone --depth 1 "$REPO_URL" "$INSTALL_DIR"
fi

# ── Create venv and install ──────────────────────────────────────────────────
echo ""
echo "Setting up virtual environment..."
if [ ! -d "$VENV_DIR" ]; then
    "$PYTHON" -m venv "$VENV_DIR"
fi

source "$VENV_DIR/bin/activate"
pip install --quiet --upgrade pip
pip install --quiet -e "$INSTALL_DIR"

echo ""
echo "[OK] bigr CLI installed: $(which bigr)"
echo ""

# ── Add to PATH hint ─────────────────────────────────────────────────────────
BIGR_BIN="$VENV_DIR/bin"
if [[ ":$PATH:" != *":$BIGR_BIN:"* ]]; then
    echo "Add to your shell profile:"
    echo "  export PATH=\"$BIGR_BIN:\$PATH\""
    echo ""
fi

# ── Interactive registration ─────────────────────────────────────────────────
echo "============================================"
echo "  Agent Registration"
echo "============================================"
echo ""

CONFIG_FILE="$HOME/.bigr/agent.yaml"
if [ -f "$CONFIG_FILE" ]; then
    echo "Existing config found at $CONFIG_FILE"
    echo "Skipping registration (delete the file to re-register)."
else
    read -rp "Cloud API URL (e.g. https://bigr-discovery-api.onrender.com): " API_URL
    read -rp "Agent name (e.g. istanbul-scanner): " AGENT_NAME
    read -rp "Site name (e.g. Istanbul Office): " SITE_NAME
    read -rp "Registration secret (leave empty if not required): " SECRET

    SECRET_FLAG=""
    if [ -n "$SECRET" ]; then
        SECRET_FLAG="--secret $SECRET"
    fi

    echo ""
    echo "Registering agent..."
    bigr agent register \
        --api-url "$API_URL" \
        --name "$AGENT_NAME" \
        --site "$SITE_NAME" \
        $SECRET_FLAG

    echo ""
    echo "[OK] Agent registered. Config saved to $CONFIG_FILE"
fi

echo ""
echo "============================================"
echo "  Quick Start"
echo "============================================"
echo ""
echo "  # Start scanning (replace with your subnet)"
echo "  bigr agent start 192.168.1.0/24 --interval 5m"
echo ""
echo "  # With shield security modules"
echo "  bigr agent start 192.168.1.0/24 --interval 5m --shield"
echo ""
echo "  # Check status"
echo "  bigr agent status"
echo ""
echo "  # Stop agent"
echo "  bigr agent stop"
echo ""
echo "Done."
