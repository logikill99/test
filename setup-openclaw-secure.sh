#!/usr/bin/env bash
# =============================================================================
# OpenClaw Bare-Metal Setup Script v2 — Permissive Agent, Hardened Network
# =============================================================================
# Target: Ubuntu Server 24.04.4 LTS on N150 Mini PC (16GB RAM)
# Method: Native install via npm (Node.js 22+)
# Access: Local network only (UFW firewall enforced)
#
# v2 changes from original:
#   • Runs as YOUR user (no dedicated openclaw user)
#   • User-level systemd service (no sudo needed to manage)
#   • Relaxed exec permissions (agent can run commands freely)
#   • Full home directory access (no workspace-only jail)
#   • Removed ProtectSystem/ProtectHome systemd restrictions
#   • Network hardening unchanged (UFW, SSH, fail2ban)
#
# What's still hardened:
#   • UFW firewall: SSH + gateway restricted to your LAN CIDR
#   • SSH hardened: root login disabled, fail2ban active
#   • Gateway binds to LAN interface (not 0.0.0.0, not public)
#   • Token-based authentication on the Control UI
#   • DM pairing: unknown senders must be approved
#   • Automatic security updates enabled
#
# Usage:
#   chmod +x setup-openclaw-bare-v2.sh
#   sudo ./setup-openclaw-bare-v2.sh
#
# If your LAN is not 192.168.0.0/24:
#   sudo LAN_CIDR="192.168.1.0/24" ./setup-openclaw-bare-v2.sh
#
# To specify which user to install under (default: the user who ran sudo):
#   sudo OPENCLAW_USER="fem" ./setup-openclaw-bare-v2.sh
#
# =============================================================================

set -euo pipefail

# ------------------------------- Configuration -------------------------------

# Local network CIDR — adjust to YOUR network
LAN_CIDR="${LAN_CIDR:-192.168.0.0/24}"

# The user who will run OpenClaw (default: whoever invoked sudo)
OPENCLAW_USER="${OPENCLAW_USER:-${SUDO_USER:-$(whoami)}}"

# Swap size
SWAP_SIZE="4G"

# Gateway port
GATEWAY_PORT="18789"

# Node.js major version
NODE_MAJOR="22"

# --------------------------------- Preflight ---------------------------------

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: This script must be run as root (use sudo)."
    exit 1
fi

if [[ "${OPENCLAW_USER}" == "root" ]]; then
    echo "ERROR: Don't run OpenClaw as root. Set OPENCLAW_USER or run with sudo from a normal user."
    exit 1
fi

if ! id "${OPENCLAW_USER}" &>/dev/null; then
    echo "ERROR: User '${OPENCLAW_USER}' does not exist."
    exit 1
fi

if ! grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
    echo "WARNING: This script targets Ubuntu 24.04. Proceed at your own risk."
fi

# Resolve home directory
OPENCLAW_HOME=$(eval echo "~${OPENCLAW_USER}")

# Detect local IP
LOCAL_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || hostname -I | awk '{print $1}')

# Generate a secure random gateway token (48 hex chars)
GATEWAY_TOKEN=$(openssl rand -hex 24)

echo "============================================================================="
echo "  OpenClaw Bare-Metal Setup v2 (Permissive Agent, Hardened Network)"
echo "============================================================================="
echo ""
echo "  Machine IP        : ${LOCAL_IP}"
echo "  Allowed LAN       : ${LAN_CIDR}"
echo "  OpenClaw user     : ${OPENCLAW_USER} (your account)"
echo "  Home directory    : ${OPENCLAW_HOME}"
echo "  Gateway port      : ${GATEWAY_PORT}"
echo "  Swap size         : ${SWAP_SIZE}"
echo "  Install method    : Native (npm, no Docker)"
echo "  Service type      : User-level systemd (no sudo to manage)"
echo ""
echo "  Wrong subnet? Exit and re-run:"
echo "    sudo LAN_CIDR=\"10.0.0.0/24\" ./setup-openclaw-bare-v2.sh"
echo ""
read -rp "  Press Enter to continue or Ctrl+C to abort..."

# ========================= STEP 1: System Update =============================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[1/8] Updating system and installing prerequisites..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

export DEBIAN_FRONTEND=noninteractive

apt-get update -y
apt-get upgrade -y
apt-get install -y \
    curl \
    wget \
    git \
    ca-certificates \
    gnupg \
    lsb-release \
    ufw \
    unattended-upgrades \
    fail2ban \
    jq \
    build-essential

echo "  ✓ System packages updated"

# ========================= STEP 2: Swap File ================================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[2/8] Configuring swap..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if swapon --show | grep -q "/swapfile"; then
    echo "  Swap already exists, skipping."
else
    fallocate -l "${SWAP_SIZE}" /swapfile
    chmod 600 /swapfile
    mkswap /swapfile
    swapon /swapfile

    if ! grep -q "/swapfile" /etc/fstab; then
        echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi

    cat > /etc/sysctl.d/99-openclaw.conf <<SYSCTL
vm.swappiness=10
vm.vfs_cache_pressure=50
SYSCTL
    sysctl -p /etc/sysctl.d/99-openclaw.conf >/dev/null 2>&1

    echo "  ✓ ${SWAP_SIZE} swap created"
fi

# ========================= STEP 3: Install Node.js 22 =======================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[3/8] Installing Node.js ${NODE_MAJOR}..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

CURRENT_NODE_MAJOR=""
if command -v node &>/dev/null; then
    CURRENT_NODE_MAJOR=$(node -v | sed 's/^v//' | cut -d. -f1)
fi

if [[ "${CURRENT_NODE_MAJOR}" -ge "${NODE_MAJOR}" ]] 2>/dev/null; then
    echo "  Node.js already installed: $(node -v)"
else
    curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
    apt-get install -y nodejs
    echo "  ✓ Node.js installed: $(node -v)"
fi

echo "  ✓ npm version: $(npm -v)"

# Configure npm global prefix for the user
NPM_GLOBAL="${OPENCLAW_HOME}/.npm-global"

su - "${OPENCLAW_USER}" -c "
    mkdir -p ${NPM_GLOBAL}
    npm config set prefix ${NPM_GLOBAL}
"

# Add npm global bin to the user's PATH permanently
BASHRC="${OPENCLAW_HOME}/.bashrc"
NPM_PATH_LINE="export PATH=\"${NPM_GLOBAL}/bin:\$PATH\""

if ! grep -qF "${NPM_GLOBAL}/bin" "${BASHRC}" 2>/dev/null; then
    echo "" >> "${BASHRC}"
    echo "# OpenClaw npm global path" >> "${BASHRC}"
    echo "${NPM_PATH_LINE}" >> "${BASHRC}"
fi

echo "  ✓ npm global prefix configured at ${NPM_GLOBAL}"

# ========================= STEP 4: Install OpenClaw ==========================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[4/8] Installing OpenClaw via npm..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

su - "${OPENCLAW_USER}" -c "
    export PATH=\"${NPM_GLOBAL}/bin:\$PATH\"
    npm install -g openclaw@latest
"

OPENCLAW_BIN="${NPM_GLOBAL}/bin/openclaw"
if [[ -x "${OPENCLAW_BIN}" ]]; then
    OPENCLAW_VERSION=$(su - "${OPENCLAW_USER}" -c "export PATH=\"${NPM_GLOBAL}/bin:\$PATH\" && openclaw --version" 2>/dev/null || echo "installed")
    echo "  ✓ OpenClaw installed: ${OPENCLAW_VERSION}"
else
    echo "ERROR: OpenClaw binary not found at ${OPENCLAW_BIN}"
    echo "  Try running manually: su - ${OPENCLAW_USER} -c 'npm install -g openclaw@latest'"
    exit 1
fi

# ========================= STEP 5: Permissive Config =========================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[5/8] Writing OpenClaw configuration (permissive agent, hardened network)..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

OPENCLAW_CONFIG_DIR="${OPENCLAW_HOME}/.openclaw"
OPENCLAW_WORKSPACE="${OPENCLAW_CONFIG_DIR}/workspace"
OPENCLAW_CONFIG_FILE="${OPENCLAW_CONFIG_DIR}/openclaw.json"

mkdir -p "${OPENCLAW_CONFIG_DIR}"
mkdir -p "${OPENCLAW_WORKSPACE}"

if [[ ! -f "${OPENCLAW_CONFIG_FILE}" ]]; then
    cat > "${OPENCLAW_CONFIG_FILE}" <<CLAWCONFIG
{
  // Permissive agent config — hardened at the network layer instead
  // Generated by setup script v2 on $(date -Iseconds)

  "gateway": {
    "port": ${GATEWAY_PORT},
    "mode": "local",
    "bind": "lan",
    "auth": {
      "mode": "token",
      "token": "${GATEWAY_TOKEN}"
    }
  },

  "session": {
    "dmScope": "per-channel-peer"
  },

  // Agent has full exec and filesystem access — no consent prompts
  "tools": {
    "fs": {
      "workspaceOnly": false
    },
    "exec": {
      "ask": "never"
    }
  },

  "agent": {
    "workspace": "~/.openclaw/workspace"
  }
}
CLAWCONFIG
    echo "  ✓ Config written to ${OPENCLAW_CONFIG_FILE}"
    echo "  ✓ Exec: agent can run commands without approval"
    echo "  ✓ Filesystem: full home directory access (not jailed)"
else
    echo "  Config already exists at ${OPENCLAW_CONFIG_FILE}, not overwriting."
fi

# Set sane ownership — no paranoid lockdown this time
chown -R "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_CONFIG_DIR}"

echo "  ✓ Config directory owned by ${OPENCLAW_USER}"

# ========================= STEP 6: User-Level Systemd Service ================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[6/8] Creating user-level systemd service..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Clean up any old system-level service from v1
if [[ -f /etc/systemd/system/openclaw-gateway.service ]]; then
    systemctl stop openclaw-gateway.service 2>/dev/null || true
    systemctl disable openclaw-gateway.service 2>/dev/null || true
    rm -f /etc/systemd/system/openclaw-gateway.service
    systemctl daemon-reload
    echo "  ✓ Removed old system-level service"
fi

# Enable lingering so the user service runs without login
loginctl enable-linger "${OPENCLAW_USER}"

# Create user-level systemd directory and service
SYSTEMD_USER_DIR="${OPENCLAW_HOME}/.config/systemd/user"
mkdir -p "${SYSTEMD_USER_DIR}"

cat > "${SYSTEMD_USER_DIR}/openclaw-gateway.service" <<SYSTEMD
[Unit]
Description=OpenClaw Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
Environment="PATH=${NPM_GLOBAL}/bin:/usr/local/bin:/usr/bin:/bin"
Environment="NODE_ENV=production"
ExecStart=${OPENCLAW_BIN} gateway --port ${GATEWAY_PORT}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
SYSTEMD

chown -R "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_HOME}/.config"

# Enable via the user's systemd instance
su - "${OPENCLAW_USER}" -c "
    export XDG_RUNTIME_DIR=/run/user/\$(id -u)
    systemctl --user daemon-reload
    systemctl --user enable openclaw-gateway.service
"

echo "  ✓ User-level systemd service created and enabled"
echo "  ✓ Lingering enabled (service runs without login)"
echo "  ✓ Manage with: systemctl --user [start|stop|restart|status] openclaw-gateway"

# ========================= STEP 7: Firewall + SSH Hardening ==================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[7/8] Configuring firewall and hardening SSH..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# --- UFW Firewall ---
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Allow SSH from LAN only
ufw allow from "${LAN_CIDR}" to any port 22 proto tcp comment "SSH from LAN"

# Allow OpenClaw from LAN only
ufw allow from "${LAN_CIDR}" to any port "${GATEWAY_PORT}" proto tcp comment "OpenClaw from LAN"

# Explicit deny for gateway from everywhere else
ufw deny "${GATEWAY_PORT}/tcp" comment "Block OpenClaw from WAN"

ufw --force enable

echo "  ✓ UFW: LAN-only access (${LAN_CIDR})"
ufw status numbered

# --- SSH hardening ---
SSH_CONFIG="/etc/ssh/sshd_config"

if grep -q "^PermitRootLogin" "${SSH_CONFIG}"; then
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "${SSH_CONFIG}"
else
    echo "PermitRootLogin no" >> "${SSH_CONFIG}"
fi

systemctl restart ssh

# --- fail2ban ---
cat > /etc/fail2ban/jail.local <<F2B
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
findtime = 600
F2B

systemctl enable fail2ban
systemctl restart fail2ban

echo "  ✓ SSH: root login disabled, fail2ban active"

# ========================= STEP 8: Automatic Updates ========================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[8/8] Enabling automatic security updates..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cat > /etc/apt/apt.conf.d/20auto-upgrades <<AUTOUPDATE
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
AUTOUPDATE

systemctl enable unattended-upgrades
echo "  ✓ Automatic security updates enabled"

# ========================= COMPLETE ==========================================
echo ""
echo ""
echo "╔═══════════════════════════════════════════════════════════════════════════╗"
echo "║                     ✅  SETUP COMPLETE (v2)                             ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Your N150 mini PC is ready. Agent is permissive, network is locked down."
echo ""
echo "  ┌─────────────────────────────────────────────────────────────────────┐"
echo "  │  WHAT CHANGED FROM v1                                             │"
echo "  └─────────────────────────────────────────────────────────────────────┘"
echo ""
echo "  • Runs as ${OPENCLAW_USER} (your account, not a separate user)"
echo "  • User-level systemd (manage without sudo)"
echo "  • Agent can execute commands freely (no consent prompts)"
echo "  • Agent can read/write anywhere in your home directory"
echo "  • No ProtectSystem/ProtectHome restrictions"
echo "  • Network security unchanged (LAN-only, token auth, fail2ban)"
echo ""
echo "  ┌─────────────────────────────────────────────────────────────────────┐"
echo "  │  NEXT STEPS                                                       │"
echo "  └─────────────────────────────────────────────────────────────────────┘"
echo ""
echo "  1. Run the onboarding wizard:"
echo ""
echo "       openclaw onboard"
echo ""
echo "  2. Restore your backup (soul, tools, user, heartbeat, etc.):"
echo ""
echo "       # Copy your backed-up files into:"
echo "       #   ~/.openclaw/          (config, cron, etc.)"
echo "       #   ~/clawd/              (soul, user, persona files)"
echo ""
echo "  3. Start the gateway:"
echo ""
echo "       systemctl --user start openclaw-gateway"
echo ""
echo "  ┌─────────────────────────────────────────────────────────────────────┐"
echo "  │  CONTROL UI                                                       │"
echo "  └─────────────────────────────────────────────────────────────────────┘"
echo ""
echo "  From any device on your LAN:"
echo ""
echo "    http://${LOCAL_IP}:${GATEWAY_PORT}/?token=${GATEWAY_TOKEN}"
echo ""
echo "  ⚠  SAVE THIS TOKEN:"
echo ""
echo "    ${GATEWAY_TOKEN}"
echo ""
echo "  Also stored in: ${OPENCLAW_CONFIG_FILE}"
echo ""
echo "  ┌─────────────────────────────────────────────────────────────────────┐"
echo "  │  DAILY COMMANDS (no sudo needed!)                                 │"
echo "  └─────────────────────────────────────────────────────────────────────┘"
echo ""
echo "  Start gateway     systemctl --user start openclaw-gateway"
echo "  Stop gateway      systemctl --user stop openclaw-gateway"
echo "  Restart gateway   systemctl --user restart openclaw-gateway"
echo "  View status       systemctl --user status openclaw-gateway"
echo "  View logs         journalctl --user -u openclaw-gateway -f"
echo "  Health check      openclaw doctor"
echo "  Update OpenClaw   npm update -g openclaw@latest"
echo ""
echo "  ┌─────────────────────────────────────────────────────────────────────┐"
echo "  │  SECURITY SUMMARY                                                 │"
echo "  └─────────────────────────────────────────────────────────────────────┘"
echo ""
echo "  ✓ Firewall        LAN-only (${LAN_CIDR}), all other inbound blocked"
echo "  ✓ Gateway auth    Token required (48 hex chars)"
echo "  ✓ DM policy       Per-channel peer isolation (pairing required)"
echo "  ✓ SSH             Root login disabled, fail2ban active"
echo "  ✓ Auto-updates    Unattended security patches enabled"
echo "  ⚡ Exec            Agent runs commands freely (no consent gate)"
echo "  ⚡ Filesystem      Full home directory access (no workspace jail)"
echo ""
echo "═══════════════════════════════════════════════════════════════════════════"
