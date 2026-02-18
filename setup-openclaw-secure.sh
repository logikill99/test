#!/usr/bin/env bash
# =============================================================================
# OpenClaw Secure Bare-Metal Setup Script (No Docker)
# =============================================================================
# Target: Ubuntu Server 24.04.4 LTS on N150 Mini PC (16GB RAM)
# Method: Native install via npm (Node.js 22+)
# Access: Local network only (UFW firewall enforced)
#
# Security hardening included:
#   • Dedicated unprivileged 'openclaw' user (no sudo)
#   • UFW firewall: SSH + gateway restricted to your LAN CIDR
#   • SSH hardened: root login disabled, fail2ban active
#   • Gateway binds to LAN interface (not 0.0.0.0, not public)
#   • Token-based authentication on the Control UI
#   • Exec consent mode: approval required before every command
#   • DM pairing: unknown senders must be approved
#   • Filesystem restricted to workspace only
#   • ~/.openclaw permissions locked to owner-only (700/600)
#   • Automatic security updates enabled
#   • Systemd service: auto-start on boot, auto-restart on crash
#
# Usage:
#   chmod +x setup-openclaw-bare.sh
#   sudo ./setup-openclaw-bare.sh
#
# If your LAN is not 192.168.1.0/24:
#   sudo LAN_CIDR="192.168.0.0/24" ./setup-openclaw-bare.sh
#
# =============================================================================

set -euo pipefail

# ------------------------------- Configuration -------------------------------

# Local network CIDR — adjust to YOUR network
LAN_CIDR="${LAN_CIDR:-192.168.1.0/24}"

# Dedicated unprivileged user (no sudo access)
OPENCLAW_USER="openclaw"

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

if ! grep -qi "ubuntu" /etc/os-release 2>/dev/null; then
    echo "WARNING: This script targets Ubuntu 24.04. Proceed at your own risk."
fi

# Detect local IP
LOCAL_IP=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}' || hostname -I | awk '{print $1}')

# Generate a secure random gateway token (48 hex chars)
GATEWAY_TOKEN=$(openssl rand -hex 24)

echo "============================================================================="
echo "  OpenClaw Bare-Metal Secure Setup"
echo "============================================================================="
echo ""
echo "  Machine IP        : ${LOCAL_IP}"
echo "  Allowed LAN       : ${LAN_CIDR}"
echo "  OpenClaw user     : ${OPENCLAW_USER}"
echo "  Gateway port      : ${GATEWAY_PORT}"
echo "  Swap size         : ${SWAP_SIZE}"
echo "  Install method    : Native (npm, no Docker)"
echo ""
echo "  Wrong subnet? Exit and re-run:"
echo "    sudo LAN_CIDR=\"10.0.0.0/24\" ./setup-openclaw-bare.sh"
echo ""
read -rp "  Press Enter to continue or Ctrl+C to abort..."

# ========================= STEP 1: System Update =============================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[1/9] Updating system and installing prerequisites..."
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
echo "[2/9] Configuring swap..."
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

# ========================= STEP 3: Create Locked-Down User ==================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[3/9] Creating dedicated '${OPENCLAW_USER}' user (no sudo)..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if id "${OPENCLAW_USER}" &>/dev/null; then
    echo "  User '${OPENCLAW_USER}' already exists."
else
    useradd -m -s /bin/bash "${OPENCLAW_USER}"
    echo "  ✓ User '${OPENCLAW_USER}' created"
fi

# Explicitly ensure this user is NOT in the sudo group
if groups "${OPENCLAW_USER}" | grep -qw sudo; then
    gpasswd -d "${OPENCLAW_USER}" sudo 2>/dev/null || true
    echo "  ✓ Removed from sudo group"
fi

echo "  ✓ User '${OPENCLAW_USER}' has no sudo/root privileges"

# ========================= STEP 4: Install Node.js 22 =======================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[4/9] Installing Node.js ${NODE_MAJOR}..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check if Node 22+ is already installed
CURRENT_NODE_MAJOR=""
if command -v node &>/dev/null; then
    CURRENT_NODE_MAJOR=$(node -v | sed 's/^v//' | cut -d. -f1)
fi

if [[ "${CURRENT_NODE_MAJOR}" -ge "${NODE_MAJOR}" ]] 2>/dev/null; then
    echo "  Node.js already installed: $(node -v)"
else
    # Install via NodeSource (official method for Ubuntu)
    curl -fsSL "https://deb.nodesource.com/setup_${NODE_MAJOR}.x" | bash -
    apt-get install -y nodejs

    echo "  ✓ Node.js installed: $(node -v)"
fi

echo "  ✓ npm version: $(npm -v)"

# Configure npm global prefix for the openclaw user (avoids permission issues)
OPENCLAW_HOME="/home/${OPENCLAW_USER}"
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

# ========================= STEP 5: Install OpenClaw ==========================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[5/9] Installing OpenClaw via npm..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

su - "${OPENCLAW_USER}" -c "
    export PATH=\"${NPM_GLOBAL}/bin:\$PATH\"
    npm install -g openclaw@latest
"

# Verify installation
OPENCLAW_BIN="${NPM_GLOBAL}/bin/openclaw"
if [[ -x "${OPENCLAW_BIN}" ]]; then
    OPENCLAW_VERSION=$(su - "${OPENCLAW_USER}" -c "export PATH=\"${NPM_GLOBAL}/bin:\$PATH\" && openclaw --version" 2>/dev/null || echo "installed")
    echo "  ✓ OpenClaw installed: ${OPENCLAW_VERSION}"
else
    echo "ERROR: OpenClaw binary not found at ${OPENCLAW_BIN}"
    echo "  Try running manually: su - ${OPENCLAW_USER} -c 'npm install -g openclaw@latest'"
    exit 1
fi

# ========================= STEP 6: Security-Hardened Config ==================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[6/9] Writing security-hardened OpenClaw configuration..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

OPENCLAW_CONFIG_DIR="${OPENCLAW_HOME}/.openclaw"
OPENCLAW_WORKSPACE="${OPENCLAW_CONFIG_DIR}/workspace"
OPENCLAW_CONFIG_FILE="${OPENCLAW_CONFIG_DIR}/openclaw.json"

mkdir -p "${OPENCLAW_CONFIG_DIR}"
mkdir -p "${OPENCLAW_WORKSPACE}"

# Only write config if one doesn't already exist (don't clobber re-runs)
if [[ ! -f "${OPENCLAW_CONFIG_FILE}" ]]; then
    cat > "${OPENCLAW_CONFIG_FILE}" <<CLAWCONFIG
{
  // Security-hardened config for LAN-only bare-metal deployment
  // Generated by setup script on $(date -Iseconds)
  //
  // Gateway: binds to LAN IP, token auth required
  "gateway": {
    "port": ${GATEWAY_PORT},
    "mode": "local",
    "bind": "lan",
    "auth": {
      "mode": "token",
      "token": "${GATEWAY_TOKEN}"
    }
  },

  // Session isolation: each sender gets their own session
  "session": {
    "dmScope": "per-channel-peer"
  },

  // Tool security: consent mode ON — you approve every exec/write
  "tools": {
    "fs": {
      "workspaceOnly": true
    },
    "exec": {
      "ask": "always"
    }
  },

  // Agent workspace
  "agent": {
    "workspace": "~/.openclaw/workspace"
  }
}
CLAWCONFIG
    echo "  ✓ Hardened config written to ${OPENCLAW_CONFIG_FILE}"
else
    echo "  Config already exists at ${OPENCLAW_CONFIG_FILE}, not overwriting."
    echo "  To apply hardened defaults, delete it and re-run this script."
fi

# Write exec-approvals.json for defense-in-depth
EXEC_APPROVALS="${OPENCLAW_CONFIG_DIR}/exec-approvals.json"
if [[ ! -f "${EXEC_APPROVALS}" ]]; then
    cat > "${EXEC_APPROVALS}" <<EXECAPPROVALS
{
  "version": 1,
  "defaults": {
    "security": "deny",
    "ask": "always",
    "askFallback": "deny"
  }
}
EXECAPPROVALS
    echo "  ✓ Exec approvals: deny-by-default, ask-always"
fi

# Lock down permissions on the config directory
chown -R "${OPENCLAW_USER}:${OPENCLAW_USER}" "${OPENCLAW_CONFIG_DIR}"
chmod 700 "${OPENCLAW_CONFIG_DIR}"
chmod 600 "${OPENCLAW_CONFIG_FILE}"
chmod 600 "${EXEC_APPROVALS}"
chmod 700 "${OPENCLAW_WORKSPACE}"

echo "  ✓ File permissions locked (700/600, owner-only)"

# ========================= STEP 7: Systemd Service ===========================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[7/9] Creating systemd service (auto-start on boot)..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# We use a system-level service (not user-level) so it starts at boot
# without needing the openclaw user to log in
cat > /etc/systemd/system/openclaw-gateway.service <<SYSTEMD
[Unit]
Description=OpenClaw Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${OPENCLAW_USER}
Group=${OPENCLAW_USER}
WorkingDirectory=${OPENCLAW_HOME}

# Set the PATH so the openclaw binary is found
Environment="PATH=${NPM_GLOBAL}/bin:/usr/local/bin:/usr/bin:/bin"
Environment="HOME=${OPENCLAW_HOME}"
Environment="NODE_ENV=production"

ExecStart=${OPENCLAW_BIN} gateway --port ${GATEWAY_PORT}

# Restart on crash, but back off to avoid hammering
Restart=always
RestartSec=10

# Security: restrict what the service can do at the OS level
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${OPENCLAW_CONFIG_DIR}
ReadWritePaths=${OPENCLAW_WORKSPACE}
PrivateTmp=true

# Resource limits (generous for 16GB machine)
MemoryMax=4G
TasksMax=256

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl daemon-reload
systemctl enable openclaw-gateway.service

echo "  ✓ Systemd service created and enabled"
echo "  ✓ Security directives: NoNewPrivileges, ProtectSystem=strict,"
echo "    ProtectHome=read-only, PrivateTmp, MemoryMax=4G"

# ========================= STEP 8: Firewall + SSH Hardening ==================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[8/9] Configuring firewall and hardening SSH..."
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

# Disable root login
if grep -q "^PermitRootLogin" "${SSH_CONFIG}"; then
    sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "${SSH_CONFIG}"
else
    echo "PermitRootLogin no" >> "${SSH_CONFIG}"
fi

# Disable SSH for the openclaw user (it should never need interactive SSH)
if ! grep -q "DenyUsers ${OPENCLAW_USER}" "${SSH_CONFIG}"; then
    echo "" >> "${SSH_CONFIG}"
    echo "# Block SSH access for the openclaw service user" >> "${SSH_CONFIG}"
    echo "DenyUsers ${OPENCLAW_USER}" >> "${SSH_CONFIG}"
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

echo "  ✓ SSH: root login disabled, '${OPENCLAW_USER}' SSH blocked, fail2ban active"

# ========================= STEP 9: Automatic Updates ========================
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "[9/9] Enabling automatic security updates..."
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
echo "║                     ✅  SETUP COMPLETE                                  ║"
echo "╚═══════════════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Your N150 mini PC is now hardened and ready."
echo ""
echo "  ┌─────────────────────────────────────────────────────────────────────┐"
echo "  │  NEXT STEP: Run the OpenClaw onboarding wizard                    │"
echo "  └─────────────────────────────────────────────────────────────────────┘"
echo ""
echo "  The wizard is interactive — it sets up your AI provider and messaging"
echo "  channel. Run it as the openclaw user:"
echo ""
echo "    sudo -iu ${OPENCLAW_USER}"
echo "    openclaw onboard"
echo ""
echo "  The wizard will ask you to:"
echo "    1. Choose an AI provider   → Anthropic Claude is strongly recommended"
echo "    2. Enter your API key      → Get one from console.anthropic.com"
echo "    3. Pick a channel          → Telegram is easiest to set up"
echo "    4. Pair your account       → Approve the pairing code when prompted"
echo ""
echo "  When the wizard finishes, start the gateway:"
echo ""
echo "    exit                                    # back to your admin user"
echo "    sudo systemctl start openclaw-gateway   # start the service"
echo ""
echo "  ┌─────────────────────────────────────────────────────────────────────┐"
echo "  │  ACCESS THE CONTROL UI                                            │"
echo "  └─────────────────────────────────────────────────────────────────────┘"
echo ""
echo "  From any device on your LAN, open:"
echo ""
echo "    http://${LOCAL_IP}:${GATEWAY_PORT}/?token=${GATEWAY_TOKEN}"
echo ""
echo "  ⚠  SAVE THIS TOKEN — you need it to log into the Control UI:"
echo ""
echo "    ${GATEWAY_TOKEN}"
echo ""
echo "  The token is also stored in: ${OPENCLAW_CONFIG_FILE}"
echo ""
echo "  ┌─────────────────────────────────────────────────────────────────────┐"
echo "  │  SECURITY SUMMARY                                                 │"
echo "  └─────────────────────────────────────────────────────────────────────┘"
echo ""
echo "  ✓ Firewall        LAN-only (${LAN_CIDR}), all other inbound blocked"
echo "  ✓ Gateway auth    Token required (auto-generated, 48 hex chars)"
echo "  ✓ Exec consent    Every command requires your approval"
echo "  ✓ Exec default    Deny-by-default with ask-always fallback"
echo "  ✓ Filesystem      Restricted to workspace directory only"
echo "  ✓ DM policy       Per-channel peer isolation (pairing required)"
echo "  ✓ Service user    No sudo, no SSH, no privilege escalation"
echo "  ✓ Systemd         NoNewPrivileges, ProtectSystem=strict, PrivateTmp"
echo "  ✓ SSH             Root login disabled, fail2ban active"
echo "  ✓ Auto-updates    Unattended security patches enabled"
echo ""
echo "  ┌─────────────────────────────────────────────────────────────────────┐"
echo "  │  USEFUL COMMANDS                                                  │"
echo "  └─────────────────────────────────────────────────────────────────────┘"
echo ""
echo "  Start gateway     sudo systemctl start openclaw-gateway"
echo "  Stop gateway      sudo systemctl stop openclaw-gateway"
echo "  Restart gateway   sudo systemctl restart openclaw-gateway"
echo "  View status       sudo systemctl status openclaw-gateway"
echo "  View logs         sudo journalctl -u openclaw-gateway -f"
echo "  Health check      sudo -iu ${OPENCLAW_USER} openclaw doctor"
echo "  Security audit    sudo -iu ${OPENCLAW_USER} openclaw security audit --deep"
echo "  Update OpenClaw   sudo -iu ${OPENCLAW_USER} npm update -g openclaw@latest"
echo "  Dashboard URL     sudo -iu ${OPENCLAW_USER} openclaw dashboard --no-open"
echo ""
echo "═══════════════════════════════════════════════════════════════════════════"