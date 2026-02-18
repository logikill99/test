#!/usr/bin/env bash
# ============================================================================
# OpenClaw Secure LAN Setup Script
# Target: Ubuntu Server 24.04.4 LTS — N150 Mini PC (16GB RAM)
# Purpose: Install OpenClaw and lock it down to local network access only
#
# Usage:
#   chmod +x setup-openclaw.sh
#   sudo ./setup-openclaw.sh
#
# What this script does:
#   1. Creates a dedicated 'openclaw' system user (least-privilege)
#   2. Installs Node.js 22 LTS via NodeSource
#   3. Installs OpenClaw globally
#   4. Configures UFW firewall (SSH + OpenClaw from LAN only)
#   5. Hardens sysctl (disable IP forwarding, ignore ICMP redirects, etc.)
#   6. Sets up OpenClaw gateway as a systemd service
#   7. Binds the gateway to the LAN interface only
#   8. Enables unattended security updates
#
# After running:
#   - Access the Control UI from any device on your LAN at:
#     http://<MINI-PC-IP>:18789
#   - Run the onboarding wizard:
#     sudo -u openclaw openclaw onboard
#   - Check status:
#     systemctl status openclaw-gateway
#   - View logs:
#     journalctl -u openclaw-gateway -f
# ============================================================================

set -euo pipefail
IFS=$'\n\t'

# ── Color helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

info()  { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
fail()  { echo -e "${RED}[FAIL]${NC}  $*"; exit 1; }

# ── Pre-flight checks ───────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || fail "This script must be run as root. Use: sudo ./setup-openclaw.sh"

# Verify we're on Ubuntu 24.04
if ! grep -q 'Ubuntu' /etc/os-release 2>/dev/null; then
    fail "This script is designed for Ubuntu Server 24.04 LTS."
fi

info "Starting OpenClaw secure LAN setup..."
echo ""

# ── Detect LAN subnet ───────────────────────────────────────────────────────
info "Detecting network configuration..."

# Get the default route interface
DEFAULT_IFACE=$(ip route show default | awk '/default/ {print $5}' | head -n1)
if [[ -z "$DEFAULT_IFACE" ]]; then
    fail "Could not detect default network interface. Check your network config."
fi

# Get the LAN IP and subnet
LAN_IP=$(ip -4 addr show "$DEFAULT_IFACE" | awk '/inet / {print $2}' | head -n1)
if [[ -z "$LAN_IP" ]]; then
    fail "Could not detect LAN IP on interface $DEFAULT_IFACE."
fi

# Extract CIDR subnet for firewall rules
LAN_SUBNET=$(ip -4 route show dev "$DEFAULT_IFACE" | awk '/proto kernel/ {print $1}' | head -n1)
if [[ -z "$LAN_SUBNET" ]]; then
    # Fallback: derive from IP (assume /24)
    LAN_SUBNET=$(echo "$LAN_IP" | sed 's|\.[0-9]*/.*|.0/24|')
    warn "Could not auto-detect subnet; assuming $LAN_SUBNET"
fi

LAN_IP_BARE=$(echo "$LAN_IP" | cut -d'/' -f1)

ok "Interface:  $DEFAULT_IFACE"
ok "LAN IP:     $LAN_IP_BARE"
ok "LAN Subnet: $LAN_SUBNET (firewall allow-range)"
echo ""

# ── 1. System updates ───────────────────────────────────────────────────────
info "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq
ok "System packages updated."

# ── 2. Install essential dependencies ────────────────────────────────────────
info "Installing essential packages..."
apt-get install -y -qq \
    curl \
    gnupg \
    ca-certificates \
    git \
    build-essential \
    unattended-upgrades \
    apt-listchanges \
    ufw \
    fail2ban \
    jq
ok "Dependencies installed."

# ── 3. Enable unattended security updates ────────────────────────────────────
info "Configuring automatic security updates..."
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
systemctl enable --now unattended-upgrades &>/dev/null
ok "Automatic security updates enabled."

# ── 4. Create dedicated openclaw user ────────────────────────────────────────
OPENCLAW_USER="openclaw"
OPENCLAW_HOME="/home/${OPENCLAW_USER}"

if id "$OPENCLAW_USER" &>/dev/null; then
    warn "User '$OPENCLAW_USER' already exists. Skipping creation."
else
    info "Creating dedicated system user '${OPENCLAW_USER}'..."
    useradd \
        --system \
        --create-home \
        --home-dir "$OPENCLAW_HOME" \
        --shell /bin/bash \
        --comment "OpenClaw Service Account" \
        "$OPENCLAW_USER"
    ok "User '${OPENCLAW_USER}' created."
fi

# ── 5. Install Node.js 22 LTS ───────────────────────────────────────────────
info "Installing Node.js 22 LTS..."
if command -v node &>/dev/null; then
    CURRENT_NODE=$(node --version 2>/dev/null || echo "unknown")
    if [[ "$CURRENT_NODE" == v22.* ]]; then
        ok "Node.js $CURRENT_NODE already installed. Skipping."
    else
        warn "Node.js $CURRENT_NODE found but need v22+. Installing v22..."
        curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
        apt-get install -y -qq nodejs
    fi
else
    curl -fsSL https://deb.nodesource.com/setup_22.x | bash -
    apt-get install -y -qq nodejs
fi
ok "Node.js $(node --version) installed."
ok "npm $(npm --version) installed."

# Set up npm global directory for openclaw user (no sudo needed for npm -g)
info "Configuring npm global directory for '${OPENCLAW_USER}'..."
NPM_GLOBAL="${OPENCLAW_HOME}/.npm-global"
sudo -u "$OPENCLAW_USER" mkdir -p "$NPM_GLOBAL"
sudo -u "$OPENCLAW_USER" bash -c "npm config set prefix '${NPM_GLOBAL}'"

# Add to PATH in .bashrc
if ! grep -q 'npm-global' "${OPENCLAW_HOME}/.bashrc" 2>/dev/null; then
    cat >> "${OPENCLAW_HOME}/.bashrc" <<EOF

# npm global binaries
export PATH="${NPM_GLOBAL}/bin:\$PATH"
export NODE_OPTIONS="--max-old-space-size=4096"
EOF
fi
ok "npm global prefix set to ${NPM_GLOBAL}."

# ── 6. Install OpenClaw ─────────────────────────────────────────────────────
info "Installing OpenClaw..."
sudo -u "$OPENCLAW_USER" bash -c "
    export PATH='${NPM_GLOBAL}/bin:\$PATH'
    npm install -g openclaw@latest 2>&1
"
ok "OpenClaw installed."

# Verify
OPENCLAW_BIN="${NPM_GLOBAL}/bin/openclaw"
if [[ ! -f "$OPENCLAW_BIN" ]]; then
    fail "OpenClaw binary not found at ${OPENCLAW_BIN}. Installation may have failed."
fi
ok "OpenClaw binary verified at ${OPENCLAW_BIN}."

# ── 7. Create OpenClaw configuration ────────────────────────────────────────
OPENCLAW_CONFIG_DIR="${OPENCLAW_HOME}/.openclaw"
info "Creating OpenClaw configuration..."

sudo -u "$OPENCLAW_USER" mkdir -p "${OPENCLAW_CONFIG_DIR}"
sudo -u "$OPENCLAW_USER" mkdir -p "${OPENCLAW_CONFIG_DIR}/workspace"

# Write a baseline secure config
# - Bind to LAN IP so it's accessible on the network but NOT on 0.0.0.0
# - Enable password auth on the gateway dashboard
# - DM policy set to pairing (default, safest)
GATEWAY_PASSWORD=$(openssl rand -base64 24 | tr -d '=/+' | head -c 24)

sudo -u "$OPENCLAW_USER" tee "${OPENCLAW_CONFIG_DIR}/openclaw.json" > /dev/null <<EOJSON
{
  "gateway": {
    "port": 18789,
    "bind": "${LAN_IP_BARE}",
    "auth": {
      "mode": "password",
      "password": "${GATEWAY_PASSWORD}"
    }
  },
  "agent": {
    "model": "anthropic/claude-sonnet-4-20250514"
  }
}
EOJSON

chown -R "$OPENCLAW_USER":"$OPENCLAW_USER" "$OPENCLAW_CONFIG_DIR"
chmod 700 "$OPENCLAW_CONFIG_DIR"
chmod 600 "${OPENCLAW_CONFIG_DIR}/openclaw.json"
ok "OpenClaw configuration created."

# ── 8. Create systemd service ───────────────────────────────────────────────
info "Creating systemd service for OpenClaw gateway..."

cat > /etc/systemd/system/openclaw-gateway.service <<EOF
[Unit]
Description=OpenClaw Gateway
Documentation=https://docs.openclaw.ai
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${OPENCLAW_USER}
Group=${OPENCLAW_USER}
WorkingDirectory=${OPENCLAW_HOME}

Environment=HOME=${OPENCLAW_HOME}
Environment=PATH=${NPM_GLOBAL}/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=NODE_OPTIONS=--max-old-space-size=4096
Environment=OPENCLAW_HOME=${OPENCLAW_HOME}

ExecStart=${OPENCLAW_BIN} gateway --port 18789
Restart=on-failure
RestartSec=10
StartLimitIntervalSec=300
StartLimitBurst=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=${OPENCLAW_HOME}
PrivateTmp=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true

# Resource limits appropriate for 16GB RAM
MemoryMax=8G
MemoryHigh=6G
TasksMax=512

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
ok "Systemd service created."

# ── 9. Configure UFW firewall ───────────────────────────────────────────────
info "Configuring UFW firewall (LAN-only access)..."

# Reset UFW to clean state
ufw --force reset &>/dev/null

# Default policies: deny all incoming, allow outgoing
ufw default deny incoming
ufw default allow outgoing

# Allow SSH from LAN only
ufw allow from "$LAN_SUBNET" to any port 22 proto tcp comment 'SSH from LAN'

# Allow OpenClaw gateway from LAN only
ufw allow from "$LAN_SUBNET" to any port 18789 proto tcp comment 'OpenClaw from LAN'

# Enable UFW
ufw --force enable
ok "UFW firewall configured — only SSH and OpenClaw allowed from ${LAN_SUBNET}."

# ── 10. Configure fail2ban ──────────────────────────────────────────────────
info "Configuring fail2ban for SSH protection..."

cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
backend  = systemd

[sshd]
enabled = true
port    = ssh
filter  = sshd
maxretry = 3
bantime  = 1h
EOF

systemctl enable --now fail2ban &>/dev/null
systemctl restart fail2ban
ok "fail2ban configured (SSH: 3 attempts, 1h ban)."

# ── 11. Sysctl hardening ────────────────────────────────────────────────────
info "Applying network security hardening (sysctl)..."

cat > /etc/sysctl.d/99-openclaw-hardening.conf <<'EOF'
# Disable IP forwarding (this is not a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Don't send ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Enable SYN flood protection
net.ipv4.tcp_syncookies = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Protect against source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF

sysctl --system &>/dev/null
ok "Sysctl hardening applied."

# ── 12. Set up log rotation ─────────────────────────────────────────────────
info "Configuring log rotation for OpenClaw..."
cat > /etc/logrotate.d/openclaw <<EOF
${OPENCLAW_HOME}/.openclaw/logs/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 0640 ${OPENCLAW_USER} ${OPENCLAW_USER}
}
EOF
ok "Log rotation configured (14 days retention)."

# ── 13. Enable and start the service ────────────────────────────────────────
info "Enabling OpenClaw gateway service..."
systemctl enable openclaw-gateway
ok "Service enabled (will start on boot)."

# Don't auto-start yet — user needs to run onboarding first
warn "Service is NOT started yet. You need to run onboarding first (see below)."

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "============================================================================"
echo -e "${GREEN}  OpenClaw Secure LAN Setup Complete!${NC}"
echo "============================================================================"
echo ""
echo "  SYSTEM"
echo "  ├─ User:          ${OPENCLAW_USER}"
echo "  ├─ Home:          ${OPENCLAW_HOME}"
echo "  ├─ Config:        ${OPENCLAW_CONFIG_DIR}/openclaw.json"
echo "  ├─ Node.js:       $(node --version)"
echo "  └─ OpenClaw:      ${OPENCLAW_BIN}"
echo ""
echo "  NETWORK"
echo "  ├─ Interface:     ${DEFAULT_IFACE}"
echo "  ├─ LAN IP:        ${LAN_IP_BARE}"
echo "  ├─ Gateway Port:  18789"
echo "  ├─ Bound to:      ${LAN_IP_BARE}:18789 (LAN only)"
echo "  └─ Firewall:      UFW active — SSH + 18789 from ${LAN_SUBNET} only"
echo ""
echo "  SECURITY"
echo "  ├─ UFW:           Deny all except SSH + OpenClaw from LAN"
echo "  ├─ fail2ban:      SSH brute-force protection (3 tries, 1h ban)"
echo "  ├─ Sysctl:        Network hardening applied"
echo "  ├─ Systemd:       Service sandboxed (NoNewPrivileges, ProtectSystem, etc.)"
echo "  ├─ Auth:          Password-protected gateway dashboard"
echo "  └─ Auto-updates:  Unattended security patches enabled"
echo ""
echo -e "  ${YELLOW}GATEWAY PASSWORD:${NC}  ${GATEWAY_PASSWORD}"
echo -e "  ${YELLOW}Save this password!${NC} You'll need it to access the Control UI."
echo "  (Also stored in ${OPENCLAW_CONFIG_DIR}/openclaw.json)"
echo ""
echo "============================================================================"
echo "  NEXT STEPS"
echo "============================================================================"
echo ""
echo "  1. Run the onboarding wizard to configure your AI provider:"
echo ""
echo "     sudo -u ${OPENCLAW_USER} bash -c \\"
echo "       'export PATH=${NPM_GLOBAL}/bin:\$PATH && openclaw onboard'"
echo ""
echo "  2. Start the gateway service:"
echo ""
echo "     sudo systemctl start openclaw-gateway"
echo ""
echo "  3. Access the Control UI from any device on your LAN:"
echo ""
echo "     http://${LAN_IP_BARE}:18789"
echo ""
echo "  4. Check status and logs:"
echo ""
echo "     systemctl status openclaw-gateway"
echo "     journalctl -u openclaw-gateway -f"
echo ""
echo "  5. (Optional) Run the gateway interactively for debugging:"
echo ""
echo "     sudo -u ${OPENCLAW_USER} bash -c \\"
echo "       'export PATH=${NPM_GLOBAL}/bin:\$PATH && openclaw gateway --port 18789 --verbose'"
echo ""
echo "============================================================================"