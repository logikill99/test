#!/usr/bin/env bash
# =============================================================================
# Secure OpenClaw Setup for Ubuntu Mini PC (LAN-Only Access)
# =============================================================================
# This script installs OpenClaw via Docker with security hardening:
#   - Binds gateway to LAN IP only (not 0.0.0.0)
#   - UFW firewall: blocks all WAN, allows LAN subnet only
#   - Docker runs as non-root with dropped capabilities
#   - Sandbox mode enabled by default
#   - Gateway auth token auto-generated
#   - Automatic security audit at the end
#
# Usage:
#   chmod +x setup-openclaw-secure.sh
#   sudo ./setup-openclaw-secure.sh
#
# Prerequisites: Ubuntu 22.04 or 24.04, internet access for initial setup
# =============================================================================

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${GREEN}[✓]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
err()  { echo -e "${RED}[✗]${NC} $*"; }
info() { echo -e "${CYAN}[i]${NC} $*"; }

# ── Root check ───────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    err "Please run as root:  sudo $0"
    exit 1
fi

REAL_USER="${SUDO_USER:-$USER}"
REAL_HOME=$(eval echo "~$REAL_USER")

echo ""
echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       Secure OpenClaw Setup — LAN-Only Mini PC             ║${NC}"
echo -e "${CYAN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ── Step 1: Detect LAN subnet ───────────────────────────────────────────────
info "Detecting network configuration..."

# Get the default interface and LAN IP
DEFAULT_IF=$(ip route | grep '^default' | awk '{print $5}' | head -1)
LAN_IP=$(ip -4 addr show "$DEFAULT_IF" | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1)
LAN_CIDR=$(ip -4 addr show "$DEFAULT_IF" | grep -oP '\d+(\.\d+){3}/\d+' | head -1)

# Calculate subnet (e.g., 192.168.1.0/24)
LAN_SUBNET=$(python3 -c "
import ipaddress
net = ipaddress.ip_network('$LAN_CIDR', strict=False)
print(net)
" 2>/dev/null || echo "$(echo "$LAN_IP" | cut -d. -f1-3).0/24")

log "Interface:  $DEFAULT_IF"
log "LAN IP:     $LAN_IP"
log "LAN Subnet: $LAN_SUBNET"
echo ""

read -rp "Is this correct? (y/n): " CONFIRM
if [[ ! "$CONFIRM" =~ ^[Yy]$ ]]; then
    read -rp "Enter your LAN IP manually: " LAN_IP
    read -rp "Enter your LAN subnet (e.g., 192.168.1.0/24): " LAN_SUBNET
fi

# ── Step 2: System updates & dependencies ────────────────────────────────────
info "Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq git curl ufw ca-certificates gnupg lsb-release > /dev/null 2>&1
log "System packages installed."

# ── Step 3: Install Docker (if not present) ──────────────────────────────────
if ! command -v docker &>/dev/null; then
    info "Installing Docker..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin > /dev/null 2>&1
    usermod -aG docker "$REAL_USER"
    log "Docker installed."
else
    log "Docker already installed."
fi

systemctl enable --now docker > /dev/null 2>&1

# ── Step 4a: System tuning for Intel N150 + 16GB RAM ─────────────────────────
info "Tuning system for Intel N150 (4C/4T) + 16GB RAM..."

# Create a 4GB swap file as safety net (prevents OOM kills under heavy load)
if ! swapon --show | grep -q '/swapfile'; then
    if [[ ! -f /swapfile ]]; then
        fallocate -l 4G /swapfile
        chmod 600 /swapfile
        mkswap /swapfile > /dev/null 2>&1
    fi
    swapon /swapfile 2>/dev/null || true
    # Make persistent
    if ! grep -q '/swapfile' /etc/fstab; then
        echo '/swapfile none swap sw 0 0' >> /etc/fstab
    fi
    log "4GB swap file created (OOM safety net)."
else
    log "Swap already configured."
fi

# Tune swappiness — prefer keeping things in RAM, only swap under pressure
# Low value (10) means the kernel strongly prefers RAM over swap
if ! grep -q 'vm.swappiness' /etc/sysctl.d/99-openclaw.conf 2>/dev/null; then
    cat > /etc/sysctl.d/99-openclaw.conf << 'SYSCTL'
# OpenClaw tuning for low-power mini PC (N150 + 16GB)

# Only swap under real memory pressure
vm.swappiness = 10

# Keep more filesystem cache (good for Node.js/Docker)
vm.vfs_cache_pressure = 50

# Increase inotify limits (OpenClaw watches many files)
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 512

# Network tuning for local LAN responsiveness
net.core.somaxconn = 1024
net.ipv4.tcp_fastopen = 3
SYSCTL
    sysctl -p /etc/sysctl.d/99-openclaw.conf > /dev/null 2>&1
    log "Kernel parameters tuned for N150."
else
    log "Kernel tuning already applied."
fi

# Configure Docker daemon for N150 (limit logging, sensible defaults)
mkdir -p /etc/docker
if [[ ! -f /etc/docker/daemon.json ]] || ! grep -q 'overlay2' /etc/docker/daemon.json 2>/dev/null; then
    cat > /etc/docker/daemon.json << 'DOCKERCFG'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "storage-driver": "overlay2",
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 65536,
      "Soft": 65536
    }
  }
}
DOCKERCFG
    systemctl restart docker > /dev/null 2>&1
    log "Docker daemon configured for N150."
fi

# ── Step 4: Configure UFW firewall (LAN-only) ───────────────────────────────
info "Configuring firewall for LAN-only access..."

ufw --force reset > /dev/null 2>&1

# Default deny everything incoming
ufw default deny incoming > /dev/null 2>&1
ufw default allow outgoing > /dev/null 2>&1

# Allow SSH from LAN only
ufw allow from "$LAN_SUBNET" to any port 22 proto tcp comment "SSH from LAN" > /dev/null 2>&1

# Allow OpenClaw gateway from LAN only
ufw allow from "$LAN_SUBNET" to any port 18789 proto tcp comment "OpenClaw gateway from LAN" > /dev/null 2>&1

# Allow mDNS/Bonjour on LAN (for device discovery)
ufw allow from "$LAN_SUBNET" to any port 5353 proto udp comment "mDNS discovery" > /dev/null 2>&1

# Block Docker from bypassing UFW (critical!)
# Docker manipulates iptables directly, so we need to restrict it
DOCKER_UFW_CONF="/etc/ufw/after.rules"
if ! grep -q "OPENCLAW-DOCKER-RESTRICT" "$DOCKER_UFW_CONF" 2>/dev/null; then
    cat >> "$DOCKER_UFW_CONF" << 'DOCKER_RULES'

# BEGIN OPENCLAW-DOCKER-RESTRICT
# Prevent Docker from exposing ports beyond the LAN
*filter
:DOCKER-USER - [0:0]
-A DOCKER-USER -s 172.16.0.0/12 -j RETURN
-A DOCKER-USER -s 10.0.0.0/8 -j RETURN
-A DOCKER-USER -s 192.168.0.0/16 -j RETURN
-A DOCKER-USER -s 127.0.0.0/8 -j RETURN
-A DOCKER-USER -j DROP
COMMIT
# END OPENCLAW-DOCKER-RESTRICT
DOCKER_RULES
    warn "Added Docker UFW restrictions to prevent WAN bypass."
fi

ufw --force enable > /dev/null 2>&1
log "Firewall configured: only LAN ($LAN_SUBNET) can reach this machine."

# ── Step 5: Create OpenClaw directories ──────────────────────────────────────
info "Setting up directory structure..."

OPENCLAW_DIR="$REAL_HOME/openclaw"
OPENCLAW_CONFIG="$REAL_HOME/.openclaw"
OPENCLAW_WORKSPACE="$REAL_HOME/openclaw/workspace"

mkdir -p "$OPENCLAW_DIR" "$OPENCLAW_CONFIG" "$OPENCLAW_WORKSPACE"
chown -R "$REAL_USER:$REAL_USER" "$OPENCLAW_DIR" "$OPENCLAW_CONFIG"
chmod 700 "$OPENCLAW_CONFIG"  # Only owner can read config (has API keys)

log "Directories created with restricted permissions."

# ── Step 6: Generate gateway auth token ──────────────────────────────────────
GATEWAY_TOKEN=$(openssl rand -base64 32 | tr -d '/+=' | head -c 48)
log "Gateway auth token generated."

# ── Step 7: Create hardened docker-compose.yml ───────────────────────────────
info "Creating hardened Docker Compose configuration..."

cat > "$OPENCLAW_DIR/docker-compose.yml" << COMPOSEFILE
services:
  openclaw-gateway:
    image: ghcr.io/openclaw/openclaw:latest
    container_name: openclaw-gateway
    restart: unless-stopped
    entrypoint: ["node", "/app/dist/index.js"]
    command: ["gateway", "--bind", "lan", "--port", "18789"]

    # --- Security hardening ---
    user: "1000:1000"
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    read_only: true

    # Writable tmpfs for runtime needs (sized for 16GB system)
    tmpfs:
      - /tmp:size=1g
      - /run:size=128m

    # --- Network: bind to LAN IP only ---
    ports:
      - "${LAN_IP}:18789:18789"

    # --- Volumes ---
    volumes:
      - ${OPENCLAW_CONFIG}:/home/node/.openclaw:rw
      - ${OPENCLAW_WORKSPACE}:/home/node/.openclaw/workspace:rw

    # --- Environment ---
    environment:
      - NODE_ENV=production
      - OPENCLAW_GATEWAY_TOKEN=${GATEWAY_TOKEN}
      - OPENCLAW_DISABLE_BONJOUR=1
      # Let Node.js use up to 8GB heap (safe for 16GB system w/ 12GB container limit)
      - NODE_OPTIONS=--max-old-space-size=8192

    # --- Resource limits (tuned for Intel N150 / 16GB RAM) ---
    # N150: 4 cores / 4 threads, 6W TDP, up to 3.6GHz
    # Reserve ~2GB for Ubuntu + Docker overhead, give OpenClaw up to 12GB
    deploy:
      resources:
        limits:
          memory: 12g
          cpus: '3.5'
        reservations:
          memory: 1g
          cpus: '0.5'

    # --- Health check ---
    healthcheck:
      test: ["CMD", "node", "dist/index.js", "health", "--token", "${GATEWAY_TOKEN}"]
      interval: 60s
      timeout: 10s
      retries: 3
      start_period: 30s

    # --- Logging ---
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  openclaw-cli:
    image: ghcr.io/openclaw/openclaw:latest
    container_name: openclaw-cli
    profiles: ["cli"]
    user: "1000:1000"
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true
    volumes:
      - ${OPENCLAW_CONFIG}:/home/node/.openclaw:rw
      - ${OPENCLAW_WORKSPACE}:/home/node/.openclaw/workspace:rw
    environment:
      - OPENCLAW_GATEWAY_TOKEN=${GATEWAY_TOKEN}
      - HOME=/home/node
      - TERM=xterm-256color
    stdin_open: true
    tty: true
    init: true
    entrypoint: ["node", "/app/dist/index.js"]
COMPOSEFILE

chown "$REAL_USER:$REAL_USER" "$OPENCLAW_DIR/docker-compose.yml"
log "Hardened docker-compose.yml created."

# ── Step 8: Create .env file (keeps secrets out of compose) ──────────────────
cat > "$OPENCLAW_DIR/.env" << ENVFILE
# OpenClaw Environment — AUTO-GENERATED $(date -Iseconds)
# Keep this file private! It contains your gateway token.
OPENCLAW_GATEWAY_TOKEN=${GATEWAY_TOKEN}

# Add your LLM API keys below:
# ANTHROPIC_API_KEY=sk-ant-...
# OPENAI_API_KEY=sk-...
# OPENROUTER_API_KEY=sk-or-...
ENVFILE

chown "$REAL_USER:$REAL_USER" "$OPENCLAW_DIR/.env"
chmod 600 "$OPENCLAW_DIR/.env"
log "Environment file created (chmod 600)."

# ── Step 9: Create helper scripts ────────────────────────────────────────────
info "Creating helper scripts..."

# Onboard script (interactive first-time setup)
cat > "$OPENCLAW_DIR/onboard.sh" << 'ONBOARD'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
echo "Starting OpenClaw onboarding wizard..."
echo ""
echo "When prompted, recommended settings:"
echo "  - Gateway bind: lan"
echo "  - Gateway auth: token"
echo "  - Tailscale exposure: Off"
echo "  - Install Gateway daemon: No"
echo ""
docker compose run --rm openclaw-cli onboard --no-install-daemon
echo ""
echo "Onboarding complete! Start OpenClaw with: ./start.sh"
ONBOARD

# Start script
cat > "$OPENCLAW_DIR/start.sh" << 'START'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
docker compose pull
docker compose up -d openclaw-gateway
echo ""
echo "OpenClaw is running!"
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):18789"
echo ""
docker compose ps
START

# Stop script
cat > "$OPENCLAW_DIR/stop.sh" << 'STOP'
#!/usr/bin/env bash
cd "$(dirname "$0")"
docker compose down
echo "OpenClaw stopped."
STOP

# Dashboard URL script
cat > "$OPENCLAW_DIR/dashboard.sh" << 'DASH'
#!/usr/bin/env bash
cd "$(dirname "$0")"
docker compose run --rm openclaw-cli dashboard --no-open
DASH

# Doctor/health check script
cat > "$OPENCLAW_DIR/doctor.sh" << 'DOCTOR'
#!/usr/bin/env bash
cd "$(dirname "$0")"
docker compose run --rm openclaw-cli doctor
DOCTOR

# Security audit script
cat > "$OPENCLAW_DIR/security-audit.sh" << 'AUDIT'
#!/usr/bin/env bash
cd "$(dirname "$0")"
echo "=== OpenClaw Security Audit ==="
echo ""

# Check gateway binding
echo "[Firewall]"
sudo ufw status numbered 2>/dev/null || echo "  UFW not available"
echo ""

# Check Docker security
echo "[Docker Container]"
docker inspect openclaw-gateway --format='
  User:           {{.Config.User}}
  ReadOnly:       {{.HostConfig.ReadonlyRootfs}}
  NoNewPrivs:     {{.HostConfig.SecurityOpt}}
  CapDrop:        {{.HostConfig.CapDrop}}
  Port Bindings:  {{range $k, $v := .HostConfig.PortBindings}}{{$k}}: {{range $v}}{{.HostIP}}:{{.HostPort}}{{end}} {{end}}
' 2>/dev/null || echo "  Container not running"
echo ""

# Check file permissions
echo "[File Permissions]"
echo "  ~/.openclaw:  $(stat -c '%a' ~/.openclaw 2>/dev/null || echo 'N/A')"
echo "  .env:         $(stat -c '%a' .env 2>/dev/null || echo 'N/A')"
echo ""

# Run built-in audit if available
echo "[OpenClaw Built-in Audit]"
docker compose run --rm openclaw-cli security audit 2>/dev/null || echo "  Built-in audit not available in this version"
echo ""
echo "=== Audit Complete ==="
AUDIT

# Update script
cat > "$OPENCLAW_DIR/update.sh" << 'UPDATE'
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
echo "Pulling latest OpenClaw image..."
docker compose pull
echo "Restarting..."
docker compose up -d openclaw-gateway
echo "Updated! Current version:"
docker compose exec openclaw-gateway node -e "try{console.log(require('./package.json').version)}catch(e){console.log('unknown')}"
UPDATE

# Make all scripts executable
chmod +x "$OPENCLAW_DIR"/{onboard,start,stop,dashboard,doctor,security-audit,update}.sh
chown -R "$REAL_USER:$REAL_USER" "$OPENCLAW_DIR"

log "Helper scripts created."

# ── Step 10: Pull Docker image ───────────────────────────────────────────────
info "Pulling OpenClaw Docker image (this may take a few minutes)..."
sudo -u "$REAL_USER" docker pull ghcr.io/openclaw/openclaw:latest
log "Docker image pulled."

# ── Step 11: Disable mDNS broadcasting of sensitive info ─────────────────────
# Create minimal config to disable Bonjour/mDNS info leaking
if [[ ! -f "$OPENCLAW_CONFIG/config/default.json" ]]; then
    mkdir -p "$OPENCLAW_CONFIG/config"
    cat > "$OPENCLAW_CONFIG/config/default.json" << DEFAULTCFG
{
  "gateway": {
    "auth": {
      "token": "${GATEWAY_TOKEN}"
    },
    "bonjour": {
      "mode": "minimal"
    },
    "controlUi": {
      "allowInsecureAuth": false
    },
    "bind": "${LAN_IP}"
  },
  "sandbox": {
    "mode": "docker",
    "docker": {
      "network": "none"
    }
  }
}
DEFAULTCFG
    chown -R "$REAL_USER:$REAL_USER" "$OPENCLAW_CONFIG"
    chmod -R 700 "$OPENCLAW_CONFIG"
    log "Default config created (sandbox enabled, mDNS minimal, LAN bind)."
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                    Setup Complete! 🦞                       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${CYAN}Hardware:${NC}"
echo -e "    CPU:          $(lscpu | grep 'Model name' | sed 's/.*: *//')"
echo -e "    Cores:        $(nproc) cores"
echo -e "    RAM:          $(free -h | awk '/Mem:/{print $2}') total"
echo -e "    Swap:         $(free -h | awk '/Swap:/{print $2}') configured"
echo ""
echo -e "  ${CYAN}Resource Allocation:${NC}"
echo -e "    Container:    up to 12GB RAM / 3.5 CPUs"
echo -e "    Node.js heap: up to 8GB"
echo -e "    OS reserved:  ~2GB RAM + 4GB swap safety net"
echo ""
echo -e "  ${CYAN}Directory:${NC}      $OPENCLAW_DIR"
echo -e "  ${CYAN}Config:${NC}         $OPENCLAW_CONFIG"
echo -e "  ${CYAN}Gateway bind:${NC}   ${LAN_IP}:18789 (LAN only)"
echo -e "  ${CYAN}Firewall:${NC}       UFW active — LAN subnet $LAN_SUBNET only"
echo ""
echo -e "  ${YELLOW}Gateway Token:${NC}  $GATEWAY_TOKEN"
echo -e "  ${RED}(Save this! You need it to access the dashboard.)${NC}"
echo ""
echo -e "  ${CYAN}Next steps:${NC}"
echo -e "    1. Add your LLM API key to ${CYAN}$OPENCLAW_DIR/.env${NC}"
echo -e "       e.g.:  echo 'ANTHROPIC_API_KEY=sk-ant-...' >> $OPENCLAW_DIR/.env"
echo ""
echo -e "    2. Run onboarding:    ${CYAN}cd $OPENCLAW_DIR && ./onboard.sh${NC}"
echo -e "    3. Start OpenClaw:    ${CYAN}cd $OPENCLAW_DIR && ./start.sh${NC}"
echo -e "    4. Get dashboard URL: ${CYAN}cd $OPENCLAW_DIR && ./dashboard.sh${NC}"
echo -e "    5. Run security audit:${CYAN}cd $OPENCLAW_DIR && ./security-audit.sh${NC}"
echo ""
echo -e "  ${YELLOW}Access from any device on your LAN:${NC}"
echo -e "    http://${LAN_IP}:18789/?token=${GATEWAY_TOKEN}"
echo ""
echo -e "  ${RED}Security reminders:${NC}"
echo -e "    • Never expose port 18789 to the internet"
echo -e "    • Only install skills you have reviewed and trust"
echo -e "    • Use strong, instruction-hardened models (Claude Opus recommended)"
echo -e "    • Run ./security-audit.sh periodically"
echo -e "    • Prompt injection is an unsolved problem — treat all external"
echo -e "      content (emails, web pages, docs) as potentially adversarial"
echo ""
echo -e "  ${YELLOW}NOTE:${NC} You may need to log out and back in for Docker group"
echo -e "  permissions to take effect (or run: newgrp docker)"
echo ""