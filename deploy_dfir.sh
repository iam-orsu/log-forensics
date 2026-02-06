#!/bin/bash
#===============================================================================
# DFIR Monitor - Production Deployment Script
#===============================================================================
#
# Deploys the DFIR monitoring system with:
#   - Systemd service for auto-start
#   - Log directory setup
#   - Dependency installation
#   - Safety checks
#
# Usage: sudo bash deploy_dfir.sh
#
#===============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="/opt/dfir"
LOG_DIR="/var/log/dfir"
SERVICE_NAME="dfir-monitor"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

#===============================================================================
# PRE-CHECKS
#===============================================================================

echo "========================================"
echo " DFIR Monitor - Production Deployment"
echo "========================================"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)"
fi

# Check Python 3
if ! command -v python3 &> /dev/null; then
    error "Python 3 is required but not installed"
fi

info "Python: $(python3 --version)"

#===============================================================================
# INSTALL DEPENDENCIES
#===============================================================================

info "Installing dependencies..."

# Detect package manager
if command -v apt-get &> /dev/null; then
    export DEBIAN_FRONTEND=noninteractive
    info "Fixing potential broken dependencies and clearing old Zeek mess..."
    # Aggressively purge all Zeek-related packages and their configuration
    apt-get purge -y 'zeek*' 2>/dev/null || true
    dpkg --purge --force-all zeek zeek-lts zeek-core zeek-lts-core zeek-spicy-dev zeek-lts-spicy-dev zeek-btest-data zeek-lts-btest-data zeekctl zeekctl-lts zeek-zkg zeek-lts-zkg 2>/dev/null || true
    apt-get install -fy -qq
    info "Updating package lists..."
    apt-get update -qq
    info "Installing tcpdump..."
    apt-get install -y -qq tcpdump
elif command -v yum &> /dev/null; then
    yum install -y -q tcpdump
elif command -v dnf &> /dev/null; then
    dnf install -y -q tcpdump
else
    warn "Could not detect package manager, assuming tcpdump is installed"
fi

info "tcpdump: $(tcpdump --version 2>&1 | head -1)"

#===============================================================================
# CREATE DIRECTORIES
#===============================================================================

info "Setting up directories..."

mkdir -p "$INSTALL_DIR"
mkdir -p "$LOG_DIR"
chmod 755 "$LOG_DIR"

#===============================================================================
# INSTALL MONITOR
#===============================================================================

info "Installing DFIR monitor..."

cp "$SCRIPT_DIR/dfir_monitor.py" "$INSTALL_DIR/dfir_monitor.py"
chmod +x "$INSTALL_DIR/dfir_monitor.py"

#===============================================================================
# CREATE SYSTEMD SERVICE
#===============================================================================

info "Creating systemd service..."

cat > /etc/systemd/system/${SERVICE_NAME}.service << 'EOF'
[Unit]
Description=DFIR Monitor - Production Forensic Logging
After=network.target
Wants=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/dfir/dfir_monitor.py
Restart=always
RestartSec=10

# Safety: Run at lowest priority
Nice=19
IOSchedulingClass=idle

# Resource limits
MemoryMax=512M
CPUQuota=15%

# Security hardening
NoNewPrivileges=false
ProtectSystem=strict
ReadWritePaths=/var/log/dfir /var/run

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=dfir-monitor

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

#===============================================================================
# SETUP LOG ROTATION (BACKUP - Python handles primary rotation)
#===============================================================================

info "Configuring log rotation backup..."

cat > /etc/logrotate.d/dfir-monitor << 'EOF'
/var/log/dfir/*.json {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 root root
}
EOF

#===============================================================================
# START SERVICE
#===============================================================================

info "Enabling and starting service..."

# Stop if already running
systemctl stop ${SERVICE_NAME} 2>/dev/null || true

# Enable and start
systemctl enable ${SERVICE_NAME}
systemctl start ${SERVICE_NAME}

sleep 2

#===============================================================================
# VERIFY
#===============================================================================

echo ""
echo "========================================"
info "Verifying installation..."
echo "========================================"

if systemctl is-active --quiet ${SERVICE_NAME}; then
    info "✓ Service is running"
else
    error "✗ Service failed to start. Check: journalctl -u ${SERVICE_NAME}"
fi

if [[ -d "$LOG_DIR" ]]; then
    info "✓ Log directory exists: $LOG_DIR"
else
    error "✗ Log directory not created"
fi

#===============================================================================
# DONE
#===============================================================================

echo ""
echo "========================================"
echo -e "${GREEN} DEPLOYMENT COMPLETE ${NC}"
echo "========================================"
echo ""
echo " Service:  systemctl status ${SERVICE_NAME}"
echo " Logs:     tail -f ${LOG_DIR}/$(date +%d-%m-%Y).json | jq ."
echo " Journal:  journalctl -u ${SERVICE_NAME} -f"
echo ""
echo " Commands:"
echo "   Start:   sudo systemctl start ${SERVICE_NAME}"
echo "   Stop:    sudo systemctl stop ${SERVICE_NAME}"
echo "   Restart: sudo systemctl restart ${SERVICE_NAME}"
echo ""
