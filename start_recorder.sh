#!/bin/bash
#===============================================================================
# Start Production Forensic Recorder
# One-click deployment for deep packet capture
#===============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_FILE="/var/log/forensic_blackbox.log"
PID_FILE="/var/run/forensic_recorder.pid"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "========================================"
echo " Production Forensic Recorder"
echo " Deep Packet Inspection Engine"
echo "========================================"
echo ""

# Check root
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR]${NC} This script must be run as root (use sudo)"
    exit 1
fi

# Install tcpdump if missing
if ! command -v tcpdump &> /dev/null; then
    echo "[INFO] Installing tcpdump..."
    apt-get update -qq && apt-get install -y -qq tcpdump
fi

# Kill any existing recorder
if [[ -f "$PID_FILE" ]]; then
    old_pid=$(cat "$PID_FILE")
    if kill -0 "$old_pid" 2>/dev/null; then
        echo "[INFO] Stopping existing recorder (PID: $old_pid)..."
        kill "$old_pid" 2>/dev/null || true
        sleep 1
    fi
fi

pkill -f "production_recorder.py" 2>/dev/null || true

# Create log file
touch "$LOG_FILE"
chmod 644 "$LOG_FILE"

# Start recorder with low priority
echo "[INFO] Starting recorder..."
echo ""

# Run in foreground for live viewing
nice -n 19 python3 "$SCRIPT_DIR/production_recorder.py"
