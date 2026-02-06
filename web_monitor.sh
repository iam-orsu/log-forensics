#!/bin/bash
#
# web_monitor.sh - Production Web Traffic Monitor
# 
# Single-script solution for real-time web traffic monitoring.
# Uses Zeek for protocol-level parsing of HTTP, HTTPS (TLS), and DNS.
# Outputs JSON lines to a single rotating log file.
#
# Author: Blue Team / DFIR
# Usage: sudo ./web_monitor.sh -i <interface> [-o <output_dir>] [-d]
#

set -euo pipefail

#------------------------------------------------------------------------------
# Configuration Defaults
#------------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ZEEK_POLICY="${SCRIPT_DIR}/web_monitor.zeek"
DEFAULT_OUTPUT_DIR="/var/log/web_monitor"
DEFAULT_INTERFACE=""
DAEMON_MODE=false
PID_FILE="/var/run/web_monitor.pid"

# BPF filter: Only web-related traffic, excludes internal-to-internal
BPF_FILTER="(port 80 or port 443 or port 53) and not (src net 10.0.0.0/8 and dst net 10.0.0.0/8) and not (src net 172.16.0.0/12 and dst net 172.16.0.0/12) and not (src net 192.168.0.0/16 and dst net 192.168.0.0/16)"

#------------------------------------------------------------------------------
# Color Output
#------------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

#------------------------------------------------------------------------------
# Usage
#------------------------------------------------------------------------------
usage() {
    cat << EOF
Usage: sudo $0 -i <interface> [-o <output_dir>] [-d]

Production web traffic monitor using Zeek.

Options:
  -i <interface>   Network interface to monitor (e.g., eth0, ens5)
  -o <output_dir>  Output directory for logs (default: ${DEFAULT_OUTPUT_DIR})
  -d               Run in daemon mode (background)
  -h               Show this help message

Examples:
  sudo $0 -i eth0                    # Monitor eth0, logs to default location
  sudo $0 -i ens5 -o /tmp/webmon     # Custom output directory
  sudo $0 -i eth0 -d                 # Run as daemon

Output:
  JSON lines file: <output_dir>/web_traffic.log

Required:
  - Root privileges (for packet capture)
  - Zeek installed (apt install zeek or from zeek.org)

EOF
    exit 1
}

#------------------------------------------------------------------------------
# Preflight Checks
#------------------------------------------------------------------------------
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (for packet capture)"
        exit 1
    fi
}

check_zeek() {
    if ! command -v zeek &> /dev/null; then
        log_error "Zeek is not installed. Install with:"
        log_error "  Debian/Ubuntu: sudo apt install zeek"
        log_error "  RHEL/CentOS:   See https://software.opensuse.org/download.html?package=zeek"
        exit 1
    fi
    log_info "Zeek found: $(zeek --version 2>&1 | head -1)"
}

check_interface() {
    local iface="$1"
    if ! ip link show "$iface" &> /dev/null; then
        log_error "Interface '$iface' does not exist"
        log_error "Available interfaces:"
        ip -o link show | awk -F': ' '{print "  " $2}'
        exit 1
    fi
    log_info "Interface '$iface' is valid"
}

check_zeek_policy() {
    if [[ ! -f "$ZEEK_POLICY" ]]; then
        log_error "Zeek policy file not found: $ZEEK_POLICY"
        exit 1
    fi
    log_info "Zeek policy found: $ZEEK_POLICY"
}

#------------------------------------------------------------------------------
# Setup Output Directory
#------------------------------------------------------------------------------
setup_output_dir() {
    local output_dir="$1"
    
    if [[ ! -d "$output_dir" ]]; then
        log_info "Creating output directory: $output_dir"
        mkdir -p "$output_dir"
    fi
    
    # Ensure proper permissions
    chmod 750 "$output_dir"
    log_info "Output directory ready: $output_dir"
}

#------------------------------------------------------------------------------
# Signal Handlers
#------------------------------------------------------------------------------
cleanup() {
    log_info "Shutting down web monitor..."
    
    # Kill Zeek if running
    if [[ -n "${ZEEK_PID:-}" ]] && kill -0 "$ZEEK_PID" 2>/dev/null; then
        kill -TERM "$ZEEK_PID" 2>/dev/null || true
        wait "$ZEEK_PID" 2>/dev/null || true
    fi
    
    # Remove PID file
    rm -f "$PID_FILE"
    
    log_info "Web monitor stopped"
    exit 0
}

trap cleanup SIGINT SIGTERM SIGHUP

#------------------------------------------------------------------------------
# Main Monitoring Function
#------------------------------------------------------------------------------
start_monitor() {
    local interface="$1"
    local output_dir="$2"
    
    log_info "Starting web traffic monitor..."
    log_info "  Interface: $interface"
    log_info "  Output:    $output_dir/web_traffic.log"
    log_info "  Filter:    HTTP (80), HTTPS (443), DNS (53)"
    log_info "  Mode:      External IPs only (RFC1918 filtered)"
    echo ""
    log_info "Press Ctrl+C to stop monitoring"
    echo ""
    
    # Change to output directory so Zeek writes logs there
    cd "$output_dir"
    
    # Run Zeek with our policy
    # -i: interface
    # -C: ignore checksum errors (common in virtualized environments)
    # -f: BPF filter (kernel-level, before packets reach Zeek)
    # LogAscii::use_json=T: Output logs in JSON format
    zeek -i "$interface" \
         -C \
         -f "$BPF_FILTER" \
         LogAscii::use_json=T \
         "$ZEEK_POLICY" &
    
    ZEEK_PID=$!
    echo "$ZEEK_PID" > "$PID_FILE"
    
    log_info "Zeek started with PID: $ZEEK_PID"
    
    # Wait for Zeek to exit (or signal)
    wait "$ZEEK_PID"
}

start_daemon() {
    local interface="$1"
    local output_dir="$2"
    
    log_info "Starting web monitor in daemon mode..."
    
    # Fork to background
    nohup "$0" -i "$interface" -o "$output_dir" >> "$output_dir/monitor.log" 2>&1 &
    local daemon_pid=$!
    
    log_info "Daemon started with PID: $daemon_pid"
    log_info "Logs: $output_dir/web_traffic.log"
    log_info "Monitor log: $output_dir/monitor.log"
    log_info "To stop: kill $daemon_pid"
}

#------------------------------------------------------------------------------
# Argument Parsing
#------------------------------------------------------------------------------
parse_args() {
    local interface=""
    local output_dir="$DEFAULT_OUTPUT_DIR"
    local daemon=false
    
    while getopts "i:o:dh" opt; do
        case $opt in
            i) interface="$OPTARG" ;;
            o) output_dir="$OPTARG" ;;
            d) daemon=true ;;
            h) usage ;;
            *) usage ;;
        esac
    done
    
    if [[ -z "$interface" ]]; then
        log_error "Interface (-i) is required"
        usage
    fi
    
    # Export for use in functions
    INTERFACE="$interface"
    OUTPUT_DIR="$output_dir"
    DAEMON_MODE="$daemon"
}

#------------------------------------------------------------------------------
# Entry Point
#------------------------------------------------------------------------------
main() {
    parse_args "$@"
    
    # Preflight checks
    check_root
    check_zeek
    check_interface "$INTERFACE"
    check_zeek_policy
    setup_output_dir "$OUTPUT_DIR"
    
    # Start monitoring
    if [[ "$DAEMON_MODE" == true ]]; then
        start_daemon "$INTERFACE" "$OUTPUT_DIR"
    else
        start_monitor "$INTERFACE" "$OUTPUT_DIR"
    fi
}

main "$@"
