#!/bin/bash
set -euo pipefail

########################################
# HTTPS TRAFFIC MONITOR - eBPF Edition
# Sees DECRYPTED HTTPS traffic
# 
# PRODUCTION SAFETY:
# - Read-only (eBPF cannot modify data)
# - Low overhead (~1-3% CPU)
# - Auto-cleanup on exit
########################################

LOG_FILE="${1:-/var/log/https_monitor.jsonl}"

export TZ="Asia/Kolkata"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1" >&2; }

#------------------------------------------------------------------------------
# Safety Checks
#------------------------------------------------------------------------------
if [[ $EUID -ne 0 ]]; then
    error "Must run as root (eBPF requires privileges)"
    exit 1
fi

# Check kernel version (need 4.9+)
KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d. -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d. -f2)

if [[ "$KERNEL_MAJOR" -lt 4 ]] || [[ "$KERNEL_MAJOR" -eq 4 && "$KERNEL_MINOR" -lt 9 ]]; then
    error "Kernel $KERNEL_VERSION too old. Need 4.9+ for eBPF"
    exit 1
fi
info "Kernel version: $KERNEL_VERSION ✓"

# Check bpftrace - auto-install if missing
if ! command -v bpftrace &>/dev/null; then
    warn "bpftrace not installed. Installing now..."
    
    if command -v apt &>/dev/null; then
        apt update -qq && apt install -y bpftrace
    elif command -v dnf &>/dev/null; then
        dnf install -y bpftrace
    elif command -v yum &>/dev/null; then
        yum install -y bpftrace
    else
        error "Could not auto-install bpftrace. Please install manually."
        exit 1
    fi
    
    if ! command -v bpftrace &>/dev/null; then
        error "bpftrace installation failed"
        exit 1
    fi
    info "bpftrace installed successfully ✓"
else
    info "bpftrace found: $(bpftrace --version 2>&1 | head -1) ✓"
fi

# Find OpenSSL library
LIBSSL=""
for lib in /lib/x86_64-linux-gnu/libssl.so.3 \
           /lib/x86_64-linux-gnu/libssl.so.1.1 \
           /usr/lib/x86_64-linux-gnu/libssl.so.3 \
           /usr/lib/x86_64-linux-gnu/libssl.so.1.1 \
           /lib64/libssl.so.3 \
           /lib64/libssl.so.1.1; do
    if [[ -f "$lib" ]]; then
        LIBSSL="$lib"
        break
    fi
done

if [[ -z "$LIBSSL" ]]; then
    error "OpenSSL library not found."
    exit 1
fi
info "OpenSSL found: $LIBSSL ✓"

# Check if SSL_read symbol exists
if ! nm -D "$LIBSSL" 2>/dev/null | grep -q "SSL_read"; then
    error "SSL_read not found in $LIBSSL"
    exit 1
fi
info "SSL_read symbol found ✓"

#------------------------------------------------------------------------------
# Create log directory
#------------------------------------------------------------------------------
mkdir -p "$(dirname "$LOG_FILE")"

#------------------------------------------------------------------------------
# Cleanup on exit
#------------------------------------------------------------------------------
cleanup() {
    echo ""
    info "Stopping HTTPS monitor..."
    exit 0
}
trap cleanup SIGINT SIGTERM SIGHUP

#------------------------------------------------------------------------------
# Start monitoring
#------------------------------------------------------------------------------
echo ""
echo "========================================"
echo "HTTPS TRAFFIC MONITOR (eBPF)"
echo "========================================"
info "Started:  $(date '+%Y-%m-%d %H:%M:%S %Z')"
info "Log:      $LOG_FILE"
info "Library:  $LIBSSL"
echo "========================================"
echo ""
warn "PRODUCTION SAFETY:"
echo "  ✓ Read-only (cannot modify traffic)"
echo "  ✓ Low overhead (~1-3% CPU)"
echo "  ✓ Auto-cleanup on Ctrl+C"
echo ""
info "Monitoring HTTPS traffic... Press Ctrl+C to stop"
info "(Make some HTTPS requests to see output)"
echo ""

# Run bpftrace inline - more reliable than external file
bpftrace -e "
BEGIN
{
    printf(\"{\\\"event\\\":\\\"STARTED\\\",\\\"ts\\\":\\\"%s\\\"}\\n\", strftime(\"%Y-%m-%d %H:%M:%S IST\", nsecs));
}

uprobe:$LIBSSL:SSL_read
{
    @buf[tid] = arg1;
}

uretprobe:$LIBSSL:SSL_read
/retval > 0/
{
    \$len = retval < 300 ? retval : 300;
    \$data = str(@buf[tid], \$len);
    \$ts = strftime(\"%Y-%m-%d %H:%M:%S IST\", nsecs);
    
    if (strcontains(\$data, \"GET \") || 
        strcontains(\$data, \"POST \") || 
        strcontains(\$data, \"PUT \") ||
        strcontains(\$data, \"DELETE \") ||
        strcontains(\$data, \"HEAD \"))
    {
        printf(\"{\\\"ts\\\":\\\"%s\\\",\\\"pid\\\":%d,\\\"process\\\":\\\"%s\\\",\\\"request\\\":\\\"%s\\\"}\\n\",
               \$ts, pid, comm, \$data);
    }
    delete(@buf[tid]);
}

END
{
    printf(\"{\\\"event\\\":\\\"STOPPED\\\"}\\n\");
    clear(@buf);
}
" 2>&1 | tee -a "$LOG_FILE"
