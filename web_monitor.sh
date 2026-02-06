#!/bin/bash
set -euo pipefail

########################################
# WEB SERVER VISITOR LOGGER
# Logs everyone who visits YOUR server
# Captures: IP, timestamp, what they accessed
# Output: JSON lines with India timezone
########################################

LOG_FILE="${1:-/var/log/visitor_log.jsonl}"
INTERFACE="any"

export TZ="Asia/Kolkata"

# Must run as root
if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Run with sudo"
    exit 1
fi

# Check dependencies
for bin in tcpdump awk; do
    command -v "$bin" &>/dev/null || { echo "Missing: $bin"; exit 1; }
done

# Create log directory
mkdir -p "$(dirname "$LOG_FILE")"

echo "========================================"
echo "WEB SERVER VISITOR LOGGER"
echo "Started: $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "Log:     $LOG_FILE"
echo "Ports:   80 (HTTP), 443 (HTTPS)"
echo "========================================"
echo "Logging all incoming web requests..."
echo "Press Ctrl+C to stop"
echo ""

# Capture incoming web traffic to YOUR server (dst port 80 or 443)
# Filter out private IPs (localhost, internal networks)
tcpdump -i "$INTERFACE" -n -l -U -s 0 -A -tttt \
    '(dst port 80 or dst port 443) and not src net 10.0.0.0/8 and not src net 172.16.0.0/12 and not src net 192.168.0.0/16 and not src net 127.0.0.0/8' \
    2>/dev/null | \
awk -v logfile="$LOG_FILE" '
function json_escape(s) {
    gsub(/\\/, "\\\\", s)
    gsub(/"/, "\\\"", s)
    gsub(/\r/, "", s)
    return s
}

function emit(json) {
    print json
    print json >> logfile
    fflush(logfile)
}

function get_ts() {
    cmd = "date \"+%Y-%m-%d %H:%M:%S IST\""
    cmd | getline ts
    close(cmd)
    return ts
}

# Capture packet header line with IPs
/^[0-9]{4}-[0-9]{2}-[0-9]{2}/ {
    # Extract visitor IP (source)
    if (match($3, /([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\./, arr)) {
        visitor_ip = arr[1]
    } else {
        visitor_ip = ""
    }
    
    # Extract destination port
    if (match($5, /\.([0-9]+):/, arr)) {
        port = arr[1]
    } else {
        port = ""
    }
    
    # Detect new connection (SYN)
    if ($0 ~ /Flags \[S\]/) {
        ts = get_ts()
        proto = (port == "443") ? "HTTPS" : "HTTP"
        json = sprintf("{\"ts\":\"%s\",\"event\":\"NEW_CONN\",\"visitor\":\"%s\",\"port\":%s,\"proto\":\"%s\"}", 
                       ts, visitor_ip, port, proto)
        emit(json)
    }
    next
}

# HTTP Request - GET, POST, etc.
/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) / {
    if (visitor_ip == "") next
    
    method = $1
    uri = $2
    ts = get_ts()
    
    json = sprintf("{\"ts\":\"%s\",\"event\":\"REQUEST\",\"visitor\":\"%s\",\"method\":\"%s\",\"path\":\"%s\"}", 
                   ts, visitor_ip, method, json_escape(uri))
    emit(json)
    next
}

# Host header - which domain they requested
/^Host: / {
    if (visitor_ip == "") next
    
    host = $2
    gsub(/\r/, "", host)
    ts = get_ts()
    
    json = sprintf("{\"ts\":\"%s\",\"event\":\"HOST\",\"visitor\":\"%s\",\"host\":\"%s\"}", 
                   ts, visitor_ip, json_escape(host))
    emit(json)
    next
}

# User-Agent - what browser/bot they used
/^User-Agent: / {
    if (visitor_ip == "") next
    
    ua = substr($0, 13)
    gsub(/\r/, "", ua)
    ts = get_ts()
    
    json = sprintf("{\"ts\":\"%s\",\"event\":\"USER_AGENT\",\"visitor\":\"%s\",\"ua\":\"%s\"}", 
                   ts, visitor_ip, json_escape(ua))
    emit(json)
    next
}

# Referer - where they came from
/^Referer: / {
    if (visitor_ip == "") next
    
    ref = $2
    gsub(/\r/, "", ref)
    ts = get_ts()
    
    json = sprintf("{\"ts\":\"%s\",\"event\":\"REFERER\",\"visitor\":\"%s\",\"from\":\"%s\"}", 
                   ts, visitor_ip, json_escape(ref))
    emit(json)
    next
}

# Cookie header (just log that cookies were sent, not the values)
/^Cookie: / {
    if (visitor_ip == "") next
    ts = get_ts()
    
    json = sprintf("{\"ts\":\"%s\",\"event\":\"HAS_COOKIES\",\"visitor\":\"%s\"}", ts, visitor_ip)
    emit(json)
    next
}

# Content-Type for POST data identification
/^Content-Type: / {
    if (visitor_ip == "") next
    
    ctype = substr($0, 15)
    gsub(/\r/, "", ctype)
    ts = get_ts()
    
    json = sprintf("{\"ts\":\"%s\",\"event\":\"CONTENT_TYPE\",\"visitor\":\"%s\",\"type\":\"%s\"}", 
                   ts, visitor_ip, json_escape(ctype))
    emit(json)
    next
}

# TLS Client Hello (HTTPS connection attempt)
/Client Hello/ {
    if (visitor_ip == "" || port != "443") next
    ts = get_ts()
    
    json = sprintf("{\"ts\":\"%s\",\"event\":\"TLS_HANDSHAKE\",\"visitor\":\"%s\",\"port\":443}", ts, visitor_ip)
    emit(json)
    next
}
'
