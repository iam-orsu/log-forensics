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

function extract_ip(field) {
    # Input: "203.0.113.45.54321" -> Output: "203.0.113.45"
    n = split(field, parts, ".")
    if (n >= 5) {
        return parts[1] "." parts[2] "." parts[3] "." parts[4]
    }
    return ""
}

function extract_port(field) {
    # Input: "10.0.0.1.80:" -> Output: "80"
    gsub(/:$/, "", field)
    n = split(field, parts, ".")
    if (n >= 5) {
        return parts[5]
    }
    return ""
}

# Capture packet header line with IPs
# Format: 2026-02-06 15:56:45.123456 IP 203.0.113.45.54321 > 10.0.0.1.80: Flags [S]
/^[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}/ {
    visitor_ip = ""
    port = ""
    
    # Find "IP" keyword and extract source (visitor) IP
    for (i = 1; i <= NF; i++) {
        if ($i == "IP" && $(i+1) != "") {
            visitor_ip = extract_ip($(i+1))
            break
        }
        if ($i == "IP6" && $(i+1) != "") {
            # IPv6 - just grab the address part
            visitor_ip = $(i+1)
            gsub(/\.[0-9]+$/, "", visitor_ip)
            break
        }
    }
    
    # Find destination port (after ">")
    for (i = 1; i <= NF; i++) {
        if ($i == ">" && $(i+1) != "") {
            port = extract_port($(i+1))
            break
        }
    }
    
    # Detect new connection (SYN flag)
    if ($0 ~ /Flags \[S\]/ || $0 ~ /Flags \[S\.\]/) {
        if (visitor_ip != "") {
            ts = get_ts()
            proto = (port == "443") ? "HTTPS" : "HTTP"
            json = sprintf("{\"ts\":\"%s\",\"event\":\"NEW_VISITOR\",\"ip\":\"%s\",\"port\":%s,\"proto\":\"%s\"}", 
                           ts, visitor_ip, (port != "" ? port : "0"), proto)
            emit(json)
        }
    }
    next
}

# HTTP Request - GET, POST, etc.
/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS) / {
    if (visitor_ip == "") next
    
    method = $1
    uri = $2
    ts = get_ts()
    
    json = sprintf("{\"ts\":\"%s\",\"event\":\"REQUEST\",\"ip\":\"%s\",\"method\":\"%s\",\"path\":\"%s\"}", 
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
    
    json = sprintf("{\"ts\":\"%s\",\"event\":\"HOST\",\"ip\":\"%s\",\"host\":\"%s\"}", 
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
    
    json = sprintf("{\"ts\":\"%s\",\"event\":\"BROWSER\",\"ip\":\"%s\",\"user_agent\":\"%s\"}", 
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
    
    json = sprintf("{\"ts\":\"%s\",\"event\":\"REFERER\",\"ip\":\"%s\",\"from\":\"%s\"}", 
                   ts, visitor_ip, json_escape(ref))
    emit(json)
    next
}

# Content-Type for POST data
/^Content-Type: / {
    if (visitor_ip == "") next
    
    ctype = substr($0, 15)
    gsub(/\r/, "", ctype)
    ts = get_ts()
    
    json = sprintf("{\"ts\":\"%s\",\"event\":\"POST_TYPE\",\"ip\":\"%s\",\"content_type\":\"%s\"}", 
                   ts, visitor_ip, json_escape(ctype))
    emit(json)
    next
}

# TLS Client Hello (HTTPS connection)
/Client Hello/ || /TLS/ {
    if (visitor_ip == "" || port != "443") next
    ts = get_ts()
    
    json = sprintf("{\"ts\":\"%s\",\"event\":\"HTTPS_HANDSHAKE\",\"ip\":\"%s\"}", ts, visitor_ip)
    emit(json)
    next
}
'
