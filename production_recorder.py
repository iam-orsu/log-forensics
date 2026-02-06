#!/usr/bin/env python3
"""
UNIVERSAL FORENSIC RECORDER v2.0
================================

Captures EVERYTHING about website visitors:
- Real IP (from X-Forwarded-For header)
- Browser/Device (User-Agent)  
- What they did (Method + URI)
- What they typed (POST body - email, password, content)

Filters out Azure health checks automatically.
"""

import sys
import re
import json
import subprocess
import signal
from datetime import datetime, timezone, timedelta
from collections import deque

#===============================================================================
# CONFIG
#===============================================================================

LOG_FILE = "/var/log/forensic_blackbox.log"
IST = timezone(timedelta(hours=5, minutes=30))

# Ignore Azure health checks
IGNORE_HOSTS = ['168.63.129.16', '169.254.169.254']

#===============================================================================
# PACKET PARSER
#===============================================================================

class HTTPExtractor:
    """Extracts HTTP request details from raw packet data."""
    
    def __init__(self):
        self.packet_buffer = deque(maxlen=100)
        self.seen_requests = set()  # Dedupe
    
    def feed(self, line: str):
        """Feed a line from tcpdump."""
        self.packet_buffer.append(line)
        
        # Check if this line contains HTTP request
        if re.search(r'(GET|POST|PUT|DELETE|PATCH)\s+\S+\s+HTTP', line):
            return self._extract_request()
        return None
    
    def _extract_request(self):
        """Extract full HTTP request from buffer."""
        # Join recent lines to get full packet
        packet = '\n'.join(self.packet_buffer)
        
        # Extract HTTP method and URI
        req_match = re.search(r'(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+HTTP/[\d.]+', packet)
        if not req_match:
            return None
        
        method = req_match.group(1)
        uri = req_match.group(2)
        
        # Dedupe (same request might appear multiple times)
        req_key = f"{method}{uri}{len(packet)}"
        if req_key in self.seen_requests:
            return None
        self.seen_requests.add(req_key)
        if len(self.seen_requests) > 1000:
            self.seen_requests.clear()
        
        # Extract headers
        headers = {}
        for match in re.finditer(r'^([A-Za-z-]+):\s*(.+?)(?:\r?\n|$)', packet, re.MULTILINE):
            headers[match.group(1).lower()] = match.group(2).strip()
        
        # Get REAL IP (X-Forwarded-For > X-Real-IP > packet source)
        real_ip = None
        if 'x-forwarded-for' in headers:
            real_ip = headers['x-forwarded-for'].split(',')[0].strip()
        elif 'x-real-ip' in headers:
            real_ip = headers['x-real-ip'].strip()
        else:
            # Try to extract from packet header
            ip_match = re.search(r'IP\s+(\d+\.\d+\.\d+\.\d+)\.\d+\s+>', packet)
            if ip_match:
                real_ip = ip_match.group(1)
        
        if not real_ip:
            real_ip = "Unknown"
        
        # Skip Azure health checks
        host = headers.get('host', '')
        if any(h in host for h in IGNORE_HOSTS) or any(h in real_ip for h in IGNORE_HOSTS):
            return None
        
        # Skip internal Docker IPs for display but keep the X-Forwarded-For
        if real_ip.startswith('172.') or real_ip.startswith('10.'):
            # This is internal, check if we have X-Forwarded-For
            if 'x-forwarded-for' not in headers:
                return None  # Skip pure internal traffic
        
        # Get User-Agent
        user_agent = headers.get('user-agent', 'Unknown')
        
        # Extract POST body
        post_body = None
        if method == 'POST':
            # Look for JSON body
            json_match = re.search(r'\{[^{}]*"[^"]+"\s*:\s*"[^"]*"[^{}]*\}', packet)
            if json_match:
                try:
                    post_body = json.loads(json_match.group(0))
                except:
                    post_body = {"raw": json_match.group(0)[:200]}
            else:
                # Look for form data
                form_match = re.search(r'(?:^|\n)([a-zA-Z_]+=.+?)(?:\n|$)', packet)
                if form_match:
                    post_body = {"form": form_match.group(1)[:200]}
        
        return {
            'timestamp': datetime.now(IST).strftime("%d-%m-%Y %I:%M:%S %p"),
            'ip': real_ip,
            'method': method,
            'uri': uri,
            'host': host,
            'user_agent': user_agent[:150],
            'post_data': post_body
        }


#===============================================================================
# LOGGER
#===============================================================================

def log_event(event: dict, log_file: str):
    """Log event to file and console with colors."""
    
    # Colors
    R = '\033[91m'  # Red
    G = '\033[92m'  # Green
    Y = '\033[93m'  # Yellow
    C = '\033[96m'  # Cyan
    M = '\033[95m'  # Magenta
    W = '\033[97m'  # White
    X = '\033[0m'   # Reset
    
    method = event['method']
    method_color = R if method == 'POST' else G
    
    # Console output
    print(f"{C}[{event['timestamp']}]{X} {method_color}{method}{X} {event['uri']}")
    print(f"    {Y}IP:{X} {W}{event['ip']}{X}")
    print(f"    {Y}Host:{X} {event['host']}")
    print(f"    {Y}Browser:{X} {event['user_agent'][:80]}")
    
    if event.get('post_data'):
        print(f"    {R}DATA:{X} {M}{json.dumps(event['post_data'])[:200]}{X}")
    
    print()
    
    # File output
    with open(log_file, 'a') as f:
        f.write(json.dumps(event, ensure_ascii=False) + '\n')


#===============================================================================
# MAIN
#===============================================================================

def main():
    print("=" * 70)
    print(" UNIVERSAL FORENSIC RECORDER v2.0")
    print(" Captures: IP | Browser | Actions | POST Data")
    print("=" * 70)
    print()
    print(f"Log File: {LOG_FILE}")
    print("Press Ctrl+C to stop")
    print()
    print("-" * 70)
    print()
    
    extractor = HTTPExtractor()
    total = [0]
    
    def shutdown(sig, frame):
        print(f"\n\n[*] Total requests captured: {total[0]}")
        print(f"[*] Log saved to: {LOG_FILE}")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    # tcpdump command - capture on all interfaces, all web ports
    cmd = [
        'tcpdump', '-i', 'any', '-A', '-s', '0', '-l', '-n',
        'tcp and (port 80 or port 443 or port 3000 or port 5000 or port 8080)',
        'and not host 168.63.129.16'  # Exclude Azure health
    ]
    
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1
        )
        
        for line in proc.stdout:
            event = extractor.feed(line)
            if event:
                log_event(event, LOG_FILE)
                total[0] += 1
    
    except FileNotFoundError:
        print("[ERROR] tcpdump not found. Run: sudo apt install tcpdump")
        sys.exit(1)
    except KeyboardInterrupt:
        shutdown(None, None)


if __name__ == "__main__":
    main()
