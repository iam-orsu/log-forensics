#!/usr/bin/env python3
"""
UNIVERSAL Production Forensic Recorder
=======================================

Works with ANY deployment: Docker, PM2, systemd, or bare metal.

Captures on ALL interfaces and ALL common web ports to ensure
nothing escapes logging.

Output: /var/log/forensic_blackbox.log
"""

import sys
import re
import json
import os
from datetime import datetime, timezone, timedelta
import subprocess
import signal

#===============================================================================
# CONFIGURATION
#===============================================================================

LOG_FILE = "/var/log/forensic_blackbox.log"
IST = timezone(timedelta(hours=5, minutes=30))

# ALL common web ports - covers Docker, PM2, direct deployment
WEB_PORTS = "80 or 443 or 3000 or 3001 or 5000 or 8000 or 8080 or 8443"

#===============================================================================
# PACKET PROCESSOR
#===============================================================================

class PacketProcessor:
    """Process tcpdump output and extract HTTP requests."""
    
    def __init__(self):
        self.current_packet = []
        self.in_packet = False
        self.requests_logged = 0
    
    def process_line(self, line: str) -> dict:
        """Process a line from tcpdump and return request if complete."""
        
        # Detect packet header (timestamp line)
        if re.match(r'^\d{2}:\d{2}:\d{2}\.\d+', line):
            # New packet starting, process previous if exists
            result = self._parse_packet()
            self.current_packet = [line]
            self.in_packet = True
            return result
        elif self.in_packet:
            self.current_packet.append(line)
        
        return None
    
    def _parse_packet(self) -> dict:
        """Parse accumulated packet data."""
        if not self.current_packet:
            return None
        
        packet_text = '\n'.join(self.current_packet)
        
        # Extract source IP from packet header
        # Format: 12:34:56.789 IP 1.2.3.4.12345 > 5.6.7.8.80: ...
        ip_match = re.search(r'IP\s+(\d+\.\d+\.\d+\.\d+)\.\d+\s+>', packet_text)
        src_ip = ip_match.group(1) if ip_match else "Unknown"
        
        # Look for HTTP request line
        http_match = re.search(
            r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP',
            packet_text
        )
        
        if not http_match:
            return None
        
        method = http_match.group(1)
        uri = http_match.group(2)
        
        # Extract headers
        host = self._extract_header(packet_text, 'Host')
        user_agent = self._extract_header(packet_text, 'User-Agent')
        content_type = self._extract_header(packet_text, 'Content-Type')
        x_forwarded_for = self._extract_header(packet_text, 'X-Forwarded-For')
        x_real_ip = self._extract_header(packet_text, 'X-Real-IP')
        
        # Use X-Forwarded-For or X-Real-IP if available (real client IP behind proxy)
        real_ip = x_forwarded_for.split(',')[0].strip() if x_forwarded_for else \
                  x_real_ip if x_real_ip else src_ip
        
        # Extract POST body (everything after empty line in HTTP)
        body = None
        if method == 'POST':
            body_match = re.search(r'\r?\n\r?\n(.+?)(?:\.\.\.|$)', packet_text, re.DOTALL)
            if body_match:
                body = body_match.group(1).strip()
                body = self._parse_body(body, content_type)
        
        return {
            'timestamp': datetime.now(IST).strftime("%d-%m-%Y %I:%M:%S %p"),
            'src_ip': real_ip,
            'method': method,
            'uri': uri,
            'host': host or 'Unknown',
            'user_agent': user_agent[:100] if user_agent else 'Unknown',
            'post_data': body
        }
    
    def _extract_header(self, text: str, header_name: str) -> str:
        """Extract a specific HTTP header value."""
        match = re.search(rf'{header_name}:\s*([^\r\n]+)', text, re.IGNORECASE)
        return match.group(1).strip() if match else ''
    
    def _parse_body(self, body: str, content_type: str) -> dict:
        """Parse POST body based on content type."""
        try:
            # Try JSON
            if 'json' in (content_type or '').lower():
                return json.loads(body)
            
            # Try to parse as JSON anyway
            return json.loads(body)
        except:
            pass
        
        try:
            # URL-encoded form data
            from urllib.parse import parse_qs
            parsed = parse_qs(body)
            return {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
        except:
            pass
        
        # Return raw (truncated)
        return {"raw": body[:200]} if body else None


#===============================================================================
# LOGGER
#===============================================================================

class ForensicLogger:
    """Write events to file and console."""
    
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.total = 0
        
        # Ensure file exists
        open(log_path, 'a').close()
    
    def log(self, event: dict):
        """Log an event."""
        self.total += 1
        
        # Write to file
        with open(self.log_path, 'a') as f:
            f.write(json.dumps(event, ensure_ascii=False) + '\n')
        
        # Print to console with colors
        self._print_live(event)
    
    def _print_live(self, e: dict):
        """Pretty print to console."""
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        CYAN = '\033[96m'
        RESET = '\033[0m'
        
        method_color = RED if e['method'] == 'POST' else GREEN
        
        print(f"{CYAN}[{e['timestamp']}]{RESET} {method_color}{e['method']}{RESET} {e['uri']}")
        print(f"    {YELLOW}IP:{RESET} {e['src_ip']}  {YELLOW}Host:{RESET} {e['host']}")
        
        if e.get('post_data'):
            data_str = json.dumps(e['post_data'])[:150]
            print(f"    {RED}DATA:{RESET} {data_str}")
        
        print()


#===============================================================================
# MAIN
#===============================================================================

def main():
    print("=" * 60)
    print(" UNIVERSAL FORENSIC RECORDER")
    print(" Works with: Docker / PM2 / Systemd / Bare Metal")
    print("=" * 60)
    print()
    print(f"[*] Interface: ALL (any)")
    print(f"[*] Ports: {WEB_PORTS}")
    print(f"[*] Log: {LOG_FILE}")
    print(f"[*] Press Ctrl+C to stop")
    print()
    print("-" * 60)
    print()
    
    processor = PacketProcessor()
    logger = ForensicLogger(LOG_FILE)
    
    # Graceful shutdown
    def shutdown(sig, frame):
        print(f"\n[*] Shutting down... Total logged: {logger.total}")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    # Build tcpdump command
    # -i any     : ALL interfaces (universal)
    # -A         : ASCII payload
    # -s 0       : Full packet
    # -l         : Line buffered
    # -n         : No DNS lookups
    port_filter = f"tcp and ({WEB_PORTS.replace(' or ', ' or port ')})"
    port_filter = f"tcp and (port {WEB_PORTS.replace(' or ', ' or port ')})"
    
    cmd = ['tcpdump', '-i', 'any', '-A', '-s', '0', '-l', '-n', port_filter]
    
    print(f"[*] Running: {' '.join(cmd)}")
    print()
    
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1
        )
        
        for line in proc.stdout:
            event = processor.process_line(line)
            if event:
                logger.log(event)
    
    except FileNotFoundError:
        print("[ERROR] tcpdump not found. Install: sudo apt install tcpdump")
        sys.exit(1)
    except PermissionError:
        print("[ERROR] Run with sudo: sudo python3 production_recorder.py")
        sys.exit(1)


if __name__ == "__main__":
    main()
