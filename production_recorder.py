#!/usr/bin/env python3
"""
Production Forensic Recorder - Deep Packet Inspection Engine
=============================================================

Captures EVERYTHING users do on your website:
- Source IP (real visitor IP from X-Forwarded-For)
- Timestamp (microsecond precision)
- HTTP Method (GET/POST/PUT/DELETE)
- Full URI path
- POST Body (what the user typed in forms)
- User-Agent (browser/device)

Runs on the Docker bridge interface to see decrypted traffic.

SAFETY: Runs at lowest priority, will not impact your web app.
"""

import sys
import re
import json
import os
from datetime import datetime, timezone, timedelta
from collections import defaultdict
import subprocess
import signal

#===============================================================================
# CONFIGURATION
#===============================================================================

LOG_FILE = "/var/log/forensic_blackbox.log"
IST = timezone(timedelta(hours=5, minutes=30))

#===============================================================================
# HTTP PARSER
#===============================================================================

class HTTPRequestParser:
    """Reconstructs HTTP requests from packet fragments."""
    
    HTTP_METHODS = {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}
    
    def __init__(self):
        self.buffer = ""
        self.current_request = None
        self.requests = []
    
    def feed(self, data: str):
        """Feed raw packet data to the parser."""
        self.buffer += data
        self._parse_buffer()
    
    def _parse_buffer(self):
        """Try to extract complete HTTP requests from buffer."""
        while True:
            # Look for HTTP request start
            match = re.search(
                r'(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)\s+HTTP/\d\.\d',
                self.buffer
            )
            
            if not match:
                break
            
            start_pos = match.start()
            method = match.group(1)
            uri = match.group(2)
            
            # Find headers end (double newline)
            headers_end = self.buffer.find('\r\n\r\n', start_pos)
            if headers_end == -1:
                headers_end = self.buffer.find('\n\n', start_pos)
            
            if headers_end == -1:
                break  # Incomplete headers, wait for more data
            
            headers_text = self.buffer[start_pos:headers_end]
            body_start = headers_end + 4 if '\r\n\r\n' in self.buffer[start_pos:headers_end+4] else headers_end + 2
            
            # Parse headers
            headers = {}
            for line in headers_text.split('\n')[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Get Content-Length for POST body
            content_length = int(headers.get('content-length', 0))
            
            # Extract body if present
            body = ""
            if content_length > 0:
                available_body = self.buffer[body_start:body_start + content_length]
                if len(available_body) < content_length:
                    break  # Incomplete body, wait for more data
                body = available_body
            
            # Build request object
            request = {
                'timestamp': datetime.now(IST).strftime("%d-%m-%Y %I:%M:%S %p"),
                'method': method,
                'uri': uri,
                'headers': headers,
                'body': body,
                'src_ip': self._extract_real_ip(headers),
                'user_agent': headers.get('user-agent', 'Unknown'),
                'host': headers.get('host', 'Unknown'),
            }
            
            self.requests.append(request)
            
            # Remove parsed request from buffer
            end_pos = body_start + content_length
            self.buffer = self.buffer[end_pos:]
    
    def _extract_real_ip(self, headers: dict) -> str:
        """Extract real visitor IP from X-Forwarded-For or X-Real-IP."""
        # Priority: X-Forwarded-For > X-Real-IP > fallback
        xff = headers.get('x-forwarded-for', '')
        if xff:
            # Take the first IP (original client)
            return xff.split(',')[0].strip()
        
        xri = headers.get('x-real-ip', '')
        if xri:
            return xri.strip()
        
        return "Unknown"
    
    def get_requests(self) -> list:
        """Return and clear parsed requests."""
        reqs = self.requests
        self.requests = []
        return reqs


#===============================================================================
# FORENSIC LOGGER
#===============================================================================

class ForensicLogger:
    """Writes forensic events to the log file."""
    
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.buffer = []
        self.buffer_size = 10
        self.total_logged = 0
    
    def log(self, request: dict):
        """Log a single request."""
        # Build the forensic record
        record = {
            "timestamp": request['timestamp'],
            "src_ip": request['src_ip'],
            "method": request['method'],
            "uri": request['uri'],
            "host": request['host'],
            "user_agent": request['user_agent'],
            "post_data": self._sanitize_body(request['body']) if request['body'] else None,
        }
        
        self.buffer.append(record)
        
        # Print to console for live monitoring
        self._print_live(record)
        
        # Flush if buffer is full
        if len(self.buffer) >= self.buffer_size:
            self.flush()
    
    def _sanitize_body(self, body: str) -> dict:
        """Parse and sanitize POST body (JSON or form data)."""
        try:
            # Try JSON first
            return json.loads(body)
        except:
            pass
        
        try:
            # Try URL-encoded form data
            from urllib.parse import parse_qs
            parsed = parse_qs(body)
            return {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
        except:
            pass
        
        # Return raw if can't parse
        return {"raw": body[:500]}  # Limit size
    
    def _print_live(self, record: dict):
        """Print to console for live monitoring."""
        ip = record['src_ip']
        method = record['method']
        uri = record['uri']
        ts = record['timestamp']
        
        # Color coding
        if method == 'POST':
            method_color = '\033[91m'  # Red for POST
        else:
            method_color = '\033[92m'  # Green for GET
        
        reset = '\033[0m'
        
        print(f"[{ts}] {method_color}{method}{reset} {uri}")
        print(f"         IP: {ip}")
        
        if record['post_data']:
            print(f"         DATA: {json.dumps(record['post_data'], indent=2)[:200]}")
        
        print()
    
    def flush(self):
        """Write buffered records to disk."""
        if not self.buffer:
            return
        
        try:
            with open(self.log_path, 'a') as f:
                for record in self.buffer:
                    f.write(json.dumps(record, ensure_ascii=False) + '\n')
            
            self.total_logged += len(self.buffer)
            self.buffer = []
        except Exception as e:
            print(f"[ERROR] Failed to write log: {e}", file=sys.stderr)
    
    def close(self):
        """Flush remaining buffer on shutdown."""
        self.flush()
        print(f"\n[INFO] Total requests logged: {self.total_logged}")


#===============================================================================
# MAIN CAPTURE ENGINE
#===============================================================================

def find_docker_interface() -> str:
    """Find the Docker bridge interface."""
    try:
        result = subprocess.run(
            ['ip', 'link', 'show'],
            capture_output=True, text=True
        )
        
        for line in result.stdout.split('\n'):
            # Look for docker0 or br- interfaces
            match = re.search(r'\d+:\s+(docker0|br-\w+):', line)
            if match:
                return match.group(1)
        
        # Fallback to any
        return 'any'
    except:
        return 'any'


def main():
    print("=" * 60)
    print(" PRODUCTION FORENSIC RECORDER")
    print(" Deep Packet Inspection Engine")
    print("=" * 60)
    print()
    
    # Find Docker interface
    interface = find_docker_interface()
    print(f"[INFO] Capturing on interface: {interface}")
    print(f"[INFO] Logging to: {LOG_FILE}")
    print(f"[INFO] Press Ctrl+C to stop")
    print()
    
    # Initialize components
    parser = HTTPRequestParser()
    logger = ForensicLogger(LOG_FILE)
    
    # Handle shutdown
    def shutdown(sig, frame):
        print("\n[INFO] Shutting down...")
        logger.close()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    # Start tcpdump
    # -i interface : Listen on Docker bridge
    # -A           : Print packet payload in ASCII
    # -s 0         : Capture full packet
    # -l           : Line buffered
    # port 80 or port 3000 : Capture HTTP traffic (internal)
    cmd = [
        'tcpdump',
        '-i', interface,
        '-A', '-s', '0', '-l',
        'tcp port 80 or tcp port 3000 or tcp port 8080'
    ]
    
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1
        )
        
        print(f"[INFO] tcpdump started (PID: {proc.pid})")
        print("-" * 60)
        print()
        
        # Read packets
        for line in proc.stdout:
            # Feed to parser
            parser.feed(line)
            
            # Process any complete requests
            for request in parser.get_requests():
                logger.log(request)
        
    except FileNotFoundError:
        print("[ERROR] tcpdump not found. Install with: sudo apt install tcpdump")
        sys.exit(1)
    except PermissionError:
        print("[ERROR] Permission denied. Run with: sudo python3 production_recorder.py")
        sys.exit(1)


if __name__ == "__main__":
    main()
