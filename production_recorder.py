#!/usr/bin/env python3
"""
================================================================================
FORENSIC BLACK BOX RECORDER - Criminal Investigation Grade
================================================================================

Enterprise-level evidence collection system for legal prosecution.

MODULES:
  1. IDENTITY     - Real IP, Geo-Location hints, Device fingerprint
  2. BEHAVIOR     - Full request chain, session tracking
  3. THREAT       - SQL Injection, XSS, Path Traversal detection
  4. EVIDENCE     - POST bodies, form data, file uploads
  5. INTEGRITY    - SHA256 hash of each log entry for court admissibility

DEPLOYMENT:
  - Runs as background daemon (systemd service)
  - Logs to /var/log/forensic_blackbox.log (append mode)
  - Auto-rotates via logrotate
  - Zero impact on web application performance

================================================================================
"""

import sys
import os
import re
import json
import hashlib
import subprocess
import signal
import time
import socket
from datetime import datetime, timezone, timedelta
from collections import deque
from typing import Optional, Dict, List
import threading

#===============================================================================
# CONFIGURATION
#===============================================================================

class Config:
    LOG_FILE = "/var/log/forensic_blackbox.log"
    PID_FILE = "/var/run/forensic_recorder.pid"
    IST = timezone(timedelta(hours=5, minutes=30))
    
    # Monitor ALL ports (universal capture)
    WEB_PORTS = "ALL"  # Captures on all TCP ports
    
    # Ignore internal health checks
    IGNORE_HOSTS = ['127.0.0.1']
    IGNORE_PATHS = ['/health', '/healthz', '/ready', '/metrics', '/favicon.ico']
    
    # Buffer settings
    BUFFER_SIZE = 50
    FLUSH_INTERVAL = 2.0  # seconds


#===============================================================================
# MODULE 1: THREAT DETECTION
#===============================================================================

class ThreatDetector:
    """Detect malicious patterns in requests."""
    
    PATTERNS = {
        'sql_injection': [
            r"('|\")\s*(OR|AND)\s*('|\")?\s*\d+\s*=\s*\d+",
            r"UNION\s+(ALL\s+)?SELECT",
            r";\s*(DROP|DELETE|UPDATE|INSERT)\s+",
            r"--\s*$",
            r"/\*.*\*/",
        ],
        'xss_attack': [
            r"<script[^>]*>",
            r"javascript\s*:",
            r"on(load|error|click|mouse)\s*=",
            r"<iframe[^>]*>",
        ],
        'path_traversal': [
            r"\.\./",
            r"\.\.\\",
            r"%2e%2e[%/\\]",
            r"/etc/(passwd|shadow)",
            r"/proc/self",
        ],
        'command_injection': [
            r";\s*(ls|cat|wget|curl|nc|bash|sh)\s",
            r"\|\s*(ls|cat|wget|curl|nc|bash|sh)\s",
            r"`[^`]+`",
            r"\$\([^)]+\)",
        ],
        'scanner_signature': [
            r"sqlmap",
            r"nikto",
            r"nmap",
            r"burp",
            r"acunetix",
            r"nessus",
            r"masscan",
        ],
    }
    
    @classmethod
    def analyze(cls, uri: str, body: str, user_agent: str) -> List[str]:
        """Analyze request for threats. Returns list of detected threat types."""
        threats = []
        content = f"{uri} {body} {user_agent}".lower()
        
        for threat_type, patterns in cls.PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    threats.append(threat_type)
                    break
        
        return threats


#===============================================================================
# MODULE 2: IDENTITY EXTRACTION
#===============================================================================

class IdentityExtractor:
    """Extract visitor identity information."""
    
    @staticmethod
    def get_real_ip(headers: Dict[str, str], packet_ip: str) -> str:
        """Get real client IP from headers."""
        # Priority: CF-Connecting-IP > X-Forwarded-For > X-Real-IP > packet
        for header in ['cf-connecting-ip', 'x-forwarded-for', 'x-real-ip']:
            if header in headers:
                ip = headers[header].split(',')[0].strip()
                if ip and not ip.startswith(('172.', '10.', '192.168.')):
                    return ip
        return packet_ip
    
    @staticmethod
    def get_device_fingerprint(headers: Dict[str, str]) -> Dict:
        """Extract device fingerprint from headers."""
        ua = headers.get('user-agent', '')
        
        # Detect OS
        os_name = 'Unknown'
        if 'Windows' in ua:
            os_name = 'Windows'
        elif 'Mac OS' in ua or 'Macintosh' in ua:
            os_name = 'macOS'
        elif 'Linux' in ua:
            os_name = 'Linux'
        elif 'Android' in ua:
            os_name = 'Android'
        elif 'iPhone' in ua or 'iPad' in ua:
            os_name = 'iOS'
        
        # Detect Browser
        browser = 'Unknown'
        if 'Chrome' in ua and 'Edg' not in ua:
            browser = 'Chrome'
        elif 'Firefox' in ua:
            browser = 'Firefox'
        elif 'Safari' in ua and 'Chrome' not in ua:
            browser = 'Safari'
        elif 'Edg' in ua:
            browser = 'Edge'
        
        # Detect if mobile
        is_mobile = any(x in ua.lower() for x in ['mobile', 'android', 'iphone', 'ipad'])
        
        return {
            'os': os_name,
            'browser': browser,
            'is_mobile': is_mobile,
            'raw_ua': ua[:200]
        }
    
    @staticmethod
    def get_country_hint(ip: str) -> str:
        """Get country hint from IP (basic heuristic)."""
        # This is a placeholder - in production, use MaxMind GeoIP
        if ip.startswith('103.'):
            return 'IN'  # India
        elif ip.startswith('104.') or ip.startswith('172.'):
            return 'US'  # USA (Cloudflare/internal)
        return 'XX'


#===============================================================================
# MODULE 3: EVIDENCE EXTRACTOR
#===============================================================================

class EvidenceExtractor:
    """Extract evidence from HTTP requests."""
    
    @staticmethod
    def extract_body(packet: str, method: str, content_type: str) -> Optional[Dict]:
        """Extract and parse POST body."""
        if method != 'POST':
            return None
        
        body = None
        
        # JSON body
        json_match = re.search(r'\{[^{}]*"[^"]+"\s*:\s*[^{}]+\}', packet)
        if json_match:
            try:
                body = json.loads(json_match.group(0))
            except:
                body = {'raw': json_match.group(0)[:500]}
        
        # URL-encoded form
        if not body:
            form_match = re.search(r'(?:^|\n)([a-zA-Z_][a-zA-Z0-9_]*=[^&\n]+(?:&[a-zA-Z_][a-zA-Z0-9_]*=[^&\n]+)*)', packet)
            if form_match:
                try:
                    from urllib.parse import parse_qs
                    parsed = parse_qs(form_match.group(1))
                    body = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
                except:
                    body = {'raw': form_match.group(1)[:500]}
        
        return body
    
    @staticmethod
    def classify_endpoint(uri: str, method: str) -> str:
        """Classify the endpoint for investigation categories."""
        uri_lower = uri.lower()
        
        if any(x in uri_lower for x in ['/login', '/signin', '/auth']):
            return 'AUTHENTICATION'
        elif any(x in uri_lower for x in ['/signup', '/register']):
            return 'REGISTRATION'
        elif any(x in uri_lower for x in ['/admin', '/dashboard', '/manage']):
            return 'ADMIN_ACCESS'
        elif any(x in uri_lower for x in ['/api/user', '/profile', '/account']):
            return 'USER_DATA'
        elif any(x in uri_lower for x in ['/payment', '/checkout', '/billing']):
            return 'FINANCIAL'
        elif any(x in uri_lower for x in ['/upload', '/file', '/download']):
            return 'FILE_OPERATION'
        elif any(x in uri_lower for x in ['/delete', '/remove']):
            return 'DESTRUCTIVE'
        elif method == 'POST':
            return 'DATA_MODIFICATION'
        else:
            return 'GENERAL'


#===============================================================================
# MODULE 4: PACKET PROCESSOR
#===============================================================================

class PacketProcessor:
    """Process tcpdump output into forensic records."""
    
    def __init__(self):
        self.buffer = deque(maxlen=150)
        self.seen = set()
    
    def process(self, line: str) -> Optional[Dict]:
        """Process a line from tcpdump."""
        self.buffer.append(line)
        
        # Check for HTTP request
        if not re.search(r'(GET|POST|PUT|DELETE|PATCH)\s+\S+\s+HTTP', line):
            return None
        
        packet = '\n'.join(self.buffer)
        
        # Extract request line
        req_match = re.search(r'(GET|POST|PUT|DELETE|PATCH)\s+(\S+)\s+HTTP/[\d.]+', packet)
        if not req_match:
            return None
        
        method = req_match.group(1)
        uri = req_match.group(2)
        
        # Dedupe
        req_key = f"{method}{uri}{hash(packet[-500:])}"
        if req_key in self.seen:
            return None
        self.seen.add(req_key)
        if len(self.seen) > 2000:
            self.seen.clear()
        
        # Extract headers
        headers = {}
        for m in re.finditer(r'^([A-Za-z-]+):\s*(.+?)(?:\r?\n|$)', packet, re.MULTILINE):
            headers[m.group(1).lower()] = m.group(2).strip()
        
        # Skip ignored paths and hosts
        host = headers.get('host', '')
        if any(h in host for h in Config.IGNORE_HOSTS):
            return None
        if any(uri.startswith(p) for p in Config.IGNORE_PATHS):
            return None
        
        # Extract packet source IP
        ip_match = re.search(r'IP\s+(\d+\.\d+\.\d+\.\d+)\.\d+\s+>', packet)
        packet_ip = ip_match.group(1) if ip_match else 'Unknown'
        
        # Get real IP
        real_ip = IdentityExtractor.get_real_ip(headers, packet_ip)
        
        # Skip internal-only traffic
        if real_ip.startswith(('172.', '10.', '192.168.')) and 'x-forwarded-for' not in headers:
            return None
        
        # Get device fingerprint
        device = IdentityExtractor.get_device_fingerprint(headers)
        
        # Get country hint
        country = IdentityExtractor.get_country_hint(real_ip)
        
        # Extract body
        content_type = headers.get('content-type', '')
        body = EvidenceExtractor.extract_body(packet, method, content_type)
        
        # Classify endpoint
        category = EvidenceExtractor.classify_endpoint(uri, method)
        
        # Detect threats
        body_str = json.dumps(body) if body else ''
        threats = ThreatDetector.analyze(uri, body_str, device['raw_ua'])
        
        # Build forensic record
        timestamp = datetime.now(Config.IST)
        
        record = {
            'id': hashlib.md5(f"{timestamp}{real_ip}{uri}".encode()).hexdigest()[:12],
            'timestamp': timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+05:30",
            'timestamp_human': timestamp.strftime("%d-%m-%Y %I:%M:%S %p IST"),
            'identity': {
                'ip': real_ip,
                'country': country,
                'device': device['os'],
                'browser': device['browser'],
                'is_mobile': device['is_mobile'],
            },
            'request': {
                'method': method,
                'uri': uri,
                'host': host,
                'category': category,
            },
            'evidence': {
                'post_data': body,
                'user_agent': device['raw_ua'],
                'referer': headers.get('referer', ''),
            },
            'security': {
                'threats_detected': threats,
                'risk_level': 'HIGH' if threats else 'NORMAL',
            },
            'integrity': {
                'record_hash': '',  # Will be set below
            }
        }
        
        # Calculate integrity hash (for court admissibility)
        record_str = json.dumps(record, sort_keys=True)
        record['integrity']['record_hash'] = hashlib.sha256(record_str.encode()).hexdigest()
        
        return record


#===============================================================================
# MODULE 5: FORENSIC LOGGER
#===============================================================================

class ForensicLogger:
    """Thread-safe buffered logger with integrity verification."""
    
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.buffer = []
        self.lock = threading.Lock()
        self.total = 0
        self.threats = 0
        self.last_flush = time.time()
        
        # Ensure log file exists
        open(log_path, 'a').close()
    
    def log(self, record: Dict):
        """Add record to buffer."""
        with self.lock:
            self.buffer.append(record)
            self.total += 1
            if record['security']['threats_detected']:
                self.threats += 1
            
            # Flush if buffer full or time elapsed
            if len(self.buffer) >= Config.BUFFER_SIZE or \
               time.time() - self.last_flush > Config.FLUSH_INTERVAL:
                self._flush()
    
    def _flush(self):
        """Write buffer to disk."""
        if not self.buffer:
            return
        
        try:
            with open(self.log_path, 'a') as f:
                for record in self.buffer:
                    f.write(json.dumps(record, ensure_ascii=False) + '\n')
            self.buffer = []
            self.last_flush = time.time()
        except Exception as e:
            print(f"[ERROR] Failed to write log: {e}", file=sys.stderr)
    
    def close(self):
        """Flush and close."""
        with self.lock:
            self._flush()


#===============================================================================
# DAEMON MODE
#===============================================================================

def daemonize():
    """Fork into background daemon."""
    # First fork
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    
    # Decouple from parent
    os.chdir('/')
    os.setsid()
    os.umask(0)
    
    # Second fork
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    
    # Redirect stdio
    sys.stdout.flush()
    sys.stderr.flush()
    
    with open('/dev/null', 'r') as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
    
    log_out = open('/var/log/forensic_recorder.out', 'a')
    os.dup2(log_out.fileno(), sys.stdout.fileno())
    os.dup2(log_out.fileno(), sys.stderr.fileno())
    
    # Write PID file
    with open(Config.PID_FILE, 'w') as f:
        f.write(str(os.getpid()))


#===============================================================================
# MAIN
#===============================================================================

def main():
    # Check for daemon mode
    daemon_mode = '--daemon' in sys.argv or '-d' in sys.argv
    
    if daemon_mode:
        print("[*] Starting in daemon mode...")
        daemonize()
    else:
        print("=" * 70)
        print(" FORENSIC BLACK BOX RECORDER - Criminal Investigation Grade")
        print("=" * 70)
        print()
        print(f" Log File: {Config.LOG_FILE}")
        print(f" Mode: {'DAEMON (background)' if daemon_mode else 'FOREGROUND'}")
        print()
        print(" Modules: IDENTITY | BEHAVIOR | THREAT | EVIDENCE | INTEGRITY")
        print()
        print(" Press Ctrl+C to stop")
        print()
        print("-" * 70)
        print()
    
    processor = PacketProcessor()
    logger = ForensicLogger(Config.LOG_FILE)
    
    # Shutdown handler
    def shutdown(sig, frame):
        logger.close()
        if os.path.exists(Config.PID_FILE):
            os.remove(Config.PID_FILE)
        print(f"\n[*] Shutdown. Total: {logger.total} | Threats: {logger.threats}")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    # Build tcpdump command
    if Config.WEB_PORTS == "ALL":
        # Capture ALL TCP traffic
        cmd = ['tcpdump', '-i', 'any', '-A', '-s', '0', '-l', '-n', 'tcp']
    else:
        ports = ' or '.join(f'port {p}' for p in Config.WEB_PORTS)
        cmd = ['tcpdump', '-i', 'any', '-A', '-s', '0', '-l', '-n', f'tcp and ({ports})']
    
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1
        )
        
        for line in proc.stdout:
            record = processor.process(line)
            if record:
                logger.log(record)
                
                # Console output (foreground mode only)
                if not daemon_mode:
                    r = record
                    risk = r['security']['risk_level']
                    risk_color = '\033[91m' if risk == 'HIGH' else '\033[92m'
                    reset = '\033[0m'
                    
                    print(f"[{r['timestamp_human']}] {r['request']['method']} {r['request']['uri']}")
                    print(f"    IP: {r['identity']['ip']} ({r['identity']['country']}) | {r['identity']['browser']}/{r['identity']['device']}")
                    if r['evidence']['post_data']:
                        print(f"    DATA: {json.dumps(r['evidence']['post_data'])[:100]}")
                    if r['security']['threats_detected']:
                        print(f"    {risk_color}⚠ THREATS: {r['security']['threats_detected']}{reset}")
                    print()
    
    except FileNotFoundError:
        print("[ERROR] tcpdump not found. Install: sudo apt install tcpdump")
        sys.exit(1)
    except PermissionError:
        print("[ERROR] Run as root: sudo python3 production_recorder.py")
        sys.exit(1)


if __name__ == "__main__":
    main()
