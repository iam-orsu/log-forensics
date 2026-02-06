#!/usr/bin/env python3
"""
================================================================================
FORENSIC BLACK BOX RECORDER v3.0 - Enterprise Criminal Investigation Grade
================================================================================

FEATURES:
  - Captures ALL HTTP methods (GET/POST/PUT/DELETE/PATCH)
  - Extracts body data for POST/PUT/DELETE (what exactly was modified/deleted)
  - Smart filtering to reduce false positives
  - Session correlation via cookies/tokens
  - Request timeline reconstruction
  - Court-admissible integrity hashing (SHA256)

MODULES:
  1. IDENTITY     - Real IP, Device fingerprint, Session tracking
  2. BEHAVIOR     - Method, URI, Parameters, Timing
  3. EVIDENCE     - Request body for ALL modifying methods
  4. THREAT       - SQLi, XSS, Path Traversal, Scanner detection
  5. INTEGRITY    - SHA256 hash for legal admissibility

USAGE:
  Foreground:  sudo python3 production_recorder.py
  Background:  sudo python3 production_recorder.py --daemon

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
    
    # Monitor ALL ports
    WEB_PORTS = "ALL"
    
    # Noise reduction - ignore these completely
    IGNORE_HOSTS = [
        '168.63.129.16',   # Azure health
        '169.254.169.254', # Cloud metadata
    ]
    
    IGNORE_PATHS = [
        '/health', '/healthz', '/ready', '/metrics',
        '/favicon.ico', '/.well-known/',
        '/machine', '/HealthService',  # Azure internals
    ]
    
    IGNORE_USER_AGENTS = [
        'kube-probe',
        'ELB-HealthChecker',
        'GoogleStackdriverMonitoring',
    ]
    
    # Only log requests to these hosts (your domains)
    # Leave empty to log all hosts
    ALLOWED_HOSTS = []  # e.g., ['learnwithorsu.xyz', 'api.example.com']
    
    # Buffer for performance
    BUFFER_SIZE = 20
    FLUSH_INTERVAL = 1.0


#===============================================================================
# THREAT DETECTOR (Improved - fewer false positives)
#===============================================================================

class ThreatDetector:
    """Detect malicious patterns with reduced false positives."""
    
    # More precise patterns
    PATTERNS = {
        'sql_injection': [
            r"'\s*(OR|AND)\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+",
            r"UNION\s+ALL\s+SELECT",
            r";\s*(DROP|DELETE|TRUNCATE)\s+(TABLE|DATABASE)",
            r"'\s*;\s*--",
        ],
        'xss_attack': [
            r"<script[^>]*>[^<]*</script>",
            r"javascript\s*:\s*[a-z]+\s*\(",
            r"onerror\s*=\s*['\"]",
            r"onload\s*=\s*['\"]",
        ],
        'path_traversal': [
            r"\.\./(\.\./)+(etc|var|usr|root)",
            r"/etc/(passwd|shadow|hosts)",
            r"/proc/self/",
        ],
        'rce_attempt': [
            r";\s*(bash|sh|nc|wget|curl)\s+-",
            r"\|\s*(bash|sh)\s*$",
            r"`[^`]+(cat|ls|id|whoami)[^`]*`",
        ],
        'scanner_tool': [
            r"(sqlmap|nikto|nessus|acunetix|burp\s*suite)",
            r"masscan|zmap|nmap",
        ],
    }
    
    @classmethod
    def analyze(cls, uri: str, body: str, user_agent: str) -> List[Dict]:
        """Returns list of detected threats with details."""
        threats = []
        content = f"{uri} {body}".lower()
        ua_lower = user_agent.lower()
        
        for threat_type, patterns in cls.PATTERNS.items():
            for pattern in patterns:
                match = re.search(pattern, content if threat_type != 'scanner_tool' else ua_lower, re.IGNORECASE)
                if match:
                    threats.append({
                        'type': threat_type,
                        'pattern_matched': match.group(0)[:50],
                        'severity': 'CRITICAL' if threat_type in ['sql_injection', 'rce_attempt'] else 'HIGH'
                    })
                    break
        
        return threats


#===============================================================================
# IDENTITY EXTRACTOR
#===============================================================================

class IdentityExtractor:
    """Extract visitor identity with session tracking."""
    
    @staticmethod
    def get_real_ip(headers: Dict[str, str], packet_ip: str) -> str:
        for header in ['cf-connecting-ip', 'x-forwarded-for', 'x-real-ip', 'true-client-ip']:
            if header in headers:
                ip = headers[header].split(',')[0].strip()
                if ip and not ip.startswith(('172.', '10.', '192.168.', '127.')):
                    return ip
        return packet_ip
    
    @staticmethod
    def get_session_id(headers: Dict[str, str]) -> Optional[str]:
        """Extract session identifier for request correlation."""
        # Check Authorization header (JWT/Bearer)
        auth = headers.get('authorization', '')
        if auth.startswith('Bearer '):
            token = auth[7:]
            return f"jwt:{hashlib.md5(token.encode()).hexdigest()[:8]}"
        
        # Check cookies for session
        cookies = headers.get('cookie', '')
        for cookie in cookies.split(';'):
            if '=' in cookie:
                name, value = cookie.strip().split('=', 1)
                if name.lower() in ['session', 'sessionid', 'sid', 'token', 'auth']:
                    return f"cookie:{hashlib.md5(value.encode()).hexdigest()[:8]}"
        
        return None
    
    @staticmethod
    def get_device_info(headers: Dict[str, str]) -> Dict:
        ua = headers.get('user-agent', '')
        
        # OS Detection
        os_name = 'Unknown'
        if 'Windows NT 10' in ua:
            os_name = 'Windows 10/11'
        elif 'Windows' in ua:
            os_name = 'Windows'
        elif 'Mac OS X' in ua:
            os_name = 'macOS'
        elif 'Android' in ua:
            os_name = 'Android'
        elif 'iPhone' in ua:
            os_name = 'iPhone'
        elif 'iPad' in ua:
            os_name = 'iPad'
        elif 'Linux' in ua:
            os_name = 'Linux'
        
        # Browser Detection
        browser = 'Unknown'
        browser_version = ''
        
        if 'Edg/' in ua:
            browser = 'Edge'
            m = re.search(r'Edg/(\d+)', ua)
            browser_version = m.group(1) if m else ''
        elif 'Chrome/' in ua and 'Edg' not in ua:
            browser = 'Chrome'
            m = re.search(r'Chrome/(\d+)', ua)
            browser_version = m.group(1) if m else ''
        elif 'Firefox/' in ua:
            browser = 'Firefox'
            m = re.search(r'Firefox/(\d+)', ua)
            browser_version = m.group(1) if m else ''
        elif 'Safari/' in ua and 'Chrome' not in ua:
            browser = 'Safari'
        
        is_mobile = any(x in ua.lower() for x in ['mobile', 'android', 'iphone', 'ipad'])
        
        return {
            'os': os_name,
            'browser': f"{browser} {browser_version}".strip(),
            'is_mobile': is_mobile,
            'raw_ua': ua[:200]
        }


#===============================================================================
# EVIDENCE EXTRACTOR (Enhanced - captures ALL method bodies)
#===============================================================================

class EvidenceExtractor:
    """Extract evidence from ALL HTTP methods."""
    
    @staticmethod
    def extract_body(packet: str, method: str) -> Optional[Dict]:
        """Extract body for POST, PUT, DELETE, PATCH methods."""
        # Only extract body for modifying methods
        if method not in ['POST', 'PUT', 'DELETE', 'PATCH']:
            return None
        
        body = None
        
        # Try to find JSON body (most common for APIs)
        # Look for JSON object that spans multiple lines or single line
        json_patterns = [
            r'\{(?:[^{}]|\{[^{}]*\})*\}',  # Nested JSON
            r'\{[^{}]+\}',  # Simple JSON
        ]
        
        for pattern in json_patterns:
            json_match = re.search(pattern, packet, re.DOTALL)
            if json_match:
                try:
                    candidate = json_match.group(0)
                    # Verify it's valid JSON
                    parsed = json.loads(candidate)
                    if isinstance(parsed, dict) and len(parsed) > 0:
                        body = parsed
                        break
                except:
                    continue
        
        # Try URL-encoded form data
        if not body:
            form_match = re.search(
                r'(?:^|\n)([a-zA-Z_][a-zA-Z0-9_]*=[^&\n\r]+(?:&[a-zA-Z_][a-zA-Z0-9_]*=[^&\n\r]+)*)',
                packet
            )
            if form_match:
                try:
                    from urllib.parse import parse_qs, unquote
                    parsed = parse_qs(form_match.group(1))
                    body = {k: unquote(v[0]) if len(v) == 1 else [unquote(x) for x in v] 
                            for k, v in parsed.items()}
                except:
                    body = {'raw_form': form_match.group(1)[:300]}
        
        return body
    
    @staticmethod
    def extract_uri_params(uri: str) -> Dict:
        """Extract query parameters from URI."""
        if '?' not in uri:
            return {}
        
        try:
            from urllib.parse import parse_qs, urlparse
            parsed = urlparse(uri)
            params = parse_qs(parsed.query)
            return {k: v[0] if len(v) == 1 else v for k, v in params.items()}
        except:
            return {}
    
    @staticmethod
    def extract_resource_id(uri: str) -> Optional[str]:
        """Extract resource ID from URI (for DELETE tracking)."""
        # Common patterns: /api/items/123, /users/abc-def, /posts/456
        patterns = [
            r'/([a-f0-9-]{20,})',  # UUID
            r'/(\d+)(?:/|$)',      # Numeric ID
            r'/([a-zA-Z0-9_-]{8,})(?:/|$)',  # String ID
        ]
        
        for pattern in patterns:
            match = re.search(pattern, uri)
            if match:
                return match.group(1)
        
        return None
    
    @staticmethod
    def classify_action(uri: str, method: str) -> Dict:
        """Detailed action classification."""
        uri_lower = uri.lower()
        
        # Determine resource type
        resource = 'unknown'
        for r in ['user', 'item', 'post', 'comment', 'order', 'product', 'file', 'image', 'document']:
            if r in uri_lower:
                resource = r
                break
        
        # Determine action
        action = 'unknown'
        if method == 'GET':
            action = 'read'
        elif method == 'POST':
            if '/login' in uri_lower or '/signin' in uri_lower:
                action = 'login'
            elif '/signup' in uri_lower or '/register' in uri_lower:
                action = 'register'
            else:
                action = 'create'
        elif method == 'PUT' or method == 'PATCH':
            action = 'update'
        elif method == 'DELETE':
            action = 'delete'
        
        # Determine sensitivity
        sensitivity = 'LOW'
        if any(x in uri_lower for x in ['/admin', '/manage', '/config', '/setting']):
            sensitivity = 'CRITICAL'
        elif any(x in uri_lower for x in ['/user', '/profile', '/account', '/password']):
            sensitivity = 'HIGH'
        elif any(x in uri_lower for x in ['/payment', '/billing', '/order']):
            sensitivity = 'CRITICAL'
        elif method in ['DELETE', 'PUT', 'PATCH']:
            sensitivity = 'MEDIUM'
        
        return {
            'action': action,
            'resource': resource,
            'sensitivity': sensitivity,
            'is_destructive': method == 'DELETE' or 'delete' in uri_lower,
        }


#===============================================================================
# PACKET PROCESSOR
#===============================================================================

class PacketProcessor:
    """Process tcpdump output with smart filtering."""
    
    def __init__(self):
        self.buffer = deque(maxlen=200)
        self.seen = {}  # For deduplication with timestamps
    
    def should_ignore(self, host: str, uri: str, user_agent: str, ip: str) -> bool:
        """Check if request should be ignored (noise reduction)."""
        # Ignore health check hosts
        if any(h in host for h in Config.IGNORE_HOSTS):
            return True
        if any(h in ip for h in Config.IGNORE_HOSTS):
            return True
        
        # Ignore health check paths
        if any(uri.startswith(p) or p in uri for p in Config.IGNORE_PATHS):
            return True
        
        # Ignore monitoring user agents
        if any(ua in user_agent for ua in Config.IGNORE_USER_AGENTS):
            return True
        
        # If ALLOWED_HOSTS is set, only allow those
        if Config.ALLOWED_HOSTS and not any(h in host for h in Config.ALLOWED_HOSTS):
            return True
        
        return False
    
    def is_duplicate(self, key: str) -> bool:
        """Check for duplicate with 1-second window."""
        now = time.time()
        
        # Clean old entries
        self.seen = {k: v for k, v in self.seen.items() if now - v < 1.0}
        
        if key in self.seen:
            return True
        
        self.seen[key] = now
        return False
    
    def process(self, line: str) -> Optional[Dict]:
        """Process tcpdump line and return forensic record if valid."""
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
        
        # Extract headers
        headers = {}
        for m in re.finditer(r'^([A-Za-z-]+):\s*(.+?)(?:\r?\n|$)', packet, re.MULTILINE):
            headers[m.group(1).lower()] = m.group(2).strip()
        
        host = headers.get('host', '')
        user_agent = headers.get('user-agent', '')
        
        # Extract IP
        ip_match = re.search(r'IP\s+(\d+\.\d+\.\d+\.\d+)\.\d+\s+>', packet)
        packet_ip = ip_match.group(1) if ip_match else 'Unknown'
        real_ip = IdentityExtractor.get_real_ip(headers, packet_ip)
        
        # Noise filtering
        if self.should_ignore(host, uri, user_agent, real_ip):
            return None
        
        # Skip pure internal traffic without X-Forwarded-For
        if real_ip.startswith(('172.', '10.', '192.168.')) and 'x-forwarded-for' not in headers:
            return None
        
        # Deduplication
        dedup_key = f"{method}:{uri}:{real_ip}"
        if self.is_duplicate(dedup_key):
            return None
        
        # Get all the details
        device = IdentityExtractor.get_device_info(headers)
        session_id = IdentityExtractor.get_session_id(headers)
        body = EvidenceExtractor.extract_body(packet, method)
        uri_params = EvidenceExtractor.extract_uri_params(uri)
        resource_id = EvidenceExtractor.extract_resource_id(uri)
        action_info = EvidenceExtractor.classify_action(uri, method)
        
        # Threat detection
        body_str = json.dumps(body) if body else ''
        threats = ThreatDetector.analyze(uri + str(uri_params), body_str, user_agent)
        
        # Build forensic record
        timestamp = datetime.now(Config.IST)
        
        record = {
            'id': hashlib.md5(f"{timestamp.isoformat()}{real_ip}{uri}".encode()).hexdigest()[:12],
            'timestamp': timestamp.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+05:30",
            'timestamp_display': timestamp.strftime("%d-%m-%Y %I:%M:%S %p"),
            
            'identity': {
                'ip': real_ip,
                'session': session_id,
                'device': device['os'],
                'browser': device['browser'],
                'is_mobile': device['is_mobile'],
            },
            
            'request': {
                'method': method,
                'uri': uri,
                'host': host,
                'params': uri_params if uri_params else None,
            },
            
            'action': action_info,
            
            'evidence': {
                'resource_id': resource_id,
                'body': body,
                'user_agent': device['raw_ua'],
                'referer': headers.get('referer'),
            },
            
            'security': {
                'threats': threats if threats else None,
                'risk_level': threats[0]['severity'] if threats else 'NORMAL',
            },
        }
        
        # Calculate integrity hash
        record_json = json.dumps(record, sort_keys=True)
        record['integrity_hash'] = hashlib.sha256(record_json.encode()).hexdigest()
        
        return record


#===============================================================================
# LOGGER
#===============================================================================

class ForensicLogger:
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.buffer = []
        self.lock = threading.Lock()
        self.stats = {'total': 0, 'threats': 0, 'deletes': 0}
        self.last_flush = time.time()
        open(log_path, 'a').close()
    
    def log(self, record: Dict):
        with self.lock:
            self.buffer.append(record)
            self.stats['total'] += 1
            if record['security']['threats']:
                self.stats['threats'] += 1
            if record['request']['method'] == 'DELETE':
                self.stats['deletes'] += 1
            
            if len(self.buffer) >= Config.BUFFER_SIZE or time.time() - self.last_flush > Config.FLUSH_INTERVAL:
                self._flush()
    
    def _flush(self):
        if not self.buffer:
            return
        try:
            with open(self.log_path, 'a') as f:
                for r in self.buffer:
                    f.write(json.dumps(r, ensure_ascii=False) + '\n')
            self.buffer = []
            self.last_flush = time.time()
        except Exception as e:
            print(f"[ERROR] Write failed: {e}", file=sys.stderr)
    
    def close(self):
        with self.lock:
            self._flush()


#===============================================================================
# DAEMON
#===============================================================================

def daemonize():
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    
    os.chdir('/')
    os.setsid()
    os.umask(0)
    
    pid = os.fork()
    if pid > 0:
        sys.exit(0)
    
    sys.stdout.flush()
    sys.stderr.flush()
    
    with open('/dev/null', 'r') as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
    
    log_out = open('/var/log/forensic_recorder.out', 'a')
    os.dup2(log_out.fileno(), sys.stdout.fileno())
    os.dup2(log_out.fileno(), sys.stderr.fileno())
    
    with open(Config.PID_FILE, 'w') as f:
        f.write(str(os.getpid()))


#===============================================================================
# MAIN
#===============================================================================

def main():
    daemon_mode = '--daemon' in sys.argv or '-d' in sys.argv
    
    if daemon_mode:
        print("[*] Starting daemon...")
        daemonize()
    else:
        print("=" * 70)
        print(" FORENSIC BLACK BOX v3.0 - Enterprise Investigation Grade")
        print("=" * 70)
        print(f" Log: {Config.LOG_FILE}")
        print(" Capturing: ALL ports | ALL methods | POST/PUT/DELETE bodies")
        print(" Press Ctrl+C to stop")
        print("-" * 70)
        print()
    
    processor = PacketProcessor()
    logger = ForensicLogger(Config.LOG_FILE)
    
    def shutdown(sig, frame):
        logger.close()
        if os.path.exists(Config.PID_FILE):
            os.remove(Config.PID_FILE)
        s = logger.stats
        print(f"\n[*] Total: {s['total']} | Threats: {s['threats']} | Deletes: {s['deletes']}")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    
    # Build command
    cmd = ['tcpdump', '-i', 'any', '-A', '-s', '0', '-l', '-n', 'tcp']
    
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, bufsize=1)
        
        for line in proc.stdout:
            record = processor.process(line)
            if record:
                logger.log(record)
                
                if not daemon_mode:
                    r = record
                    m = r['request']['method']
                    
                    # Color coding
                    if m == 'DELETE':
                        mc = '\033[91m'  # Red
                    elif m == 'POST':
                        mc = '\033[93m'  # Yellow
                    elif m in ['PUT', 'PATCH']:
                        mc = '\033[95m'  # Magenta
                    else:
                        mc = '\033[92m'  # Green
                    
                    rst = '\033[0m'
                    
                    print(f"[{r['timestamp_display']}] {mc}{m}{rst} {r['request']['uri']}")
                    print(f"    IP: {r['identity']['ip']} | {r['identity']['browser']}")
                    
                    if r['evidence']['resource_id']:
                        print(f"    Resource ID: {r['evidence']['resource_id']}")
                    
                    if r['evidence']['body']:
                        print(f"    Body: {json.dumps(r['evidence']['body'])[:120]}")
                    
                    if r['security']['threats']:
                        print(f"    \033[91m⚠ THREATS: {r['security']['threats']}{rst}")
                    
                    print()
    
    except FileNotFoundError:
        print("[ERROR] tcpdump not found")
        sys.exit(1)


if __name__ == "__main__":
    main()
