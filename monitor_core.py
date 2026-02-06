#!/usr/bin/env python3
"""
DFIR Monitor Core - Forensic-Grade Log Aggregator
=================================================

A high-performance, production-safe log aggregator that collects, normalizes,
and unifies security events from multiple sources into a single JSON-Lines file.

SAFETY GUARANTEES:
- Runs at lowest priority (controlled by deploy script)
- Buffered I/O to minimize disk IOPS
- Graceful degradation if log sources disappear
- Will NEVER block, crash, or interfere with web applications

Author: DFIR Monitor Team
License: MIT
"""

import json
import os
import re
import signal
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
import subprocess
import threading


#===============================================================================
# CONFIGURATION
#===============================================================================

class Config:
    """Central configuration for the monitor."""
    
    # Output file
    LOG_FILE = "/var/log/dfir_monitor.json"
    PID_FILE = "/var/run/dfir_monitor.pid"
    
    # Buffer settings (CRITICAL for 200,000+ hits/day)
    BUFFER_MAX_SIZE = 500        # Flush after 500 events
    BUFFER_MAX_AGE_SEC = 1.0     # Flush after 1 second
    
    # Polling interval (balance between latency and CPU usage)
    POLL_INTERVAL_SEC = 0.1      # 100ms
    
    # Log sources to monitor
    WEB_LOG_PATHS = [
        "/var/log/nginx/access.log",
        "/var/log/apache2/access.log",
        "/var/log/httpd/access_log",
    ]
    
    AUTH_LOG_PATHS = [
        "/var/log/auth.log",        # Debian/Ubuntu
        "/var/log/secure",          # RHEL/CentOS
    ]
    
    ZEEK_LOG_DIR = "/var/log/zeek/current"
    ZEEK_LOGS = ["conn.log", "dns.log", "ssl.log", "weird.log", "http.log"]
    
    # Timezone: Indian Standard Time (IST = UTC+5:30)
    TIMEZONE_OFFSET_HOURS = 5.5


#===============================================================================
# TIMESTAMP UTILITIES
#===============================================================================

def get_ist_timestamp() -> str:
    """
    Get current timestamp in Indian Standard Time.
    Format: DD-MM-YYYY H:MM am/pm
    """
    utc_now = datetime.utcnow()
    ist_offset = Config.TIMEZONE_OFFSET_HOURS * 3600
    ist_now = datetime.utcfromtimestamp(utc_now.timestamp() + ist_offset)
    
    # Format: "06-02-2026 9:15 am"
    hour = ist_now.hour
    am_pm = "am" if hour < 12 else "pm"
    if hour == 0:
        hour = 12
    elif hour > 12:
        hour -= 12
    
    return f"{ist_now.day:02d}-{ist_now.month:02d}-{ist_now.year} {hour}:{ist_now.minute:02d} {am_pm}"


def parse_timestamp_to_ist(ts_str: str, fmt: str = None) -> str:
    """Convert various timestamp formats to IST format."""
    try:
        if fmt:
            dt = datetime.strptime(ts_str, fmt)
        else:
            # Try common formats
            for f in ["%Y-%m-%dT%H:%M:%S", "%d/%b/%Y:%H:%M:%S", "%Y-%m-%d %H:%M:%S"]:
                try:
                    dt = datetime.strptime(ts_str.split('.')[0].split('+')[0], f)
                    break
                except ValueError:
                    continue
            else:
                return get_ist_timestamp()
        
        # Assume UTC, convert to IST
        ist_offset = Config.TIMEZONE_OFFSET_HOURS * 3600
        ist_dt = datetime.utcfromtimestamp(dt.timestamp() + ist_offset)
        
        hour = ist_dt.hour
        am_pm = "am" if hour < 12 else "pm"
        if hour == 0:
            hour = 12
        elif hour > 12:
            hour -= 12
        
        return f"{ist_dt.day:02d}-{ist_dt.month:02d}-{ist_dt.year} {hour}:{ist_dt.minute:02d} {am_pm}"
    except Exception:
        return get_ist_timestamp()


#===============================================================================
# LOG TAILER CLASS
#===============================================================================

class LogTailer:
    """
    Robust log file tailer with inode tracking and rotation handling.
    
    Handles:
    - Log rotation (file replaced with new file)
    - File truncation
    - File deletion and recreation
    - External rotation by logrotate/nginx
    """
    
    def __init__(self, filepath: str, name: str = None):
        self.filepath = filepath
        self.name = name or os.path.basename(filepath)
        self.file_handle: Optional[Any] = None
        self.inode: Optional[int] = None
        self.position: int = 0
        self._open_file()
    
    def _open_file(self) -> bool:
        """Open the file and seek to end. Returns True if successful."""
        try:
            if not os.path.exists(self.filepath):
                return False
            
            self.file_handle = open(self.filepath, 'r', encoding='utf-8', errors='replace')
            stat = os.fstat(self.file_handle.fileno())
            self.inode = stat.st_ino
            
            # Seek to end (we only want new lines)
            self.file_handle.seek(0, 2)
            self.position = self.file_handle.tell()
            return True
        except (IOError, OSError, PermissionError) as e:
            self.file_handle = None
            return False
    
    def _check_rotation(self) -> bool:
        """Check if the file was rotated (inode changed or truncated)."""
        try:
            if not os.path.exists(self.filepath):
                return True
            
            stat = os.stat(self.filepath)
            
            # Inode changed = file was rotated
            if stat.st_ino != self.inode:
                return True
            
            # File is smaller than our position = file was truncated
            if stat.st_size < self.position:
                return True
            
            return False
        except (IOError, OSError):
            return True
    
    def read_new_lines(self) -> List[str]:
        """Read and return any new lines from the file."""
        lines = []
        
        try:
            # Check for rotation
            if self._check_rotation():
                if self.file_handle:
                    self.file_handle.close()
                self._open_file()
                if not self.file_handle:
                    return lines
            
            if not self.file_handle:
                self._open_file()
                if not self.file_handle:
                    return lines
            
            # Read new lines
            while True:
                line = self.file_handle.readline()
                if not line:
                    break
                line = line.strip()
                if line:
                    lines.append(line)
            
            self.position = self.file_handle.tell()
            
        except (IOError, OSError, UnicodeDecodeError) as e:
            # Graceful degradation - don't crash
            pass
        
        return lines
    
    def close(self):
        """Clean up file handle."""
        if self.file_handle:
            try:
                self.file_handle.close()
            except:
                pass


#===============================================================================
# AUDITD LOG READER
#===============================================================================

class AuditdReader:
    """
    Read audit events using ausearch for reliable parsing.
    Tracks progress using timestamp to avoid duplicates.
    """
    
    def __init__(self):
        self.last_event_time = time.time()
        self.seen_serials: set = set()
        self.max_seen_serials = 10000  # Prevent memory bloat
    
    def read_new_events(self) -> List[Dict]:
        """Read new audit events since last check."""
        events = []
        
        try:
            # Use ausearch to get recent events in interpretable format
            cmd = [
                'ausearch',
                '-ts', 'recent',  # Last 10 minutes
                '-i',             # Interpret (human-readable)
                '--format', 'text'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode != 0:
                return events
            
            # Parse ausearch output
            current_event = {}
            for line in result.stdout.split('\n'):
                line = line.strip()
                
                if line.startswith('----'):
                    # New event boundary
                    if current_event and 'serial' in current_event:
                        serial = current_event.get('serial', '')
                        if serial not in self.seen_serials:
                            self.seen_serials.add(serial)
                            events.append(current_event)
                    current_event = {}
                    continue
                
                if not line:
                    continue
                
                # Parse key=value pairs
                if '=' in line:
                    # Handle type=SYSCALL, type=EXECVE, etc.
                    if line.startswith('type='):
                        parts = line.split(' ', 1)
                        current_event['type'] = parts[0].split('=')[1]
                        if len(parts) > 1:
                            line = parts[1]
                    
                    # Parse remaining key=value pairs
                    for match in re.finditer(r'(\w+)=("[^"]*"|\S+)', line):
                        key, value = match.groups()
                        value = value.strip('"')
                        current_event[key] = value
            
            # Don't forget last event
            if current_event and 'serial' in current_event:
                serial = current_event.get('serial', '')
                if serial not in self.seen_serials:
                    self.seen_serials.add(serial)
                    events.append(current_event)
            
            # Prevent memory bloat
            if len(self.seen_serials) > self.max_seen_serials:
                self.seen_serials = set(list(self.seen_serials)[-5000:])
            
        except subprocess.TimeoutExpired:
            pass
        except FileNotFoundError:
            # ausearch not installed
            pass
        except Exception as e:
            pass
        
        return events


#===============================================================================
# EVENT PARSERS
#===============================================================================

class EventParser:
    """Parse raw log lines into normalized event dictionaries."""
    
    # Regex patterns for web logs (Combined Log Format)
    WEB_LOG_PATTERN = re.compile(
        r'^(?P<ip>[\d.]+)\s+'                          # Source IP
        r'(?P<ident>\S+)\s+'                           # Ident
        r'(?P<user>\S+)\s+'                            # User
        r'\[(?P<timestamp>[^\]]+)\]\s+'                # Timestamp
        r'"(?P<method>\w+)\s+(?P<uri>\S+)\s+\S+"\s+'   # Request
        r'(?P<status>\d+)\s+'                          # Status code
        r'(?P<size>\d+|-)\s*'                          # Size
        r'(?:"(?P<referrer>[^"]*)"\s*)?'               # Referrer (optional)
        r'(?:"(?P<user_agent>[^"]*)")?'                # User-Agent (optional)
    )
    
    # Regex patterns for auth.log
    SSH_LOGIN_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+'
        r'\S+\s+sshd\[\d+\]:\s+'
        r'(?P<result>Accepted|Failed)\s+(?P<method>\w+)\s+'
        r'for\s+(?:invalid user\s+)?(?P<user>\S+)\s+'
        r'from\s+(?P<ip>[\d.]+)'
    )
    
    SSH_INVALID_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+'
        r'\S+\s+sshd\[\d+\]:\s+'
        r'Invalid user\s+(?P<user>\S+)\s+'
        r'from\s+(?P<ip>[\d.]+)'
    )
    
    SUDO_PATTERN = re.compile(
        r'(?P<timestamp>\w+\s+\d+\s+[\d:]+)\s+'
        r'\S+\s+sudo\S*:\s+'
        r'(?P<user>\S+)\s+:\s+.*?'
        r'COMMAND=(?P<command>.+)$'
    )
    
    @classmethod
    def parse_web_log(cls, line: str) -> Optional[Dict]:
        """Parse nginx/apache access log line."""
        match = cls.WEB_LOG_PATTERN.match(line)
        if not match:
            return None
        
        data = match.groupdict()
        return {
            "timestamp": parse_timestamp_to_ist(data['timestamp'], "%d/%b/%Y:%H:%M:%S"),
            "event_type": "web_http",
            "src_ip": data['ip'],
            "details": {
                "method": data['method'],
                "uri": data['uri'],
                "status": int(data['status']),
                "size": int(data['size']) if data['size'] != '-' else 0,
                "user_agent": data.get('user_agent', ''),
                "referrer": data.get('referrer', ''),
                "raw_log": line
            }
        }
    
    @classmethod
    def parse_auth_log(cls, line: str) -> Optional[Dict]:
        """Parse auth.log/secure lines for SSH and sudo events."""
        
        # SSH login (accepted/failed)
        match = cls.SSH_LOGIN_PATTERN.search(line)
        if match:
            data = match.groupdict()
            event_type = "ssh_login" if data['result'] == 'Accepted' else "ssh_fail"
            return {
                "timestamp": get_ist_timestamp(),
                "event_type": event_type,
                "src_ip": data['ip'],
                "details": {
                    "user": data['user'],
                    "auth_method": data['method'],
                    "result": data['result'].lower(),
                    "raw_log": line
                }
            }
        
        # Invalid user attempts
        match = cls.SSH_INVALID_PATTERN.search(line)
        if match:
            data = match.groupdict()
            return {
                "timestamp": get_ist_timestamp(),
                "event_type": "ssh_invalid_user",
                "src_ip": data['ip'],
                "details": {
                    "attempted_user": data['user'],
                    "raw_log": line
                }
            }
        
        # Sudo commands
        match = cls.SUDO_PATTERN.search(line)
        if match:
            data = match.groupdict()
            return {
                "timestamp": get_ist_timestamp(),
                "event_type": "sudo_exec",
                "src_ip": "127.0.0.1",
                "details": {
                    "user": data['user'],
                    "command": data['command'],
                    "raw_log": line
                }
            }
        
        return None
    
    @classmethod
    def parse_zeek_log(cls, line: str, log_type: str) -> Optional[Dict]:
        """Parse Zeek JSON log line."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None
        
        # Get timestamp
        ts = data.get('ts', '')
        if ts:
            try:
                dt = datetime.fromtimestamp(float(ts))
                timestamp = parse_timestamp_to_ist(dt.isoformat())
            except:
                timestamp = get_ist_timestamp()
        else:
            timestamp = get_ist_timestamp()
        
        src_ip = data.get('id.orig_h', data.get('orig_h', ''))
        
        if log_type == 'conn.log':
            return {
                "timestamp": timestamp,
                "event_type": "network_conn",
                "src_ip": src_ip,
                "details": {
                    "dst_ip": data.get('id.resp_h', data.get('resp_h', '')),
                    "src_port": data.get('id.orig_p', data.get('orig_p', '')),
                    "dst_port": data.get('id.resp_p', data.get('resp_p', '')),
                    "proto": data.get('proto', ''),
                    "duration": data.get('duration', 0),
                    "orig_bytes": data.get('orig_bytes', 0),
                    "resp_bytes": data.get('resp_bytes', 0),
                    "conn_state": data.get('conn_state', ''),
                    "raw_log": line
                }
            }
        
        elif log_type == 'dns.log':
            return {
                "timestamp": timestamp,
                "event_type": "dns_query",
                "src_ip": src_ip,
                "details": {
                    "query": data.get('query', ''),
                    "qtype": data.get('qtype_name', data.get('qtype', '')),
                    "rcode": data.get('rcode_name', data.get('rcode', '')),
                    "answers": data.get('answers', []),
                    "raw_log": line
                }
            }
        
        elif log_type == 'ssl.log':
            return {
                "timestamp": timestamp,
                "event_type": "ssl_conn",
                "src_ip": src_ip,
                "details": {
                    "server_name": data.get('server_name', ''),
                    "dst_ip": data.get('id.resp_h', data.get('resp_h', '')),
                    "version": data.get('version', ''),
                    "cipher": data.get('cipher', ''),
                    "ja3": data.get('ja3', ''),
                    "ja3s": data.get('ja3s', ''),
                    "raw_log": line
                }
            }
        
        elif log_type == 'weird.log':
            return {
                "timestamp": timestamp,
                "event_type": "anomaly",
                "src_ip": src_ip,
                "details": {
                    "name": data.get('name', ''),
                    "addl": data.get('addl', ''),
                    "notice": data.get('notice', False),
                    "raw_log": line
                }
            }
        
        elif log_type == 'http.log':
            return {
                "timestamp": timestamp,
                "event_type": "zeek_http",
                "src_ip": src_ip,
                "details": {
                    "method": data.get('method', ''),
                    "host": data.get('host', ''),
                    "uri": data.get('uri', ''),
                    "status_code": data.get('status_code', ''),
                    "user_agent": data.get('user_agent', ''),
                    "raw_log": line
                }
            }
        
        return None
    
    @classmethod
    def parse_auditd_event(cls, event: Dict) -> Optional[Dict]:
        """Parse auditd event dictionary."""
        event_type = event.get('type', '')
        
        if event_type == 'EXECVE' or 'SYSCALL' in event_type:
            # Command execution
            # Build command line from a0, a1, a2, etc.
            cmd_parts = []
            for i in range(20):  # Max 20 arguments
                arg = event.get(f'a{i}')
                if arg:
                    # Decode hex if needed
                    if arg.startswith('0x') or all(c in '0123456789abcdefABCDEF' for c in arg):
                        try:
                            decoded = bytes.fromhex(arg.replace('0x', '')).decode('utf-8', errors='replace')
                            if decoded.isprintable():
                                arg = decoded
                        except:
                            pass
                    cmd_parts.append(arg)
                else:
                    break
            
            command_line = event.get('comm', '') or event.get('exe', '')
            if event.get('proctitle'):
                command_line = event.get('proctitle')
            
            return {
                "timestamp": get_ist_timestamp(),
                "event_type": "process_exec",
                "src_ip": "127.0.0.1",
                "details": {
                    "command": command_line,
                    "exe": event.get('exe', ''),
                    "comm": event.get('comm', ''),
                    "auid": event.get('auid', ''),
                    "uid": event.get('uid', ''),
                    "euid": event.get('euid', ''),
                    "pid": event.get('pid', ''),
                    "ppid": event.get('ppid', ''),
                    "key": event.get('key', ''),
                    "raw_log": json.dumps(event)
                }
            }
        
        elif event_type == 'USER_AUTH' or event_type == 'USER_LOGIN':
            return {
                "timestamp": get_ist_timestamp(),
                "event_type": "audit_auth",
                "src_ip": event.get('addr', '127.0.0.1'),
                "details": {
                    "user": event.get('acct', event.get('auid', '')),
                    "terminal": event.get('terminal', ''),
                    "result": event.get('res', ''),
                    "raw_log": json.dumps(event)
                }
            }
        
        return None


#===============================================================================
# BUFFERED WRITER
#===============================================================================

class BufferedWriter:
    """
    High-performance buffered writer for JSON-Lines output.
    
    Flushes to disk when:
    - Buffer size >= BUFFER_MAX_SIZE (500 events)
    - Time since last flush >= BUFFER_MAX_AGE_SEC (1 second)
    
    This prevents disk thrashing on high-traffic servers.
    """
    
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.buffer: List[Dict] = []
        self.last_flush_time = time.time()
        self.lock = threading.Lock()
        self.total_events_written = 0
    
    def write(self, event: Dict):
        """Add event to buffer (thread-safe)."""
        with self.lock:
            self.buffer.append(event)
    
    def should_flush(self) -> bool:
        """Check if buffer should be flushed."""
        if len(self.buffer) >= Config.BUFFER_MAX_SIZE:
            return True
        if time.time() - self.last_flush_time >= Config.BUFFER_MAX_AGE_SEC:
            return True
        return False
    
    def flush(self):
        """Write buffered events to disk (thread-safe)."""
        with self.lock:
            if not self.buffer:
                return
            
            events_to_write = self.buffer
            self.buffer = []
            self.last_flush_time = time.time()
        
        try:
            with open(self.filepath, 'a', encoding='utf-8') as f:
                for event in events_to_write:
                    f.write(json.dumps(event, ensure_ascii=False) + '\n')
            
            self.total_events_written += len(events_to_write)
            
        except (IOError, OSError) as e:
            # On error, put events back in buffer (best effort)
            with self.lock:
                self.buffer = events_to_write + self.buffer
    
    def force_flush(self):
        """Force flush all buffered events (for shutdown)."""
        self.flush()


#===============================================================================
# MAIN MONITOR
#===============================================================================

class DFIRMonitor:
    """
    Main forensic monitor that aggregates all log sources.
    """
    
    def __init__(self):
        self.running = True
        self.writer = BufferedWriter(Config.LOG_FILE)
        self.tailers: Dict[str, LogTailer] = {}
        self.auditd_reader = AuditdReader()
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self._signal_handler)
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGHUP, self._signal_handler)
        
        # Write PID file
        self._write_pid()
        
        # Initialize log tailers
        self._init_tailers()
    
    def _write_pid(self):
        """Write our PID to the PID file."""
        try:
            with open(Config.PID_FILE, 'w') as f:
                f.write(str(os.getpid()))
        except:
            pass
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print(f"\n[DFIR Monitor] Received signal {signum}, shutting down...")
        self.running = False
    
    def _init_tailers(self):
        """Initialize log file tailers for each source."""
        
        # Web server logs (auto-detect)
        for path in Config.WEB_LOG_PATHS:
            if os.path.exists(path):
                self.tailers[f"web:{path}"] = LogTailer(path, "web")
                print(f"[DFIR Monitor] Tailing web log: {path}")
                break  # Usually only one web server
        
        # Auth logs
        for path in Config.AUTH_LOG_PATHS:
            if os.path.exists(path):
                self.tailers[f"auth:{path}"] = LogTailer(path, "auth")
                print(f"[DFIR Monitor] Tailing auth log: {path}")
                break
        
        # Zeek logs
        zeek_dir = Path(Config.ZEEK_LOG_DIR)
        if zeek_dir.exists():
            for log_name in Config.ZEEK_LOGS:
                log_path = zeek_dir / log_name
                if log_path.exists():
                    self.tailers[f"zeek:{log_name}"] = LogTailer(str(log_path), f"zeek:{log_name}")
                    print(f"[DFIR Monitor] Tailing Zeek log: {log_path}")
    
    def _process_web_logs(self):
        """Process new lines from web server logs."""
        for key, tailer in list(self.tailers.items()):
            if not key.startswith("web:"):
                continue
            
            for line in tailer.read_new_lines():
                event = EventParser.parse_web_log(line)
                if event:
                    self.writer.write(event)
    
    def _process_auth_logs(self):
        """Process new lines from auth logs."""
        for key, tailer in list(self.tailers.items()):
            if not key.startswith("auth:"):
                continue
            
            for line in tailer.read_new_lines():
                event = EventParser.parse_auth_log(line)
                if event:
                    self.writer.write(event)
    
    def _process_zeek_logs(self):
        """Process new lines from Zeek logs."""
        for key, tailer in list(self.tailers.items()):
            if not key.startswith("zeek:"):
                continue
            
            log_type = key.split(":")[1]
            for line in tailer.read_new_lines():
                event = EventParser.parse_zeek_log(line, log_type)
                if event:
                    self.writer.write(event)
    
    def _process_auditd(self):
        """Process new auditd events."""
        for audit_event in self.auditd_reader.read_new_events():
            event = EventParser.parse_auditd_event(audit_event)
            if event:
                self.writer.write(event)
    
    def run(self):
        """Main monitoring loop."""
        print("[DFIR Monitor] Starting forensic monitor...")
        print(f"[DFIR Monitor] PID: {os.getpid()}")
        print(f"[DFIR Monitor] Output: {Config.LOG_FILE}")
        print(f"[DFIR Monitor] Buffer: {Config.BUFFER_MAX_SIZE} events / {Config.BUFFER_MAX_AGE_SEC}s")
        print("[DFIR Monitor] Press Ctrl+C to stop\n")
        
        last_status_time = time.time()
        
        while self.running:
            try:
                # Process all log sources
                self._process_web_logs()
                self._process_auth_logs()
                self._process_zeek_logs()
                self._process_auditd()
                
                # Flush buffer if needed
                if self.writer.should_flush():
                    self.writer.flush()
                
                # Periodic status (every 60 seconds)
                if time.time() - last_status_time > 60:
                    print(f"[DFIR Monitor] Status: {self.writer.total_events_written} events written")
                    last_status_time = time.time()
                
                # Sleep to avoid CPU spin
                time.sleep(Config.POLL_INTERVAL_SEC)
                
            except Exception as e:
                # Log error but don't crash
                print(f"[DFIR Monitor] Error: {e}", file=sys.stderr)
                time.sleep(1)  # Brief pause on error
        
        # Graceful shutdown
        print("[DFIR Monitor] Flushing remaining buffer...")
        self.writer.force_flush()
        
        # Close all tailers
        for tailer in self.tailers.values():
            tailer.close()
        
        # Remove PID file
        try:
            os.remove(Config.PID_FILE)
        except:
            pass
        
        print(f"[DFIR Monitor] Shutdown complete. Total events: {self.writer.total_events_written}")


#===============================================================================
# ENTRY POINT
#===============================================================================

def main():
    """Entry point for the DFIR monitor."""
    
    # Ensure we're running as root (needed for auditd and some logs)
    if os.geteuid() != 0:
        print("[DFIR Monitor] Warning: Not running as root. Some logs may not be accessible.")
    
    # Create log directory if needed
    log_dir = os.path.dirname(Config.LOG_FILE)
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    # Start monitor
    monitor = DFIRMonitor()
    monitor.run()


if __name__ == "__main__":
    main()
