# Role Definition

You are a Staff Security Engineer, Digital Forensics & Incident Response (DFIR) Specialist, and Senior Linux Systems Architect. You have 20+ years of experience in building "Set-and-Forget" production monitoring systems for high-value targets (HVT).

# Mission Objective

The user (a production server admin) requires a **Forensic-Grade "Black Box" Recorder** for their Linux Cloud VPS. This server runs a high-traffic web application (200,000+ hits/day) and is under active adversarial attack. Your goal is to design and implement a single-deployment solution that captures **100% of security-relevant events** without crashing the server or starving the web application.

# Acceptance Criteria (The "Definition of Done")

The solution will be considered complete ONLY when it produces **Admissible Forensic Evidence**—logs detailed enough to reconstruct an attack timeline for legal prosecution ("Jail Evidence").

# Detailed Technical Specifications

## 1. Core Architecture

- **Single Entrypoint**: The entire system must be deployable via one shell script (`deploy_monitor.sh`).
- **Zero-Touch Maintenance**: The system must run as a background daemon, handle its own log rotation, and require no manual intervention.
- **Safety First**:
  - Must use `nice -n 10` (or stricter) to ensure it runs at Low CPU Priority.
  - Must NEVER block web traffic.
  - Must NEVER write to the web application's database or files.
- **Unified Output**: All data sources must be aggregated into a single JSON-Lines file: `/var/log/dfir_monitor.json`.

## 2. Evidence Collection (Forensic Data Sources)

### A. The "Wire" (Network Sensor) - Tool: **Zeek (Bro)**

You must configure Zeek to sit on the public interface and capture wire-data.
**Must Capture:**

1.  **Connections (`conn.log`)**:
    - Source IP, Source Port, Destination IP, Destination Port.
    - Protocol (TCP/UDP/ICMP).
    - Duration of connection.
    - Byte counts (confirm exfiltration size).
    - Connection State (e.g., S0, SF, REJ - vital for detecting scans vs successful connects).
2.  **DNS Traffic (`dns.log`)**:
    - **CRITICAL**: Capture every DNS query to detect malware "phoning home" (C2 callbacks).
    - Query Name (e.g., `evil-c2.com`), Record Type (A, AAAA, TXT), Response Code (NXDOMAIN, NOERROR).
3.  **Encrypted Metadata (`ssl.log`)**:
    - SNI (Server Name Indication) - proving they visited `bank.com` even if encrypted.
    - TLS Version (detect dowgrade attacks).
    - Cipher Suite.
    - JA3 Fingerprints (if available/possible via script).
4.  **Anomalies (`weird.log`)**:
    - Detect protocol violations, fragmented packets, and evasion attempts.

### B. The "Kernel" (Host Sensor) - Tool: **Auditd**

You must configure the Linux Audit Framework (`auditd`) with aggressive rules.
**Must Capture:**

1.  **Process Execution (`execve` Syscall)**:
    - **REQUIREMENT**: Log EVERY command executed by ANY user (root, www-data, ubuntu).
    - **Context**: Must capture the full command line arguments (e.g., `wget http://malware.sh`).
    - **Attribution**: Map the `auid` (Audit User ID) to the real user, even if they `sudo su`.
2.  **Network Socket Creation (`connect`, `accept`)**:
    - Detect when a process (e.g., python script) opens a reverse shell connection outbound.
3.  **File Integrity**:
    - (Optional but recommended) Watch `/etc/passwd`, `/etc/shadow`, `/etc/ssh/sshd_config` for writes.

### C. The "Application" (Decrypted Visibility) - Tool: **Log Tailer**

Since network traffic is encrypted (HTTPS), Zeek cannot see the URI path. You must ingest Application Logs.
**Must Capture:**

1.  **Auto-Detection**: The script MUST automatically find standard logs:
    - `/var/log/nginx/access.log`
    - `/var/log/apache2/access.log`
    - `/var/log/httpd/access_log`
2.  **Decrypted Context**:
    - Full Request URI (e.g., `/admin/login.php?id=1' OR 1=1`).
    - User-Agent String (detect SQLMap, Nikto, BurpSuite).
    - HTTP Status Codes (200 vs 403 vs 500).
    - Referrer Headers.

### D. The "Identity" (Auth Sensor) - Tool: **Syslog/Auth.log**

**Must Capture:**

1.  **SSH Activity**:
    - Successful Logins (Accepted publickey/password).
    - Failed Logins (Brute force attempts).
    - Invalid User attempts.
2.  **Privilege Escalation**:
    - `sudo` command usage.
    - `su` switching.

## 3. Data Schema (Unified JSON)

The Python Aggregator must normalize all above sources into this rigid schema:

```json
{
  "timestamp": "06-02-2026 9:15 am", // Indian Standard Time (DD-MM-YYYY H:MM am/pm)
  "event_type": "ENUM", // web_http, ssh_login, process_exec, dns_query...
  "src_ip": "IP_ADDRESS", // Unified field for filtering
  "details": {
    // Flexible dict based on event type
    "method": "...",
    "uri": "...",
    "command_line": "...",
    "raw_log": "..." // Always preserve the original log line for integrity
  }
}
```

## 4. Performance Engineering (Pro Scale)

### The "200,000 Logs" Problem

A naive python script doing `open().write()` for every line will thrash the disk IOPS and choke the CPU.
**Mandatory Optimization:**

- **Buffered/Batched Writing**: The aggregator MUST buffer events in memory.
- **Flush Condition**: Write to disk ONLY when:
  - Buffer size > 500 records OR
  - Time since last flush > 1.0 seconds.
- **Graceful Shutdown**: Must flush remaining buffer on SIGTERM/Kevin.

## 5. Log Rotation & Archival Strategy (The "Time Machine")

### Requirement

"If an incident happened 3 days ago, I want to type `zgrep anomaly date-file.gz` and see it."

### Implementation Details

1.  **Daily Rotation**: Logs must rotate at 00:00 system time.
2.  **Naming Convention**: Archive files MUST look like `dfir_monitor.json-2025-02-06.gz`.
3.  **Retention**: Keep 7-14 days of logs (configurable).
4.  **Compression**: Use `gzip` (level 9/best) to save disk space.
5.  **Tools**: Use `logrotate`. You must generate the config file `/etc/logrotate.d/dfir_monitor` dynamically in the deploy script.

# Deliverable Code Structure

## File 1: `deploy_monitor.sh`

- **Validation**: Check if run as root. Exit if not.
- **OS Detection**: Handle apt (Debian/Ubuntu) vs yum (RHEL/CentOS).
- **Dependency Install**: `zeek`, `auditd`, `python3`.
- **Configuration**:
  - Add Auditd rules: `-a always,exit -F arch=b64 -S execve -k process_monitor`.
  - Configure Zeek: `redef LogAscii::use_json = T;`.
- **Logrotate Setup**: Write the `/etc/logrotate.d/` config.
- **Execution**:
  - Kill existing monitor instances.
  - Start `monitor_core.py` using `nohup nice -n 10 ... &`.
  - Print success message with PID.

## File 2: `monitor_core.py`

- **Class `LogTailer`**: Robust implementation using `seek(0, 2)` and inode tracking to handle external log rotation (when Nginx rotates its own logs).
- **Function `normalize_event()`**: The massive switch-statement logic to parse pure JSON (Zeek), Regex (Auth/Web), and key-value pairs (Auditd).
- **Main Loop**:
  - Polls all files.
  - Parses lines.
  - Buffers JSON objects.
  - Writes to `/var/log/dfir_monitor.json`.

# Final Instruction to the AI

"Proceed to generate the full, production-ready code for `deploy_monitor.sh` and `monitor_core.py`. Ensure every single requirement above (Buffered IO, Auditd Rules, Unified JSON) is implemented strictly. Do not omit any features."
