# Web Traffic Monitor

Production-ready web traffic monitoring for Linux web servers using Zeek.

## Features

- **HTTP**: Method, URI, Host, User-Agent (plaintext only)
- **HTTPS**: SNI, TLS version, cipher (handshake metadata)
- **DNS**: Query domain names and types
- **Filtering**: External IPs only (RFC1918/localhost excluded)
- **Output**: JSON lines for easy parsing

## Quick Start

```bash
# Install Zeek
sudo apt install zeek   # Debian/Ubuntu

# Run monitor
sudo ./web_monitor.sh -i eth0

# Logs appear in /var/log/web_monitor/web_traffic.log
```

## Usage

```
sudo ./web_monitor.sh -i <interface> [-o <output_dir>] [-d]

Options:
  -i <interface>   Network interface (required)
  -o <output_dir>  Log directory (default: /var/log/web_monitor)
  -d               Daemon mode
```

## Output Format

JSON lines, one event per line:

```json
{"ts":"2026-02-06T10:15:30.123456Z","proto":"HTTP","src_ip":"203.0.113.45","dst_port":"80/tcp","method":"POST","uri":"/api/login","host":"example.com","user_agent":"Mozilla/5.0..."}
{"ts":"2026-02-06T10:15:30.234567Z","proto":"HTTPS","src_ip":"198.51.100.22","dst_port":"443/tcp","sni":"secure.example.com","tls_version":"TLSv1.3","cipher":"TLS_AES_256_GCM_SHA384"}
{"ts":"2026-02-06T10:15:30.345678Z","proto":"DNS","src_ip":"203.0.113.45","dst_port":"53/udp","query":"api.example.com","qtype":"A"}
```

## Log Rotation

Copy to `/etc/logrotate.d/web_monitor`:

```
/var/log/web_monitor/web_traffic.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

## Limitations

| What             | Limitation                             |
| ---------------- | -------------------------------------- |
| HTTPS content    | **Encrypted** - no method/path/headers |
| User-Agent       | Only from plaintext HTTP               |
| ECH (future TLS) | Will hide SNI                          |
| Requires         | Root privileges, Zeek installed        |

## Files

| File               | Purpose                          |
| ------------------ | -------------------------------- |
| `web_monitor.sh`   | Main orchestration script        |
| `web_monitor.zeek` | Zeek policy for protocol parsing |
| `README.md`        | This file                        |

## Production Notes

1. **Test first** on a staging VM
2. **Dedicate log partition** to prevent disk fill
3. **Monitor CPU** - Zeek uses ~1-5% under moderate load
4. **Use logrotate** - configure before deployment
5. **Safe during incidents** - graceful signal handling
