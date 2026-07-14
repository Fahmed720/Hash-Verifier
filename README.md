# Log Analyser

A Python tool that parses Apache/Nginx access logs and SSH auth logs to automatically detect suspicious activity patterns. Outputs findings as a clean HTML dashboard or plain-text report.

Built as part of a cybersecurity portfolio to demonstrate knowledge of threat detection, log analysis, SIEM concepts, and the OWASP Top 10.

---

## Detection capabilities

| Finding type | Log source | Severity | What it detects |
|---|---|---|---|
| SSH Brute Force | auth.log | HIGH | N failed SSH logins from one IP within a time window |
| Web Auth Brute Force | access.log | HIGH | N HTTP 401/403 responses from one IP |
| SQL Injection | access.log | HIGH | SQLi payloads in request paths and parameters |
| XSS Attempt | access.log | HIGH | Script injection patterns in URLs |
| Path Traversal | access.log | HIGH | `../`, `/etc/passwd`, encoded traversal sequences |
| Shell Injection | access.log | HIGH | Shell command patterns in request paths |
| Security Scanner | access.log | MEDIUM | Known tool signatures: sqlmap, nikto, DirBuster, Nmap, Burp |
| Directory Scanning | access.log | MEDIUM | High volume of unique path requests from one IP |
| Traffic Spike | access.log | LOW | Requests per minute significantly above that IP's average |
| High Error Rate | access.log | LOW | IP generating large numbers of 4xx/5xx responses |

---

## Requirements

- Python 3.10 or higher (uses the walrus operator `:=`)
- No external packages required (stdlib only: `re`, `json`, `argparse`, `collections`, `datetime`)

---

## Usage

```bash
# Analyse an Apache/Nginx access log (auto-detects format)
python analyser.py /var/log/nginx/access.log

# Analyse an SSH auth log
python analyser.py /var/log/auth.log --type ssh

# Choose report format
python analyser.py access.log --format text
python analyser.py access.log --format html

# Specify output path
python analyser.py access.log --report reports/my_report.html

# Also export findings as JSON (useful for piping into other tools)
python analyser.py access.log --json findings.json

# Suppress per-finding console output (report only)
python analyser.py access.log --quiet
```

### Try it with the included sample logs

```bash
# Web log with SQLi, XSS, path traversal, and scanning activity
python analyser.py sample_logs/access.log

# SSH log with three brute-force sources
python analyser.py sample_logs/auth.log --type ssh
```

---

## Sample output

```
======================================================================
  LOG ANALYSER  —  Suspicious Activity Detector
======================================================================

[*] Loaded 63 lines from: sample_logs/access.log
[*] Log type: APACHE
[*] Parsed 60 valid events.
[*] Running detection rules...

  [HIGH]   XSS Attempt
           IP     : 203.0.113.42
           Detail : 1 request(s) with XSS Attempt payload.

  [HIGH]   Path Traversal
           IP     : 172.16.0.99
           Detail : 4 request(s) with Path Traversal payload.

  [MEDIUM] Directory Scanning
           IP     : 198.51.100.7
           Detail : 31 unique paths requested. Likely automated scanning.

  [MEDIUM] Security Scanner Detected
           IP     : 198.51.100.7
           Detail : Tool identified: dirbuster. 31 request(s) made.

[*] Analysis complete — 5 finding(s) (2 HIGH severity)
[*] HTML report saved to: reports/access_report.html
```

The HTML report renders a card-based dashboard with severity-colour-coded findings and a top-IPs table.

---

## How it works

1. **Auto-detection** — the tool samples the first 50 lines and scores them against Apache and SSH regex patterns to determine the log format without requiring the user to specify it
2. **Regex parsing** — named capture groups extract structured fields (IP, timestamp, method, path, status code, user-agent) from each log line
3. **Detection rules** — each rule is a standalone function that receives the parsed event list and returns a list of findings; this makes rules easy to add, remove, or tune independently
4. **Sliding window** — brute-force detection uses a sliding time window rather than a fixed counter, so an attacker who spreads attempts across window boundaries is still caught
5. **Deduplication** — the same (type, IP) pair is only reported once, even if multiple windows trigger
6. **Report generation** — findings are written to either a self-contained HTML file or a plain-text file; JSON export allows findings to be piped into other tools or dashboards

---

## What I learned

- How Apache/Nginx and SSH log formats are structured and how to parse them with regex named groups
- How SIEM tools (Splunk, Elastic SIEM) work at a conceptual level — this tool replicates their core loop: ingest → parse → correlate → alert
- The OWASP Top 10 attack patterns: SQLi, XSS, path traversal, broken authentication
- How brute-force detection uses time-windowed thresholds rather than raw counts
- Why log analysis is a core skill for SOC analyst, security engineer, and blue-team roles

---

## Tuning the thresholds

Edit the `THRESHOLDS` dict at the top of `analyser.py`:

```python
THRESHOLDS = {
    "brute_force_ssh":        5,    # failed SSH logins from one IP within window
    "brute_force_web":       20,    # HTTP 401/403 from one IP
    "high_error_rate":       50,    # total 4xx/5xx from one IP
    "scan_unique_paths":     30,    # unique URLs from one IP
    "traffic_spike_factor":   3.0,  # requests > mean × factor triggers alert
    "time_window_minutes":    5,    # rolling window for brute-force checks
}
```

Lower values = more sensitive (more false positives). Higher values = less noise (more false negatives). This trade-off is the same one SOC teams tune in real SIEM deployments.

---

## Real-world log sources

| OS / Service | Log location |
|---|---|
| Apache | `/var/log/apache2/access.log` |
| Nginx | `/var/log/nginx/access.log` |
| SSH (Debian/Ubuntu) | `/var/log/auth.log` |
| SSH (RHEL/CentOS) | `/var/log/secure` |

---

## Limitations and possible extensions

- Parses one file at a time; could be extended to tail a live log with `watchdog`
- No IP geolocation (could add with `ip-api.com` or MaxMind GeoLite2)
- No allowlisting for known internal IPs
- Could export to STIX/TAXII format for threat intelligence sharing
- Could add email or Slack alerting for HIGH severity findings

---

## Project structure

```
log-analyser/
├── analyser.py           — main script
├── README.md             — this file
├── sample_logs/
│   ├── access.log        — sample Apache log with attack traffic
│   └── auth.log          — sample SSH log with brute-force attempts
└── reports/              — auto-created; stores generated reports
```
