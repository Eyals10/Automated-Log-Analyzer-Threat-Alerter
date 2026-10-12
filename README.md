# Automated Log Analyzer & Threat Alerter

A Python tool that ingests Linux authentication logs (`/var/log/auth.log`, `/var/log/secure`), detects SSH brute-force attacks, raises real-time alerts for offending IP addresses, enriches them with GeoIP data, and exports machine-readable reports ready for a SIEM such as Splunk.

No third-party dependencies: it runs on any machine with Python 3.8+.

```
$ python3 ssh_bruteforce_detector.py sample_logs/sample_auth.log

Scanning sample_logs/sample_auth.log for SSH brute-force activity...
[ALERT] 2026-10-11 02:13:16  203.0.113.45  5 failed logins (threshold 5)  | Country: Private/Reserved
[ALERT] 2026-10-11 05:02:27  198.51.100.77  5 failed logins (threshold 5)  | Country: Private/Reserved
[ALERT] 2026-10-11 05:06:02  192.0.2.10  5 failed logins (threshold 5)  | Country: Private/Reserved
[ALERT] 2026-10-11 14:41:15  198.51.100.9  5 failed logins (threshold 5)  | Country: Private/Reserved
[CRITICAL] 2026-10-11 14:42:49  198.51.100.9  logged in as 'root' (password) after 25 failed attempts - possible compromise!
[ALERT] 2026-10-11 18:05:43  2001:db8::bad:1  5 failed logins (threshold 5)  | Country: Private/Reserved

==============================================================================
 SSH BRUTE-FORCE SUMMARY
==============================================================================
 Lines scanned ............ 1,052
 sshd auth events ......... 451
 Failed logins ............ 501 from 7 source IPs
 Flagged IPs .............. 5  (threshold 5, window: whole log)
 Possible compromises ..... 1

 SEVERITY  SOURCE           FAILS  COUNTRY          TOP USERNAMES
 ----------------------------------------------------------------------------
 CRITICAL  198.51.100.9        25  Private/Reserved root(25)
 HIGH      203.0.113.45       360  Private/Reserved root(360)
 HIGH      198.51.100.77       91  Private/Reserved postgres(15), hadoop(12), minecraft(10)
 MEDIUM    2001:db8::bad:1     12  Private/Reserved ubuntu(12)
 MEDIUM    192.0.2.10           8  Private/Reserved root(8)

Reports written:
  reports/ssh_bruteforce_20261012-125338.csv
  reports/ssh_bruteforce_20261012-125338.json
```

> The bundled sample log uses reserved documentation IP ranges (RFC 5737 / RFC 3849), so GeoIP correctly reports them as *Private/Reserved*. Run it on a real `auth.log` to see countries and network owners.

## Features

- **Regex-based parsing** of every sshd line into a structured event: timestamp, event type, source IP, username.
- **Threshold alerting**: an `ALERT` fires the moment an IP reaches `FAILED_LOGIN_THRESHOLD` failed logins (default 5), once per IP.
- **Sliding time window** (`--window`): optionally flag only IPs that reach the threshold within *N* minutes, separating fast automated attacks from occasional typos.
- **Compromise detection**: if a flagged IP later logs in successfully, a `CRITICAL` alert fires, because the brute force may have worked.
- **Severity scoring**: `CRITICAL` (login after brute force), `HIGH` (10× the threshold or more), `MEDIUM` (everything else flagged).
- **GeoIP enrichment** of flagged IPs via the ipinfo.io API or an offline `.mmdb` database, with caching. If the network is down or rate-limited, it warns once and keeps scanning.
- **Exports** to CSV, JSON and (optionally) JSON Lines for direct SIEM ingestion.
- **Robust input handling**: rotated `.gz` logs, multiple files, stdin (`journalctl` output), classic syslog *and* ISO-8601 timestamps, IPv4 and IPv6 (including `::ffff:` mapped addresses), New Year rollover in year-less syslog timestamps, rsyslog's `message repeated N times` compression, and OpenSSH 9.8+ `sshd-session` process names.
- **No false positives from other services**: only sshd lines are counted, so FTP/IMAP "Failed password" messages are ignored.

## Quick start

```bash
git clone https://github.com/Eyals10/Automated-Log-Analyzer-Threat-Alerter.git
cd Automated-Log-Analyzer-Threat-Alerter

# Try it on the bundled sample
python3 ssh_bruteforce_detector.py sample_logs/sample_auth.log

# Run it on your own server (auth logs are readable by root and the 'adm' group)
sudo python3 ssh_bruteforce_detector.py /var/log/auth.log

# systemd-only systems without auth.log (the unit is "sshd" on RHEL/Fedora)
sudo journalctl -u ssh --no-pager | python3 ssh_bruteforce_detector.py -
```

## Usage

```
python3 ssh_bruteforce_detector.py LOGFILE [LOGFILE ...] [options]
```

| Option | Default | Description |
|---|---|---|
| `-t`, `--threshold N` | `5` | Failed logins before an IP is flagged |
| `-w`, `--window MINUTES` | off | Only flag IPs that hit the threshold within this many minutes |
| `-o`, `--output-dir DIR` | `reports` | Where reports are written |
| `--jsonl` | off | Also write a JSON Lines report (one event per line) |
| `--geoip {ipinfo,local,off}` | `ipinfo` | GeoIP source for flagged IPs |
| `--geoip-db PATH` | | Offline `.mmdb` database; implies `--geoip local` |
| `--ipinfo-token TOKEN` | `$IPINFO_TOKEN` | Enables the ipinfo Lite API (see below) |
| `--year YYYY` | auto | Year for syslog timestamps, which don't include one |
| `--top N` | `15` | Rows shown in the terminal table |
| `--no-color` | | Disable coloured output (also respects `NO_COLOR`) |

Examples:

```bash
# Stricter: 10 failures within 5 minutes
python3 ssh_bruteforce_detector.py /var/log/auth.log -t 10 -w 5

# A week of rotated logs, oldest first, with a Splunk-friendly export
python3 ssh_bruteforce_detector.py /var/log/auth.log.{4,3,2}.gz /var/log/auth.log.1 /var/log/auth.log --jsonl
```

## How it works

```
 auth.log ──► 1. PARSE ──► 2. DETECT ──► 3. ENRICH ──► 4. REPORT
              regex        dict of        GeoIP for      terminal table
              per line     IP → stats     flagged IPs    CSV / JSON / JSONL
```

**1. Parse.** Each line is matched against a regex for the syslog envelope (timestamp, host, `sshd[pid]`), then against message patterns:

| Event | Example log message |
|---|---|
| `FAILED_LOGIN` | `Failed password for root from 203.0.113.45 port 56131 ssh2` |
| `INVALID_USER` | `Invalid user oracle from 198.51.100.77 port 40022` |
| `ACCEPTED_LOGIN` | `Accepted password for root from 198.51.100.9 port 44122 ssh2` |

`message repeated 5 times: [ Failed password ... ]` lines are unwrapped and counted as 5 attempts. Ignoring them is a common bug that undercounts real attacks.

**2. Detect.** A dictionary maps each source IP to its stats. Every failed login increments that IP's counter; when it reaches the threshold, an alert is printed immediately. In window mode, each IP keeps a bounded queue of its last *N* failure timestamps and is flagged when the oldest and newest are within the window. Invalid-username probes are tracked separately so they are not double-counted against the `Failed password for invalid user …` line that follows them.

**3. Enrich.** Flagged public IPs are geolocated once and cached. Private and reserved ranges are never sent to an external API.

**4. Report.** Results are sorted by severity, then by number of failures.

## GeoIP options

| Source | Setup | Limits | Returns |
|---|---|---|---|
| ipinfo.io, no token (default) | nothing | about 1,000 requests/day | country code, ASN, organisation |
| ipinfo.io Lite | free token from ipinfo.io, then `export IPINFO_TOKEN=...` | unlimited | country name and code, ASN, organisation |
| Offline database | `pip install maxminddb`, then `--geoip-db GeoLite2-Country.mmdb` (MaxMind) or an IPinfo Lite `.mmdb` | none, works air-gapped | country (plus ASN with the IPinfo database) |

## Output formats

Reports are timestamped so scheduled runs never overwrite each other. Samples generated from the bundled log are in [`examples/`](examples/).

- **CSV**: one row per flagged IP. Columns: `severity, ip, failed_attempts, invalid_user_attempts, unique_usernames, top_usernames, first_seen, last_seen, flagged_at, successful_logins_after_flag, country, country_code, asn, org`.
- **JSON**: a `report` metadata block (threshold, window, totals, source files, generation time) plus a `flagged_ips` array with the full per-username breakdown and details of any successful logins.
- **JSON Lines** (`--jsonl`): one self-contained event per line, the format log pipelines ingest most easily. In Splunk, point a file monitor input at the `reports/` directory with `sourcetype=_json`; Elastic Filebeat's `ndjson` parser reads it the same way.

All timestamps are ISO 8601.

## Testing

```bash
python3 -m unittest discover -s tests -v
```

The 18 tests (passing on Python 3.8 through 3.13) cover parsing of every supported line format, exact detection counts, window mode, severity scoring, GeoIP behaviour (mocked: caching, private ranges, offline fallback) and all three export formats.

The sample log is synthetic but realistic, built by [`sample_logs/generate_sample_log.py`](sample_logs/generate_sample_log.py). It includes:

- a 360-attempt root brute force with rsyslog compression
- a username-dictionary attack
- a low-and-slow attacker (8 attempts over 8 hours)
- an IPv6 attacker
- a brute force that ends in a successful login
- a legitimate admin who mistypes their password twice
- decoy "Failed password" lines from FTP and IMAP services

The generator writes the exact expected count per IP to `expected_failed_logins.json`, and the tests check the detector against it.

For real-world data, the `OpenSSH` folder of the [Loghub](https://github.com/logpai/loghub) dataset collection contains logs captured from an internet-facing server.

## Project structure

```
├── ssh_bruteforce_detector.py      # the tool (single file, standard library only)
├── sample_logs/
│   ├── sample_auth.log             # realistic test log
│   ├── expected_failed_logins.json # ground truth for the tests
│   └── generate_sample_log.py      # regenerates both files
├── examples/                       # sample CSV / JSON / JSONL reports
└── tests/
    └── test_detector.py
```

## Roadmap

- Live monitoring mode (`tail -f` style) for continuous alerting
- Parsers for web server access logs (Nginx/Apache 401/403 floods, path scanning)
- Alert delivery to Slack, email or a webhook
- Automatic blocking via `iptables`/`nftables`, or fail2ban integration
