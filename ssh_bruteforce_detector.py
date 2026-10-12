#!/usr/bin/env python3
"""
ssh_bruteforce_detector.py
==========================

Detects SSH brute-force activity in Linux authentication logs.

    parse  ->  detect  ->  enrich (GeoIP)  ->  report (terminal, CSV, JSON)

1. Parse   Read the log line by line and use regular expressions to extract the
           timestamp, event type and source IP of every sshd authentication event.
2. Detect  Keep a dictionary of source IP -> stats, increment a counter on every
           failed login, and raise an ALERT the moment an IP reaches the threshold
           (optionally within a sliding time window). If a flagged IP later logs
           in successfully, raise a CRITICAL alert: the attack may have worked.
3. Enrich  Look up the country / network owner of each flagged IP, via the
           ipinfo.io API or an offline .mmdb database (MaxMind GeoLite2 or
           IPinfo Lite), with caching and graceful fallback when offline.
4. Report  Print a summary table and export the flagged IPs to CSV and JSON
           (plus optional JSON Lines, the easiest format for Splunk / ELK).

Handles Debian/Ubuntu /var/log/auth.log, RHEL /var/log/secure, rotated .gz files,
journalctl output, classic syslog and ISO-8601 timestamps, IPv4 and IPv6, rsyslog
"message repeated N times" compression, and OpenSSH 9.8+ `sshd-session` lines.

Standard library only. Optional:  pip install maxminddb   (offline GeoIP)

Examples
--------
    python3 ssh_bruteforce_detector.py /var/log/auth.log
    python3 ssh_bruteforce_detector.py auth.log --threshold 10 --window 5
    python3 ssh_bruteforce_detector.py auth.log.2.gz auth.log.1 auth.log --jsonl
    python3 ssh_bruteforce_detector.py auth.log --geoip-db GeoLite2-Country.mmdb
    sudo journalctl -u ssh --no-pager | python3 ssh_bruteforce_detector.py -
"""

from __future__ import annotations

import argparse
import csv
import gzip
import ipaddress
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator, NamedTuple, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
FAILED_LOGIN_THRESHOLD = 5        # failed attempts before an IP is flagged
HIGH_SEVERITY_MULTIPLIER = 10     # failures >= threshold x this  ->  HIGH severity
GEOIP_TIMEOUT_SECONDS = 5
DEFAULT_OUTPUT_DIR = "reports"

# ---------------------------------------------------------------------------
# Regular expressions
# ---------------------------------------------------------------------------
# One sshd line:   <timestamp> <host> sshd[pid]: <message>
LOG_LINE_RE = re.compile(
    r"^(?P<timestamp>"
    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?"  # 2026-10-11T02:14:29.123+03:00
    r"|[A-Z][a-z]{2} +\d{1,2} \d{2}:\d{2}:\d{2}"                           # Oct 11 02:14:29
    r")\s+(?P<host>\S+)\s+"
    r"(?P<process>sshd(?:-session|-auth)?)(?:\[\d+\])?:\s+"                 # sshd[123] / sshd-session[123]
    r"(?P<message>.*)$"
)

# "Failed password for root from 203.0.113.45 port 56131 ssh2"
# "Failed password for invalid user admin from 198.51.100.77 port 40022 ssh2"
FAILED_LOGIN_RE = re.compile(
    r"^Failed (?P<method>password|keyboard-interactive/pam) for "
    r"(?:invalid user )?(?P<user>.*?) from (?P<ip>\S+) port \d+"
)

# "Invalid user oracle from 198.51.100.77 port 40022"   (username probing)
INVALID_USER_RE = re.compile(r"^Invalid user (?P<user>.*?) from (?P<ip>\S+)(?: port \d+)?\s*$")

# "Accepted password for root from 198.51.100.9 port 44122 ssh2"
ACCEPTED_LOGIN_RE = re.compile(r"^Accepted (?P<method>\S+) for (?P<user>.*?) from (?P<ip>\S+) port \d+")

# rsyslog collapses identical lines: "message repeated 5 times: [ Failed password for ...]"
REPEATED_RE = re.compile(r"^message repeated (?P<count>\d+) times: \[\s*(?P<inner>.*?)\]\s*$")

FRACTION_RE = re.compile(r"\.(\d+)")                    # fractional seconds in ISO timestamps

FAILED_LOGIN, INVALID_USER, ACCEPTED_LOGIN = "FAILED_LOGIN", "INVALID_USER", "ACCEPTED_LOGIN"
EVENT_PATTERNS = (
    (FAILED_LOGIN, FAILED_LOGIN_RE),
    (INVALID_USER, INVALID_USER_RE),
    (ACCEPTED_LOGIN, ACCEPTED_LOGIN_RE),
)


# ---------------------------------------------------------------------------
# 1. Parsing
# ---------------------------------------------------------------------------
class AuthEvent(NamedTuple):
    timestamp: datetime
    event_type: str        # FAILED_LOGIN | INVALID_USER | ACCEPTED_LOGIN
    ip: str
    user: str
    method: str = ""       # password, publickey, ...
    count: int = 1         # > 1 when rsyslog collapsed repeated lines


class TimestampParser:
    """Converts log timestamps to datetimes.

    Classic syslog timestamps ("Oct 11 02:14:29") have no year, so we assume the
    current year, step back a year if that would put the log in the future, and
    roll forward when the log crosses New Year (Dec -> Jan). ISO-8601 timestamps
    are kept as local wall-clock time so both formats compare consistently.
    """

    def __init__(self, year: Optional[int] = None):
        self.year = year
        self._last_month: Optional[int] = None

    def parse(self, raw: str) -> datetime:
        if raw[0].isdigit():
            # Pad/trim fractional seconds to 6 digits: Python < 3.11 accepts no other length.
            iso_text = FRACTION_RE.sub(lambda m: "." + (m[1] + "000000")[:6], raw.replace("Z", "+00:00"))
            return datetime.fromisoformat(iso_text).replace(tzinfo=None)

        stamp = " ".join(raw.split())                       # "Oct  1" -> "Oct 1"
        if self.year is None:
            now = datetime.now()
            self.year = now.year
            if self._with_year(stamp) > now + timedelta(days=1):
                self.year -= 1
        parsed = self._with_year(stamp)
        if self._last_month == 12 and parsed.month == 1:
            self.year += 1
            parsed = parsed.replace(year=self.year)
        self._last_month = parsed.month
        return parsed

    def _with_year(self, stamp: str) -> datetime:
        return datetime.strptime(f"{self.year} {stamp}", "%Y %b %d %H:%M:%S")


def normalize_source(raw: str) -> str:
    """Canonicalise an address ('::ffff:1.2.3.4' -> '1.2.3.4'). Hostnames pass through
    unchanged (sshd logs hostnames instead of IPs when UseDNS=yes)."""
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return raw
    if addr.version == 6 and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


def parse_line(line: str, clock: TimestampParser) -> Optional[AuthEvent]:
    """Extract timestamp, event type and source IP from one log line (None if irrelevant)."""
    line_match = LOG_LINE_RE.match(line.rstrip("\n"))
    if not line_match:
        return None                                    # not an sshd line

    message, count = line_match["message"], 1
    repeated = REPEATED_RE.match(message)
    if repeated:
        message, count = repeated["inner"], int(repeated["count"])

    for event_type, pattern in EVENT_PATTERNS:
        match = pattern.match(message)
        if match:
            try:
                timestamp = clock.parse(line_match["timestamp"])
            except ValueError:
                return None                            # e.g. Feb 29 in a non-leap year
            return AuthEvent(
                timestamp=timestamp,
                event_type=event_type,
                ip=normalize_source(match["ip"]),
                user=match["user"],
                method=match.groupdict().get("method") or "",
                count=count,
            )
    return None


def read_lines(path: str) -> Iterator[str]:
    """Yield lines from a plain or gzip-compressed log file, or from stdin ('-')."""
    if path == "-":
        yield from sys.stdin
        return
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as handle:
        yield from handle


# ---------------------------------------------------------------------------
# 2. Detection
# ---------------------------------------------------------------------------
@dataclass
class SourceStats:
    ip: str
    failed_attempts: int = 0
    invalid_user_attempts: int = 0
    usernames: Counter = field(default_factory=Counter)          # user -> failed attempts
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    flagged_at: Optional[datetime] = None
    logins_after_flag: list = field(default_factory=list)       # successful logins once flagged
    recent_failures: deque = field(default_factory=deque)       # sliding-window timestamps
    geo: dict = field(default_factory=dict)

    @property
    def flagged(self) -> bool:
        return self.flagged_at is not None

    def severity(self, threshold: int) -> str:
        if self.logins_after_flag:
            return "CRITICAL"
        if self.failed_attempts >= threshold * HIGH_SEVERITY_MULTIPLIER:
            return "HIGH"
        return "MEDIUM"


class BruteForceDetector:
    def __init__(self, threshold: int, window: Optional[timedelta], geo: "GeoLocator", console: "Console"):
        self.threshold = threshold
        self.window = window
        self.geo = geo
        self.console = console
        self.sources: dict[str, SourceStats] = {}               # the IP -> counter dictionary
        self.lines_scanned = 0
        self.events_parsed = 0

    def process(self, event: AuthEvent) -> None:
        self.events_parsed += 1
        if event.event_type == ACCEPTED_LOGIN:
            self._check_successful_login(event)
            return

        stats = self.sources.get(event.ip)
        if stats is None:
            stats = self.sources[event.ip] = SourceStats(event.ip, recent_failures=deque(maxlen=self.threshold))
        stats.first_seen = stats.first_seen or event.timestamp
        stats.last_seen = event.timestamp

        if event.event_type == INVALID_USER:
            stats.invalid_user_attempts += event.count
            return

        stats.failed_attempts += event.count                   # <- the core counter
        stats.usernames[event.user] += event.count
        if not stats.flagged and self._reached_threshold(stats, event):
            stats.flagged_at = event.timestamp
            self._raise_alert(stats)

    def _reached_threshold(self, stats: SourceStats, event: AuthEvent) -> bool:
        if self.window is None:
            return stats.failed_attempts >= self.threshold
        # Sliding window: keep the last `threshold` failure times; flag when the
        # oldest and newest of them are no further apart than the window.
        recent = stats.recent_failures
        recent.extend([event.timestamp] * min(event.count, self.threshold))
        return len(recent) == self.threshold and recent[-1] - recent[0] <= self.window

    def _raise_alert(self, stats: SourceStats) -> None:
        stats.geo = self.geo.lookup(stats.ip)
        if self.window is None:
            what = f"{stats.failed_attempts} failed logins (threshold {self.threshold})"
        else:
            what = f"{self.threshold} failed logins within {format_minutes(self.window)}"
        self.console.alert(
            "ALERT",
            f"{stats.flagged_at:%Y-%m-%d %H:%M:%S}  {stats.ip}  {what}  | {geo_label(stats.geo)}",
        )

    def _check_successful_login(self, event: AuthEvent) -> None:
        stats = self.sources.get(event.ip)
        if stats is None or not stats.flagged:
            return                                             # ordinary login, not interesting
        stats.logins_after_flag.append(
            {"timestamp": iso(event.timestamp), "user": event.user, "method": event.method}
        )
        self.console.alert(
            "CRITICAL",
            f"{event.timestamp:%Y-%m-%d %H:%M:%S}  {event.ip}  logged in as '{event.user}' "
            f"({event.method}) after {stats.failed_attempts} failed attempts - possible compromise!",
        )

    def flagged(self) -> list[SourceStats]:
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
        hits = [s for s in self.sources.values() if s.flagged]
        return sorted(hits, key=lambda s: (rank[s.severity(self.threshold)], -s.failed_attempts))


# ---------------------------------------------------------------------------
# 3. GeoIP enrichment
# ---------------------------------------------------------------------------
class GeoLocator:
    """Country / network lookup with caching. Never crashes the scan: if the API is
    unreachable or rate-limited, lookups are switched off for the rest of the run."""

    def __init__(self, provider: str, token: Optional[str], db_path: Optional[str], console: "Console"):
        self.provider = provider              # "ipinfo" | "local" | "off"
        self.token = token
        self.console = console
        self.cache: dict[str, dict] = {}
        self.disabled = provider == "off"
        self.reader = None
        if provider == "local":
            try:
                import maxminddb
            except ImportError:
                raise SystemExit("Offline GeoIP needs the maxminddb package:  pip install maxminddb")
            self.reader = maxminddb.open_database(db_path)

    def lookup(self, ip: str) -> dict:
        if ip not in self.cache:
            self.cache[ip] = self._resolve(ip)
        return self.cache[ip]

    def _resolve(self, ip: str) -> dict:
        result = {"country": "", "country_code": "", "asn": "", "org": ""}
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return {**result, "country": "Hostname (not resolved)"}
        if not addr.is_global:
            return {**result, "country": "Private/Reserved"}
        if self.disabled:
            return result
        try:
            found = self._from_mmdb(ip) if self.provider == "local" else self._from_ipinfo(ip)
            return {**result, **{k: v for k, v in found.items() if v}}
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403, 429):                    # bad token / rate limited
                self._disable(f"ipinfo.io returned HTTP {exc.code}")
            return result
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            self._disable(f"lookup failed ({getattr(exc, 'reason', exc)})")
            return result

    def _disable(self, reason: str) -> None:
        self.disabled = True
        self.console.warn(f"GeoIP turned off for the rest of this run: {reason}")

    def _from_ipinfo(self, ip: str) -> dict:
        if self.token:   # IPinfo Lite: free, unlimited, token required; country names + ASN
            url = f"https://api.ipinfo.io/lite/{urllib.parse.quote(ip)}?token={urllib.parse.quote(self.token)}"
        else:            # legacy free endpoint: no token, ~1,000 requests/day, ISO country code
            url = f"https://ipinfo.io/{urllib.parse.quote(ip)}/json"
        request = urllib.request.Request(url, headers={"Accept": "application/json",
                                                       "User-Agent": "ssh-bruteforce-detector/1.0"})
        with urllib.request.urlopen(request, timeout=GEOIP_TIMEOUT_SECONDS) as response:
            data = json.load(response)

        if self.token:
            return {"country": data.get("country"), "country_code": data.get("country_code"),
                    "asn": data.get("asn"), "org": data.get("as_name")}
        asn, _, owner = (data.get("org") or "").partition(" ")   # "AS4134 CHINANET-BACKBONE"
        return {"country": data.get("country"), "country_code": data.get("country"),
                "asn": asn if asn.startswith("AS") else "", "org": owner if asn.startswith("AS") else asn}

    def _from_mmdb(self, ip: str) -> dict:
        record = self.reader.get(ip) or {}
        country = record.get("country") or record.get("registered_country") or {}
        if isinstance(country, dict):                          # MaxMind GeoLite2 layout
            return {"country": country.get("names", {}).get("en"), "country_code": country.get("iso_code")}
        return {"country": record.get("country"),              # IPinfo Lite .mmdb layout (flat)
                "country_code": record.get("country_code"),
                "asn": record.get("asn"), "org": record.get("as_name")}


def geo_label(geo: dict) -> str:
    if not geo.get("country"):
        return "Country: unknown"
    label = geo["country"]
    if geo.get("country_code") and geo["country_code"] != geo["country"]:
        label += f" ({geo['country_code']})"
    if geo.get("org"):
        label += f" - {' '.join(filter(None, [geo.get('asn'), geo['org']]))}"
    return f"Country: {label}"


# ---------------------------------------------------------------------------
# 4. Reporting
# ---------------------------------------------------------------------------
class Console:
    STYLES = {"ALERT": "1;31", "CRITICAL": "1;97;41", "HIGH": "1;31", "MEDIUM": "33",
              "WARN": "33", "OK": "32", "BOLD": "1", "DIM": "2"}

    def __init__(self, color: bool):
        self.color = color

    def paint(self, text: str, style: str) -> str:
        return f"\033[{self.STYLES[style]}m{text}\033[0m" if self.color else text

    def alert(self, level: str, message: str) -> None:
        try:
            print(f"{self.paint(f'[{level}]', level)} {message}", flush=True)
        except BrokenPipeError:          # reader went away (e.g. `| head`): keep scanning
            silence_stdout()

    def warn(self, message: str) -> None:
        print(self.paint(f"[WARN] {message}", "WARN"), file=sys.stderr, flush=True)


def silence_stdout() -> None:
    """Point stdout at /dev/null so the scan can finish and still write its reports."""
    os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())


def iso(value: Optional[datetime]) -> str:
    return value.isoformat(timespec="seconds") if value else ""


def format_minutes(window: timedelta) -> str:
    return f"{window.total_seconds() / 60:g} min"


def top_users(stats: SourceStats, n: int = 3) -> str:
    return ", ".join(f"{user or '(empty)'}({count})" for user, count in stats.usernames.most_common(n))


CSV_FIELDS = [
    "severity", "ip", "failed_attempts", "invalid_user_attempts", "unique_usernames",
    "top_usernames", "first_seen", "last_seen", "flagged_at", "successful_logins_after_flag",
    "country", "country_code", "asn", "org",
]


def report_rows(detector: BruteForceDetector) -> list[dict]:
    rows = []
    for s in detector.flagged():
        rows.append({
            "severity": s.severity(detector.threshold),
            "ip": s.ip,
            "failed_attempts": s.failed_attempts,
            "invalid_user_attempts": s.invalid_user_attempts,
            "unique_usernames": len(s.usernames),
            "top_usernames": top_users(s, 5),
            "first_seen": iso(s.first_seen),
            "last_seen": iso(s.last_seen),
            "flagged_at": iso(s.flagged_at),
            "successful_logins_after_flag": len(s.logins_after_flag),
            "country": s.geo.get("country", ""),
            "country_code": s.geo.get("country_code", ""),
            "asn": s.geo.get("asn", ""),
            "org": s.geo.get("org", ""),
        })
    return rows


def print_summary(detector: BruteForceDetector, rows: list[dict], console: Console, top: int) -> None:
    total_failed = sum(s.failed_attempts for s in detector.sources.values())
    attackers = sum(1 for s in detector.sources.values() if s.failed_attempts)
    critical = sum(1 for r in rows if r["severity"] == "CRITICAL")
    window = format_minutes(detector.window) if detector.window else "whole log"
    rule = "=" * 78

    print(f"\n{rule}\n{console.paint(' SSH BRUTE-FORCE SUMMARY', 'BOLD')}\n{rule}")
    print(f" Lines scanned ............ {detector.lines_scanned:,}")
    print(f" sshd auth events ......... {detector.events_parsed:,}")
    print(f" Failed logins ............ {total_failed:,} from {attackers:,} source IPs")
    print(f" Flagged IPs .............. {len(rows):,}  (threshold {detector.threshold}, window: {window})")
    if critical:
        print(console.paint(f" Possible compromises ..... {critical}", "ALERT"))
    if not rows:
        print(console.paint("\n No IP reached the threshold.", "OK"))
        return

    ip_width = max(15, max(len(r["ip"]) for r in rows[:top]))
    header = f" {'SEVERITY':<9} {'SOURCE':<{ip_width}} {'FAILS':>6}  {'COUNTRY':<16} {'TOP USERNAMES'}"
    print(f"\n{console.paint(header, 'BOLD')}\n {'-' * 76}")
    flagged = detector.flagged()
    for r, stats in zip(rows[:top], flagged):
        country = (r["country_code"] or r["country"] or "-")[:16]
        severity = console.paint(f"{r['severity']:<9}", r["severity"])
        print(f" {severity} {r['ip']:<{ip_width}} {r['failed_attempts']:>6}  {country:<16} {top_users(stats, 3)}")
    if len(rows) > top:
        print(console.paint(f" ... and {len(rows) - top} more in the exported reports", "DIM"))


def export_reports(detector: BruteForceDetector, rows: list[dict], args: argparse.Namespace) -> list[Path]:
    out_dir = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    generated = datetime.now(timezone.utc)
    stem = out_dir / f"ssh_bruteforce_{datetime.now():%Y%m%d-%H%M%S}"   # local time in the file name
    written = []

    csv_path = stem.with_suffix(".csv")
    with csv_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
        writer.writeheader()
        writer.writerows(rows)
    written.append(csv_path)

    metadata = {
        "generated_at": generated.isoformat(timespec="seconds"),
        "tool": "ssh_bruteforce_detector",
        "source_files": args.logfiles,
        "threshold": detector.threshold,
        "window_minutes": detector.window.total_seconds() / 60 if detector.window else None,
        "lines_scanned": detector.lines_scanned,
        "failed_logins_total": sum(s.failed_attempts for s in detector.sources.values()),
        "source_ips_with_failures": sum(1 for s in detector.sources.values() if s.failed_attempts),
        "flagged_ip_count": len(rows),
    }
    detail = {s.ip: s for s in detector.flagged()}
    flagged = [
        {**row,
         "usernames": dict(detail[row["ip"]].usernames.most_common()),
         "successful_logins_after_flag": detail[row["ip"]].logins_after_flag}
        for row in rows
    ]
    json_path = stem.with_suffix(".json")
    json_path.write_text(json.dumps({"report": metadata, "flagged_ips": flagged}, indent=2), encoding="utf-8")
    written.append(json_path)

    if args.jsonl:   # one self-contained event per line: what Splunk/ELK ingest most easily
        jsonl_path = stem.with_suffix(".jsonl")
        with jsonl_path.open("w", encoding="utf-8") as handle:
            for record in flagged:
                event = {"event_type": "ssh_bruteforce", "report_generated_at": metadata["generated_at"],
                         "threshold": detector.threshold, **record}
                handle.write(json.dumps(event) + "\n")
        written.append(jsonl_path)
    return written


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------
def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Detect SSH brute-force attempts in Linux auth logs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("logfiles", nargs="+", help="log file(s), oldest first; .gz supported; '-' for stdin")
    parser.add_argument("-t", "--threshold", type=int, default=FAILED_LOGIN_THRESHOLD,
                        help="failed logins before an IP is flagged")
    parser.add_argument("-w", "--window", type=float, metavar="MINUTES",
                        help="only flag IPs that hit the threshold within this many minutes")
    parser.add_argument("-o", "--output-dir", default=DEFAULT_OUTPUT_DIR, help="where reports are written")
    parser.add_argument("--jsonl", action="store_true", help="also write a JSON Lines report (Splunk/ELK)")
    parser.add_argument("--geoip", choices=["ipinfo", "local", "off"], default="ipinfo",
                        help="GeoIP source for flagged IPs")
    parser.add_argument("--geoip-db", metavar="PATH",
                        help=".mmdb file (MaxMind GeoLite2 or IPinfo Lite); implies --geoip local")
    parser.add_argument("--ipinfo-token", metavar="TOKEN",
                        help="ipinfo.io token, or set IPINFO_TOKEN; enables the unlimited Lite API")
    parser.add_argument("--year", type=int, help="year for syslog timestamps that have none (auto if unset)")
    parser.add_argument("--top", type=int, default=15, help="rows to show in the terminal table")
    parser.add_argument("--no-color", action="store_true", help="disable coloured output")
    args = parser.parse_args(argv)

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if args.window is not None and args.window <= 0:
        parser.error("--window must be positive")
    args.ipinfo_token = args.ipinfo_token or os.environ.get("IPINFO_TOKEN")   # kept out of --help
    if args.geoip_db:
        args.geoip = "local"
    if args.geoip == "local" and not args.geoip_db:
        parser.error("--geoip local needs --geoip-db PATH")
    return args


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    use_color = not args.no_color and sys.stdout.isatty() and "NO_COLOR" not in os.environ
    console = Console(color=use_color)
    geo = GeoLocator(args.geoip, args.ipinfo_token, args.geoip_db, console)
    window = timedelta(minutes=args.window) if args.window else None
    detector = BruteForceDetector(args.threshold, window, geo, console)

    print(console.paint(f"Scanning {', '.join(args.logfiles)} for SSH brute-force activity...", "BOLD"))
    for path in args.logfiles:
        clock = TimestampParser(args.year)                     # year inference is per file
        try:
            for line in read_lines(path):
                detector.lines_scanned += 1
                event = parse_line(line, clock)
                if event:
                    detector.process(event)
        except FileNotFoundError:
            console.warn(f"File not found: {path}")
            return 2
        except PermissionError:
            console.warn(f"Permission denied: {path} (auth logs are usually readable only by root "
                         "and the 'adm' group; try sudo)")
            return 2

    rows = report_rows(detector)
    paths = export_reports(detector, rows, args)        # write files first: they are the real output
    print_summary(detector, rows, console, args.top)
    print("\nReports written:\n" + "\n".join(f"  {p}" for p in paths))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:                              # e.g. piped into `head`
        silence_stdout()
        sys.exit(0)
