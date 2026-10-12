"""Unit tests for ssh_bruteforce_detector.py (standard library only).

    python3 -m unittest discover -s tests -v
"""
import contextlib
import csv
import io
import json
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from argparse import Namespace
from datetime import datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import ssh_bruteforce_detector as d  # noqa: E402

SAMPLE_LOG = ROOT / "sample_logs" / "sample_auth.log"
EXPECTED = json.loads((ROOT / "sample_logs" / "expected_failed_logins.json").read_text())


def run_detector(lines, threshold=5, window_minutes=None, year=2026):
    """Feed lines through the detector with GeoIP off and terminal output captured."""
    console = d.Console(color=False)
    geo = d.GeoLocator("off", None, None, console)
    window = timedelta(minutes=window_minutes) if window_minutes else None
    detector = d.BruteForceDetector(threshold, window, geo, console)
    clock = d.TimestampParser(year)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        for line in lines:
            detector.lines_scanned += 1
            event = d.parse_line(line, clock)
            if event:
                detector.process(event)
    return detector, output.getvalue()


class ParseLineTests(unittest.TestCase):
    def setUp(self):
        self.clock = d.TimestampParser(2026)

    def test_classic_failed_password(self):
        e = d.parse_line("Oct 11 02:14:29 web sshd[201]: Failed password for root from 203.0.113.45 port 56131 ssh2",
                         self.clock)
        self.assertEqual((e.event_type, e.ip, e.user, e.count), (d.FAILED_LOGIN, "203.0.113.45", "root", 1))
        self.assertEqual(e.timestamp, datetime(2026, 10, 11, 2, 14, 29))

    def test_invalid_user_variant(self):
        e = d.parse_line("Oct  1 02:14:29 web sshd[201]: Failed password for invalid user oracle from 192.0.2.7 "
                         "port 4000 ssh2", self.clock)
        self.assertEqual((e.user, e.ip, e.timestamp.day), ("oracle", "192.0.2.7", 1))

    def test_message_repeated_counts_all_attempts(self):
        e = d.parse_line("Oct 11 02:14:29 web sshd[201]: message repeated 5 times: "
                         "[ Failed password for root from 203.0.113.45 port 56131 ssh2]", self.clock)
        self.assertEqual((e.event_type, e.count), (d.FAILED_LOGIN, 5))

    def test_iso_timestamp_and_openssh_98_process_name(self):
        e = d.parse_line("2026-10-11T03:14:07.123456+03:00 bastion sshd-session[4321]: "
                         "Failed keyboard-interactive/pam for root from 198.51.100.4 port 51122 ssh2", self.clock)
        self.assertEqual((e.method, e.timestamp), ("keyboard-interactive/pam", datetime(2026, 10, 11, 3, 14, 7, 123456)))

    def test_iso_timestamp_with_short_fraction_and_utc_suffix(self):
        e = d.parse_line("2026-10-11T03:14:07.5Z bastion sshd[1]: Failed password for root from 198.51.100.4 "
                         "port 1 ssh2", self.clock)
        self.assertEqual(e.timestamp, datetime(2026, 10, 11, 3, 14, 7, 500000))

    def test_invalid_and_accepted_events(self):
        invalid = d.parse_line("Oct 11 05:02:27 web sshd[9]: Invalid user pi from 198.51.100.77 port 40022", self.clock)
        accepted = d.parse_line("Oct 11 14:42:49 web sshd[9]: Accepted password for root from 198.51.100.9 "
                                "port 44122 ssh2", self.clock)
        self.assertEqual((invalid.event_type, invalid.user), (d.INVALID_USER, "pi"))
        self.assertEqual((accepted.event_type, accepted.method), (d.ACCEPTED_LOGIN, "password"))

    def test_ipv4_mapped_ipv6_is_normalised(self):
        e = d.parse_line("Oct 11 02:14:29 web sshd[1]: Failed password for root from ::ffff:192.0.2.55 port 1 ssh2",
                         self.clock)
        self.assertEqual(e.ip, "192.0.2.55")

    def test_non_ssh_and_irrelevant_lines_are_ignored(self):
        for line in (
            "Oct 11 11:01:00 web dovecot[902]: auth: Failed password for alice from 192.0.2.99 port 993",
            "Oct 11 00:00:00 web CRON[1]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
            "Oct 11 00:56:00 web sshd[2]: Connection closed by 203.0.113.37 port 49628 [preauth]",
            "garbage",
        ):
            self.assertIsNone(d.parse_line(line, self.clock), line)

    def test_year_rolls_over_at_new_year(self):
        clock = d.TimestampParser(2025)
        self.assertEqual(clock.parse("Dec 31 23:59:59").year, 2025)
        self.assertEqual(clock.parse("Jan  1 00:00:01").year, 2026)


class DetectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lines = SAMPLE_LOG.read_text().splitlines()
        cls.detector, cls.output = run_detector(cls.lines)

    def test_counts_match_ground_truth_exactly(self):
        counts = {ip: s.failed_attempts for ip, s in self.detector.sources.items() if s.failed_attempts}
        self.assertEqual(counts, EXPECTED)

    def test_only_ips_at_or_above_threshold_are_flagged(self):
        flagged = {s.ip for s in self.detector.flagged()}
        self.assertEqual(flagged, {ip for ip, n in EXPECTED.items() if n >= 5})
        self.assertNotIn("10.0.4.22", flagged)        # legit admin who mistyped twice

    def test_alert_is_printed_once_per_ip(self):
        self.assertEqual(self.output.count("[ALERT]"), 5)
        self.assertEqual(self.output.count("203.0.113.45  5 failed logins"), 1)

    def test_successful_login_after_brute_force_is_critical(self):
        severities = {s.ip: s.severity(5) for s in self.detector.flagged()}
        self.assertEqual(severities["198.51.100.9"], "CRITICAL")
        self.assertEqual(severities["203.0.113.45"], "HIGH")
        self.assertEqual(severities["192.0.2.10"], "MEDIUM")
        self.assertIn("[CRITICAL]", self.output)
        self.assertEqual(self.detector.flagged()[0].ip, "198.51.100.9")   # sorted first

    def test_sliding_window_ignores_low_and_slow_attacker(self):
        detector, _ = run_detector(self.lines, window_minutes=10)
        flagged = {s.ip for s in detector.flagged()}
        self.assertNotIn("192.0.2.10", flagged)        # 8 attempts spread over ~8 hours
        self.assertIn("203.0.113.45", flagged)


class GeoIPTests(unittest.TestCase):
    def setUp(self):
        self.console = d.Console(color=False)
        self._urlopen = urllib.request.urlopen

    def tearDown(self):
        urllib.request.urlopen = self._urlopen

    def test_private_and_documentation_ranges_are_not_looked_up(self):
        geo = d.GeoLocator("ipinfo", None, None, self.console)
        urllib.request.urlopen = lambda *a, **k: self.fail("should not call the API")
        self.assertEqual(geo.lookup("10.0.0.5")["country"], "Private/Reserved")
        self.assertEqual(geo.lookup("2001:db8::1")["country"], "Private/Reserved")

    def test_ipinfo_lite_response_is_mapped_and_cached(self):
        calls = []

        def fake(request, timeout):
            calls.append(request.full_url)
            return io.BytesIO(json.dumps({"country": "United States", "country_code": "US",
                                          "asn": "AS15169", "as_name": "Google LLC"}).encode())

        urllib.request.urlopen = fake
        geo = d.GeoLocator("ipinfo", "TOKEN", None, self.console)
        first, second = geo.lookup("8.8.8.8"), geo.lookup("8.8.8.8")
        self.assertEqual(first, {"country": "United States", "country_code": "US", "asn": "AS15169", "org": "Google LLC"})
        self.assertIs(first, second)
        self.assertEqual(len(calls), 1)
        self.assertIn("api.ipinfo.io/lite/8.8.8.8", calls[0])

    def test_network_failure_disables_lookups_after_one_warning(self):
        calls = []

        def offline(request, timeout):
            calls.append(1)
            raise urllib.error.URLError("no route to host")

        urllib.request.urlopen = offline
        geo = d.GeoLocator("ipinfo", None, None, self.console)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertEqual(geo.lookup("8.8.8.8")["country"], "")
            self.assertEqual(geo.lookup("1.1.1.1")["country"], "")
        self.assertEqual(len(calls), 1)
        self.assertEqual(err.getvalue().count("[WARN]"), 1)


class ExportTests(unittest.TestCase):
    def test_csv_json_and_jsonl_reports(self):
        detector, _ = run_detector(SAMPLE_LOG.read_text().splitlines())
        rows = d.report_rows(detector)
        with tempfile.TemporaryDirectory() as tmp:
            args = Namespace(output_dir=tmp, logfiles=["sample_auth.log"], jsonl=True)
            csv_path, json_path, jsonl_path = d.export_reports(detector, rows, args)

            with csv_path.open() as handle:
                table = list(csv.DictReader(handle))
            self.assertEqual(list(table[0]), d.CSV_FIELDS)
            self.assertEqual([r["ip"] for r in table], [r["ip"] for r in rows])

            report = json.loads(json_path.read_text())
            self.assertEqual(report["report"]["failed_logins_total"], sum(EXPECTED.values()))
            critical = report["flagged_ips"][0]
            self.assertEqual(critical["successful_logins_after_flag"][0]["user"], "root")

            events = [json.loads(line) for line in jsonl_path.read_text().splitlines()]
            self.assertEqual(len(events), 5)
            self.assertTrue(all(e["event_type"] == "ssh_bruteforce" for e in events))


if __name__ == "__main__":
    unittest.main()
