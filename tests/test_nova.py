#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Super Nova v1.00 tests — the three new engines (api, deps, timeline)
plus the Executive Summary, all against the local lab server from
tests.test_supernova (nothing touches the real internet except the
mocked RDAP / Wayback / CT calls in the timeline test).
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from supernova.core import engine as engine_mod
from supernova.core import storage as storage_mod
from supernova.core import summary as summary_mod
from supernova.engines import api, deps, timeline
from tests.test_supernova import Lab, lab_ctx


def _public_ctx(url):
    """A ctx for a public (non-local) domain, with local lab transport."""
    ctx = lab_ctx(url)
    ctx["domain"] = "example.com"
    ctx["host"] = url.split("/")[2]
    ctx["tls"] = {"cert": {"not_before": "Jan 10 00:00:00 2024 GMT",
                           "not_after": "Apr 10 00:00:00 2025 GMT"},
                  "days_left": 90}
    return ctx


class TestApiEngine(unittest.TestCase):
    def test_finds_openapi_docs_and_endpoints(self):
        with Lab() as lab:
            out = api.run(lab_ctx(lab.url))
        data = out["data"]
        self.assertEqual(out["status"], "completed")
        self.assertIn("/openapi.json", data["docs_found"])
        self.assertIn("/api/users", data["endpoints"])
        self.assertIn("/api/orders", data["endpoints"])
        names = [f["name"] for f in out["findings"]]
        self.assertTrue(any("Public API documentation" in n for n in names))
        self.assertTrue(any("Public API surface" in n for n in names))

    def test_auth_required_is_info_not_a_finding(self):
        # /swagger.json answers 401 on the lab: auth required, not a vuln.
        with Lab() as lab:
            out = api.run(lab_ctx(lab.url))
        self.assertTrue(out["data"]["auth_required"])
        self.assertFalse(any(f["severity"] in ("critical", "high", "medium")
                             for f in out["findings"]))
        self.assertTrue(any("require authentication" in f["name"]
                            for f in out["findings"]))

    def test_unreachable_site_is_error(self):
        ctx = {"url": "http://127.0.0.1:9/", "host": "127.0.0.1",
               "domain": "127.0.0.1", "authorized": False, "timeout": 3,
               "html": "", "headers": {}, "cookie_headers": [],
               "status": None, "ips": [], "pages": [], "scripts": [],
               "subdomains": []}
        out = api.run(ctx)
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["findings"], [])


class TestDepsEngine(unittest.TestCase):
    def test_parsed_versions_and_outdated_jquery(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ctx["scripts"] = [lab.url + "jquery-1.12.4.min.js",
                              lab.url + "react-18.2.0.min.js"]
            out = deps.run(ctx)
        by_name = {l["name"]: l for l in out["data"]["libraries"]}
        self.assertEqual(by_name["jQuery"]["version"], "1.12.4")
        self.assertEqual(by_name["React"]["version"], "18.2.0")
        names = [f["name"] for f in out["findings"]]
        self.assertIn("Outdated library: jQuery 1.12.4", names)
        self.assertFalse(any("React" in n for n in names))

    def test_version_never_guessed(self):
        # /vue.min.js has no version anywhere: listed, version None,
        # and no finding is raised for it.
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ctx["scripts"] = [lab.url + "vue.min.js"]
            out = deps.run(ctx)
        by_name = {l["name"]: l for l in out["data"]["libraries"]}
        self.assertIn("Vue.js", by_name)
        self.assertIsNone(by_name["Vue.js"]["version"])
        # No finding is ever raised for the version-less library itself
        # (the lab homepage's old jQuery may still be flagged).
        self.assertFalse(any("Vue" in f["name"] for f in out["findings"]))

    def test_unreachable_site_is_error(self):
        ctx = {"url": "http://127.0.0.1:9/", "host": "127.0.0.1",
               "domain": "127.0.0.1", "authorized": False, "timeout": 3,
               "html": "", "headers": {}, "cookie_headers": [],
               "status": None, "ips": [], "pages": [], "scripts": [],
               "subdomains": []}
        out = deps.run(ctx)
        self.assertEqual(out["status"], "error")


class TestTimelineEngine(unittest.TestCase):
    def test_local_target_has_empty_timeline(self):
        with Lab() as lab:
            out = timeline.run(lab_ctx(lab.url))
        self.assertEqual(out["status"], "completed")
        self.assertEqual(out["data"]["events"], [])
        self.assertEqual(out["data"]["count"], 0)

    def test_sorted_events_from_public_records_only(self):
        def fake_fetch(url, timeout=12, max_bytes=500000):
            if "rdap.org" in url:
                return ({"handle": "EXAMPLE",
                         "events": [
                             {"eventAction": "registration",
                              "eventDate": "2020-01-15T00:00:00Z"},
                             {"eventAction": "expiration",
                              "eventDate": "2027-06-01T00:00:00Z"}]},
                        None)
            if "web.archive.org" in url:
                return ([["timestamp", "original"],
                         ["20190301000000", "http://example.com/"],
                         ["20250101000000", "http://example.com/about"]],
                        None)
            if "crt.sh" in url:
                return ([{"entry_timestamp": "2019-02-01T00:00:00Z"}],
                        None)
            return None, "unexpected url"

        with Lab() as lab:
            ctx = _public_ctx(lab.url)
            with mock.patch("supernova.engines.timeline.fetch_json",
                            side_effect=fake_fetch):
                out = timeline.run(ctx)
        self.assertEqual(out["status"], "completed")
        events = out["data"]["events"]
        dates = [e["date"] for e in events]
        self.assertEqual(dates, sorted(dates))
        self.assertEqual(dates[0], "2019-02-01")
        self.assertEqual(dates[-1], "2027-06-01")
        by_event = {e["event"]: e for e in events}
        self.assertEqual(by_event["Domain registered"]["date"],
                         "2020-01-15")
        self.assertEqual(by_event["TLS certificate expires"]["date"],
                         "2025-04-10")
        self.assertEqual(by_event["Domain registration expires"]["date"],
                         "2027-06-01")
        self.assertTrue(all(e.get("source") for e in events))
        self.assertEqual(out["data"]["errors"], {})


class TestExecutiveSummary(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self._cwd)

    def test_summary_built_for_lab_scan(self):
        with Lab() as lab:
            scan = engine_mod.run_scan(lab.url, profile="quick",
                                       scope=None)
        summary = scan.get("summary")
        self.assertIsNotNone(summary)
        self.assertEqual(summary["target"], lab.url.rstrip("/"))
        self.assertIsInstance(summary["score"], int)
        self.assertEqual(summary["grade"], scan["grade"])
        self.assertEqual(set(summary["metrics"]),
                         {"security_score", "confidence",
                          "coverage_percent", "verification_rate"})
        self.assertEqual(summary["metrics"]["coverage_percent"], 100)
        self.assertEqual(summary["owner"]["registrar"], "UNKNOWN")
        self.assertLessEqual(len(summary["top_findings"]), 5)
        self.assertLessEqual(len(summary["priority_actions"]), 3)
        text = summary_mod.format_summary(summary)
        self.assertIn("Executive Summary", text)
        self.assertIn(lab.url.rstrip("/"), text)

    def test_summary_top5_ordered_and_priority_actions(self):
        scan = {
            "tool": "Super Nova v1.00", "target": "https://example.com",
            "profile": "deep", "score": 40, "grade": "F",
            "confidence": 80, "coverage": {"percent": 90},
            "metrics": {"security_score": 40, "confidence": 80,
                        "coverage_percent": 90, "verification_rate": 50},
            "results": {"owner": {"data": {"registrar": "Example Reg",
                                            "registrant": "Example Org",
                                            "expires": "2027-01-01",
                                            "days_left": 400,
                                            "cert_days_left": 90}},
                        "tls": {"data": {"days_left": 90}}},
            "assets": {}, "domain": "example.com",
            "severity_distribution": {"high": 2, "medium": 2, "low": 2},
            "recommendations": ["Keep everything updated."],
            "findings": [
                {"severity": "low", "confirmation": "indicator",
                 "name": "Low one", "evidence": "e", "fix": "Fix low 1"},
                {"severity": "high", "confirmation": "confirmed",
                 "name": "High confirmed", "evidence": "e",
                 "fix": "Fix high confirmed"},
                {"severity": "medium", "confirmation": "indicator",
                 "name": "Medium one", "evidence": "e",
                 "fix": "Fix medium 1"},
                {"severity": "critical", "confirmation": "confirmed",
                 "name": "Critical one", "evidence": "e",
                 "fix": "Fix critical"},
                {"severity": "high", "confirmation": "indicator",
                 "name": "High indicator", "evidence": "e",
                 "fix": "Fix high indicator"},
                {"severity": "low", "confirmation": "indicator",
                 "name": "Low two", "evidence": "e", "fix": "Fix low 2"},
                {"severity": "info", "confirmation": "info",
                 "name": "Info only", "evidence": "e", "fix": "Fix info"},
            ],
        }
        summary = summary_mod.build_summary(scan)
        self.assertEqual(len(summary["top_findings"]), 5)
        self.assertEqual(summary["top_findings"][0]["name"],
                         "Critical one")
        self.assertEqual(summary["top_findings"][1]["name"],
                         "High confirmed")
        self.assertFalse(any(f["name"] == "Info only"
                             for f in summary["top_findings"]))
        self.assertEqual(summary["priority_actions"],
                         ["Fix critical", "Fix high confirmed",
                          "Fix high indicator"])
        self.assertEqual(summary["owner"]["registrar"], "Example Reg")

    def test_summary_round_trip_from_sqlite(self):
        with Lab() as lab:
            scan = engine_mod.run_scan(lab.url, profile="quick",
                                       scope=None)
            db = os.path.join(self.tmp, "supernova-scans.db")
            scan_id = storage_mod.save_scan(db, scan)
            stored = storage_mod.get_scan(db, scan_id)
        summary = stored.get("summary") or summary_mod.build_summary(
            stored)
        self.assertEqual(summary["target"], lab.url.rstrip("/"))
        self.assertIsInstance(summary["score"], int)
        self.assertIn("Executive Summary",
                      summary_mod.format_summary(summary))


if __name__ == "__main__":
    unittest.main()
