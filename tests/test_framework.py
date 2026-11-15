#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Super Nova v1.00 framework tests — evidence, validation,
correlation, scoring, assets, DNS intelligence, scan comparison.

The validator tests run against the same local lab server as
test_supernova.py (a deliberately weak site), so re-checks really hit
the network instead of being mocked.
"""
import datetime
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from supernova.core import assets as assets_mod
from supernova.core import correlation as correlation_mod
from supernova.core import engine as engine_mod
from supernova.core import evidence as evidence_mod
from supernova.core import scoring as scoring_mod
from supernova.core import storage as storage_mod
from supernova.core import validator as validator_mod
from supernova.engines import dns
from tests.test_supernova import Lab, lab_ctx


def _ev(name, severity="medium", evidence="", engine="web"):
    return {"engine": engine, "name": name, "severity": severity,
            "evidence": evidence, "fix": "fix it"}


class TestScoring(unittest.TestCase):
    def test_weights_and_grades(self):
        score, grade, dist = scoring_mod.score_findings([
            {"severity": "high", "confirmation": "confirmed"},
            {"severity": "medium", "confirmation": "confirmed"}])
        self.assertEqual(score, 77)
        self.assertEqual(grade, "C")
        self.assertEqual(dist, {"high": 1, "medium": 1})
        # Same findings as unconfirmed indicators weigh half.
        score2, _, _ = scoring_mod.score_findings([
            {"severity": "high", "confirmation": "indicator"},
            {"severity": "medium", "confirmation": "indicator"}])
        self.assertEqual(score2, 89)

    def test_empty_is_perfect(self):
        score, grade, _ = scoring_mod.score_findings([])
        self.assertEqual((score, grade), (100, "A+"))

    def test_grade_boundaries(self):
        self.assertEqual(scoring_mod.grade_for(95), "A+")
        self.assertEqual(scoring_mod.grade_for(90), "A")
        self.assertEqual(scoring_mod.grade_for(59), "F")
        self.assertEqual(scoring_mod.grade_for(None), "INCOMPLETE")


class TestEvidence(unittest.TestCase):
    def test_collect_assigns_ids_and_keeps_engine(self):
        recs = evidence_mod.collect([
            _ev("Missing Content-Security-Policy", "high", engine="web"),
            _ev("No SPF record", "low", engine="dns")])
        self.assertEqual(len(recs), 2)
        self.assertTrue(recs[0]["id"].startswith("EV-"))
        self.assertNotEqual(recs[0]["id"], recs[1]["id"])
        self.assertEqual(recs[1]["engine"], "dns")
        self.assertEqual(recs[0]["validation"]["status"], "collected")


class TestValidator(unittest.TestCase):
    def test_missing_header_verified_on_lab(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ev = evidence_mod.collect([
                _ev("Missing Content-Security-Policy", "high")])[0]
            out = validator_mod.validate_one(ev, ctx)
        self.assertEqual(out["status"], "verified")
        self.assertGreaterEqual(out["confidence"], 90)

    def test_exposed_file_verified_on_lab(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ev = evidence_mod.collect([
                _ev("Git repository exposed (.git/HEAD is public)", "high",
                    "/.git/HEAD -> HTTP 200", engine="vuln")])[0]
            out = validator_mod.validate_one(ev, ctx)
        self.assertEqual(out["status"], "verified")

    def test_missing_file_is_false_positive(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ev = evidence_mod.collect([
                _ev("Environment file exposed (.env is public)", "critical",
                    "/.env.bak -> HTTP 200", engine="vuln")])[0]
            out = validator_mod.validate_one(ev, ctx)
        self.assertEqual(out["status"], "false_positive")

    def test_secret_pattern_verified_on_lab(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ev = evidence_mod.collect([
                _ev("Possible exposed secret: Generic API key assignment",
                    "high",
                    "pattern 'Generic API key assignment' found in %sapp.js "
                    "(value redacted)" % lab.url, engine="secrets")])[0]
            out = validator_mod.validate_one(ev, ctx)
        self.assertEqual(out["status"], "verified")

    def test_unknown_finding_is_observed(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ev = evidence_mod.collect([
                _ev("WordPress 5.8 detected", "info")])[0]
            out = validator_mod.validate_one(ev, ctx)
        self.assertEqual(out["status"], "observed")


class TestCorrelation(unittest.TestCase):
    def test_dedupe_merges_engines(self):
        recs = evidence_mod.collect([
            _ev("Missing Content-Security-Policy", "high", engine="web"),
            _ev("Missing Content-Security-Policy", "high",
                engine="vuln")])
        for r in recs:
            r["validation"] = {"status": "verified", "confidence": 90}
        findings, chains, _ = correlation_mod.correlate(recs, {})
        self.assertEqual(len(findings), 1)
        self.assertEqual(sorted(findings[0]["engines"]), ["vuln", "web"])

    def test_xss_chain_fires_on_lab(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            recs = evidence_mod.collect([
                _ev("Missing Content-Security-Policy", "high"),
                _ev("Cookie without HttpOnly flag", "medium",
                    "cookie lab_session"),
                _ev("Site served over plain HTTP", "high")])
            for r in recs:
                r["validation"] = {"status": "verified", "confidence": 90}
            findings, chains, _ = correlation_mod.correlate(
                recs, {"web": {"data": {"forms": 1, "password_fields": 1}}})
        names = [c["name"] for c in chains]
        self.assertIn("Attack chain: XSS session theft", names)
        self.assertIn("Attack chain: session hijack on the wire", names)

    def test_source_secrets_chain(self):
        recs = evidence_mod.collect([
            _ev("Git repository exposed (.git/HEAD is public)", "high"),
            _ev("Environment file exposed (.env is public)", "critical")])
        for r in recs:
            r["validation"] = {"status": "verified", "confidence": 90}
        _findings, chains, _ = correlation_mod.correlate(recs, {})
        self.assertTrue(any("source code + secrets" in c["name"]
                            for c in chains))


class TestDnsEngine(unittest.TestCase):
    def _doh(self, domain, rtype, timeout=8):
        table = {
            "A": ["93.184.216.34"], "AAAA": [], "MX": ["10 mail.example.com"],
            "NS": ["a.iana-servers.net"], "TXT": ["v=spf1 -all"],
            "CNAME": [], "SOA": ["ns.icann.org. noc.dns.icann.org. 1 2 3 4 5"],
            "CAA": [], "DS": [],
        }
        if domain.startswith("_dmarc."):
            return []
        return table.get(rtype, [])

    def test_dns_records_and_missing_dmarc(self):
        ctx = {"url": "https://example.com", "host": "example.com",
               "domain": "example.com", "authorized": False, "timeout": 5,
               "html": "", "headers": {}, "cookie_headers": [],
               "status": 200, "ips": [], "pages": [], "scripts": [],
               "subdomains": []}
        with mock.patch("supernova.engines.dns.doh", side_effect=self._doh):
            out = dns.run(ctx)
        self.assertTrue(out["data"]["spf"])
        self.assertFalse(out["data"]["dmarc"])
        self.assertFalse(out["data"]["dnssec"])
        self.assertTrue(any(f["name"] == "No DMARC record"
                            for f in out["findings"]))
        self.assertTrue(any(f["name"] == "DNSSEC not enabled"
                            for f in out["findings"]))


class TestAssets(unittest.TestCase):
    def test_asset_graph_links(self):
        scan = {"results": {
            "subdomains": {"data": {"subdomains": ["api.example.com"]}},
            "network": {"data": {"open_ports": [{"port": 443}]}},
            "tech": {"data": {"technologies": [{"name": "Server: x"}],
                              "cms": None}},
            "tls": {"data": {"cert": {"issuer": "X"}, "days_left": 90}},
            "owner": {"data": {"expires": "2027-01-01", "days_left": 400,
                               "registrar": "R", "registrant": "O"}},
            "web": {"data": {"cookies": [{}, {}]}},
            "crawl": {"data": {"pages": [{}, {}]}},
            "resources": {"data": {"count": 5}}}}
        ctx = {"domain": "example.com", "ips": ["93.184.216.34"]}
        assets = assets_mod.build_assets(scan, ctx)
        self.assertEqual(assets["domain"], "example.com")
        self.assertEqual(assets["subdomain_count"], 1)
        self.assertEqual(assets["open_ports"], [443])
        self.assertEqual(assets["domain_days_left"], 400)
        self.assertEqual(len(assets["links"]), 3)


class TestCompare(unittest.TestCase):
    def test_compare_scans(self):
        a = {"score": 80, "coverage": {"percent": 90},
             "findings": [{"name": "Missing CSP", "severity": "high"},
                          {"name": "Old jQuery", "severity": "medium"}]}
        b = {"score": 60, "coverage": {"percent": 85},
             "findings": [{"name": "Missing CSP", "severity": "critical"},
                          {"name": "No DMARC record", "severity": "medium"}]}
        diff = storage_mod.compare_scans(a, b)
        self.assertEqual(diff["score"], (80, 60))
        self.assertEqual([f["name"] for f in diff["added"]],
                         ["No DMARC record"])
        self.assertEqual([f["name"] for f in diff["removed"]],
                         ["Old jQuery"])
        self.assertEqual(diff["changed"][0]["from"], "high")
        self.assertEqual(diff["changed"][0]["to"], "critical")


class TestFrameworkOrchestrator(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self._cwd)

    def test_deep_scan_has_evidence_chains_assets(self):
        from supernova.core.scope import Scope
        scope = Scope(base_dir=self.tmp)
        with Lab() as lab:
            scope.authorize(lab.url)
            scan = engine_mod.run_scan(lab.url, profile="deep",
                                       scope=scope)
        self.assertIn("evidence", scan)
        self.assertIn("validation", scan)
        self.assertIn("assets", scan)
        self.assertEqual(scan["assets"]["domain"], "127.0.0.1")
        self.assertIn("dns", scan["engine_status"])
        names = [c["name"] for c in scan["chains"]]
        self.assertIn("Attack chain: XSS session theft", names)
        self.assertIsInstance(scan["score"], int)
        self.assertEqual(scan["tool"], "Super Nova v1.00")


if __name__ == "__main__":
    unittest.main()
