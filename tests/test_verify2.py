#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Super Nova v1.00 tests — content-aware verification, service
states, four metrics, resume, CT/RDAP errors as errors.

The aadl.dz v2.00 report showed why this matters: a bare HTTP 200
was treated as a confirmed leak, 61 open TCP ports were treated as
61 confirmed services, a 403 was treated as a finding, and 15
unconfirmed "High" findings produced a misleading 0%.
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from supernova.core import content as content_mod
from supernova.core import engine as engine_mod
from supernova.core import evidence as evidence_mod
from supernova.core import scoring as scoring_mod
from supernova.core import storage as storage_mod
from supernova.core import validator as validator_mod
from supernova.engines import fuzz, network, owner, semgrep, subdomains, vuln
from tests.test_supernova import Lab, lab_ctx


class TestContent(unittest.TestCase):
    def test_fingerprint_learns_lab_error_page(self):
        with Lab() as lab:
            fp = content_mod.fingerprint_error_page(lab.url)
        self.assertIsNotNone(fp)
        self.assertEqual(fp["status"], 404)
        self.assertEqual(fp["length"], len("not found"))

    def test_classify_statuses(self):
        fp = {"status": 404, "length": 9, "sha256": "x", "sample": ""}
        self.assertEqual(content_mod.classify(
            403, "", 0, "", fp)["kind"], "forbidden")
        self.assertEqual(content_mod.classify(
            401, "", 0, "", fp)["kind"], "auth_required")
        self.assertEqual(content_mod.classify(
            301, "", 0, "", fp)["kind"], "redirect")
        self.assertEqual(content_mod.classify(
            404, "", 0, "", fp)["kind"], "absent")
        self.assertEqual(content_mod.classify(
            429, "", 0, "", fp)["kind"], "rate_limited")
        self.assertEqual(content_mod.classify(
            500, "", 0, "", fp)["kind"], "server_error")
        self.assertEqual(content_mod.classify(
            200, "text/html", 100, "<html>hello</html>", fp)["kind"], "ok")
        self.assertEqual(content_mod.classify(
            200, "text/html", 9, "not found", fp)["kind"],
            "error_page_200")

    def test_analyze_env(self):
        ok, detail = content_mod.analyze_sensitive(
            "/.env", "text/plain", 30, "DB_PASSWORD=hunter2\nAPI_KEY=x")
        self.assertTrue(ok)
        self.assertIn("KEY=", detail)
        ok, _ = content_mod.analyze_sensitive(
            "/.env", "text/html", 9, "not found")
        self.assertFalse(ok)

    def test_analyze_sql_and_git(self):
        ok, _ = content_mod.analyze_sensitive(
            "/db.sql", "text/plain", 40, "CREATE TABLE users (id INT);")
        self.assertTrue(ok)
        ok, _ = content_mod.analyze_sensitive(
            "/db.sql", "text/html", 9, "not found")
        self.assertFalse(ok)
        ok, _ = content_mod.analyze_sensitive(
            "/.git/HEAD", "text/plain", 21, "ref: refs/heads/main")
        self.assertTrue(ok)


class TestVulnContentAware(unittest.TestCase):
    def test_lab_env_confirmed_robots_info_only(self):
        with Lab() as lab:
            out = vuln.run(lab_ctx(lab.url))
        names = {f["name"]: f for f in out["findings"]}
        self.assertIn("Environment file exposed (.env is public)", names)
        self.assertIn("KEY=", names[
            "Environment file exposed (.env is public)"]["evidence"])
        self.assertEqual(
            names["robots.txt present"]["severity"], "info")
        # 404 paths are not findings.
        self.assertNotIn("Backup environment file exposed", names)
        self.assertNotIn("Database dump publicly downloadable", names)
        checked = {c["path"]: c for c in out["data"]["checked"]}
        self.assertEqual(checked["/.env.bak"]["kind"], "absent")
        self.assertEqual(checked["/.env"]["kind"], "ok")

    def test_validator_rejects_error_page_200(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ev = evidence_mod.collect([{
                "engine": "fuzz",
                "name": "Sensitive path publicly reachable: /fake-error",
                "severity": "high",
                "evidence": "/fake-error -> HTTP 200",
                "fix": "fix"}])[0]
            out = validator_mod.validate_one(ev, ctx)
        self.assertEqual(out["status"], "false_positive")

    def test_validator_rejects_403(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ev = evidence_mod.collect([{
                "engine": "fuzz",
                "name": "Sensitive path publicly reachable: /forbidden",
                "severity": "high",
                "evidence": "/forbidden -> HTTP 403",
                "fix": "fix"}])[0]
            out = validator_mod.validate_one(ev, ctx)
        self.assertEqual(out["status"], "false_positive")


class TestFuzzClassification(unittest.TestCase):
    def test_lab_fuzz_by_kind(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ctx["authorized"] = True
            out = fuzz.run(ctx)
        self.assertIn("by_kind", out["data"])
        self.assertGreater(out["data"]["by_kind"].get("absent", 0), 10)
        self.assertEqual(out["data"]["by_kind"].get("forbidden", 0), 0)
        names = [f["name"] for f in out["findings"]]
        self.assertTrue(any("/.git/HEAD" in n for n in names))
        self.assertTrue(any("/.env" in n for n in names))


class TestNetworkStates(unittest.TestCase):
    def test_identify_banners(self):
        self.assertEqual(network._identify("SSH-2.0-OpenSSH_8.9"),
                         ("ssh", True))
        self.assertEqual(network._identify("HTTP/1.1 200 OK"),
                         ("http", True))
        self.assertEqual(network._identify("220 mail.example.com ESMTP"),
                         ("smtp/ftp", False))
        self.assertEqual(network._identify(""), (None, False))

    def test_lab_port_is_confirmed_http(self):
        with Lab() as lab:
            res = network._check("127.0.0.1", lab.port)
        self.assertIsNotNone(res)
        self.assertEqual(res["state"], "service_confirmed")
        self.assertEqual(res["service"], "http")

    def test_closed_port_is_none(self):
        self.assertIsNone(network._check("127.0.0.1", 9))


class TestMetrics(unittest.TestCase):
    def test_confirmation_weighted_score(self):
        score, grade, _ = scoring_mod.score_findings([
            {"severity": "high", "confirmation": "confirmed"},
            {"severity": "high", "confirmation": "indicator"},
            {"severity": "info", "confirmation": "info"}])
        # 15 + 7 + 0 = 22 deducted.
        self.assertEqual(score, 78)
        self.assertEqual(grade, "C")

    def test_confidence_and_verification_rate(self):
        counts = {"verified": 4, "observed": 2, "false_positive": 2}
        self.assertEqual(scoring_mod.compute_confidence(counts), 62)
        self.assertEqual(
            scoring_mod.compute_verification_rate(counts), 50)
        self.assertEqual(scoring_mod.compute_confidence(
            {"verified": 6, "observed": 0, "false_positive": 0}), 100)

    def test_measured_coverage(self):
        cov = scoring_mod.compute_coverage(
            ["web", "crawl"], {"web": {"status": "completed"},
                               "crawl": {"status": "completed"}},
            {"crawl": {"data": {"discovered": 5, "page_count": 3}},
             "network": {"data": {"phase1": 75}}})
        self.assertEqual(cov["components"]["engines"], 100)
        self.assertEqual(cov["components"]["crawl"], 60)
        self.assertEqual(cov["components"]["ports"], 100)
        self.assertEqual(cov["percent"], 87)


class TestResume(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self._cwd)

    def test_update_scan_round_trip(self):
        from supernova.core.scope import Scope
        scope = Scope(base_dir=self.tmp)
        with Lab() as lab:
            scan = engine_mod.run_scan(lab.url, profile="quick",
                                       scope=scope)
        db = os.path.join(self.tmp, "supernova-scans.db")
        sid = storage_mod.save_scan(db, scan)
        scan["score"] = 42
        storage_mod.update_scan(db, sid, scan)
        self.assertEqual(storage_mod.get_scan(db, sid)["score"], 42)

    def test_resume_reruns_timed_out_engine(self):
        from supernova.core.scope import Scope
        scope = Scope(base_dir=self.tmp)
        with Lab() as lab:
            scan = engine_mod.run_scan(lab.url, profile="deep",
                                       scope=scope)
            db = os.path.join(self.tmp, "supernova-scans.db")
            sid = storage_mod.save_scan(db, scan)
            # Fake a timeout on the dns engine, then resume.
            scan["engine_status"]["dns"] = {
                "status": "timeout", "duration_s": 30,
                "retries": 0, "error": "timeout after 30s"}
            scan["results"]["dns"] = {"engine": "dns", "status": "timeout",
                                      "findings": [], "data": {}}
            storage_mod.update_scan(db, sid, scan)
            new_scan, resumed = engine_mod.resume_scan(
                db, sid, scope=scope)
        self.assertEqual(resumed, ["dns"])
        self.assertEqual(
            new_scan["engine_status"]["dns"]["status"], "completed")
        self.assertEqual(new_scan.get("resumed_from"), sid)


class TestCtRdapErrors(unittest.TestCase):
    def test_subdomains_ct_error_is_error_not_absence(self):
        ctx = {"url": "https://example.com", "host": "example.com",
               "domain": "example.com", "authorized": False, "timeout": 5,
               "html": "", "headers": {}, "cookie_headers": [],
               "status": 200, "ips": [], "pages": [], "scripts": [],
               "subdomains": []}
        with mock.patch("supernova.engines.subdomains.fetch_json",
                        return_value=(None, "HTTP 404")), \
             mock.patch("supernova.engines.subdomains.doh",
                        return_value=[]):
            out = subdomains.run(ctx)
        self.assertEqual(out["status"], "error")
        self.assertIn("unknown, not absent", out["data"]["ct_note"])

    def test_owner_rdap_error_is_unknown_not_absent(self):
        ctx = {"url": "https://example.com", "host": "example.com",
               "domain": "example.com", "authorized": False, "timeout": 5,
               "html": "", "headers": {}, "cookie_headers": [],
               "status": 200, "ips": [], "pages": [], "scripts": [],
               "subdomains": [], "tls": {}}
        with mock.patch("supernova.engines.owner.fetch_json",
                        return_value=(None, "HTTP 404")):
            out = owner.run(ctx)
        self.assertEqual(out["status"], "error")
        self.assertIn("unknown, not absent", out["data"]["rdap_error"])


class TestSemgrepSplit(unittest.TestCase):
    def test_external_scripts_separated(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ctx["scripts"] = [lab.url + "app.js",
                              "https://cdn.example.com/bootstrap.min.js"]
            out = semgrep.run(ctx)
        self.assertEqual(out["data"]["external_scripts"], 1)
        self.assertEqual(out["data"]["internal_scripts"], 1)
        self.assertTrue(any("eval" in f["name"] for f in out["findings"]))


class TestSecretsScope(unittest.TestCase):
    def test_checked_count_includes_pages(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ctx["pages"] = [{"url": lab.url + "about"},
                            {"url": lab.url + "contact"}]
            from supernova.engines import secrets
            out = secrets.run(ctx)
        self.assertGreaterEqual(len(out["data"]["checked"]), 3)


if __name__ == "__main__":
    unittest.main()
