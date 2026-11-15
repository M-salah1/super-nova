#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Super Nova v1.00 tests — every engine against a local lab server.

The lab serves a deliberately weak site: no security headers, a
cookie without flags, /.git/HEAD and /.env public, WordPress 5.8,
old jQuery, and JS with eval() + a hardcoded api key. Nothing here
touches the real internet except the mocked CT/Wayback calls.
"""
import http.server
import json
import os
import socketserver
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from supernova.core import engine as engine_mod
from supernova.core import storage as storage_mod
from supernova.core import verify as verify_mod
from supernova.core.scope import Scope
from supernova.engines import (crawl, fuzz, history, httpx, network, owner,
                         resources, secrets, semgrep, shodan, subdomains,
                         tech, tls, vuln, web, wordpress)

HOME = """<!DOCTYPE html><html><head>
<title>Nova Lab</title>
<meta name="generator" content="WordPress 5.8">
<script src="/jquery-1.12.4.min.js"></script>
<script src="/react-18.2.0.min.js"></script>
<script src="/app.js"></script>
<link rel="stylesheet" href="/style.css">
</head><body>
<a href="/about">About</a> <a href="/contact">Contact</a>
<form action="/login" method="post"><input name="user">
<input type="hidden" name="csrf_token" value="abc123hidden">
<input type="password" name="pwd"></form>
<img src="/wp-content/themes/twentytwenty/logo.png">
<img src="/wp-content/plugins/akismet/logo.png">
<img src="/logo.png">
<img src="/missing.png">
</body></html>"""

APP_JS = ('var api_key = "secret12345";\n'
          'var x = eval(userInput);\n'
          'var t = Math.random();\n'
          'fetch("/api/users").then(r => r.json());\n')


class LabHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="text/html", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Server", "TestServer/1.0")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body.encode())

    def do_GET(self):
        if self.path == "/":
            self._send(200, HOME, extra={
                "Set-Cookie": "lab_session=abc123; Path=/"})
        elif self.path == "/app.js":
            self._send(200, APP_JS, "application/javascript")
        elif self.path == "/jquery-1.12.4.min.js":
            self._send(200, "/* jQuery 1.12.4 */", "application/javascript")
        elif self.path == "/react-18.2.0.min.js":
            self._send(200, "/* React 18.2.0 */", "application/javascript")
        elif self.path == "/vue.min.js":
            self._send(200, "/* Vue.js */", "application/javascript")
        elif self.path == "/openapi.json":
            self._send(200, '{"openapi": "3.0.0", "info": {"title": "Lab API"},'
                       ' "paths": {"/api/users": {}, "/api/orders": {}}}',
                       "application/json")
        elif self.path == "/api/docs":
            self._send(200, "<html><title>Lab API docs</title></html>")
        elif self.path == "/api/users":
            self._send(200, '[{"id": 1}]', "application/json")
        elif self.path == "/swagger.json":
            self._send(401, "Unauthorized", "application/json")
        elif self.path == "/style.css":
            self._send(200, "body{}", "text/css")
        elif self.path in ("/about", "/contact", "/login"):
            self._send(200, "<html><title>%s</title></html>" % self.path)
        elif self.path == "/robots.txt":
            self._send(200, "User-agent: *\nDisallow: /admin\n", "text/plain")
        elif self.path == "/.git/HEAD":
            self._send(200, "ref: refs/heads/main\n", "text/plain")
        elif self.path == "/.env":
            self._send(200, "DB_PASSWORD=hunter2\n", "text/plain")
        elif self.path == "/wp-json/":
            self._send(200, '{"namespaces": ["wp/v2"]}',
                       "application/json")
        elif self.path == "/wp-json/wp/v2/":
            self._send(200, '{"routes": {}}', "application/json")
        elif self.path == "/readme.html":
            self._send(200, "<html>WordPress Version 5.8</html>")
        elif self.path == "/admin":
            self._send(200, "<html>admin</html>")
        elif self.path == "/logo.png":
            self._send(200, "PNGFAKE", "image/png")
        elif self.path == "/fake-error":
            # An error page that wrongly answers 200.
            self._send(200, "not found", "text/html")
        elif self.path == "/forbidden":
            self._send(403, "Forbidden", "text/html")
        else:
            self._send(404, "not found", "text/plain")


class Lab:
    def __enter__(self):
        self.server = socketserver.TCPServer(("127.0.0.1", 0), LabHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       daemon=True)
        self.thread.start()
        self.url = "http://127.0.0.1:%d/" % self.port
        return self

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()


def lab_ctx(url, authorized=False, html=None, headers=None):
    from supernova.core.http import get, lower_headers
    r = get(url, timeout=5)
    ctx = {"url": url, "host": url.split("/")[2], "domain": "127.0.0.1",
           "authorized": authorized, "timeout": 5,
           "html": html if html is not None else (r.get("body") or ""),
           "headers": headers if headers is not None
                      else lower_headers(r.get("headers") or {}),
           "cookie_headers": [], "status": r.get("status"), "ips": ["127.0.0.1"],
           "pages": [], "scripts": [], "subdomains": []}
    try:
        ctx["cookie_headers"] = list(
            r.get("headers").get_all("Set-Cookie") or [])
    except Exception:
        pass
    return ctx


class TestWebEngine(unittest.TestCase):
    def test_missing_headers_and_cookie_flags(self):
        with Lab() as lab:
            out = web.run(lab_ctx(lab.url))
        names = [f["name"] for f in out["findings"]]
        self.assertIn("Missing Content-Security-Policy", names)
        self.assertIn("Missing Strict-Transport-Security (HSTS)", names)
        # Secure-flag findings only apply on HTTPS sites; the lab is HTTP.
        self.assertIn("Cookie without HttpOnly flag", names)
        self.assertIn("Cookie without SameSite attribute", names)
        self.assertIn("Server version disclosed", names)
        self.assertEqual(out["status"], "completed")

    def test_unreachable_site_is_error_not_findings(self):
        ctx = {"url": "http://127.0.0.1:9/", "host": "127.0.0.1",
               "domain": "127.0.0.1", "authorized": False, "timeout": 3,
               "html": "", "headers": {}, "cookie_headers": [],
               "status": None, "ips": [], "pages": [], "scripts": [],
               "subdomains": []}
        out = web.run(ctx)
        self.assertEqual(out["status"], "error")
        self.assertEqual(out["findings"], [])


class TestVulnEngine(unittest.TestCase):
    def test_templates_find_exposed_files(self):
        with Lab() as lab:
            out = vuln.run(lab_ctx(lab.url))
        names = [f["name"] for f in out["findings"]]
        self.assertIn("Git repository exposed (.git/HEAD is public)", names)
        self.assertIn("Environment file exposed (.env is public)", names)
        self.assertIn("robots.txt present", names)
        self.assertEqual(out["data"]["templates"], len(vuln.TEMPLATES))


class TestNetworkEngine(unittest.TestCase):
    def test_open_lab_port_found(self):
        with Lab() as lab:
            # Direct connect check on the lab's own (ephemeral) port.
            res = network._check("127.0.0.1", lab.port)
            self.assertIsNotNone(res)
            self.assertEqual(res["port"], lab.port)
            out = network.run(lab_ctx(lab.url, authorized=True))
        self.assertEqual(out["status"], "completed")
        self.assertEqual(out["data"]["phase1"], len(network.COMMON_PORTS))

    def test_needs_authorization(self):
        with Lab() as lab:
            out = network.run(lab_ctx(lab.url, authorized=False))
        self.assertEqual(out["status"], "not_tested")


class TestCrawlEngine(unittest.TestCase):
    def test_crawl_finds_pages_and_assets(self):
        with Lab() as lab:
            out = crawl.run(lab_ctx(lab.url))
        urls = [p["url"] for p in out["data"]["pages"]]
        self.assertIn(lab.url, urls)
        self.assertIn(lab.url + "about", urls)
        self.assertTrue(any(s.endswith("/app.js")
                            for s in out["data"]["scripts"]))


class TestFuzzEngine(unittest.TestCase):
    def test_fuzz_finds_sensitive_paths(self):
        with Lab() as lab:
            out = fuzz.run(lab_ctx(lab.url, authorized=True))
        interesting = {e["path"] for e in out["data"]["interesting"]}
        self.assertIn("/.git/HEAD", interesting)
        self.assertIn("/.env", interesting)
        self.assertEqual(out["data"]["probed"], len(fuzz.WORDLIST))


class TestTlsEngine(unittest.TestCase):
    def test_http_site_has_no_tls(self):
        with Lab() as lab:
            out = tls.run(lab_ctx(lab.url))
        self.assertEqual(out["status"], "completed")
        self.assertTrue(any("No TLS" in f["name"] for f in out["findings"]))


class TestTechEngine(unittest.TestCase):
    def test_wordpress_and_old_jquery(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ctx["scripts"] = [lab.url + "jquery-1.12.4.min.js",
                              lab.url + "app.js"]
            out = tech.run(ctx)
        self.assertEqual(out["data"]["cms"], "WordPress")
        self.assertTrue(any("Outdated jQuery" in f["name"]
                            for f in out["findings"]))


class TestWordPressEngine(unittest.TestCase):
    def test_detects_old_wordpress(self):
        with Lab() as lab:
            out = wordpress.run(lab_ctx(lab.url))
        self.assertTrue(out["data"]["detected"])
        self.assertEqual(out["data"]["version"], "5.8")
        self.assertIn("akismet", out["data"]["plugins"])
        self.assertTrue(any("Outdated WordPress" in f["name"]
                            for f in out["findings"]))


class TestSemgrepEngine(unittest.TestCase):
    def test_dangerous_js_patterns(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ctx["scripts"] = [lab.url + "app.js"]
            out = semgrep.run(ctx)
        names = [f["name"] for f in out["findings"]]
        self.assertIn("Use of eval() in public JavaScript", names)
        self.assertIn("Hardcoded credential name in public JavaScript", names)


class TestSecretsEngine(unittest.TestCase):
    def test_secret_pattern_found_value_never_shown(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ctx["scripts"] = [lab.url + "app.js"]
            out = secrets.run(ctx)
        self.assertGreater(len(out["findings"]), 0)
        blob = json.dumps(out, ensure_ascii=False)
        self.assertNotIn("secret12345", blob)


class TestSubdomainsEngine(unittest.TestCase):
    def test_ct_subdomains_mocked(self):
        ctx = {"url": "https://example.com", "host": "example.com",
               "domain": "example.com", "authorized": False, "timeout": 5,
               "html": "", "headers": {}, "cookie_headers": [],
               "status": 200, "ips": [], "pages": [], "scripts": [],
               "subdomains": []}
        with mock.patch("supernova.engines.subdomains._ct_subdomains",
                        return_value=(["api.example.com",
                                       "www.example.com"], None)), \
             mock.patch("supernova.engines.subdomains.doh", return_value=[]):
            out = subdomains.run(ctx)
        self.assertIn("api.example.com", out["data"]["subdomains"])
        self.assertEqual(out["data"]["count"], 2)


class TestHistoryEngine(unittest.TestCase):
    def test_wayback_mocked(self):
        ctx = {"url": "https://example.com", "host": "example.com",
               "domain": "example.com", "authorized": False, "timeout": 5,
               "html": "", "headers": {}, "cookie_headers": [],
               "status": 200, "ips": [], "pages": [], "scripts": [],
               "subdomains": []}
        rows = [["timestamp", "original"],
                ["20200101000000", "https://example.com/old-page"],
                ["20210101000000", "https://example.com/admin"]]
        with mock.patch("supernova.engines.history.fetch_json",
                        return_value=(rows, None)):
            out = history.run(ctx)
        self.assertEqual(out["data"]["count"], 2)
        self.assertEqual(out["data"]["first"], "20200101000000")


class TestHttpxEngine(unittest.TestCase):
    def test_lab_host_is_live(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            out = httpx.run(ctx)
        self.assertEqual(out["data"]["live"], 1)
        self.assertEqual(out["data"]["hosts"][0]["status"], 200)


class TestWebHiddenFields(unittest.TestCase):
    def test_hidden_field_names_only_and_password_field(self):
        with Lab() as lab:
            out = web.run(lab_ctx(lab.url))
        self.assertIn("csrf_token", out["data"]["hidden_fields"])
        self.assertEqual(out["data"]["password_fields"], 1)
        self.assertTrue(any("Password field on a non-HTTPS page" in f["name"]
                            for f in out["findings"]))
        # The hidden value is never collected, shown or stored.
        blob = json.dumps(out, ensure_ascii=False)
        self.assertNotIn("abc123hidden", blob)
        cookie = out["data"]["cookies"][0]
        self.assertTrue(cookie["session"])
        self.assertIsNone(cookie["expires"])


class TestOwnerEngine(unittest.TestCase):
    RDAP = {
        "handle": "12345-DOMAIN",
        "entities": [
            {"roles": ["registrar"],
             "vcardArray": ["vcard",
                            [["fn", {}, "text", "Example Registrar, Inc."]]]},
            {"roles": ["registrant"], "handle": "REG-1",
             "vcardArray": ["vcard",
                            [["fn", {}, "text", "Example Org"]]]},
        ],
        "events": [
            {"eventAction": "registration",
             "eventDate": "2020-01-01T00:00:00Z"},
            {"eventAction": "expiration",
             "eventDate": "2027-06-01T00:00:00Z"},
        ],
        "nameservers": [{"ldhName": "ns1.example.com"}],
        "status": ["active"],
    }

    def _ctx(self):
        return {"url": "https://example.com", "host": "example.com",
                "domain": "example.com", "authorized": False, "timeout": 5,
                "html": "", "headers": {}, "cookie_headers": [],
                "status": 200, "ips": [], "pages": [], "scripts": [],
                "subdomains": [], "tls": {}}

    def test_rdap_owner_and_expiry(self):
        with mock.patch("supernova.engines.owner.fetch_json",
                        return_value=(self.RDAP, None)):
            out = owner.run(self._ctx())
        self.assertEqual(out["data"]["registrar"],
                         "Example Registrar, Inc.")
        self.assertEqual(out["data"]["registrant"], "Example Org")
        self.assertEqual(out["data"]["registrant_id"], "REG-1")
        self.assertEqual(out["data"]["handle"], "12345-DOMAIN")
        self.assertGreater(out["data"]["days_left"], 100)
        self.assertEqual(out["data"]["nameservers"],
                         ["ns1.example.com"])
        self.assertEqual(out["findings"], [])

    def test_expiry_soon_is_flagged(self):
        import datetime
        soon = (datetime.datetime.utcnow()
                + datetime.timedelta(days=10)).strftime(
                    "%Y-%m-%dT%H:%M:%SZ")
        rdap = dict(self.RDAP)
        rdap["events"] = [
            {"eventAction": "registration",
             "eventDate": "2020-01-01T00:00:00Z"},
            {"eventAction": "expiration", "eventDate": soon},
        ]
        with mock.patch("supernova.engines.owner.fetch_json",
                        return_value=(rdap, None)):
            out = owner.run(self._ctx())
        self.assertEqual(out["data"]["days_left"], 9)
        self.assertTrue(any("expires soon" in f["name"]
                            for f in out["findings"]))


class TestResourcesEngine(unittest.TestCase):
    def test_assets_and_broken(self):
        with Lab() as lab:
            ctx = lab_ctx(lab.url)
            ctx["scripts"] = [lab.url + "app.js",
                              lab.url + "jquery-1.12.4.min.js"]
            out = resources.run(ctx)
        self.assertGreaterEqual(out["data"]["count"], 4)
        broken = [r["url"] for r in out["data"]["broken"]]
        self.assertTrue(any(u.endswith("/missing.png") for u in broken))
        self.assertGreater(out["data"]["total_kb"], 0)
        self.assertTrue(any("broken resources" in f["name"]
                            for f in out["findings"]))


class TestVerify(unittest.TestCase):
    def test_verify_finds_secret_in_public_js_without_showing_it(self):
        with Lab() as lab:
            scan = {"target": lab.url,
                    "results": {
                        "crawl": {"data": {
                            "pages": [{"url": lab.url}],
                            "scripts": [lab.url + "app.js"]}},
                        "fuzz": {"data": {"interesting": []}}}}
            out = verify_mod.verify_secret(scan, "secret12345")
        self.assertEqual(len(out["found"]), 1)
        self.assertTrue(out["found"][0]["where"].endswith("/app.js"))
        self.assertNotIn("secret12345", json.dumps(out))
        absent = verify_mod.verify_secret(scan, "definitely-not-here-xyz")
        self.assertEqual(absent["found"], [])


class TestShodanEngine(unittest.TestCase):
    def test_not_configured_without_key(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("SHODAN_API_KEY", None)
            out = shodan.run({"ips": ["1.2.3.4"]})
        self.assertEqual(out["status"], "not_configured")


class TestOrchestrator(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._cwd = os.getcwd()
        os.chdir(self.tmp)

    def tearDown(self):
        os.chdir(self._cwd)

    def test_quick_scan_on_lab(self):
        with Lab() as lab:
            scan = engine_mod.run_scan(lab.url, profile="quick",
                                       scope=None)
        self.assertEqual(scan["tool"], "Super Nova v1.00")
        self.assertIsInstance(scan["score"], int)
        self.assertEqual(scan["coverage"]["percent"], 100)
        self.assertEqual(set(scan["engine_status"]),
                         {"web", "crawl", "tls", "tech", "api", "deps"})
        self.assertLess(scan["duration_s"], 90)

    def test_deep_scan_on_lab_authorized(self):
        scope = Scope(base_dir=self.tmp)
        with Lab() as lab:
            scope.authorize(lab.url)
            scan = engine_mod.run_scan(lab.url, profile="deep",
                                       scope=scope)
        self.assertIsInstance(scan["score"], int)
        self.assertGreaterEqual(scan["coverage"]["percent"], 80)
        names = [f["name"] for f in scan["findings"]]
        self.assertIn("Git repository exposed (.git/HEAD is public)", names)
        self.assertIn("network", scan["engine_status"])
        self.assertIn("fuzz", scan["engine_status"])
        self.assertIn("owner", scan["engine_status"])
        self.assertIn("resources", scan["engine_status"])
        self.assertIn("dns", scan["engine_status"])
        self.assertEqual(scan["engine_status"]["owner"]["status"],
                         "completed")
        self.assertEqual(scan["engine_status"]["resources"]["status"],
                         "completed")
        self.assertLess(scan["duration_s"], 180)

    def test_dead_target_is_incomplete_not_zero(self):
        scan = engine_mod.run_scan("http://127.0.0.1:9/", profile="quick",
                                   scope=None)
        self.assertIsNone(scan["score"])
        self.assertEqual(scan["grade"], "INCOMPLETE")
        self.assertTrue(scan["unreachable"])
        self.assertLess(scan["duration_s"], 90)

    def test_scan_saved_to_sqlite(self):
        with Lab() as lab:
            scan = engine_mod.run_scan(lab.url, profile="quick",
                                       scope=None)
            db = os.path.join(self.tmp, "supernova-scans.db")
            scan_id = storage_mod.save_scan(db, scan)
            rows = storage_mod.list_scans(db)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["id"], scan_id)
        self.assertEqual(rows[0]["target"], lab.url.rstrip("/"))


if __name__ == "__main__":
    unittest.main()
