#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Path Fuzzing engine — FFUF style (v1.00).

Bounded parallel wordlist probing of public paths. Every answer is
classified: a 200 is only "interesting" when it is real content
(not an error page wearing 200); 403 means forbidden — not a
finding; 301/302 is a redirect; 401 needs authentication. A
sensitive path is only reported when its content structurally
matches what it claims to be. Authorized targets only.
"""
import concurrent.futures

from ..core import content as content_mod
from ..core.http import request

NAME = "fuzz"
TITLE = "Path Fuzzer (FFUF)"

WORDLIST = [
    "/robots.txt", "/sitemap.xml", "/security.txt",
    "/.well-known/security.txt", "/admin", "/login", "/register",
    "/signup", "/dashboard", "/api", "/api/docs", "/swagger.json",
    "/openapi.json", "/.git/HEAD", "/.env", "/wp-admin", "/wp-login.php",
    "/wp-config.php", "/config.php", "/backup.zip", "/db.sql",
    "/.env.bak", "/sitemap_index.xml", "/about", "/contact", "/privacy",
    "/terms", "/feed", "/rss.xml", "/static", "/assets", "/uploads",
    "/images", "/css", "/js", "/health", "/status", "/metrics",
    "/.well-known/robots.txt", "/.htaccess", "/crossdomain.xml",
    "/clientaccesspolicy.xml", "/.git/config", "/.svn/entries",
    "/.DS_Store", "/phpinfo.php", "/server-status", "/.bash_history",
    "/web.config", "/composer.json", "/package.json", "/.npmrc",
    "/.dockerignore", "/Dockerfile", "/.gitlab-ci.yml", "/.travis.yml",
    "/README.md", "/CHANGELOG.md", "/LICENSE", "/.idea/", "/.vscode/",
    "/debug", "/test", "/old", "/bak", "/backup", "/tmp",
]

SENSITIVE = {"/.git/HEAD", "/.env", "/wp-config.php", "/backup.zip",
             "/db.sql", "/.git/config", "/.env.bak"}


def _probe(base, path, timeout, error_fp):
    r = request(base + path, timeout=timeout, max_bytes=5000)
    body = r.get("body") or ""
    ctype = ""
    try:
        ctype = (r.get("headers") or {}).get("Content-Type", "") or ""
    except Exception:
        pass
    verdict = content_mod.classify(r.get("status"), ctype,
                                   len(body), body, error_fp)
    return {"path": path, "status": r.get("status"),
            "size": len(body), "kind": verdict["kind"],
            "detail": verdict["detail"], "error": r.get("error"),
            "content_type": ctype, "body": body}


def run(ctx):
    if not ctx.get("authorized"):
        return {"engine": NAME, "status": "not_tested",
                "findings": [], "data": {"note": "needs authorization"}}
    base = (ctx.get("url") or "").rstrip("/")
    timeout = min(ctx.get("timeout", 8), 8)
    error_fp = content_mod.fingerprint_error_page(base, timeout=timeout)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(_probe, base, p, timeout, error_fp): p
                for p in WORDLIST}
        for fut in futs:
            try:
                results.append(fut.result(timeout=timeout + 5))
            except Exception as exc:
                results.append({"path": futs[fut], "status": None,
                                "size": 0, "kind": "unreachable",
                                "detail": "", "error": str(exc),
                                "content_type": "", "body": ""})
    by_kind = {}
    for e in results:
        by_kind[e["kind"]] = by_kind.get(e["kind"], 0) + 1
    interesting = [e for e in results if e.get("kind") == "ok"]
    findings = []
    for e in interesting:
        if e["path"] not in SENSITIVE:
            continue
        confirmed, detail = content_mod.analyze_sensitive(
            e["path"], e.get("content_type", ""), e["size"],
            e.get("body", ""))
        if confirmed:
            findings.append({
                "severity": "high", "confirmation": "confirmed",
                "name": "Sensitive path publicly reachable: %s" % e["path"],
                "evidence": "%s -> HTTP 200 (%s, %s)"
                            % (e["path"], e.get("content_type") or "?",
                               detail),
                "fix": "Remove or block %s on the web server." % e["path"]})
    # The report shows statuses and sizes, not bodies.
    for e in results:
        e.pop("body", None)
    return {"engine": NAME, "status": "completed", "findings": findings,
            "data": {"probed": len(results), "interesting": interesting,
                     "by_kind": by_kind, "results": results}}
