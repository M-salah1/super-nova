#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Vulnerability Detection engine — Nuclei / Nikto style (v1.00).

Template-based checks, now content-aware: a bare HTTP 200 proves
nothing. Each response is classified (real file / error page wearing
200 / redirect / forbidden / absent) and, for sensitive files, its
body must structurally match what the path claims to be (.env must
have KEY= lines, .sql must have SQL keywords, .git/HEAD must start
with "ref:"). robots.txt and API docs are information, never
vulnerabilities. Only key NAMES are ever reported — values are
never extracted, stored or shown.
"""
from ..core import content as content_mod
from ..core.http import request

NAME = "vuln"
TITLE = "Vulnerability Detection (Nuclei)"

# (path, severity, name, kind, fix)
# kind: "sensitive" (must be content-confirmed) | "info" (public info)
TEMPLATES = [
    ("/.git/HEAD", "high", "Git repository exposed (.git/HEAD is public)",
     "sensitive", "Block access to /.git/ on the web server."),
    ("/.env", "critical", "Environment file exposed (.env is public)",
     "sensitive", "Move .env outside the web root; block dotfiles."),
    ("/.env.bak", "high", "Backup environment file exposed",
     "sensitive", "Delete backup files from the web root."),
    ("/wp-config.php", "high", "WordPress config exposed",
     "sensitive", "Block access to wp-config.php."),
    ("/config.php", "medium", "Config file publicly readable",
     "sensitive", "Block direct access to config files."),
    ("/backup.zip", "high", "Backup archive publicly downloadable",
     "sensitive", "Move backups outside the web root."),
    ("/db.sql", "high", "Database dump publicly downloadable",
     "sensitive", "Move database dumps outside the web root."),
    ("/phpinfo.php", "medium", "phpinfo() page exposed",
     "sensitive", "Remove phpinfo pages from production."),
    ("/server-status", "medium", "Apache server-status exposed",
     "sensitive", "Restrict /server-status to localhost only."),
    ("/.DS_Store", "low", "macOS metadata file exposed",
     "sensitive", "Delete .DS_Store files from the web root."),
    ("/.svn/entries", "medium", "Subversion metadata exposed",
     "sensitive", "Block access to /.svn/ on the web server."),
    ("/api/docs", "info", "API documentation publicly exposed",
     "info", "Protect API docs behind authentication if they are internal."),
    ("/swagger.json", "info", "OpenAPI definition publicly exposed",
     "info", "Protect API definitions if they are internal."),
    ("/admin", "low", "Admin panel reachable without prior check",
     "info", "Protect /admin with strong authentication and rate limiting."),
    ("/.well-known/security.txt", "info",
     "security.txt present (good practice)",
     "info", "Keep security.txt up to date."),
    ("/robots.txt", "info", "robots.txt present",
     "info", "Check robots.txt does not list sensitive paths."),
]


def run(ctx):
    base = (ctx.get("url") or "").rstrip("/")
    timeout = ctx.get("timeout", 8)
    findings = []
    checked = []
    error_fp = content_mod.fingerprint_error_page(base, timeout=timeout)
    for path, sev, name, kind, fix in TEMPLATES:
        r = request(base + path, timeout=timeout, max_bytes=20000)
        body = r.get("body") or ""
        ctype = ""
        try:
            ctype = (r.get("headers") or {}).get("Content-Type", "") or ""
        except Exception:
            pass
        verdict = content_mod.classify(r.get("status"), ctype,
                                       len(body), body, error_fp)
        checked.append({"path": path, "status": r.get("status"),
                        "kind": verdict["kind"],
                        "detail": verdict["detail"]})
        if verdict["kind"] != "ok":
            continue
        if kind == "info":
            findings.append({
                "severity": sev, "name": name, "confirmation": "confirmed",
                "evidence": "%s -> HTTP 200 (%s, %d bytes)"
                            % (path, ctype or "?", len(body)),
                "fix": fix})
            continue
        confirmed, detail = content_mod.analyze_sensitive(
            path, ctype, len(body), body)
        if confirmed:
            findings.append({
                "severity": sev, "name": name, "confirmation": "confirmed",
                "evidence": "%s -> HTTP 200 (%s, %d bytes, %s)"
                            % (path, ctype or "?", len(body), detail),
                "fix": fix})
    return {"engine": NAME, "status": "completed",
            "findings": findings,
            "data": {"templates": len(TEMPLATES), "checked": checked,
                     "hits": len(findings),
                     "error_page": (error_fp or {}).get("sample", "")}}
