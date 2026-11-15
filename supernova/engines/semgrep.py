#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""JS Static Analysis engine — Semgrep style.

Fetches the site's public JavaScript files and matches them against
dangerous code patterns (eval, innerHTML sinks, document.write,
insecure randomness, hardcoded credential names). Static text
matching only — nothing is executed, values are never printed.
"""
import re
import urllib.parse

from ..core.http import get

NAME = "semgrep"
TITLE = "JS Static Analysis (Semgrep)"

# (pattern, severity, name, fix)
RULES = [
    (r"\beval\s*\(", "high", "Use of eval() in public JavaScript",
     "Remove eval(); use JSON.parse or safe alternatives."),
    (r"\.innerHTML\s*=", "medium", "innerHTML sink in public JavaScript",
     "Use textContent or a sanitizer before inserting HTML."),
    (r"document\.write\s*\(", "medium", "document.write() in public JavaScript",
     "Avoid document.write; build DOM nodes instead."),
    (r"Math\.random\(\)", "low", "Math.random() used (not cryptographic)",
     "Use crypto.getRandomValues() for tokens or secrets."),
    (r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][^'\"]+",
     "high", "Hardcoded credential name in public JavaScript",
     "Move credentials to the server; never ship them in JS."),
    (r"localStorage\s*\[\s*['\"]password", "high",
     "Password stored in localStorage",
     "Never store passwords in localStorage."),
    (r"location\.href\s*=\s*[^;]*\+", "medium",
     "Open redirect pattern (location.href with concatenation)",
     "Validate redirect targets against an allow-list."),
    (r"\.outerHTML\s*=", "medium", "outerHTML sink in public JavaScript",
     "Use textContent or a sanitizer before inserting HTML."),
]


def run(ctx):
    if ctx.get("status") is None:
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "homepage unreachable"}}
    findings = []
    checked = []
    host = ctx.get("host") or ""
    scripts = ctx.get("scripts") or []
    if not scripts:
        # Fall back to script URLs found in the homepage HTML.
        scripts = re.findall(r'<script[^>]+src\s*=\s*["\']([^"\']+)',
                             ctx.get("html") or "", re.I)[:5]
    internal = []
    external = []
    for url in scripts:
        if url.startswith("/"):
            internal.append((ctx.get("url") or "").rstrip("/") + url)
        elif url.startswith("http"):
            try:
                if urllib.parse.urlparse(url).netloc == host:
                    internal.append(url)
                else:
                    external.append(url)
            except Exception:
                continue
    # Only the site's own code is the site's problem. Third-party
    # libraries are reported separately, never as site findings.
    for url in internal[:10]:
        r = get(url, timeout=ctx.get("timeout", 8), max_bytes=200000)
        body = r.get("body") or ""
        if not body:
            continue
        checked.append(url)
        for pattern, sev, name, fix in RULES:
            try:
                m = re.search(pattern, body)
            except re.error:
                continue
            if m:
                findings.append({"severity": sev, "name": name,
                                 "confirmation": "confirmed",
                                 "evidence": "%s: pattern %r (line value "
                                             "redacted)" % (url[:80], name),
                                 "fix": fix})
    for url in external:
        r = get(url, timeout=ctx.get("timeout", 8), max_bytes=200000)
        body = r.get("body") or ""
        if not body:
            continue
        for pattern, sev, name, fix in RULES:
            try:
                m = re.search(pattern, body)
            except re.error:
                continue
            if m:
                findings.append({
                    "severity": "info", "confirmation": "indicator",
                    "name": "Pattern in third-party script: %s" % name,
                    "evidence": "%s (external library — not the site's "
                                "own code)" % url[:80],
                    "fix": "Check whether the library version is "
                           "outdated; the site's own code is not at "
                           "fault here."})
                break
    # De-duplicate by rule name.
    seen = set()
    unique = []
    for f in findings:
        if f["name"] not in seen:
            seen.add(f["name"])
            unique.append(f)
    return {"engine": NAME, "status": "completed",
            "findings": unique,
            "data": {"checked": checked, "rules": len(RULES),
                     "hits": len(unique),
                     "internal_scripts": len(internal),
                     "external_scripts": len(external)}}
