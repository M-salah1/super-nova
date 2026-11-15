#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Secret Exposure engine — Gitleaks style.

Scans public text the site itself serves (homepage, public JS,
robots/sitemap) for secret PATTERNS. Only the pattern name and the
place are reported — values are NEVER shown, stored or logged.
A match means "a value shaped like a secret is public here", and the
owner must rotate it.
"""
import re

from ..core.http import get

NAME = "secrets"
TITLE = "Secret Exposure (Gitleaks)"

# (name, regex) — regexes match the SHAPE of a secret, never used to
# print the value: only the match location is reported.
PATTERNS = [
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("AWS Secret Key assignment", r"aws_secret_access_key\s*=\s*['\"][^'\"]+"),
    ("Slack token", r"xox[baprs]-[0-9A-Za-z-]{10,}"),
    ("GitHub token", r"ghp_[0-9A-Za-z]{20,}"),
    ("Generic API key assignment", r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][^'\"]{8,}"),
    ("Password assignment in JS", r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}"),
    ("Private key block", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("JWT token", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}"),
    ("Google API key", r"AIza[0-9A-Za-z_-]{35}"),
    ("Database URL with credentials", r"(?i)(mysql|postgres|mongodb)://[^:\s]+:[^@\s]+@"),
]


def _scan_text(text, where, findings):
    for name, pattern in PATTERNS:
        try:
            if re.search(pattern, text):
                findings.append({
                    "severity": "high",
                    "name": "Possible exposed secret: %s" % name,
                    "evidence": "pattern %r found in %s (value redacted)"
                                % (name, where),
                    "fix": "Rotate this credential immediately and remove "
                           "it from every public file."})
        except re.error:
            continue


def run(ctx):
    if ctx.get("status") is None:
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "homepage unreachable"}}
    findings = []
    checked = []
    html = ctx.get("html") or ""
    _scan_text(html, "homepage", findings)
    checked.append("homepage")
    for url in (ctx.get("scripts") or [])[:10]:
        r = get(url, timeout=ctx.get("timeout", 8), max_bytes=200000)
        if r.get("body"):
            _scan_text(r["body"], url, findings)
            checked.append(url)
    for page in (ctx.get("pages") or [])[:5]:
        url = page.get("url") if isinstance(page, dict) else page
        if not url or url in checked:
            continue
        r = get(url, timeout=ctx.get("timeout", 8), max_bytes=200000)
        if r.get("body"):
            _scan_text(r["body"], url, findings)
            checked.append(url)
    return {"engine": NAME, "status": "completed",
            "findings": findings,
            "data": {"checked": checked, "hits": len(findings)}}
