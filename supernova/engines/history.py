#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Historical Discovery engine — GAU style.

Queries the public Wayback Machine CDX API for URLs the domain had
in the past: old pages, forgotten endpoints, archived files. Public
archive data only, no key needed.
"""
import urllib.parse

from ..core.http import fetch_json

NAME = "history"
TITLE = "Historical Discovery (GAU)"


def run(ctx):
    domain = ctx.get("domain") or ""
    timeout = ctx.get("timeout", 12)
    findings = []
    data = {"domain": domain, "urls": [], "count": 0, "first": None,
            "last": None, "error": None}
    if not domain or "." not in domain or domain.startswith("127.") \
            or domain == "localhost":
        data["note"] = "Local test target — no archive history exists."
        return {"engine": NAME, "status": "completed",
                "findings": [], "data": data}
    q = ("https://web.archive.org/cdx/search/cdx?url=%s/*"
         "&output=json&limit=300&collapse=urlkey&fl=timestamp,original"
         "&filter=statuscode:200" % urllib.parse.quote(domain))
    rows, err = fetch_json(q, timeout=timeout, max_bytes=1000000)
    if not rows:
        data["error"] = err or "no archived URLs"
        return {"engine": NAME, "status": "completed",
                "findings": [], "data": data}
    urls = []
    stamps = []
    for row in rows[1:]:
        if len(row) >= 2:
            stamps.append(row[0])
            urls.append(row[1])
    data["urls"] = sorted(set(urls))[:100]
    data["count"] = len(set(urls))
    if stamps:
        data["first"] = min(stamps)
        data["last"] = max(stamps)
    interesting = [u for u in data["urls"]
                   if any(k in u.lower() for k in
                          ("admin", "login", "backup", ".zip", ".sql",
                           "config", "old", "test", "dev", ".bak"))]
    if interesting:
        findings.append({"severity": "low",
                         "name": "Historical URLs include sensitive paths",
                         "evidence": "%d archived URLs, e.g. %s"
                                     % (data["count"], interesting[0][:100]),
                         "fix": "Check that old/archived paths are not "
                                "still live on the server."})
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
