#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""External Intel engine — Shodan style (optional).

Queries Shodan's public host API for the target IP — open ports,
organization, OS, known CVEs listed by Shodan. Works ONLY when the
user provides their own Shodan API key in the SHODAN_API_KEY
environment variable. The key is never stored, printed or sent
anywhere except api.shodan.io. Without a key the engine reports
"not_configured" — it never invents Shodan data.
"""
import os

from ..core.http import fetch_json

NAME = "shodan"
TITLE = "External Intel (Shodan)"


def run(ctx):
    ips = ctx.get("ips") or []
    key = os.environ.get("SHODAN_API_KEY", "").strip()
    if not key:
        return {"engine": NAME, "status": "not_configured",
                "findings": [],
                "data": {"note": "Set SHODAN_API_KEY in the environment "
                                 "to enable Shodan host intelligence."}}
    if not ips:
        return {"engine": NAME, "status": "error",
                "findings": [], "data": {"error": "no IP resolved"}}
    url = ("https://api.shodan.io/shodan/host/%s?key=%s"
           % (ips[0], key))
    data, err = fetch_json(url, timeout=15, max_bytes=500000)
    if not data:
        return {"engine": NAME, "status": "error",
                "findings": [], "data": {"error": err or "Shodan query failed"}}
    findings = []
    for cve in (data.get("vulns") or [])[:10]:
        findings.append({"severity": "high",
                         "name": "Shodan reports %s" % cve,
                         "evidence": "shodan host %s" % ips[0],
                         "fix": "Check %s against the affected service "
                                "and patch it." % cve})
    return {"engine": NAME, "status": "completed", "findings": findings,
            "data": {"ip": ips[0], "org": data.get("org"),
                     "os": data.get("os"), "ports": data.get("ports"),
                     "hostnames": data.get("hostnames"),
                     "vulns": data.get("vulns") or []}}
