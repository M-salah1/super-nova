#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WordPress Audit engine — WPScan style (detection only).

Detects WordPress from public markers, reads the public version
(generator meta / readme.html / wp-json), enumerates publicly
listed themes and plugins, and checks the public REST API.
No login, no brute force, no exploitation — version numbers are
public facts; "outdated" only means "older than the current floor".
"""
import re

from ..core.http import get

NAME = "wordpress"
TITLE = "WordPress Audit (WPScan)"

CURRENT_FLOOR = (6, 0)


def _version_tuple(v):
    try:
        parts = [int(p) for p in v.split(".")[:3]]
        return tuple(parts + [0] * (3 - len(parts)))
    except Exception:
        return None


def run(ctx):
    if ctx.get("status") is None:
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "homepage unreachable"}}
    html = ctx.get("html") or ""
    base = (ctx.get("url") or "").rstrip("/")
    timeout = ctx.get("timeout", 8)
    findings = []
    data = {"detected": False, "version": None, "themes": [],
            "plugins": [], "rest_api": False}
    is_wp = ("wp-content" in html or "wp-includes" in html
             or "/wp-json/" in html)
    if not is_wp:
        r = get(base + "/wp-json/", timeout=timeout, max_bytes=20000)
        if r.get("status") == 200 and "wp" in (r.get("body") or "").lower():
            is_wp = True
    if not is_wp:
        return {"engine": NAME, "status": "completed",
                "findings": [], "data": data}
    data["detected"] = True
    m = re.search(r'<meta[^>]+name\s*=\s*["\']generator["\'][^>]+content\s*=\s*["\']WordPress\s+([\d.]+)',
                  html, re.I)
    version = m.group(1) if m else None
    if not version:
        r = get(base + "/readme.html", timeout=timeout, max_bytes=20000)
        m2 = re.search(r"Version\s+([\d.]+)", r.get("body") or "", re.I)
        version = m2.group(1) if m2 else None
    data["version"] = version
    themes = sorted(set(re.findall(r"wp-content/themes/([\w-]+)", html)))
    plugins = sorted(set(re.findall(r"wp-content/plugins/([\w-]+)", html)))
    data["themes"] = themes[:20]
    data["plugins"] = plugins[:20]
    r = get(base + "/wp-json/wp/v2/", timeout=timeout, max_bytes=20000)
    data["rest_api"] = r.get("status") == 200
    if version:
        vt = _version_tuple(version)
        if vt and vt < CURRENT_FLOOR:
            findings.append({"severity": "medium",
                             "name": "Outdated WordPress %s" % version,
                             "evidence": "public version %s" % version,
                             "fix": "Update WordPress to the latest release."})
        else:
            findings.append({"severity": "info",
                             "name": "WordPress %s detected" % version,
                             "evidence": "public generator meta",
                             "fix": "Keep WordPress, themes and plugins updated."})
    if data["rest_api"]:
        findings.append({"severity": "low",
                         "name": "WordPress REST API is public",
                         "evidence": "/wp-json/wp/v2/ -> HTTP 200",
                         "fix": "Restrict the REST API if user enumeration "
                                "or post listing is not needed publicly."})
    if plugins:
        findings.append({"severity": "info",
                         "name": "%d plugins publicly visible" % len(plugins),
                         "evidence": ", ".join(plugins[:5]),
                         "fix": "Audit every listed plugin for known "
                                "vulnerabilities and remove unused ones."})
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
