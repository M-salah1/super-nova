#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Technology Fingerprinting engine — WhatWeb style.

Server header, X-Powered-By, generator meta tags, CMS markers and
JavaScript library versions found in public HTML and script URLs.
Everything reported comes from what the site itself publishes.
"""
import re

NAME = "tech"
TITLE = "Technology Fingerprint (WhatWeb)"

LIB_PATTERNS = [
    ("jQuery", r"jquery[-.](\d+\.\d+\.\d+)", "js"),
    ("React", r"react(?:\.production|\.min)?[-.]?(\d+\.\d+\.\d+)?", "js"),
    ("Vue.js", r"vue(?:\.min)?[-.]?(\d+\.\d+\.\d+)?", "js"),
    ("Angular", r"angular(?:\.min)?[-.]?(\d+\.\d+\.\d+)?", "js"),
    ("Bootstrap", r"bootstrap[-.](\d+\.\d+\.\d+)", "js"),
    ("WordPress", r"wp-(?:content|includes|json)", "cms"),
    ("Joomla", r"joomla", "cms"),
    ("Drupal", r"drupal", "cms"),
    ("Laravel", r"laravel", "framework"),
    ("Django", r"csrfmiddlewaretoken|django", "framework"),
    ("ASP.NET", r"asp\.net|__VIEWSTATE", "framework"),
    ("PHP", r"\.php", "lang"),
]

CMS_MARKERS = [
    ("WordPress", ["wp-content", "wp-includes", "/wp-json/"]),
    ("Joomla", ["option=com_", "/media/jui/"]),
    ("Drupal", ["sites/default/files", "drupal.js"]),
    ("Shopify", ["cdn.shopify.com"]),
    ("Wix", ["static.wixstatic.com"]),
]


def run(ctx):
    if ctx.get("status") is None:
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "homepage unreachable"}}
    html = ctx.get("html") or ""
    headers = ctx.get("headers") or {}
    scripts = ctx.get("scripts") or []
    findings = []
    tech = []
    server = headers.get("server", "")
    if server:
        tech.append({"name": "Server: %s" % server[:60], "version": None})
    powered = headers.get("x-powered-by", "")
    if powered:
        tech.append({"name": "X-Powered-By: %s" % powered[:60],
                     "version": None})
    gen = re.search(r'<meta[^>]+name\s*=\s*["\']generator["\'][^>]+content\s*=\s*["\']([^"\']+)',
                    html, re.I)
    if gen:
        tech.append({"name": "Generator: %s" % gen.group(1)[:60],
                     "version": None})
    hay = html + "\n" + "\n".join(scripts)
    for name, pattern, kind in LIB_PATTERNS:
        m = re.search(pattern, hay, re.I)
        if m:
            version = m.group(1) if m.lastindex else None
            tech.append({"name": name, "version": version, "kind": kind})
    cms = None
    for name, markers in CMS_MARKERS:
        if any(mk in html for mk in markers):
            cms = name
            break
    data = {"technologies": tech, "cms": cms,
            "server": server, "scripts": len(scripts)}
    if cms:
        findings.append({"severity": "info",
                         "name": "CMS detected: %s" % cms,
                         "evidence": "public markers in HTML",
                         "fix": "Keep %s and its plugins updated." % cms})
    old_jquery = next((t for t in tech if t["name"] == "jQuery"
                       and t.get("version")
                       and t["version"].startswith(("1.", "2."))), None)
    if old_jquery:
        findings.append({"severity": "medium",
                         "name": "Outdated jQuery %s" % old_jquery["version"],
                         "evidence": "jQuery %s in public scripts"
                                     % old_jquery["version"],
                         "fix": "Upgrade jQuery to 3.x or newer."})
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
