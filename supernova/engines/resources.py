#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Resource Inventory engine — what the site is made of.

Collects every public asset the homepage references (scripts,
stylesheets, images, fonts), fetches each one (bounded, parallel)
and reports status, size and origin (internal / external). Broken
assets are flagged. Only public URLs the site itself publishes.
"""
import concurrent.futures
import re
import urllib.parse

from ..core.http import request

NAME = "resources"
TITLE = "Resource Inventory"


def _asset_urls(base, html):
    urls = set()
    for pat in (r'<script[^>]+src\s*=\s*["\']([^"\']+)',
                r'<link[^>]+href\s*=\s*["\']([^"\']+)',
                r'<img[^>]+src\s*=\s*["\']([^"\']+)',
                r'<source[^>]+src\s*=\s*["\']([^"\']+)'):
        for u in re.findall(pat, html, re.I):
            full = urllib.parse.urljoin(base, u.split("#")[0])
            if full.startswith(("http://", "https://")):
                urls.add(full)
    return sorted(urls)


def _probe(url, timeout):
    r = request(url, timeout=timeout, max_bytes=100000)
    ctype = ""
    try:
        ctype = str(dict(r.get("headers") or {}).get("Content-Type", ""))
    except Exception:
        pass
    return {"url": url, "status": r.get("status"),
            "size": len(r.get("body") or ""),
            "type": ctype.split(";")[0]}


def run(ctx):
    base = ctx.get("url") or ""
    host = ctx.get("host") or ""
    html = ctx.get("html") or ""
    if ctx.get("status") is None:
        return {"engine": NAME, "status": "error",
                "findings": [], "data": {"error": "homepage unreachable"}}
    urls = _asset_urls(base, html)
    for u in (ctx.get("scripts") or []):
        if u not in urls:
            urls.append(u)
    urls = urls[:25]
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(_probe, u, ctx.get("timeout", 8)): u
                for u in urls}
        for fut in futs:
            try:
                results.append(fut.result())
            except Exception:
                results.append({"url": futs[fut], "status": None,
                                "size": 0, "type": ""})
    broken = [r for r in results if r.get("status") != 200]
    internal = [r for r in results
                if urllib.parse.urlparse(r["url"]).netloc == host]
    findings = []
    if broken:
        findings.append({
            "severity": "low",
            "name": "%d broken resources" % len(broken),
            "evidence": ", ".join(r["url"][:80] for r in broken[:3]),
            "fix": "Fix or remove the broken resource links."})
    return {"engine": NAME, "status": "completed", "findings": findings,
            "data": {"assets": results, "count": len(results),
                     "total_kb": round(sum(r["size"] for r in results)
                                       / 1024, 1),
                     "broken": broken, "internal": len(internal),
                     "external": len(results) - len(internal)}}
