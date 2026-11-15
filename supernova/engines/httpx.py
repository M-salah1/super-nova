#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Live HTTP Probe engine — httpx style.

For every discovered host (target + subdomains, capped): status,
title, server, content length, TLS presence. Answers one question:
which of the discovered names actually serve a website?
"""
import concurrent.futures
import re

from ..core.http import request

NAME = "httpx"
TITLE = "Live HTTP Probe (httpx)"


def _probe(host, timeout=8):
    out = {"host": host, "url": None, "status": None, "title": None,
           "server": None, "length": None, "tls": False}
    for scheme in ("https", "http"):
        url = "%s://%s/" % (scheme, host)
        r = request(url, timeout=timeout, max_bytes=50000)
        if r.get("status"):
            out.update({"url": r.get("final_url") or url,
                        "status": r.get("status"),
                        "server": (dict(r.get("headers") or {})
                                   .get("Server", ""))[:60],
                        "length": len(r.get("body") or ""),
                        "tls": scheme == "https"})
            m = re.search(r"<title[^>]*>(.*?)</title>", r.get("body") or "",
                          re.I | re.S)
            if m:
                out["title"] = re.sub(r"\s+", " ", m.group(1)).strip()[:80]
            return out
    out["error"] = "no response"
    return out


def run(ctx):
    hosts = []
    target_host = ctx.get("host") or ""
    if target_host:
        hosts.append(target_host)
    for sub in (ctx.get("subdomains") or [])[:9]:
        if sub not in hosts:
            hosts.append(sub)
    timeout = ctx.get("timeout", 8)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
        futs = {pool.submit(_probe, h, timeout): h for h in hosts}
        for fut in futs:
            try:
                results.append(fut.result())
            except Exception:
                pass
    live = [r for r in results if r.get("status")]
    return {"engine": NAME, "status": "completed", "findings": [],
            "data": {"hosts": results, "live": len(live),
                     "total": len(hosts)}}
