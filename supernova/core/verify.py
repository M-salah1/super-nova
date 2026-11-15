#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Verification Mode — compare an owner-provided value without ever
displaying it.

The settled rule: a displayed secret is a leaked secret (terminal
scrollback, screenshots, saved reports). So the operator types the
value hidden (getpass); Super Nova re-fetches in memory the public places
the scan found and answers YES/NO + location only. The value never
appears in any result, report or log, and the local reference is
wiped after the check.

Note: cookie values are never collected by any Super Nova engine (names and
flags only), so they cannot be compared here — only public content.
"""
from ..core.http import get


def candidate_urls(scan):
    """Public URLs the scan found, capped at 25."""
    urls = []

    def add(u):
        if u and u not in urls and len(urls) < 25:
            urls.append(u)

    add(scan.get("target"))
    res = scan.get("results") or {}
    crawl = (res.get("crawl") or {}).get("data") or {}
    for p in crawl.get("pages") or []:
        add(p.get("url"))
    for s in crawl.get("scripts") or []:
        add(s)
    fuzz = (res.get("fuzz") or {}).get("data") or {}
    for e in fuzz.get("interesting") or []:
        add((scan.get("target") or "").rstrip("/") + e.get("path", ""))
    return urls


def verify_secret(scan, secret, timeout=10):
    """Check whether `secret` appears in any public place the scan
    found. Returns {"found": [{where, kind}], "checked": n} — the
    secret itself is never in the result."""
    found = []
    checked = 0
    for url in candidate_urls(scan):
        r = get(url, timeout=timeout, max_bytes=200000)
        checked += 1
        if r.get("body") and secret in r["body"]:
            found.append({"where": url, "kind": "public content"})
    return {"found": found, "checked": checked}
