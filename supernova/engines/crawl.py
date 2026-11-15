#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Crawler engine — Katana style.

Breadth-first crawl of same-host pages (bounded pages/depth),
collecting internal links, forms, scripts, stylesheets and
public e-mail addresses from the site's own pages.
"""
import re
import urllib.parse

from ..core.http import get

NAME = "crawl"
TITLE = "Crawler (Katana)"


def _links(base, html):
    out = set()
    for href in re.findall(r'href\s*=\s*["\']([^"\']+)', html, re.I):
        full = urllib.parse.urljoin(base, href.split("#")[0])
        if full.startswith(("http://", "https://")):
            out.add(full)
    return out


def run(ctx):
    base = ctx.get("url") or ""
    host = ctx.get("host") or ""
    timeout = ctx.get("timeout", 8)
    max_pages = int(ctx.get("max_pages", 15))
    queue = [base]
    seen = set()
    pages = []
    scripts = set()
    styles = set()
    emails = set()
    forms = 0
    while queue and len(pages) < max_pages:
        url = queue.pop(0)
        if url in seen:
            continue
        seen.add(url)
        r = get(url, timeout=timeout, max_bytes=200000)
        if r.get("status") != 200 or not r.get("body"):
            continue
        body = r["body"]
        pages.append({"url": url, "status": r["status"],
                      "title": (re.search(r"<title[^>]*>(.*?)</title>", body,
                                          re.I | re.S).group(1).strip()[:80]
                                if re.search(r"<title[^>]*>(.*?)</title>",
                                             body, re.I | re.S) else "")})
        forms += len(re.findall(r"<form\b", body, re.I))
        for src in re.findall(r'<script[^>]+src\s*=\s*["\']([^"\']+)',
                              body, re.I):
            scripts.add(urllib.parse.urljoin(url, src))
        for href in re.findall(
                r'<link[^>]+rel\s*=\s*["\']stylesheet["\'][^>]+href\s*=\s*["\']([^"\']+)',
                body, re.I):
            styles.add(urllib.parse.urljoin(url, href))
        for mail in re.findall(r"[\w.+-]+@[\w-]+\.[\w.]+", body):
            emails.add(mail)
        for link in _links(url, body):
            if link not in seen and len(queue) < max_pages * 2:
                try:
                    if urllib.parse.urlparse(link).netloc == host:
                        queue.append(link)
                except Exception:
                    pass
    return {"engine": NAME, "status": "completed", "findings": [],
            "data": {"pages": pages, "page_count": len(pages),
                     "discovered": len(seen),
                     "scripts": sorted(scripts)[:20],
                     "stylesheets": sorted(styles)[:20],
                     "emails": sorted(emails)[:10], "forms": forms}}
