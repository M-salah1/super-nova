#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""API Intelligence engine — public API surface discovery.

Read-only GETs only. Discovers the public API surface from:
  1. well-known OpenAPI / Swagger paths (openapi.json, swagger.json,
     /api/docs, /api/openapi.json, ...),
  2. endpoint-like paths found in the homepage's own JavaScript
     (fetch/XHR URLs starting with /api/),
  3. robots.txt / sitemap.xml mentions of /api/ paths.

A 401/403 on a docs path means authentication is required — that is
information, never a finding. No authentication is ever attempted,
no POST/PUT/DELETE is ever sent, and no request body is ever sent.
Only endpoint PATHS are reported — never request/response bodies,
never keys, tokens or values.
"""
import re
import urllib.parse

from ..core.http import get

NAME = "api"
TITLE = "API Intelligence (OpenAPI)"

WELL_KNOWN = [
    "/openapi.json", "/swagger.json", "/api/openapi.json",
    "/api/swagger.json", "/api/docs", "/swagger-ui.html",
    "/api/docs/swagger.json", "/docs/openapi.json",
]

API_PATH_RE = re.compile(
    r"""["'`](/api/[A-Za-z0-9/_\-{}.?=&%]+)["'`]""")
FETCH_RE = re.compile(
    r"""(?:fetch|axios\.(?:get|post)|XMLHttpRequest)\s*\(\s*["'`]([^"'`]+)""",
    re.I)


def _is_openapi_doc(body):
    """True if a JSON body looks like an OpenAPI/Swagger definition."""
    low = (body or "")[:2000].lower()
    return ("\"openapi\"" in low or "\"swagger\"" in low) and (
        "\"paths\"" in low or "\"info\"" in low)


def _openapi_paths(body):
    """Endpoint paths listed inside an OpenAPI JSON body (keys only)."""
    import json
    try:
        doc = json.loads(body or "")
    except Exception:
        return []
    paths = doc.get("paths") or {}
    if not isinstance(paths, dict):
        return []
    return sorted(str(p) for p in paths)[:50]


def run(ctx):
    base = (ctx.get("url") or "").rstrip("/")
    host = ctx.get("host") or ""
    timeout = ctx.get("timeout", 8)
    findings = []
    endpoints = set()
    docs = []
    auth_required = False
    sources = []
    if ctx.get("status") is None:
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "homepage unreachable"}}
    # 1. Well-known OpenAPI / docs paths (read-only GET).
    for path in WELL_KNOWN:
        url = base + path
        r = get(url, timeout=timeout, max_bytes=200000)
        status = r.get("status")
        if status in (401, 403):
            auth_required = True
            docs.append({"path": path, "status": status,
                         "auth_required": True})
            continue
        if status != 200 or not r.get("body"):
            continue
        body = r.get("body") or ""
        is_doc = _is_openapi_doc(body)
        entry = {"path": path, "status": status,
                 "auth_required": False, "openapi": is_doc}
        docs.append(entry)
        if is_doc:
            sources.append(path)
            for p in _openapi_paths(body):
                endpoints.add(p)
    # 2. Endpoint paths in the site's own JavaScript.
    scripts = ctx.get("scripts") or []
    if not scripts:
        scripts = re.findall(
            r'<script[^>]+src\s*=\s*["\']([^"\']+)',
            ctx.get("html") or "", re.I)[:5]
    for url in scripts[:5]:
        full = url if url.startswith("http") else base + url \
            if url.startswith("/") else url
        try:
            if urllib.parse.urlparse(full).netloc not in ("", host):
                continue
        except Exception:
            continue
        r = get(full, timeout=timeout, max_bytes=200000)
        body = r.get("body") or ""
        if not body:
            continue
        for m in API_PATH_RE.finditer(body):
            endpoints.add(m.group(1).split("?")[0])
        for m in FETCH_RE.finditer(body):
            u = m.group(1)
            if u.startswith("/api/"):
                endpoints.add(u.split("?")[0])
    # 3. robots.txt / sitemap.xml mentions of /api/.
    for path in ("/robots.txt", "/sitemap.xml"):
        r = get(base + path, timeout=timeout, max_bytes=200000)
        body = r.get("body") or ""
        for m in re.finditer(r"/api/[A-Za-z0-9/_\-]+", body):
            endpoints.add(m.group(0))
    endpoints = sorted(endpoints)[:50]
    data = {"endpoints": endpoints, "endpoint_count": len(endpoints),
            "docs": docs, "docs_found": [d["path"] for d in docs
                                         if d.get("openapi")],
            "auth_required": auth_required, "sources": sources}
    if data["docs_found"]:
        findings.append({
            "severity": "info",
            "name": "Public API documentation found: %s"
                    % ", ".join(data["docs_found"][:3]),
            "evidence": "%d OpenAPI/Swagger document(s) publicly readable"
                        % len(data["docs_found"]),
            "fix": "Protect API docs behind authentication if they are "
                   "internal-only."})
    if endpoints:
        findings.append({
            "severity": "info",
            "name": "Public API surface: %d endpoint path(s) discovered"
                    % len(endpoints),
            "evidence": "e.g. %s" % endpoints[0],
            "fix": "Review that every listed endpoint enforces "
                   "authentication and authorization."})
    if auth_required:
        findings.append({
            "severity": "info",
            "name": "Some API docs require authentication",
            "evidence": "a docs path answered 401/403 — auth required, "
                        "not a vulnerability",
            "fix": "No action — authentication is working as intended."})
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
