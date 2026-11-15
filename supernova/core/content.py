#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Content-aware response analysis — the heart of v1.00.

A bare HTTP 200 proves nothing. A server can answer 200 with an
error page, a login page, or an empty body. This module answers the
real question: is this response a REAL file, and does its content
actually look like what the path claims to be?

- fingerprint_error_page: fetch two random non-existent paths and
  learn what this server's error page looks like (status, normalized
  length, hash of the body with digits stripped).
- classify: one status code, one verdict — ok / error_page_200 /
  redirect / auth_required / forbidden / absent / rate_limited /
  server_error / unreachable.
- analyze_sensitive: does the body structurally match the file
  type (.env must have KEY= lines, .sql must have SQL keywords,
  .git/HEAD must start with "ref:")? Only key NAMES are ever
  reported — values are never extracted, stored or shown.
"""
import hashlib
import random
import re
import string

from ..core.http import get

_ERROR_MARKERS = ("404", "not found", "page introuvable", "not exist")


def _normalize(body):
    """Strip digits and collapse whitespace so dynamic bits
    (request ids, timestamps) do not change the fingerprint."""
    body = re.sub(r"\d+", "#", body or "")
    return re.sub(r"\s+", " ", body).strip()


def _fingerprint_of(body):
    norm = _normalize(body)
    return {"length": len(norm),
            "sha256": hashlib.sha256(norm.encode(errors="ignore"))
                      .hexdigest()[:16],
            "sample": norm[:120]}


def fingerprint_error_page(base, timeout=6):
    """Learn the server's error page by requesting two random paths."""
    fps = []
    for _ in range(2):
        probe = "".join(random.choice(string.ascii_lowercase)
                        for _ in range(16))
        r = get("%s/supernova-no-such-page-%s.html" % (base, probe),
                timeout=timeout, max_bytes=50000)
        if r.get("status") is not None:
            fps.append({"status": r.get("status"),
                        **_fingerprint_of(r.get("body") or "")})
    if not fps:
        return None
    # The error page is the fingerprint that repeats.
    return fps[0]


def classify(status, content_type, size, body, error_fp):
    """One verdict for one response. Returns {"kind", "detail"}."""
    if status is None:
        return {"kind": "unreachable", "detail": "no response"}
    if status in (301, 302, 303, 307, 308):
        return {"kind": "redirect",
                "detail": "HTTP %s" % status}
    if status == 401:
        return {"kind": "auth_required",
                "detail": "authentication required (HTTP 401)"}
    if status == 403:
        return {"kind": "forbidden",
                "detail": "access forbidden (HTTP 403) — not a finding"}
    if status == 404:
        return {"kind": "absent", "detail": "HTTP 404"}
    if status == 429:
        return {"kind": "rate_limited",
                "detail": "rate limited (HTTP 429)"}
    if status >= 500:
        return {"kind": "server_error",
                "detail": "HTTP %s" % status}
    if status != 200:
        return {"kind": "other", "detail": "HTTP %s" % status}
    # HTTP 200 — is it a real file or an error page wearing 200?
    if error_fp:
        fp = _fingerprint_of(body or "")
        if fp["sha256"] == error_fp["sha256"]:
            return {"kind": "error_page_200",
                    "detail": "body matches the server error page"}
        if (abs(fp["length"] - error_fp["length"])
                <= max(5, error_fp["length"] // 10)
                and any(m in fp["sample"].lower()
                        for m in _ERROR_MARKERS)):
            return {"kind": "error_page_200",
                    "detail": "body looks like the server error page"}
    if (content_type or "").startswith("text/html") and size < 2000 \
            and any(m in (body or "").lower()[:500]
                    for m in _ERROR_MARKERS):
        return {"kind": "error_page_200",
                "detail": "small HTML body mentioning a missing page"}
    return {"kind": "ok", "detail": "HTTP 200, real content"}


def _key_value_lines(body):
    """Count KEY=VALUE lines (names only — values never read)."""
    names = set()
    for line in (body or "").splitlines():
        m = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*)\s*=", line)
        if m:
            names.add(m.group(1))
    return names


def analyze_sensitive(path, content_type, size, body):
    """Does the body structurally match what the path claims to be?
    Returns (confirmed: bool, detail: str)."""
    low = (path or "").lower()
    text = body or ""
    if low.endswith((".env", ".env.bak")):
        names = _key_value_lines(text)
        if len(names) >= 1:
            return True, "%d KEY= lines (names only: %s)" % (
                len(names), ", ".join(sorted(names)[:5]))
        return False, "no KEY= structure in body"
    if low.endswith((".sql", ".dump")):
        hits = sum(1 for kw in ("CREATE TABLE", "INSERT INTO",
                                "DROP TABLE", "CREATE DATABASE")
                   if kw in text.upper())
        if hits >= 1:
            return True, "SQL structure present (%d keywords)" % hits
        return False, "no SQL structure in body"
    if low.endswith("/head") or low.endswith(".git/head"):
        if text.startswith("ref:"):
            return True, "starts with ref: (git HEAD)"
        return False, "not a git HEAD file"
    if low.endswith("wp-config.php"):
        if "DB_" in text:
            return True, "contains DB_ constants"
        return False, "no WP config structure"
    if low.endswith("config.php"):
        if "<?php" in text:
            return True, "PHP source present"
        return False, "no PHP structure"
    if low.endswith("phpinfo.php"):
        if "PHP Version" in text:
            return True, "phpinfo output present"
        return False, "no phpinfo output"
    if low.endswith("server-status"):
        if "Apache Server Status" in text:
            return True, "Apache server-status output"
        return False, "no server-status output"
    if low.endswith((".json",)):
        try:
            import json
            doc = json.loads(text)
            paths = (doc.get("paths") or {}) if isinstance(doc, dict) \
                else {}
            if paths:
                return True, "API definition enumerates %d endpoints" \
                    % len(paths)
            if isinstance(doc, dict) and ("openapi" in doc
                                         or "swagger" in doc):
                return True, "OpenAPI document (no paths listed)"
        except Exception:
            pass
        return False, "not a parseable API definition"
    if low.endswith((".zip", ".gz", ".tar", ".bak", ".old")):
        if size > 100 and not (content_type or "").startswith("text/html"):
            return True, "%d bytes, non-HTML content" % size
        return False, "not a real archive (HTML or tiny)"
    if low.endswith((".ds_store",)):
        if size > 0 and not (content_type or "").startswith("text/html"):
            return True, "%d bytes binary content" % size
        return False, "not a real metadata file"
    if "svn" in low and low.endswith("entries"):
        if size > 0 and "dir" in text.lower():
            return True, "SVN entries present"
        return False, "no SVN structure"
    # Generic file: real 200 content of any substance.
    if size > 0:
        return True, "%d bytes" % size
    return False, "empty body"
