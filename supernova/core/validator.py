#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Validation Engine — re-check every finding before it counts.

A scanner that never re-checks produces false positives: a cached
page, a transient error, a proxy artifact. The validator re-fetches
the exact thing each finding claims, independently of the engine
that found it:

- missing-header findings   -> re-fetch the homepage headers
- cookie-flag findings     -> re-fetch the homepage cookies
- exposed-file findings    -> re-GET the path (and its marker)
- secret / JS-pattern findings -> re-fetch the file, re-match
- TLS findings             -> re-run the exact handshake / cert read
- everything else          -> "observed": directly measured once

Result per finding: verified / observed / false_positive, with a
confidence and the method used. False positives are removed from
the score and listed separately in the report.
"""
import concurrent.futures
import re
import time

from ..core import content as content_mod
from ..core.http import get, lower_headers
from ..engines import secrets as secrets_mod
from ..engines import semgrep as semgrep_mod

HEADER_NAMES = {
    "Missing Content-Security-Policy": "content-security-policy",
    "Missing Strict-Transport-Security (HSTS)": "strict-transport-security",
    "Missing X-Frame-Options (clickjacking protection)": "x-frame-options",
    "Missing X-Content-Type-Options": "x-content-type-options",
    "Missing Referrer-Policy": "referrer-policy",
    "Missing Permissions-Policy": "permissions-policy",
}

COOKIE_FLAGS = {
    "Cookie without Secure flag": "secure",
    "Cookie without HttpOnly flag": "httponly",
    "Cookie without SameSite attribute": "samesite",
}


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _result(status, confidence, method):
    return {"status": status, "confidence": confidence,
            "method": method, "checked_at": _now()}


def _reget(url, timeout=6):
    return get(url, timeout=timeout, max_bytes=50000)


def validate_one(ev, ctx, error_fp=None):
    name = ev.get("name", "")
    evidence = ev.get("evidence", "")
    base = (ctx.get("url") or "").rstrip("/")
    host = ctx.get("host") or ""

    # 1. Missing security headers — re-fetch the homepage.
    if name in HEADER_NAMES:
        r = _reget(ctx.get("url"))
        if r.get("status") is None:
            return _result("observed", 60,
                           "re-check unreachable; original stands")
        headers = lower_headers(r.get("headers") or {})
        if HEADER_NAMES[name] in headers:
            return _result("false_positive", 95,
                           "header present on re-check")
        return _result("verified", 90, "header still absent on re-check")

    # 2. Cookie flags — re-fetch the homepage cookies.
    if name in COOKIE_FLAGS:
        m = re.search(r"cookie (\S+)", evidence)
        flag = COOKIE_FLAGS[name]
        r = _reget(ctx.get("url"))
        if r.get("status") is None or not m:
            return _result("observed", 60, "re-check unreachable")
        try:
            raw_cookies = list(r.get("headers").get_all("Set-Cookie") or [])
        except Exception:
            raw_cookies = []
        for raw in raw_cookies:
            parts = [p.strip().lower() for p in raw.split(";")]
            cname = parts[0].split("=")[0] if parts else ""
            if cname == m.group(1).lower():
                has = {"secure": "secure" in parts,
                       "httponly": "httponly" in parts,
                       "samesite": any(p.startswith("samesite")
                                       for p in parts)}[flag]
                if has:
                    return _result("false_positive", 95,
                                   "flag present on re-check")
                return _result("verified", 90,
                               "flag still missing on re-check")
        return _result("false_positive", 80, "cookie no longer set")

    # 3. Exposed secrets — re-fetch the file, re-match the pattern.
    if name.startswith("Possible exposed secret: "):
        pat_name = name.split(":", 1)[1].strip()
        m = re.search(r"found in (\S+) \(value redacted\)", evidence)
        url = m.group(1) if m else None
        pattern = next((p for n, p in secrets_mod.PATTERNS
                        if n == pat_name), None)
        if not url or not pattern:
            return _result("observed", 60, "cannot re-check")
        r = _reget(url)
        if r.get("status") is None:
            return _result("observed", 60, "re-check unreachable")
        try:
            found = re.search(pattern, r.get("body") or "") is not None
        except re.error:
            found = False
        if found:
            return _result("verified", 90, "pattern still present")
        return _result("false_positive", 95, "pattern gone on re-check")

    # 4. JS static-analysis patterns — re-fetch the file, re-match.
    if name in [r[2] for r in semgrep_mod.RULES]:
        url = evidence.split(": pattern")[0]
        pattern = next((p for p, _s, n, _f in semgrep_mod.RULES
                        if n == name), None)
        if not url.startswith("http") or not pattern:
            return _result("observed", 60, "cannot re-check")
        r = _reget(url)
        if r.get("status") is None:
            return _result("observed", 60, "re-check unreachable")
        try:
            found = re.search(pattern, r.get("body") or "") is not None
        except re.error:
            found = False
        if found:
            return _result("verified", 90, "pattern still present")
        return _result("false_positive", 95, "pattern gone on re-check")

    # 5. Exposed files (vuln templates + fuzz) — re-GET the path and
    #    classify the answer: a 200 that is an error page, a 403 or a
    #    body without the claimed structure is a false positive.
    if "exposed" in name.lower() or "publicly reachable" in name:
        path = evidence.split(" -> ")[0].strip()
        if not path.startswith("/"):
            return _result("observed", 60, "no path in evidence")
        r = _reget(base + path)
        if r.get("status") is None:
            return _result("observed", 60, "re-check unreachable")
        body = r.get("body") or ""
        ctype = ""
        try:
            ctype = (r.get("headers") or {}).get("Content-Type", "") or ""
        except Exception:
            pass
        verdict = content_mod.classify(r.get("status"), ctype,
                                       len(body), body, error_fp)
        if verdict["kind"] != "ok":
            return _result("false_positive", 95,
                           "re-check: %s" % verdict["detail"])
        confirmed, detail = content_mod.analyze_sensitive(
            path, ctype, len(body), body)
        if not confirmed:
            return _result("false_positive", 90,
                           "re-check: %s" % detail)
        return _result("verified", 90, "re-check: %s" % detail)

    # 6. TLS claims — re-run the exact handshake / cert read.
    if name.startswith("Weak TLS protocol supported: "):
        import ssl
        from ..engines.tls import _handshake
        label = name.split(":", 1)[1].strip()
        vers = {"TLSv1.0": ssl.TLSVersion.TLSv1,
                "TLSv1.1": ssl.TLSVersion.TLSv1_1}
        v = vers.get(label)
        if v is None:
            return _result("observed", 60, "unknown version")
        try:
            _handshake(host, 443, v, v)
            return _result("verified", 90,
                           "weak protocol still negotiates")
        except Exception:
            return _result("false_positive", 90,
                           "protocol no longer negotiates")
    if "TLS certificate" in name:
        import datetime
        import ssl
        from ..engines.tls import _handshake
        try:
            info = _handshake(host, 443, ssl.TLSVersion.TLSv1_2,
                              ssl.TLSVersion.TLSv1_3)
            cert = info.get("cert") or {}
            exp = datetime.datetime.strptime(
                cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days = (exp - datetime.datetime.utcnow()).days
            if "EXPIRED" in name:
                if days < 0:
                    return _result("verified", 90,
                                   "certificate still expired")
                return _result("false_positive", 95,
                               "certificate renewed")
            if days < 30:
                return _result("verified", 85,
                               "expiry re-checked: %d days left" % days)
            return _result("false_positive", 90,
                           "certificate now valid for %d days" % days)
        except Exception:
            return _result("observed", 60, "re-check unreachable")

    # 7. Everything else: a direct measurement, not re-checked.
    return _result("observed", 70, "direct measurement")


def validate_all(evidences, ctx):
    """Validate every evidence record in parallel."""
    error_fp = None
    try:
        error_fp = content_mod.fingerprint_error_page(
            (ctx.get("url") or "").rstrip("/"), timeout=6)
    except Exception:
        error_fp = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        futs = {pool.submit(validate_one, ev, ctx, error_fp): ev
                for ev in evidences}
        for fut in futs:
            ev = futs[fut]
            try:
                ev["validation"] = fut.result()
            except Exception as exc:  # noqa: BLE001 - recorded
                ev["validation"] = _result(
                    "observed", 60,
                    "validator error: %s" % str(exc)[:80])
    return evidences
