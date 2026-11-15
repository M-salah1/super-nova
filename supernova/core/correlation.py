#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Correlation Engine — link evidence, kill duplicates, find chains.

One finding per problem: results that describe the same issue from
different engines are merged, not counted twice. Then the engine
looks for what no single engine can see: attack chains — findings
that are only dangerous together — and contradictions between
engines that need a human to decide.
"""
import re


def _norm(name):
    return re.sub(r"\s+", " ", (name or "").strip().lower())


def correlate(evidences, results):
    """evidences: validated records (false positives already removed).
    Returns (findings, chains, contradictions)."""
    seen = {}
    findings = []
    for ev in evidences:
        key = _norm(ev.get("name"))
        if key in seen:
            prev = seen[key]
            if ev.get("engine") not in prev.get("engines", []):
                prev.setdefault("engines", []).append(ev.get("engine"))
            continue
        f = {"name": ev.get("name"), "severity": ev.get("severity"),
             "confirmation": ev.get("confirmation", "indicator"),
             "evidence": ev.get("evidence"), "fix": ev.get("fix"),
             "engines": [ev.get("engine")],
             "validation": ev.get("validation", {})}
        seen[key] = f
        findings.append(f)

    names = {_norm(f["name"]) for f in findings}
    web_data = ((results.get("web") or {}).get("data") or {})
    chains = []

    def chain(sev, name, parts, fix):
        c = {"name": name, "severity": sev, "confirmation": "indicator",
             "evidence": " + ".join(parts), "fix": fix,
             "engines": ["correlation"],
             "validation": {"status": "observed", "confidence": 80,
                            "method": "correlation of verified evidence",
                            "checked_at": None}}
        chains.append(c)
        findings.append(c)

    if ("missing content-security-policy" in names
            and "cookie without httponly flag" in names
            and web_data.get("forms", 0) > 0):
        chain("high", "Attack chain: XSS session theft",
              ["no Content-Security-Policy", "cookie without HttpOnly",
               "forms present"],
              "Fix all three together: add CSP, set HttpOnly on every "
              "cookie, and validate form input.")
    if ("site served over plain http" in names
            and "cookie without httponly flag" in names
            and web_data.get("password_fields", 0) > 0):
        chain("high", "Attack chain: session hijack on the wire",
              ["site over plain HTTP", "cookie without HttpOnly",
               "password field present"],
              "Move the whole site to HTTPS, set Secure + HttpOnly on "
              "cookies, and never serve a login form over HTTP.")
    sensitive = [f for f in findings
                 if "exposed" in f["name"].lower()
                 and f["severity"] in ("high", "critical")]
    if len(sensitive) >= 2:
        chain("critical", "Attack chain: source code + secrets exposure",
              [f["name"] for f in sensitive[:3]],
              "Remove every exposed file from the web root and rotate "
              "any credential that was in them.")

    contradictions = []
    tls_data = ((results.get("tls") or {}).get("data") or {})
    if ("site served over plain http" in names
            and tls_data.get("versions", {}).get("TLSv1.2")):
        contradictions.append(
            "Web engine saw plain HTTP, but the TLS engine negotiated "
            "TLS 1.2 — the site may serve both; check the redirect.")
    owner_data = ((results.get("owner") or {}).get("data") or {})
    od = owner_data.get("cert_days_left")
    td = tls_data.get("days_left")
    if od is not None and td is not None and abs(od - td) > 30:
        contradictions.append(
            "Owner and TLS engines disagree on certificate expiry "
            "(%s vs %s days) — re-check the certificate." % (od, td))
    return findings, chains, contradictions
