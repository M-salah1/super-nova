#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Subdomain Discovery engine — Subfinder / Amass style.

Two public sources, no API key:
1. Certificate Transparency (crt.sh) — every hostname ever issued
   a certificate for the domain.
2. DNS wordlist via DNS-over-HTTPS — common subdomain names.
A wildcard check (random subdomain) prevents invented results.
"""
import random
import string

from ..core.http import doh, fetch_json

NAME = "subdomains"
TITLE = "Subdomain Discovery (Subfinder)"

WORDLIST = ["www", "mail", "ftp", "api", "dev", "staging", "stage", "test",
            "admin", "blog", "shop", "app", "cdn", "vpn", "webmail", "cpanel",
            "whm", "ns1", "ns2", "mx", "smtp", "pop", "imap", "portal",
            "support", "help", "docs", "status", "beta", "demo", "secure",
            "login", "sso", "auth", "db", "mysql", "git", "jenkins", "ci",
            "monitor", "static", "assets", "media", "files", "m", "mobile",
            "old", "new", "v2", "internal", "private", "remote", "cloud",
            "crm", "erp", "hr", "pay", "billing", "store", "forum", "wiki"]


def _ct_subdomains(domain, timeout=12):
    url = ("https://crt.sh/?q=%%25.%s&output=json" % domain)
    data, err = fetch_json(url, timeout=timeout, max_bytes=1000000)
    if not data:
        return [], err
    found = set()
    for entry in data:
        for name in str(entry.get("name_value", "")).split("\n"):
            name = name.strip().lower().lstrip("*.")
            if name.endswith("." + domain) or name == domain:
                found.add(name)
    return sorted(found), None


def run(ctx):
    domain = ctx.get("domain") or ""
    timeout = ctx.get("timeout", 8)
    findings = []
    data = {"domain": domain, "ct": [], "dns": [], "wildcard": False,
            "ct_error": None}
    if not domain or "." not in domain or domain.startswith("127.") \
            or domain == "localhost":
        data["note"] = "Local test target — no public subdomains exist."
        return {"engine": NAME, "status": "completed",
                "findings": [], "data": data}
    ct, err = _ct_subdomains(domain, timeout=timeout)
    data["ct"] = ct
    data["ct_error"] = err
    if err:
        # A CT error proves nothing about subdomains — they are
        # UNKNOWN, not absent. The wordlist below still runs.
        data["ct_note"] = ("Certificate Transparency unreachable (%s) — "
                           "subdomains from CT are unknown, not absent."
                           % err)
    # Wildcard check: a random name must NOT resolve.
    probe = "".join(random.choice(string.ascii_lowercase) for _ in range(12))
    if doh("%s.%s" % (probe, domain), "A", timeout=timeout):
        data["wildcard"] = True
    dns_found = []
    for sub in WORDLIST:
        name = "%s.%s" % (sub, domain)
        if doh(name, "A", timeout=timeout):
            dns_found.append(name)
    data["dns"] = dns_found
    all_subs = sorted(set(ct) | set(dns_found))
    data["subdomains"] = all_subs
    data["count"] = len(all_subs)
    if data["wildcard"]:
        findings.append({
            "severity": "low",
            "name": "Wildcard DNS is enabled",
            "evidence": "random subdomain %s.%s resolves" % (probe, domain),
            "fix": "Disable wildcard DNS unless it is required."})
    if err and not dns_found:
        # Both sources failed: the engine did not measure anything.
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {**data, "error": data.get("ct_note")}}
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
