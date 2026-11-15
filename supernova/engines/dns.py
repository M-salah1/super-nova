#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS Intelligence engine — records, DNSSEC, mail authentication.

DNS-over-HTTPS for A, AAAA, MX, NS, TXT, CNAME, SOA, CAA and DS,
plus SPF and DMARC from TXT records. Everything is a public
record; missing records are reported as findings with fixes.
"""
from ..core.http import doh

NAME = "dns"
TITLE = "DNS Intelligence"

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "DS"]


def run(ctx):
    domain = ctx.get("domain") or ""
    findings = []
    data = {"domain": domain, "records": {}, "spf": False,
            "dmarc": False, "dnssec": False, "dmarc_record": None}
    if not domain or "." not in domain or domain.startswith("127.") \
            or domain == "localhost":
        data["note"] = "Local test target — no public DNS exists."
        return {"engine": NAME, "status": "completed",
                "findings": [], "data": data}
    timeout = ctx.get("timeout", 8)
    for rtype in RECORD_TYPES:
        try:
            data["records"][rtype] = doh(domain, rtype, timeout=timeout)
        except Exception:
            data["records"][rtype] = []
    txt = data["records"].get("TXT") or []
    data["spf"] = any("v=spf1" in r for r in txt)
    dmarc_txt = doh("_dmarc." + domain, "TXT", timeout=timeout)
    data["dmarc_record"] = next(
        (r for r in dmarc_txt if "v=DMARC1" in r), None)
    data["dmarc"] = data["dmarc_record"] is not None
    data["dnssec"] = bool(data["records"].get("DS"))
    if not data["spf"]:
        findings.append({
            "severity": "low", "name": "No SPF record",
            "evidence": "no v=spf1 TXT record for %s" % domain,
            "fix": "Publish an SPF TXT record listing the servers "
                   "allowed to send mail for the domain."})
    if not data["dmarc"]:
        findings.append({
            "severity": "medium", "name": "No DMARC record",
            "evidence": "no v=DMARC1 TXT record at _dmarc.%s" % domain,
            "fix": "Publish a DMARC record (start with p=none, then "
                   "quarantine/reject)."})
    if not data["dnssec"]:
        findings.append({
            "severity": "low", "name": "DNSSEC not enabled",
            "evidence": "no DS record for %s" % domain,
            "fix": "Enable DNSSEC at the registrar and publish DS "
                   "records."})
    if not data["records"].get("MX"):
        findings.append({
            "severity": "info", "name": "No MX records",
            "evidence": "no MX record for %s" % domain,
            "fix": "Add MX records if the domain should receive mail."})
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
