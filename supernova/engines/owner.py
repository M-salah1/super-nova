#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Owner Intelligence engine — who owns the site, and when things expire.

Public RDAP (Registration Data Access Protocol) for the domain:
registrar, registrant organization/name and handle (the public
registration ID) when the registry publishes them, registration /
expiry / last-change dates, nameservers and status. Certificate
expiry comes from the TLS engine (fed in through ctx["tls"]).
Nothing here is guessed: redacted or missing data is reported
UNKNOWN, never invented.
"""
import datetime

from ..core.http import fetch_json

NAME = "owner"
TITLE = "Owner Intelligence"

RDAP_URL = "https://rdap.org/domain/%s"


def _days_left(datestr):
    """Days from now until an ISO-8601 date. None if unparsable."""
    try:
        d = datetime.datetime.strptime(datestr[:19], "%Y-%m-%dT%H:%M:%S")
        return (d - datetime.datetime.utcnow()).days
    except Exception:
        return None


def _vcard_value(vcard, key):
    """Read one field out of a vCardArray, e.g. 'fn'."""
    try:
        for item in vcard[1]:
            if item[0] == key:
                return item[3]
    except Exception:
        pass
    return None


def run(ctx):
    domain = ctx.get("domain") or ""
    findings = []
    data = {"domain": domain, "registrar": None, "registrant": None,
            "registrant_id": None, "handle": None, "created": None,
            "expires": None, "days_left": None, "last_changed": None,
            "nameservers": [], "status": [], "cert_days_left": None,
            "rdap_error": None}
    if not domain or "." not in domain or domain.startswith("127.") \
            or domain == "localhost":
        data["note"] = "Local test target — no public registration exists."
        return {"engine": NAME, "status": "completed",
                "findings": [], "data": data}
    rdap, err = fetch_json(RDAP_URL % domain, timeout=12,
                           max_bytes=200000)
    if not rdap:
        # A failed RDAP query proves nothing about the owner — the
        # owner is UNKNOWN, not absent. Many registries (including
        # .dz) do not publish RDAP at all.
        data["rdap_error"] = (
            "%s — owner unknown, not absent (the registry may not "
            "publish RDAP for this TLD)" % (err or "RDAP query failed"))
        tls = ctx.get("tls") or {}
        if tls.get("days_left") is not None:
            data["cert_days_left"] = tls["days_left"]
            return {"engine": NAME, "status": "completed",
                    "findings": [], "data": data}
        return {"engine": NAME, "status": "error",
                "findings": [], "data": data}
    data["handle"] = rdap.get("handle")
    for ent in rdap.get("entities") or []:
        roles = ent.get("roles") or []
        if "registrar" in roles:
            data["registrar"] = _vcard_value(ent.get("vcardArray"), "fn")
        if "registrant" in roles:
            data["registrant"] = _vcard_value(ent.get("vcardArray"), "fn")
            data["registrant_id"] = ent.get("handle")
    for ev in rdap.get("events") or []:
        action = ev.get("eventAction")
        if action == "registration":
            data["created"] = ev.get("eventDate")
        elif action == "expiration":
            data["expires"] = ev.get("eventDate")
        elif action == "last changed":
            data["last_changed"] = ev.get("eventDate")
    data["nameservers"] = [ns.get("ldhName")
                           for ns in rdap.get("nameservers") or []
                           if ns.get("ldhName")]
    data["status"] = rdap.get("status") or []
    if data["expires"]:
        data["days_left"] = _days_left(data["expires"])
        if data["days_left"] is not None:
            if data["days_left"] < 0:
                findings.append({
                    "severity": "critical",
                    "name": "Domain registration EXPIRED",
                    "evidence": "expired %s" % data["expires"][:10],
                    "fix": "Renew the domain registration immediately."})
            elif data["days_left"] < 30:
                findings.append({
                    "severity": "medium",
                    "name": "Domain registration expires soon",
                    "evidence": "%d days left (expires %s)"
                                % (data["days_left"], data["expires"][:10]),
                    "fix": "Renew the domain registration before it "
                           "expires."})
    tls = ctx.get("tls") or {}
    if tls.get("days_left") is not None:
        data["cert_days_left"] = tls["days_left"]
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
