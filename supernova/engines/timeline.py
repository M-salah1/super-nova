#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Digital Forensics Timeline engine.

Builds a dated timeline of the target from PUBLIC facts only, each
event carrying its source:
  - domain registration / expiry / last change (public RDAP),
  - TLS certificate notBefore / notAfter (the TLS handshake),
  - first / last capture in the Wayback Machine (public CDX API),
  - earliest certificate seen in Certificate Transparency (crt.sh).

Nothing is invented: a source that fails or is redacted makes its
events UNKNOWN, never absent — the timeline simply has fewer events
and says which sources failed. Local test targets (127.0.0.1 /
localhost) have no public history and return an empty timeline.
"""
import datetime
import urllib.parse

from ..core.http import fetch_json

NAME = "timeline"
TITLE = "Digital Forensics Timeline"


def _norm_date(value):
    """Normalize many public date formats to YYYY-MM-DD (or None)."""
    if not value:
        return None
    text = str(value).strip()
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%d", "%b %d %H:%M:%S %Y %Z",
                "%Y%m%d%H%M%S", "%Y%m%d"):
        try:
            return datetime.datetime.strptime(
                text[:19] if fmt.startswith("%Y-%m-%dT") else text,
                fmt).strftime("%Y-%m-%d")
        except Exception:
            continue
    # Wayback compact timestamp YYYYMMDDHHMMSS
    if len(text) >= 8 and text[:8].isdigit():
        try:
            return datetime.datetime.strptime(text[:8], "%Y%m%d") \
                .strftime("%Y-%m-%d")
        except Exception:
            pass
    return None


def _rdap_events(domain, timeout):
    data, err = fetch_json("https://rdap.org/domain/%s" % domain,
                           timeout=timeout, max_bytes=200000)
    if not data:
        return [], err or "RDAP query failed"
    events = []
    labels = {"registration": "Domain registered",
              "expiration": "Domain registration expires",
              "last changed": "Domain record last changed"}
    for ev in data.get("events") or []:
        action = ev.get("eventAction")
        if action in labels:
            date = _norm_date(ev.get("eventDate"))
            if date:
                events.append({"date": date, "event": labels[action],
                               "source": "RDAP (%s)" % (
                                   data.get("handle") or domain)})
    return events, None


def _wayback_events(domain, timeout):
    q = ("https://web.archive.org/cdx/search/cdx?url=%s/*"
         "&output=json&limit=2&fl=timestamp&filter=statuscode:200"
         % urllib.parse.quote(domain))
    rows, err = fetch_json(q, timeout=timeout, max_bytes=100000)
    if not rows or len(rows) < 2:
        return [], err or "no archived captures"
    stamps = sorted(r[0] for r in rows[1:] if r)
    events = []
    first = _norm_date(stamps[0])
    last = _norm_date(stamps[-1])
    if first:
        events.append({"date": first,
                       "event": "First archived capture (Wayback Machine)",
                       "source": "Wayback CDX"})
    if last and last != first:
        events.append({"date": last,
                       "event": "Most recent archived capture "
                                "(Wayback Machine)",
                       "source": "Wayback CDX"})
    return events, None


def _ct_events(domain, timeout):
    data, err = fetch_json(
        "https://crt.sh/?q=%%25.%s&output=json" % domain,
        timeout=timeout, max_bytes=500000)
    if not data:
        return [], err or "CT log query failed"
    dates = []
    for entry in data:
        d = _norm_date(entry.get("entry_timestamp")
                       or entry.get("not_before"))
        if d:
            dates.append(d)
    if not dates:
        return [], "CT log returned no usable dates"
    return [{"date": min(dates),
             "event": "Earliest certificate in Certificate Transparency",
             "source": "crt.sh"}], None


def run(ctx):
    domain = ctx.get("domain") or ""
    timeout = ctx.get("timeout", 12)
    events = []
    errors = {}
    if not domain or "." not in domain or domain.startswith("127.") \
            or domain == "localhost":
        return {"engine": NAME, "status": "completed",
                "findings": [],
                "data": {"domain": domain, "events": [], "count": 0,
                         "note": "Local test target — no public history "
                                 "exists.", "errors": {}}}
    # TLS certificate dates come from the TLS engine (ctx["tls"]).
    tls = ctx.get("tls") or {}
    cert = (tls.get("cert") or {})
    for key, label in (("not_before", "TLS certificate issued"),
                       ("not_after", "TLS certificate expires")):
        date = _norm_date(cert.get(key))
        if date:
            events.append({"date": date, "event": label,
                           "source": "TLS certificate"})
    for fetcher, key in ((_rdap_events, "rdap"),
                         (_wayback_events, "wayback"),
                         (_ct_events, "ct")):
        try:
            found, err = fetcher(domain, timeout)
        except Exception as exc:  # noqa: BLE001 - recorded, never raised
            found, err = [], str(exc)
        if err:
            errors[key] = "%s — events from this source are unknown, " \
                          "not absent" % err
        events.extend(found)
    events.sort(key=lambda e: e["date"])
    findings = []
    if events:
        findings.append({
            "severity": "info",
            "name": "Public timeline: %d dated event(s) from %d source(s)"
                    % (len(events),
                       len({e["source"].split(" (")[0]
                            for e in events})),
            "evidence": "earliest %s — latest %s"
                        % (events[0]["date"], events[-1]["date"]),
            "fix": "Use the timeline to spot unexpected changes "
                   "(ownership, certificate, first exposure)."})
    return {"engine": NAME, "status": "completed",
            "findings": findings,
            "data": {"domain": domain, "events": events,
                     "count": len(events), "errors": errors}}
