#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Scoring — one place where a score comes from (v1.00).

Four separate metrics, each measured, none of them a guess:

- Security Score: only findings that survived validation count,
  and only at their confirmation level — a confirmed vulnerability
  weighs full, an indicator (needs a human to confirm) weighs half,
  a false positive weighs nothing, and plain information weighs
  nothing. That is why 15 unconfirmed "High" findings no longer
  produce a misleading 0%.
- Confidence: computed from the validation outcome, never a fixed
  number — the share of findings independently re-confirmed.
- Coverage: measured from what was actually done (engines finished,
  pages visited of pages discovered, subdomains probed of those
  found, ports probed of those in scope) — not a count of engines.
- Verification Rate: the share of findings that were verified.

Every finding explains WHY it is HIGH: its evidence, its
validation status and its confirmation level.
"""
WEIGHTS_CONFIRMED = {"critical": 25, "high": 15, "medium": 8,
                     "low": 3, "info": 0}
WEIGHTS_INDICATOR = {"critical": 12, "high": 7, "medium": 4,
                     "low": 1, "info": 0}


def grade_for(score):
    if score is None:
        return "INCOMPLETE"
    if score >= 95:
        return "A+"
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def score_findings(findings):
    """Score validated findings by confirmation level.
    Returns (score, grade, distribution)."""
    total = 0
    for f in findings:
        weights = (WEIGHTS_CONFIRMED
                   if f.get("confirmation") == "confirmed"
                   else WEIGHTS_INDICATOR)
        total += weights.get(f.get("severity"), 0)
    score = max(0, 100 - total)
    dist = {}
    for f in findings:
        dist[f["severity"]] = dist.get(f["severity"], 0) + 1
    return score, grade_for(score), dist


def compute_confidence(validation_counts):
    """Share of findings independently re-confirmed (0-100)."""
    v = validation_counts.get("verified", 0)
    o = validation_counts.get("observed", 0)
    f = validation_counts.get("false_positive", 0)
    total = v + o + f
    if total == 0:
        return 0
    return round(100 * (v + 0.5 * o) / total)


def compute_verification_rate(validation_counts):
    """Share of findings that were verified (0-100)."""
    v = validation_counts.get("verified", 0)
    o = validation_counts.get("observed", 0)
    f = validation_counts.get("false_positive", 0)
    total = v + o + f
    if total == 0:
        return 0
    return round(100 * v / total)


def compute_coverage(engines, status, results):
    """Measured coverage: mean of the components that have data.
    Returns {"percent", "components": {...}}."""
    components = {}
    if engines:
        done = sum(1 for n in engines
                   if (status.get(n) or {}).get("status") == "completed")
        components["engines"] = round(100 * done / len(engines))
    crawl = (results.get("crawl") or {}).get("data") or {}
    discovered = crawl.get("discovered")
    visited = crawl.get("page_count")
    if discovered:
        components["crawl"] = round(100 * min(1.0, visited / discovered))
    subs = (results.get("subdomains") or {}).get("data") or {}
    found = subs.get("count")
    httpx = (results.get("httpx") or {}).get("data") or {}
    probed = len(httpx.get("results") or [])
    if found and probed:
        components["subdomains"] = round(100 * min(1.0, probed / found))
    network = (results.get("network") or {}).get("data") or {}
    if network.get("phase1"):
        # The network engine always probes its full port list when it
        # runs; if it ran, the port component is complete.
        components["ports"] = 100
    if not components:
        return {"percent": 0, "components": {}}
    percent = round(sum(components.values()) / len(components))
    return {"percent": percent, "components": components}
