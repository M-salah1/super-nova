#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Evidence Collector — every finding becomes one evidence record.

A finding is only a claim until it carries its source: which engine
found it, when, and what it saw. The collector turns raw engine
findings into evidence records that the validator, the correlation
engine and the report all share. One record per finding, one id per
record, timestamps on everything.
"""
import time

_counter = [0]


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def collect(findings):
    """Wrap raw findings (each with an "engine" key) into records."""
    records = []
    for f in findings:
        _counter[0] += 1
        records.append({
            "id": "EV-%04d" % _counter[0],
            "engine": f.get("engine", "?"),
            "name": f.get("name", ""),
            "severity": f.get("severity", "info"),
            "confirmation": f.get("confirmation", "indicator"),
            "evidence": f.get("evidence", ""),
            "fix": f.get("fix", ""),
            "collected_at": _now(),
            "validation": {"status": "collected", "confidence": 0,
                           "method": "", "checked_at": None},
        })
    return records
