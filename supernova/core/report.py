#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Super Nova reports: terminal, JSON and HTML.

Every report shows the same honest picture: score (or INCOMPLETE),
coverage, per-engine status, unified findings with evidence and fix,
and recommendations. Secret values never appear — engines only
record names, flags and redacted evidence.
"""
import html as html_mod
import json

from .i18n import t

SEV_ORDER = ["critical", "high", "medium", "low", "info"]


def score_line(scan, lang):
    if scan.get("score") is None:
        return "%s: %s   %s: %s   %s: %s%%   %s: %s s" % (
            t(lang, "score"), t(lang, "incomplete"),
            t(lang, "grade"), t(lang, "incomplete"),
            t(lang, "coverage"),
            (scan.get("coverage") or {}).get("percent", 0),
            t(lang, "duration"), scan.get("duration_s"))
    return "%s: %s%%   %s: %s   %s: %s%%   %s: %s%%   %s: %s%%   %s: %s s" % (
        t(lang, "score"), scan.get("score"),
        t(lang, "grade"), scan.get("grade"),
        t(lang, "confidence"), scan.get("confidence"),
        t(lang, "coverage"), (scan.get("coverage") or {}).get("percent", 0),
        t(lang, "verification_rate"),
        (scan.get("metrics") or {}).get("verification_rate", 0),
        t(lang, "duration"), scan.get("duration_s"))


def print_report(scan, lang="ar"):
    print("=" * 60)
    print("🦊 Super Nova v1.00 — %s" % t(lang, "report"))
    print("%s: %s" % (t(lang, "target"), scan.get("target")))
    print("%s: %s" % (t(lang, "profile"), scan.get("profile")))
    print(score_line(scan, lang))
    val = scan.get("validation") or {}
    if val:
        print("%s: %s %s, %s %s, %s %s" % (
            t(lang, "validation"), val.get("verified", 0),
            t(lang, "verified"), val.get("observed", 0),
            t(lang, "observed"), val.get("false_positive", 0),
            t(lang, "false_positives")))
    dist = scan.get("severity_distribution") or {}
    print("%s: %s" % (t(lang, "findings"),
                      ", ".join("%s=%d" % (k, v) for k, v in dist.items()
                                if v) or "0"))
    comps = ((scan.get("coverage") or {}).get("components") or {})
    if comps:
        print("%s: %s" % (t(lang, "coverage"),
                          ", ".join("%s %s%%" % (k, v)
                                    for k, v in comps.items())))
    if scan.get("chains"):
        print("%s:" % t(lang, "chains"))
        for c in scan["chains"]:
            print("  [%s] %s" % (c["severity"].upper(), c["name"]))
            print("      %s" % c.get("evidence", "")[:200])
    if scan.get("contradictions"):
        print("%s:" % t(lang, "contradictions"))
        for c in scan["contradictions"]:
            print("  • %s" % c[:200])
    print("=" * 60)
    print("%s:" % t(lang, "engine_status"))
    for name in scan.get("engines") or []:
        run = (scan.get("engine_status") or {}).get(name) or {}
        line = "  • %s: %s (%ss" % (name, run.get("status"),
                                   run.get("duration_s"))
        if run.get("retries"):
            line += ", %d retries" % run["retries"]
        if run.get("error"):
            line += " — %s" % str(run["error"])[:70]
        print(line + ")")
    # Validated evidence, grouped by engine (false positives excluded).
    by_engine = {}
    for ev in scan.get("evidence") or []:
        if (ev.get("validation") or {}).get("status") == "false_positive":
            continue
        by_engine.setdefault(ev.get("engine"), []).append(ev)
    for name in scan.get("engines") or []:
        res = (scan.get("results") or {}).get(name) or {}
        if res.get("status") != "completed":
            continue
        print("-" * 60)
        print("Engine: %s" % name)
        for key, val in (res.get("data") or {}).items():
            if isinstance(val, dict):
                print("  %s: %s" % (key, ", ".join(
                    "%s=%s" % (k, v) for k, v in val.items()) or "—"))
            elif key in ("checked", "results", "pages", "scripts", "urls",
                         "hosts", "subdomains", "open_ports", "checked"):
                if isinstance(val, list):
                    print("  %s: %d items" % (key, len(val)))
                else:
                    print("  %s: %s" % (key, val))
            elif isinstance(val, (str, int, float, bool)) or val is None:
                print("  %s: %s" % (key, val))
        for ev in by_engine.get(name) or []:
            conf = ev.get("confirmation") or (
                (ev.get("validation") or {}).get("status") == "verified"
                and "confirmed" or "indicator")
            print("  [%s|%s] %s" % (ev["severity"].upper(), conf,
                                    ev["name"]))
            print("      %s" % ev.get("evidence", "")[:160])
            v = ev.get("validation") or {}
            print("      %s: %s (%s%%)" % (t(lang, "validation"),
                                           v.get("status"),
                                           v.get("confidence")))
    if scan.get("false_positives"):
        print("-" * 60)
        print("%s:" % t(lang, "false_positives"))
        for fp in scan["false_positives"]:
            print("  ✗ %s (%s)" % (fp["name"], fp.get("engine")))
    assets = scan.get("assets") or {}
    if assets:
        print("-" * 60)
        print("%s: %s" % (t(lang, "assets"), assets.get("domain")))
        print("  subdomains: %d  |  IPs: %s  |  ports: %s" % (
            assets.get("subdomain_count", 0),
            ", ".join(assets.get("ips") or []) or "—",
            ", ".join(str(p) for p in assets.get("open_ports")
                      or []) or "—"))
        print("  CMS: %s  |  %s: %s  |  %s: %s" % (
            assets.get("cms") or "—", "registrar",
            assets.get("registrar") or "—", "domain days left",
            assets.get("domain_days_left")))
    summary = scan.get("summary")
    if summary:
        print("=" * 60)
        print("Super Nova v1.00 — Executive Summary")
        print("Score: %s  Grade: %s  |  Owner: %s / %s" % (
            "INCOMPLETE" if summary.get("score") is None
            else "%s%%" % summary.get("score"), summary.get("grade"),
            (summary.get("owner") or {}).get("registrar"),
            (summary.get("owner") or {}).get("registrant")))
        for f in summary.get("top_findings") or []:
            print("  [%s] %s" % ((f.get("severity") or "").upper(),
                                 f.get("name")))
            print("      Fix: %s" % f.get("fix"))
        for a in summary.get("priority_actions") or []:
            print("  • Priority: %s" % a)
    print("=" * 60)
    print("%s:" % t(lang, "recommendations"))
    for fix in (scan.get("recommendations") or [])[:8]:
        print("  • %s" % fix)
    print("=" * 60)


def to_json(scan, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(scan, f, ensure_ascii=False, indent=2)
    return path


def to_html(scan, path):
    def esc(v):
        return html_mod.escape(str(v))
    rows = ""
    for f in scan.get("findings") or []:
        rows += ("<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                 "<td>%s</td></tr>"
                 % (esc(f.get("severity", "")),
                    esc(f.get("confirmation", "")),
                    esc(f.get("name", "")),
                    esc(f.get("evidence", "")[:200]),
                    esc(f.get("fix", "")[:200])))
    engines = ""
    for name in scan.get("engines") or []:
        run = (scan.get("engine_status") or {}).get(name) or {}
        engines += "<li>%s: %s (%ss)</li>" % (esc(name),
                                              esc(run.get("status", "")),
                                              esc(run.get("duration_s", "")))
    score = scan.get("score")
    score_txt = "INCOMPLETE" if score is None else "%s%% (%s)" % (
        score, scan.get("grade"))
    doc = """<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<title>Super Nova Report — %s</title>
<style>body{font-family:sans-serif;margin:2em}table{border-collapse:collapse}
td,th{border:1px solid #ccc;padding:6px;text-align:left}</style></head>
<body><h1>🦊 Super Nova v1.00 — %s</h1>
<p><b>Target:</b> %s &nbsp; <b>Profile:</b> %s &nbsp; <b>Score:</b> %s
&nbsp; <b>Confidence:</b> %s%% &nbsp; <b>Coverage:</b> %s%%
&nbsp; <b>Verification rate:</b> %s%% &nbsp; <b>Duration:</b> %s s</p>
<h2>Engines</h2><ul>%s</ul>
<h2>Findings</h2><table><tr><th>Severity</th><th>Confirmation</th>
<th>Finding</th>
<th>Evidence</th><th>Fix</th></tr>%s</table>
<h2>Recommendations</h2><ul>%s</ul>
<p>Super Nova v1.00 — FOX COMPANY — Developer: Hafed Mehdi Salah Eddine</p>
</body></html>""" % (
        esc(scan.get("target")), esc(scan.get("target")),
        esc(scan.get("target")), esc(scan.get("profile")), esc(score_txt),
        esc(scan.get("confidence", 0)),
        esc((scan.get("coverage") or {}).get("percent", 0)),
        esc((scan.get("metrics") or {}).get("verification_rate", 0)),
        esc(scan.get("duration_s")), engines, rows,
        "".join("<li>%s</li>" % esc(x)
                for x in scan.get("recommendations") or []))
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return path
