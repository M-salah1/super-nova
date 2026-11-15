#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Code / Dependency Intelligence engine.

Parses the site's OWN JavaScript and CSS (script/style URLs from the
homepage and the crawl) for library names and versions — from file
names, CDN URLs and version comments inside the files themselves
(jQuery, React, Vue, Angular, Bootstrap, Lodash, Moment, Axios,
Underscore, ...).

A version is reported ONLY when it is actually parsed from the file
or its URL — never guessed. A library seen without a version is
listed with version None and produces no finding. A parsed version
older than the known-safe floor is reported as LOW (or INFO) only —
this engine never claims a vulnerability it did not confirm, it
flags outdated libraries for the owner to update.
"""
import re
import urllib.parse

from ..core.http import get

NAME = "deps"
TITLE = "Code / Dependency Intelligence"

# (library, [filename/URL patterns], [in-file version patterns],
#  oldest safe version tuple, severity when older, upgrade advice)
LIBRARIES = [
    ("jQuery",
     [r"jquery[-.](\d+\.\d+\.\d+)", r"jquery/(\d+\.\d+\.\d+)"],
     [r"jQuery\s+(?:JavaScript Library\s+)?v?(\d+\.\d+\.\d+)"],
     (3, 0, 0), "low", "Upgrade jQuery to 3.x or newer."),
    ("React",
     [r"react(?:\.production|\.min)?[-.]?(\d+\.\d+\.\d+)"],
     [r"React\s+v?(\d+\.\d+\.\d+)"],
     (16, 0, 0), "low", "Upgrade React to a supported release."),
    ("Vue.js",
     [r"vue(?:\.min)?[-.]?(\d+\.\d+\.\d+)"],
     [r"Vue\.js\s+v?(\d+\.\d+\.\d+)"],
     (2, 7, 0), "low", "Upgrade Vue.js to a supported release."),
    ("AngularJS",
     [r"angular(?:\.min)?[-.]?(\d+\.\d+\.\d+)"],
     [r"AngularJS\s+v?(\d+\.\d+\.\d+)"],
     (1, 8, 0), "low", "AngularJS is end-of-life — migrate to Angular."),
    ("Bootstrap",
     [r"bootstrap[-.](\d+\.\d+\.\d+)", r"bootstrap/(\d+\.\d+\.\d+)"],
     [r"Bootstrap\s+v?(\d+\.\d+\.\d+)"],
     (4, 0, 0), "low", "Upgrade Bootstrap to 4.x or newer."),
    ("Lodash",
     [r"lodash[-.](\d+\.\d+\.\d+)", r"lodash/(\d+\.\d+\.\d+)"],
     [r"Lodash\s+v?(\d+\.\d+\.\d+)"],
     (4, 17, 21), "low", "Upgrade Lodash to 4.17.21 or newer."),
    ("Moment.js",
     [r"moment[-.](\d+\.\d+\.\d+)", r"moment/(\d+\.\d+\.\d+)"],
     [r"Moment\.js\s+v?(\d+\.\d+\.\d+)"],
     (2, 29, 2), "info", "Moment.js is in maintenance mode — consider "
                          "a modern date library."),
    ("Axios",
     [r"axios[-.](\d+\.\d+\.\d+)", r"axios/(\d+\.\d+\.\d+)"],
     [r"Axios\s+v?(\d+\.\d+\.\d+)"],
     (1, 0, 0), "info", "Upgrade Axios to 1.x or newer."),
    ("Underscore.js",
     [r"underscore[-.](\d+\.\d+\.\d+)"],
     [r"Underscore\.js\s+(\d+\.\d+\.\d+)"],
     (1, 13, 0), "info", "Upgrade Underscore.js to 1.13 or newer."),
    ("D3.js",
     [r"d3[-.](\d+\.\d+\.\d+)"],
     [r"D3\.js\s+v?(\d+\.\d+\.\d+)"],
     (5, 0, 0), "info", "Upgrade D3.js to a supported release."),
]


def _ver_tuple(version):
    try:
        return tuple(int(x) for x in version.split(".")[:3])
    except Exception:
        return None


def _detect_from_text(name, url_patterns, content_patterns, text, url):
    """Return a parsed version string, or None (never guessed)."""
    for pat in url_patterns:
        m = re.search(pat, url, re.I)
        if m and m.lastindex:
            return m.group(1)
    for pat in content_patterns:
        m = re.search(pat, text[:4000], re.I)
        if m and m.lastindex:
            return m.group(1)
    # Name seen but no version anywhere: report the name, no version.
    hay = (url + "\n" + text[:4000]).lower()
    if name.lower().replace(".js", "") in hay or \
            name.lower().split(".")[0] in hay:
        return None
    return None


def run(ctx):
    if ctx.get("status") is None:
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "homepage unreachable"}}
    base = (ctx.get("url") or "").rstrip("/")
    host = ctx.get("host") or ""
    timeout = ctx.get("timeout", 8)
    html = ctx.get("html") or ""
    urls = []
    for u in (ctx.get("scripts") or []):
        urls.append(u)
    for u in re.findall(
            r'<link[^>]+href\s*=\s*["\']([^"\']+\.css[^"\']*)',
            html, re.I):
        urls.append(u)
    for u in re.findall(
            r'<script[^>]+src\s*=\s*["\']([^"\']+)', html, re.I):
        if u not in urls:
            urls.append(u)
    libraries = {}
    checked = []
    for url in urls[:12]:
        full = url if url.startswith("http") else base + url \
            if url.startswith("/") else url
        try:
            netloc = urllib.parse.urlparse(full).netloc
        except Exception:
            continue
        own = netloc in ("", host)
        r = get(full, timeout=timeout, max_bytes=200000)
        body = r.get("body") or ""
        if not body and r.get("status") != 200:
            continue
        checked.append(full)
        for name, url_pats, content_pats, floor, sev, advice in LIBRARIES:
            if name in libraries:
                continue
            version = _detect_from_text(name, url_pats, content_pats,
                                        body, full)
            if version is not None or (
                    name.lower().replace(".js", "") in
                    (full + body[:2000]).lower()):
                libraries[name] = {
                    "name": name, "version": version,
                    "source": full[:120], "own_code": own}
    libs = [libraries[k] for k in sorted(libraries)]
    findings = []
    for lib in libs:
        version = lib.get("version")
        if not version:
            continue  # version unknown — never guessed, no finding
        spec = next(s for s in LIBRARIES if s[0] == lib["name"])
        floor, sev, advice = spec[3], spec[4], spec[5]
        vt = _ver_tuple(version)
        if vt is not None and vt < floor:
            findings.append({
                "severity": sev,
                "name": "Outdated library: %s %s" % (lib["name"], version),
                "evidence": "%s %s found in %s (safe floor %s)"
                            % (lib["name"], version, lib["source"][:60],
                               ".".join(str(x) for x in floor)),
                "fix": advice})
    return {"engine": NAME, "status": "completed",
            "findings": findings,
            "data": {"libraries": libs, "count": len(libs),
                     "checked": checked,
                     "outdated": [f["name"] for f in findings]}}
