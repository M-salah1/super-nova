#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Engine registry: every engine in Super Nova, in run order."""
from . import api, crawl, deps, dns, fuzz, history, httpx, network
from . import owner, resources, secrets, semgrep, shodan, subdomains
from . import tech, timeline, tls, vuln, web, wordpress

ENGINES = [web, crawl, tls, tech, vuln, subdomains, history, httpx,
           wordpress, semgrep, secrets, network, fuzz, shodan,
           owner, resources, dns, api, deps, timeline]

BY_NAME = {e.NAME: e for e in ENGINES}

# Profiles: which engines run.
PROFILES = {
    "quick": ["web", "crawl", "tls", "tech", "api", "deps"],
    "deep": ["web", "crawl", "tls", "tech", "vuln", "subdomains",
             "httpx", "wordpress", "semgrep", "secrets", "network", "fuzz",
             "owner", "resources", "dns", "api", "deps", "timeline"],
    "forensic": ["web", "crawl", "tls", "tech", "vuln", "subdomains",
                 "history", "httpx", "wordpress", "semgrep", "secrets",
                 "network", "fuzz", "shodan", "owner", "resources", "dns",
                 "api", "deps", "timeline"],
}
