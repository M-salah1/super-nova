#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Asset Intelligence — one linked inventory of everything found.

The asset graph links what the engines discovered separately: the
domain, its subdomains, its IPs, its open ports, its certificates,
its technologies and its cookies. The report shows the inventory;
the links show how the pieces connect.
"""


def build_assets(scan, ctx):
    res = scan.get("results") or {}

    def data(engine):
        return (res.get(engine) or {}).get("data") or {}

    tech = data("tech")
    tls = data("tls")
    owner = data("owner")
    network = data("network")
    subdomains = data("subdomains").get("subdomains") or []
    ips = ctx.get("ips") or []
    domain = ctx.get("domain") or ""
    links = []
    for s in subdomains:
        links.append({"from": domain, "to": s, "type": "subdomain"})
    for ip in ips:
        links.append({"from": domain, "to": ip, "type": "resolves_to"})
    for p in network.get("open_ports") or []:
        links.append({"from": ips[0] if ips else domain,
                      "to": "port %s" % p["port"], "type": "serves"})
    return {
        "domain": domain,
        "subdomains": subdomains, "subdomain_count": len(subdomains),
        "ips": ips,
        "open_ports": [p["port"] for p in network.get("open_ports") or []],
        "technologies": [t.get("name")
                         for t in tech.get("technologies") or []],
        "cms": tech.get("cms"),
        "certificate": {"issuer": (tls.get("cert") or {}).get("issuer"),
                        "days_left": tls.get("days_left")},
        "domain_expires": owner.get("expires"),
        "domain_days_left": owner.get("days_left"),
        "registrar": owner.get("registrar"),
        "registrant": owner.get("registrant"),
        "cookies": len(data("web").get("cookies") or []),
        "pages": len(data("crawl").get("pages") or []),
        "assets": data("resources").get("count", 0),
        "links": links,
    }
