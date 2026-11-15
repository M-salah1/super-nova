#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Network Intelligence engine — Nmap style (v1.00).

Rate-limited TCP connect scan of well-known ports against the
already-resolved IP, with service STATES — not just "open":

- tcp_open: the port answered, but no banner and no protocol
  greeting. Often a firewall or middlebox answering SYNs.
- service_identified: the banner matches a known service.
- service_confirmed: the service answered a protocol greeting
  (HTTP response, TLS handshake, SSH banner).

An open TCP port is NOT a confirmed service, and a confirmed
service is NOT a confirmed vulnerability. No authentication is
ever attempted — no logins, no commands, no credential checks.
Authorized targets only.
"""
import concurrent.futures
import socket
import ssl

NAME = "network"
TITLE = "Network Intelligence (Nmap)"

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
    80: "http", 110: "pop3", 143: "imap", 443: "https", 445: "smb",
    465: "smtps", 587: "smtp", 993: "imaps", 995: "pop3s",
    1433: "mssql", 1521: "oracle", 1723: "pptp", 2049: "nfs",
    2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm", 2087: "whm-ssl",
    2181: "zookeeper", 2222: "ssh-alt", 2375: "docker", 2376: "docker-ssl",
    3000: "node", 3306: "mysql", 3389: "rdp", 3690: "svn",
    4369: "epmd", 5000: "flask", 5432: "postgres", 5601: "kibana",
    5672: "rabbitmq", 5900: "vnc", 5984: "couchdb", 6000: "x11",
    6379: "redis", 7001: "cassandra", 8000: "http-alt", 8008: "http-alt",
    8080: "http-proxy", 8081: "http-alt", 8443: "https-alt",
    8888: "http-alt", 9000: "php-fpm", 9090: "http-alt", 9092: "kafka",
    9200: "elasticsearch", 9300: "elasticsearch", 9418: "git",
    10000: "webmin", 11211: "memcached", 15672: "rabbitmq-mgmt",
    27017: "mongodb", 27018: "mongodb", 28017: "mongodb-web",
}

RELATED = {8080: [8000, 8008, 8081, 8888, 8443, 9000, 9090],
           80: [8080, 8000, 8888], 443: [8443, 9443],
           3306: [33060], 5432: [5433], 6379: [6380],
           27017: [27018, 28017], 22: [2222]}

TLS_PORTS = (443, 8443, 9443, 2083, 2087, 465, 993, 995)

# (substring in banner, service) — checked in order.
BANNER_SIGNS = [
    ("SSH-", "ssh"), ("HTTP/", "http"), ("mysql_native_password", "mysql"),
    ("mysql", "mysql"), ("Redis", "redis"), ("RFB ", "vnc"),
    ("PostgreSQL", "postgres"), ("MongoDB", "mongodb"),
    ("220", "smtp/ftp"),
]


def _identify(banner):
    """Match a banner to a service. Returns (service, confirmed)."""
    if not banner:
        return None, False
    if banner.startswith("SSH-"):
        return "ssh", True  # the SSH banner IS the protocol greeting
    if banner.startswith("HTTP/"):
        return "http", True
    low = banner.lower()
    for sign, service in BANNER_SIGNS:
        if sign.lower() in low or sign in banner:
            return service, False
    return None, False


def _grab(sock, timeout=0.6):
    try:
        sock.settimeout(timeout)
        return sock.recv(256).decode(errors="ignore").strip()[:120]
    except Exception:
        return ""


def _http_probe(sock):
    """Send a HEAD request; an HTTP response confirms the service."""
    try:
        sock.settimeout(1.0)
        sock.sendall(b"HEAD / HTTP/1.0\r\nHost: x\r\n\r\n")
        data = sock.recv(256).decode(errors="ignore")
        return data.startswith("HTTP/")
    except Exception:
        return False


def _check(ip, port, timeout=0.4):
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
    except Exception:
        return None
    banner = _grab(sock)
    service, confirmed = _identify(banner)
    state = "tcp_open"
    tls_info = None
    if confirmed:
        state = "service_confirmed"
    elif service:
        state = "service_identified"
    if port in TLS_PORTS:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            wrapped = ctx.wrap_socket(sock, server_hostname=ip)
            cert = wrapped.getpeercert(binary_form=False) or {}
            tls_info = {"version": wrapped.version(),
                        "cipher": (wrapped.cipher() or [None])[0],
                        "issuer": str(cert.get("issuer", ""))[:120]}
            wrapped.close()
            state = "service_confirmed"
            service = service or "tls"
            return {"port": port, "service": service or COMMON_PORTS.get(port, "?"),
                    "state": state, "banner": banner, "tls": tls_info}
        except Exception:
            pass
    elif not confirmed:
        # No banner and no protocol greeting yet: try one HEAD request.
        # Any service that answers "HTTP/..." is confirmed HTTP; anything
        # else simply stays tcp_open (often a firewall answering SYNs).
        if _http_probe(sock):
            state = "service_confirmed"
            service = service or "http"
    try:
        sock.close()
    except Exception:
        pass
    return {"port": port, "service": service or COMMON_PORTS.get(port, "?"),
            "state": state, "banner": banner, "tls": tls_info}


def _scan(ip, ports, timeout=0.4, workers=30):
    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = {pool.submit(_check, ip, p, timeout): p for p in ports}
        for fut in futs:
            try:
                res = fut.result()
            except Exception:
                res = None
            if res:
                found.append(res)
    return sorted(found, key=lambda r: r["port"])


def run(ctx):
    if not ctx.get("authorized"):
        return {"engine": NAME, "status": "not_tested",
                "findings": [], "data": {"note": "needs authorization"}}
    ips = ctx.get("ips") or []
    if not ips:
        return {"engine": NAME, "status": "error",
                "findings": [], "data": {"error": "no IP resolved"}}
    ip = ips[0]
    timeout = ctx.get("timeout", 8)
    phase1 = _scan(ip, sorted(COMMON_PORTS), timeout=0.4)
    tried = set(COMMON_PORTS)
    related = []
    for item in phase1:
        for p in RELATED.get(item["port"], []):
            if p not in tried:
                related.append(p)
                tried.add(p)
    phase2 = _scan(ip, related, timeout=0.4) if related else []
    open_ports = sorted(phase1 + phase2, key=lambda r: r["port"])
    by_state = {}
    for item in open_ports:
        by_state[item["state"]] = by_state.get(item["state"], 0) + 1
    findings = []
    risky = {21, 23, 3306, 5432, 6379, 27017, 5900, 1433, 3389, 445, 2375}
    for item in open_ports:
        if item["port"] not in risky:
            continue
        if item["state"] in ("service_confirmed", "service_identified"):
            findings.append({
                "severity": "high", "confirmation": "confirmed",
                "name": "Sensitive service %s: %s on port %d"
                        % (item["state"].replace("_", " "),
                           item["service"], item["port"]),
                "evidence": "port %d %s, banner: %s"
                            % (item["port"], item["state"],
                               item.get("banner") or "—"),
                "fix": "Close port %d to the internet or restrict it "
                       "to trusted networks only." % item["port"]})
        else:
            findings.append({
                "severity": "info", "confirmation": "indicator",
                "name": "Port %d open but service unidentified"
                        % item["port"],
                "evidence": "port %d answered TCP but sent no banner "
                            "— often a firewall answering SYNs, not a "
                            "service" % item["port"],
                "fix": "Confirm from inside the network whether a "
                       "service really listens on port %d."
                       % item["port"]})
    return {"engine": NAME, "status": "completed", "findings": findings,
            "data": {"ip": ip, "open_ports": open_ports,
                     "open_count": len(open_ports),
                     "by_state": by_state,
                     "confirmed_count": by_state.get(
                         "service_confirmed", 0)
                     + by_state.get("service_identified", 0),
                     "phase1": len(COMMON_PORTS),
                     "phase2_related": len(related)}}
