#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TLS Intelligence engine — testssl.sh / SSLyze style.

Protocol versions the server actually negotiates, the cipher of the
handshake, certificate details (issuer, subject, SANs, days left)
and HSTS. Passive handshake only.
"""
import socket
import ssl

NAME = "tls"
TITLE = "TLS Intelligence (testssl.sh)"


def _handshake(host, port, minimum, maximum, timeout=8):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = minimum
    ctx.maximum_version = maximum
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        wrapped = ctx.wrap_socket(sock, server_hostname=host)
        info = {"version": wrapped.version(),
                "cipher": (wrapped.cipher() or [None, None])[0],
                "cert": wrapped.getpeercert() or {}}
        wrapped.close()
        return info
    finally:
        try:
            sock.close()
        except Exception:
            pass


def run(ctx):
    host = ctx.get("host") or ""
    url = ctx.get("url") or ""
    findings = []
    data = {"host": host, "versions": {}, "cipher": None, "cert": {},
            "days_left": None, "hsts": None}
    if ctx.get("status") is None:
        return {"engine": NAME, "status": "error",
                "findings": [],
                "data": {"error": "homepage unreachable"}}
    if not url.startswith("https://"):
        data["note"] = "Site is plain HTTP — no TLS to test."
        findings.append({"severity": "high",
                         "name": "No TLS: site served over plain HTTP",
                         "evidence": url,
                         "fix": "Enable HTTPS with a valid certificate."})
        return {"engine": NAME, "status": "completed",
                "findings": findings, "data": data}
    port = 443
    for label, minimum, maximum in (
            ("TLSv1.0", ssl.TLSVersion.TLSv1, ssl.TLSVersion.TLSv1),
            ("TLSv1.1", ssl.TLSVersion.TLSv1_1, ssl.TLSVersion.TLSv1_1),
            ("TLSv1.2", ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2),
            ("TLSv1.3", ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)):
        try:
            info = _handshake(host, port, minimum, maximum)
            data["versions"][label] = True
            if label in ("TLSv1.2", "TLSv1.3") and not data["cipher"]:
                data["cipher"] = info.get("cipher")
        except Exception:
            data["versions"][label] = False
    for label in ("TLSv1.0", "TLSv1.1"):
        if data["versions"].get(label):
            findings.append({"severity": "medium",
                             "name": "Weak TLS protocol supported: %s" % label,
                             "evidence": "%s handshake succeeded" % label,
                             "fix": "Disable %s; require TLS 1.2 or newer." % label})
    try:
        info = _handshake(host, port, ssl.TLSVersion.TLSv1_2,
                          ssl.TLSVersion.TLSv1_3)
        cert = info.get("cert") or {}
        data["cipher"] = info.get("cipher")
        data["cert"] = {
            "issuer": str(cert.get("issuer", ""))[:160],
            "subject": str(cert.get("subject", ""))[:160],
            "sans": [v for _k, v in cert.get("subjectAltName", [])][:10],
            "not_after": cert.get("notAfter"),
            "not_before": cert.get("notBefore")}
        import datetime
        try:
            exp = datetime.datetime.strptime(cert["notAfter"],
                                             "%b %d %H:%M:%S %Y %Z")
            data["days_left"] = (exp - datetime.datetime.utcnow()).days
            if data["days_left"] < 0:
                findings.append({"severity": "critical",
                                 "name": "TLS certificate EXPIRED",
                                 "evidence": "expired %s" % cert["notAfter"],
                                 "fix": "Renew the certificate immediately."})
            elif data["days_left"] < 30:
                findings.append({"severity": "medium",
                                 "name": "TLS certificate expires soon",
                                 "evidence": "%d days left" % data["days_left"],
                                 "fix": "Renew the certificate before it expires."})
        except Exception:
            pass
    except Exception as exc:
        data["cert_error"] = str(exc)[:120]
    hsts = (ctx.get("headers") or {}).get("strict-transport-security")
    data["hsts"] = hsts
    return {"engine": NAME, "status": "completed",
            "findings": findings, "data": data}
