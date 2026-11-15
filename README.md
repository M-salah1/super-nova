# 🌟 Super Nova v1.00 — ULTIMATE SECURITY INVESTIGATION SYSTEM

**Developer:** Hafed Mehdi Salah Eddine — Algeria
**Organization:** FOX COMPANY
**Platform:** Python 3 (standard library only) — Termux / Linux / Windows
**Interface:** Terminal console in Arabic / English / French

One tool, **twenty engines**. Each engine does the job of a famous
professional tool — re-implemented in Python for Termux, defensive
only, for your own site or a site with written permission. No
exploitation, no login bypass, no secret values ever shown.

## The engines

| # | Engine | Does the job of | What it really does |
| - | ------ | --------------- | ------------------- |
| 1 | `web` | OWASP ZAP | Security headers, cookie flags, forms, HTTPS enforcement, mixed content |
| 2 | `vuln` | Nuclei / Nikto | 16 read-only templates: exposed .git, .env, backups, configs, phpinfo, server-status, API docs |
| 3 | `network` | Nmap | Rate-limited TCP connect scan (common ports + related neighbours), banner grab, TLS probe |
| 4 | `subdomains` | Subfinder / Amass | Certificate Transparency (crt.sh) + DNS wordlist via DoH + wildcard check |
| 5 | `httpx` | httpx | Live probe of every discovered host: status, title, server, TLS |
| 6 | `crawl` | Katana | Same-host crawl: pages, links, forms, scripts, stylesheets, e-mails |
| 7 | `fuzz` | FFUF | 60-path parallel wordlist probe (authorized targets only) |
| 8 | `tls` | testssl.sh / SSLyze | TLS 1.0–1.3 negotiation, cipher, certificate (issuer/SANs/expiry), HSTS |
| 9 | `tech` | WhatWeb | Server, X-Powered-By, generator, CMS, JS library versions |
| 10 | `history` | GAU | Wayback Machine CDX API: archived URLs, first/last seen |
| 11 | `secrets` | Gitleaks | Secret patterns in public text — names + locations only, values redacted |
| 12 | `wordpress` | WPScan | WP detection, public version, themes/plugins, REST API (detection only) |
| 13 | `semgrep` | Semgrep | Static patterns in public JS: eval, innerHTML, hardcoded credentials |
| 14 | `shodan` | Shodan | Host intel — only with your own `SHODAN_API_KEY` env var, else `not_configured` |
| 15 | `owner` | Owner Intelligence | Public RDAP: registrar, registrant org + handle (ID), registration/expiry dates, nameservers; certificate days left |
| 16 | `resources` | Resource Inventory | Every public asset (JS/CSS/images/fonts): status, size, internal/external, broken links |
| 17 | `dns` | DNS Intelligence | A/AAAA/MX/NS/TXT/CNAME/SOA/CAA/DS via DoH, SPF, DMARC, DNSSEC |
| 18 | `api` | **NEW — API Intelligence** | Public API surface: well-known OpenAPI/Swagger paths (GET only), endpoint paths from the site's own JS, robots/sitemap mentions. 401/403 = auth required, never a finding. No auth attempted, no POST. |
| 19 | `deps` | **NEW — Code/Dependency Intelligence** | Library names + versions parsed from the site's own JS/CSS (filenames, CDN URLs, version comments). Outdated parsed versions flagged LOW/INFO only. A version is never guessed — no version, no finding. |
| 20 | `timeline` | **NEW — Digital Forensics Timeline** | Dated timeline from public facts only: RDAP registration/expiry, TLS cert notBefore/notAfter, Wayback first/last capture, earliest CT certificate — each event with its source, sorted chronologically. Failed sources = unknown, not absent. |

## Executive Summary

Every scan ends with a short summary — printed in the terminal and
stored in the scan (`scan["summary"]`, also in the JSON report):

- score + grade, and the four separate metrics (Security Score,
  Confidence, Coverage, Verification Rate),
- the owner: registrar / registrant / domain expiry (days left) /
  certificate days left — or UNKNOWN when redacted or unavailable,
- the top 5 verified findings, each with its fix,
- the top 3 priority actions.

Re-print the summary of any stored scan from the console:

```
supernova > summary 3
```

## Framework Core — the brain

Engines no longer report straight to the score. Every finding flows
through a central pipeline:

```
engines -> Evidence Collector -> Validation Engine -> Correlation Engine
        -> Scoring -> Final Intelligence Report (+ Asset Intelligence)
        -> Executive Summary
```

- **Evidence Collector** (`core/evidence.py`) — every finding becomes
  one evidence record: engine, time, what was seen. One ID per record.
- **Validation Engine** (`core/validator.py`) — every finding is
  re-checked independently of the engine that found it: missing
  headers re-fetched, cookies re-checked, exposed paths re-GET,
  secret/JS patterns re-matched, TLS re-handshaken. Result: verified /
  observed / false_positive + confidence. False positives are removed
  from the score and listed separately — never silently counted.
- **Correlation Engine** (`core/correlation.py`) — merges duplicate
  findings across engines (one finding per problem) and detects
  attack chains no single engine can see (XSS session theft,
  session hijack on the wire, source + secrets exposure), plus
  contradictions between engines.
- **Scoring** (`core/scoring.py`) — one place where a score comes
  from; only validated findings count, and every finding explains
  WHY it is HIGH (evidence + validation + chain).
- **Asset Intelligence** (`core/assets.py`) — one linked inventory:
  domain, subdomains, IPs, ports, certificates, technologies,
  cookies, pages — and the links between them.
- **Executive Summary** (`core/summary.py`) — builds the short
  summary described above from the finished scan.

Console (per-engine menu and comparison):

```
supernova > engines                 # list all 20 engines
supernova > engine web https://example.com   # run one engine alone
supernova > compare 1 2             # diff two previous investigations
supernova > summary 1               # executive summary of scan #1
```

Still Python stdlib only — no pip installs in Termux. External tools
(ZAP, Nmap, testssl.sh) stay optional integrations for authorized
audits, never dependencies.

## Intelligent Verification — four honest metrics

A bare HTTP 200 was once treated as a confirmed leak, open TCP ports
as confirmed services, a 403 as a finding, and unconfirmed "High"
findings produced a misleading 0%. Super Nova does not do that:

- **Content-aware verification** (`core/content.py`) — the error
  page is fingerprinted first (two random paths); a 200 whose body
  matches it is an error page, not a file. Sensitive files must
  structurally match what they claim (.env needs KEY= lines, .sql
  needs SQL keywords, .git/HEAD must start with "ref:"). Only key
  NAMES are ever reported.
- **Status classification** — 200 real content / redirect /
  auth required / forbidden (not a finding) / absent / rate
  limited / server error. 403 is never a vulnerability.
- **Network service states** — tcp_open → service_identified →
  service_confirmed (banner match / HTTP response / TLS handshake).
  An empty banner is usually a firewall answering SYNs, not a
  service. No authentication is ever attempted.
- **Four separate metrics** — Security Score (confirmed findings
  only; indicators weigh half; false positives and info weigh
  nothing), Confidence (computed from validation, never fixed),
  Coverage (measured: engines + crawl visited/discovered +
  subdomains probed/found + ports), Verification Rate (share of
  findings verified).
- **Resume** — `resume <id>` re-runs only the timed-out / failed
  engines of a stored scan and updates it.
- **Errors are errors** — a CT 404 or RDAP 404 means "unknown, not
  absent"; subdomains/owner/timeline report the error instead of
  claiming nothing exists.
- **Semgrep** analyses only the site's own scripts; third-party
  libraries are reported separately as info. **Secrets** checks
  the homepage + 10 scripts + 5 crawled pages. **Crawl** reports
  discovered vs visited pages.

## Owner, cookies and verification

- **Welcome screen** — on entry: tool introduction, the 20 engines,
  developer credit, how-to. `about` shows it again any time.
- **Owner Intelligence** — the site owner's public identity and ID
  (registrar + registrant handle from RDAP), domain expiry in days,
  certificate expiry in days. Redacted data is reported UNKNOWN.
- **Cookies, fully detailed** — every cookie by name with Secure /
  HttpOnly / SameSite / domain / path / expiry / session flags.
  Values are never collected or shown.
- **Hidden fields & password fields** — hidden `<input>` names,
  password-field count, HTML-comment pattern scan. Names only;
  values are never collected or shown.
- **Resource inventory** — all public assets with status and size.
- **Verification Mode** — after a scan, dashboard option **4. Verify**:
  type an owner-provided value hidden; Super Nova checks in memory
  whether it appears in any public place the scan found and answers
  YES/NO + location only. The value never appears in any result or
  report. Real passwords and session values are never displayed —
  a displayed secret is a leaked secret.

## What is NOT inside, and why

- **Burp Suite** — a commercial Java proxy with manual interception.
  Super Nova's `web` engine does its automated part (request/response
  analysis); interactive proxying needs Burp itself.
- **Metasploit / sqlmap** — exploitation frameworks. Super Nova is
  defensive only: it finds and reports holes, it never exploits them.
- **Wireshark** — packet capture needs root and pcap; not possible
  from a Termux Python tool. Super Nova's `network` engine covers the
  reachable equivalent (connect scan + banners).
- **Shodan / Censys data** — commercial APIs. Super Nova queries
  Shodan only when you set your own key; it never invents Shodan data.
- **Exploitation, SQLi/XSS payloads, brute force, login bypass,
  DDoS, hack-back** — never included, by design. This is an audit
  tool for authorized targets only.

## Profiles

- `quick` — web + crawl + tls + tech + api + deps (fast, passive).
- `deep` — all engines except history/shodan; network + fuzz need authorization.
- `forensic` — everything, including history + Shodan (if configured).

## Honest scoring

- Score = 100 − confirmation-weighted severity weights
  (confirmed: critical 25, high 15, medium 8, low 3; indicators half).
- Coverage below 50%, or an unreachable target, gives **INCOMPLETE** —
  never a misleading 0%.
- Confidence and Verification Rate are computed from validation,
  never fixed numbers.

## Install (Termux)

```bash
pkg update && pkg install -y python git
git clone <repo-url>
cd super-nova
python3 supernova.py
```

No dependencies to install — Python standard library only.

## Run

```bash
python3 supernova.py                                  # console
python3 supernova.py https://example.com              # direct scan (deep)
python3 supernova.py https://example.com --profile quick --json supernova-report.json
python3 supernova.py https://example.com --profile forensic --html supernova-report.html
```

Console commands: `scan <url>`, `profile <quick|deep|forensic>`,
`history`, `summary <id>`, `compare <a> <b>`, `resume <id>`,
`engines`, `engine <name> <url>`, `lang`, `help`, `exit`. The first
scan asks for the ethical terms (type `y`); active checks ask once
for authorization (your own site or written permission).

Optional: `SHODAN_API_KEY=... python3 supernova.py <url>` enables the
Shodan engine. The key is read from the environment only — it is
never stored in a file or shown in any report.

## Storage

- `supernova-scans.db` — SQLite: one row per scan + one row per engine run.
- `supernova-scope.json` — remembered authorizations.
- `supernova-settings.json` — language + profile.
- `supernova-report.json` / `supernova-report.html` — exports.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

72 tests, all passing (2026-11-15): every engine against a local lab
server (weak site: no security headers, cookie without flags,
`/.git/HEAD` and `/.env` public, WordPress 5.8, old jQuery, JS with
`eval()` + a hardcoded api key, plus OpenAPI docs, React 18.2.0 and a
version-less Vue file for the new engines), framework/validation/
correlation tests, content-aware verification tests, orchestrator
quick/deep scans, INCOMPLETE on a dead target, SQLite round-trip,
and the Executive Summary (built, ordered top-5, priority actions,
re-printed from SQLite).
