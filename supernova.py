#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Super Nova v1.00 — entry point.

Terminal console (Arabic / French / English) + direct scan mode.
    python3 supernova.py                  # console
    python3 supernova.py https://example.com
    python3 supernova.py https://example.com --profile forensic --json out.json
"""
import getpass
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from supernova import __version__  # noqa: E402
from supernova.core import engine as engine_mod  # noqa: E402
from supernova.core import report as report_mod  # noqa: E402
from supernova.core import storage as storage_mod  # noqa: E402
from supernova.core import summary as summary_mod  # noqa: E402
from supernova.core import verify as verify_mod  # noqa: E402
from supernova.core.http import (get, lower_headers, request_retry,  # noqa: E402
                           resolve_ips)
from supernova.core.i18n import t  # noqa: E402
from supernova.core.scope import Scope, normalize_url, valid_url  # noqa: E402
from supernova.engines import BY_NAME, PROFILES  # noqa: E402

SETTINGS_FILE = "supernova-settings.json"
DB_FILE = "supernova-scans.db"

SUPERNOVA_BANNER = r"""
   /\   /\
  (  o   o  )
   (   =^=   )
    (       )
     |  |  |
  🦊 Super Nova v%s — FOX COMPANY
"""

WELCOME = {
    "ar": [
        "🦊 Super Nova v1.00 — نسخة عالية",
        "نظام التحقيق الأمني الموحد — FOX COMPANY",
        "المطور: حافظ مهدي صلاح الدين — الجزائر",
        "",
        "ماذا تفعل الأداة؟",
        "• 20 محرك تحقيق: فحص الويب، الثغرات، الشبكة، النطاقات الفرعية،",
        "  TLS، التقنيات، الأرشيف، الأسرار، ووردبريس، تحليل JS،",
        "  المالك، وموارد الموقع، واجهات API، المكتبات، والخط الزمني",
        "• التعريف بصاحب الموقع: المعرّف العام، المسجّل، وتاريخ انتهاء",
        "  النطاق والشهادات — بالأيام المتبقية",
        "• جلب الكوكيز (بالأسماء والأعلام فقط) وموارد الموقع",
        "  والحقول المخفية (بالأسماء فقط) وحقول كلمات السر",
        "• تقارير JSON/HTML وحفظ كل فحص في قاعدة بيانات",
        "",
        "كيف تعمل؟",
        "اكتب:  scan https://example.com",
        "ثم وافق على الشروط بـ y — وسيبدأ الفحص.",
        "الأوامر: profile (quick/deep/forensic) — history — lang — about — exit",
    ],
    "en": [
        "🦊 Super Nova v1.00 — high edition",
        "Unified Security Investigation System — FOX COMPANY",
        "Developer: Hafed Mehdi Salah Eddine — Algeria",
        "",
        "What does it do?",
        "• 20 investigation engines: web, vulnerabilities, network,",
        "  subdomains, TLS, tech, history, secrets, WordPress, JS",
        "  analysis, owner intelligence, site resources, API, deps, timeline",
        "• Owner identification: public ID, registrar, and expiry",
        "  dates of the domain and its certificates — days left",
        "• Cookies (names and flags only), site resources, hidden",
        "  fields (names only) and password fields",
        "• JSON/HTML reports and every scan saved in a database",
        "",
        "How to work?",
        "Type:  scan https://example.com",
        "Then accept the terms with y — and the scan begins.",
        "Commands: profile (quick/deep/forensic) — history — lang — about — exit",
    ],
    "fr": [
        "🦊 Super Nova v1.00 — édition avancée",
        "Système unifié d'investigation de sécurité — FOX COMPANY",
        "Développeur : Hafed Mehdi Salah Eddine — Algérie",
        "",
        "Que fait l'outil ?",
        "• 20 moteurs : web, vulnérabilités, réseau, sous-domaines,",
        "  TLS, technologies, archives, secrets, WordPress, analyse JS,",
        "  propriétaire, ressources, API, dépendances, chronologie",
        "• Identification du propriétaire : identifiant public, bureau",
        "  d'enregistrement, dates d'expiration du domaine et des",
        "  certificats — jours restants",
        "• Cookies (noms et drapeaux uniquement), ressources du site,",
        "  champs cachés (noms uniquement) et champs de mot de passe",
        "• Rapports JSON/HTML et chaque scan sauvé en base de données",
        "",
        "Comment l'utiliser ?",
        "Tapez :  scan https://example.com",
        "Puis acceptez les conditions avec y — le scan commence.",
        "Commandes : profile (quick/deep/forensic) — history — lang — about — exit",
    ],
}


def show_welcome(lang, pause=True):
    print("=" * 60)
    for line in WELCOME.get(lang, WELCOME["en"]):
        print(line)
    print("=" * 60)
    if pause:
        try:
            input("%s " % t(lang, "welcome_press"))
        except (EOFError, KeyboardInterrupt):
            pass


def load_settings():
    try:
        with open(SETTINGS_FILE, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"language": "ar", "profile": "deep"}


def save_settings(settings):
    try:
        with open(SETTINGS_FILE, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False)
    except Exception:
        pass


def choose_language():
    print("1. العربية    2. English    3. Français")
    try:
        choice = input("> ").strip()
    except (EOFError, KeyboardInterrupt):
        return "ar"
    return {"1": "ar", "2": "en", "3": "fr"}.get(choice, "ar")


class Spinner:
    """One-line loader: spinner + current engine + % + elapsed."""

    SPINNER = ["◐", "◓", "◑", "◒"]

    def __init__(self, total, lang):
        self.total = max(1, total)
        self.done = set()
        self.current = ""
        self.lang = lang
        self.started = time.time()
        self.stop = False
        self.thread = None

    def progress(self, name):
        self.done.add(name)
        self.current = name

    def _run(self):
        frame = 0
        while not self.stop:
            spin = self.SPINNER[frame % len(self.SPINNER)]
            pct = min(99, int(100 * len(self.done) / self.total))
            elapsed = int(time.time() - self.started)
            line = "\r%s %s %d%%" % (spin, t(self.lang, "scanning"), pct)
            if self.current:
                line += " — %s" % self.current[:24]
            line += " %ds" % elapsed
            sys.stdout.write(line)
            sys.stdout.flush()
            time.sleep(0.12)
            frame += 1

    def start(self):
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def finish(self, duration):
        self.stop = True
        if self.thread:
            self.thread.join(timeout=1)
        sys.stdout.write("\r%s %s %.1fs — %d/%d %s\n" % (
            "✓", t(self.lang, "done"), duration, len(self.done),
            self.total, t(self.lang, "phases")))
        sys.stdout.flush()


def accept_terms(lang, scope, url):
    print("=" * 60)
    print("  ⚖  %s" % t(lang, "terms_title"))
    for i in range(1, 5):
        print("   • %s" % t(lang, "terms_%d" % i))
    print("=" * 60)
    try:
        ans = input("%s " % t(lang, "terms_accept")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if ans != "y":
        print(t(lang, "terms_declined"))
        return False
    print(t(lang, "terms_accepted"))
    return True


def ask_authorization(lang, scope, url):
    if scope.is_authorized(url):
        return True
    print(t(lang, "auth_needed"))
    try:
        ans = input("%s " % t(lang, "auth_question")).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return False
    if ans == "y":
        scope.authorize(url)
        return True
    return False


def do_scan(url, profile, lang, scope, settings):
    url = normalize_url(url)
    if not valid_url(url):
        print(t(lang, "invalid_url"))
        return None
    if not accept_terms(lang, scope, url):
        return None
    # Active engines (network + fuzz) need authorization; ask once.
    needs_auth = profile in ("deep", "forensic")
    if needs_auth and not scope.is_authorized(url):
        if ask_authorization(lang, scope, url):
            pass  # authorized now; passive run continues either way
    total = len(PROFILES[profile])
    spin = Spinner(total, lang)
    spin.start()
    try:
        scan = engine_mod.run_scan(url, profile=profile, scope=scope,
                                   settings=settings,
                                   progress=spin.progress)
    finally:
        spin.finish(scan["duration_s"] if "scan" in dir() else 0)
    report_mod.print_report(scan, lang)
    try:
        scan_id = storage_mod.save_scan(DB_FILE, scan)
        scan["scan_id"] = scan_id
    except Exception:
        pass
    return scan


def dashboard(scan, lang):
    while True:
        print("-" * 60)
        print("0. %s    1. %s    2. JSON    3. HTML    4. %s" % (
            t(lang, "back"), t(lang, "findings"), t(lang, "verify")))
        try:
            choice = input("%s " % t(lang, "enter_choice")).strip()
        except (EOFError, KeyboardInterrupt):
            return
        if choice == "0" or choice == "":
            return
        if choice == "1":
            for f in scan.get("findings") or []:
                print("  [%s] %s" % (f["severity"].upper(), f["name"]))
                print("      %s" % f.get("evidence", "")[:180])
                print("      Fix: %s" % f.get("fix", "")[:180])
        elif choice == "2":
            path = report_mod.to_json(scan, "supernova-report.json")
            print("Saved: %s" % path)
        elif choice == "3":
            path = report_mod.to_html(scan, "supernova-report.html")
            print("Saved: %s" % path)
        elif choice == "4":
            # Verification Mode: compare without ever displaying.
            try:
                secret = getpass.getpass("%s " % t(lang, "verify_prompt"))
            except (EOFError, KeyboardInterrupt):
                continue
            if not secret:
                continue
            res = verify_mod.verify_secret(scan, secret)
            secret = ""
            if res["found"]:
                print("%s" % t(lang, "verify_found"))
                for f in res["found"]:
                    print("  • %s (%s)" % (f["where"], f["kind"]))
            else:
                print(t(lang, "verify_not_found"))
            print("%s: %d" % (t(lang, "verify_checked"), res["checked"]))


def show_history(lang):
    rows = storage_mod.list_scans(DB_FILE)
    print("=" * 60)
    print("🦊 %s" % t(lang, "history"))
    if not rows:
        print(t(lang, "no_history"))
        return
    for r in rows:
        score = r["score"] if r["score"] is not None else "INCOMPLETE"
        print("#%s  %s  [%s]  score=%s  grade=%s  coverage=%s%%  %s" % (
            r["id"], r["target"], r["profile"], score, r["grade"],
            r["coverage"], r["finished_at"] or ""))


def list_engines():
    print("=" * 60)
    for name, mod in sorted(BY_NAME.items()):
        print("  %-12s — %s" % (name, mod.TITLE))
    print("=" * 60)


def run_single_engine(name, url, lang, scope):
    """Run one engine standalone (framework menu per engine)."""
    if name not in BY_NAME:
        print("unknown engine — type engines")
        return
    url = normalize_url(url)
    if not valid_url(url):
        print(t(lang, "invalid_url"))
        return
    host = url.split("/")[2]
    domain = host.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]
    r = request_retry(url, timeout=10, attempts=2)
    ctx = {"url": url, "host": host, "domain": domain,
           "authorized": scope.is_authorized(url), "timeout": 8,
           "html": r.get("body") or "",
           "headers": lower_headers(r.get("headers") or {}),
           "cookie_headers": [], "status": r.get("status"),
           "ips": resolve_ips(domain if "." in domain else host),
           "pages": [], "scripts": [], "subdomains": [], "tls": {}}
    try:
        ctx["cookie_headers"] = list(
            r.get("headers").get_all("Set-Cookie") or [])
    except Exception:
        pass
    if name in ("semgrep", "secrets", "api", "deps"):
        crawl_res = BY_NAME["crawl"].run(ctx)
        ctx["scripts"] = (crawl_res.get("data") or {}).get("scripts") or []
    out = engine_mod.call_with_timeout(
        lambda: BY_NAME[name].run(ctx), 60)
    if isinstance(out, dict) and out.get("timed_out"):
        print("timeout")
        return
    print("Engine: %s — %s" % (name, (out or {}).get("status")))
    for f in (out or {}).get("findings") or []:
        print("  [%s] %s" % (f["severity"].upper(), f["name"]))
        print("      %s" % f.get("evidence", "")[:180])


def compare_cmd(arg, lang):
    parts = arg.split()
    if len(parts) != 2:
        print("compare <id1> <id2>   (see history for ids)")
        return
    try:
        a = storage_mod.get_scan(DB_FILE, int(parts[0]))
        b = storage_mod.get_scan(DB_FILE, int(parts[1]))
    except ValueError:
        a = b = None
    if not a or not b:
        print("scan not found — type history")
        return
    diff = storage_mod.compare_scans(a, b)
    print("=" * 60)
    print("Compare #%s -> #%s" % (parts[0], parts[1]))
    print("Score: %s -> %s    Coverage: %s%% -> %s%%" % (
        diff["score"][0], diff["score"][1],
        diff["coverage"][0], diff["coverage"][1]))
    for f in diff["added"]:
        print("  + [%s] %s" % (f["severity"].upper(), f["name"]))
    for f in diff["removed"]:
        print("  - [%s] %s" % (f["severity"].upper(), f["name"]))
    for c in diff["changed"]:
        print("  ~ %s: %s -> %s" % (c["name"], c["from"], c["to"]))
    if not diff["added"] and not diff["removed"] and not diff["changed"]:
        print("  (no changes)")
    print("=" * 60)


def resume_cmd(arg, lang, scope):
    parts = arg.split()
    if len(parts) != 1:
        print("resume <id>   (see history for ids)")
        return
    try:
        scan_id = int(parts[0])
    except ValueError:
        print("resume <id>   (see history for ids)")
        return
    print("%s #%d ..." % (t(lang, "help_resume"), scan_id))
    scan, resumed = engine_mod.resume_scan(DB_FILE, scan_id, scope=scope)
    if scan is None:
        print("scan not found — type history")
        return
    if not resumed:
        print("nothing to resume — no timed-out or failed engines")
        return
    print("resumed: %s" % ", ".join(resumed))
    report_mod.print_report(scan, lang)


def summary_cmd(arg, lang):
    """Re-print the executive summary of a stored scan: summary <id>."""
    try:
        scan_id = int(arg.split()[0])
    except (ValueError, IndexError):
        print("summary <id>   (see history for ids)")
        return
    scan = storage_mod.get_scan(DB_FILE, scan_id)
    if not scan:
        print("scan not found — type history")
        return
    summary = scan.get("summary") or summary_mod.build_summary(scan)
    print(summary_mod.format_summary(summary, lang))


def print_help(lang):
    print("=" * 60)
    print("🦊 %s" % t(lang, "help_title"))
    print("  scan <url>      — %s" % t(lang, "help_scan"))
    print("  engine <n> <url> — %s" % t(lang, "help_engine"))
    print("  engines         — %s" % t(lang, "help_engines"))
    print("  compare <a> <b> — %s" % t(lang, "help_compare"))
    print("  resume <id>     — %s" % t(lang, "help_resume"))
    print("  summary <id>    — Executive summary of a stored scan")
    print("  profile <name>  — %s (quick / deep / forensic)" % t(lang, "help_profile"))
    print("  history         — %s" % t(lang, "help_history"))
    print("  lang            — %s" % t(lang, "help_lang"))
    print("  about           — %s" % t(lang, "about"))
    print("  help            — %s" % t(lang, "help_title"))
    print("  exit / 0        — %s" % t(lang, "help_exit"))
    print("=" * 60)


def console():
    settings = load_settings()
    print(SUPERNOVA_BANNER % __version__)
    print(t("ar", "choose_language"))
    lang = choose_language()
    settings["language"] = lang
    save_settings(settings)
    profile = settings.get("profile", "deep")
    scope = Scope()
    print("%s — %s" % (t(lang, "app_subtitle"), t(lang, "org")))
    print(t(lang, "developer"))
    print(t(lang, "welcome"))
    print(t(lang, "how_to"))
    print("profile: %s" % profile)
    show_welcome(lang)
    while True:
        try:
            raw = input("\nsupernova > ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n%s" % t(lang, "goodbye"))
            return
        if not raw:
            continue
        parts = raw.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""
        if cmd in ("exit", "quit", "0"):
            print(t(lang, "goodbye"))
            return
        if cmd == "help":
            print_help(lang)
        elif cmd in ("about", "welcome"):
            show_welcome(lang, pause=False)
        elif cmd == "lang":
            lang = choose_language()
            settings["language"] = lang
            save_settings(settings)
            print("Language: %s" % lang)
        elif cmd == "profile":
            if arg in PROFILES:
                profile = arg
                settings["profile"] = profile
                save_settings(settings)
                print("profile: %s" % profile)
            else:
                print("quick / deep / forensic")
        elif cmd == "history":
            show_history(lang)
        elif cmd == "engines":
            list_engines()
        elif cmd == "engine":
            parts = arg.split(None, 1)
            if len(parts) != 2:
                print("engine <name> <url>")
            else:
                run_single_engine(parts[0], parts[1], lang, scope)
        elif cmd == "compare":
            compare_cmd(arg, lang)
        elif cmd == "resume":
            resume_cmd(arg, lang, scope)
        elif cmd == "summary":
            summary_cmd(arg, lang)
        elif cmd == "scan":
            if not arg:
                try:
                    arg = input("%s " % t(lang, "enter_url")).strip()
                except (EOFError, KeyboardInterrupt):
                    continue
            scan = do_scan(arg, profile, lang, scope, settings)
            if scan:
                dashboard(scan, lang)
        elif valid_url(normalize_url(raw)):
            scan = do_scan(raw, profile, lang, scope, settings)
            if scan:
                dashboard(scan, lang)
        else:
            print(t(lang, "unknown_command"))


def main(argv):
    if "--version" in argv:
        print("Super Nova v%s" % __version__)
        return 0
    settings = load_settings()
    lang = settings.get("language", "ar")
    profile = settings.get("profile", "deep")
    url = None
    json_out = None
    html_out = None
    i = 1
    while i < len(argv):
        a = argv[i]
        if a == "--profile" and i + 1 < len(argv):
            profile = argv[i + 1]
            i += 2
        elif a == "--lang" and i + 1 < len(argv):
            lang = argv[i + 1]
            i += 2
        elif a == "--json" and i + 1 < len(argv):
            json_out = argv[i + 1]
            i += 2
        elif a == "--html" and i + 1 < len(argv):
            html_out = argv[i + 1]
            i += 2
        elif not a.startswith("-"):
            url = a
            i += 1
        else:
            i += 1
    if profile not in PROFILES:
        profile = "deep"
    if not url:
        console()
        return 0
    scope = Scope()
    url = normalize_url(url)
    if not valid_url(url):
        print(t(lang, "invalid_url"))
        return 2
    scan = engine_mod.run_scan(url, profile=profile, scope=scope,
                               settings=settings)
    report_mod.print_report(scan, lang)
    try:
        storage_mod.save_scan(DB_FILE, scan)
    except Exception:
        pass
    if json_out:
        print("Saved: %s" % report_mod.to_json(scan, json_out))
    if html_out:
        print("Saved: %s" % report_mod.to_html(scan, html_out))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
