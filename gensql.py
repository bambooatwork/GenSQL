#!/usr/bin/env python
"""
GenSQL v2.0.0 — Next-Generation Web Security Assessment Framework
Author  : Jeevraj

 ██████╗ ███████╗███╗   ██╗███████╗ ██████╗ ██╗
██╔════╝ ██╔════╝████╗  ██║██╔════╝██╔═══██╗██║
██║  ███╗█████╗  ██╔██╗ ██║███████╗██║   ██║██║
██║   ██║██╔══╝  ██║╚██╗██║╚════██║██║▄▄ ██║██║
╚██████╔╝███████╗██║ ╚████║███████║╚██████╔╝███████╗
 ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚══▀▀═╝ ╚══════╝
"""
from __future__ import print_function

# ── GenSQL-only flags (stripped before core engine sees argv) ─────────────────
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
    "--bypass-403", "--bypass-404", "--bypass-429", "--bypass-503",
    "--auto-bypass",
    "--adv-dump", "--dump-hex", "--dump-blind", "--dump-bitwise",
    "--dump-time", "--dump-error", "--dump-parallel", "--dump-creds",
    "--dump-all-tables", "--dump-resume", "--force-dump",
    "--no-banner",
}
_GENSQL_VALUE_FLAGS = {
    "--nosql-type", "--cloud-provider", "--encoder-chain", "--swagger-url",
    "--shodan-key", "--oob-domain", "--oob-http", "--report-html",
    "--report-json", "--report-md", "--profile", "--idor-range",
    "--max-concurrent", "--ai-top-payloads", "--oob-listen",
    "--rotate-identity", "--dashboard-port",
    "--dump-technique", "--dump-table", "--dump-columns",
    "--dump-output", "--dump-threads", "--dump-chunk",
    "--bypass-url", "--bypass-payload",
    "--target",   # GenSQL alias for -u
    "--mode",     # bypass mode
}


def _strip_gensql_args(argv):
    """Strip GenSQL-specific flags before the core engine sees argv."""
    clean = []
    i = 1
    while i < len(argv):
        a = argv[i]
        if a in _GENSQL_BOOL_FLAGS:
            i += 1; continue
        if a in _GENSQL_VALUE_FLAGS:
            i += 2; continue
        key = a.split("=")[0]
        if key in _GENSQL_VALUE_FLAGS:
            i += 1; continue
        # Map GenSQL aliases to core flags
        if a == "--target":
            i += 1  # skip the flag, next arg is handled below
            continue
        clean.append(a)
        i += 1
    return [argv[0]] + clean


# ─────────────────────────────────────────────────────────────────────────────
try:
    import sys, os, bdb, glob, inspect, json, logging, re
    import shutil, threading, time, traceback, warnings, argparse

    sys.dont_write_bytecode = True

    # Install GenSQL UI first — before ANY logging happens
    try:
        from lib.core.gensql_ui import install as _install_ui, C, info, warn, error, fatal, banner_line, success
        _install_ui()
        _UI_READY = True
    except Exception as _ui_err:
        _UI_READY = False
        C = type("C", (), {"RESET": "", "BOLD": "", "CYAN": "", "GREEN": "",
                            "YELLOW": "", "RED": "", "GRAY": "", "WHITE": ""})()
        def info(m): print("[ ~ ] " + m)
        def warn(m): print("[ ! ] " + m)
        def error(m): print("[ERR] " + m)
        def fatal(m): print("[!!!] " + m)
        def success(m): print("[ + ] " + m)
        def banner_line(t=""): print("  ── " + t)

    try:
        __import__("lib.utils.versioncheck")
    except ImportError:
        fatal("Run GenSQL from its root directory  →  cd GenSQL && python gensql.py")
        sys.exit(1)

    try: ResourceWarning
    except NameError: ResourceWarning = Warning

    if "--deprecations" not in sys.argv:
        warnings.filterwarnings(action="ignore", category=DeprecationWarning)
    warnings.filterwarnings(action="ignore", message="Python 2 is no longer supported")
    warnings.filterwarnings(action="ignore", message=".*was already imported", category=UserWarning)
    warnings.filterwarnings(action="ignore", category=UserWarning, module="psycopg2")
    warnings.filterwarnings(action="ignore", category=ResourceWarning)

    from lib.core.data import logger
    from lib.core.common import (checkPipedInput, codeIsModified, createGithubIssue,
        dataToStdout, filterNone, getDaysFromLastUpdate, getFileItems,
        getSafeExString, maskSensitiveData, openFile, setPaths,
        weAreFrozen, setColor, unhandledExceptionMessage)
    from lib.core.convert import getUnicode
    from lib.core.compat import LooseVersion, xrange
    from lib.core.data import cmdLineOptions, conf, kb
    from lib.core.datatype import OrderedSet
    from lib.core.enums import MKSTEMP_PREFIX
    from lib.core.exception import (SqlmapBaseException, SqlmapShellQuitException,
        SqlmapSilentQuitException, SqlmapUserQuitException)
    from lib.core.option import init, initOptions
    from lib.core.patch import dirtyPatches, resolveCrossReferences
    from lib.core.settings import (GIT_PAGE, LAST_UPDATE_NAGGING_DAYS,
        LEGAL_DISCLAIMER, THREAD_FINALIZATION_TIMEOUT,
        UNICODE_ENCODING, VERSION, JEEVSQL_BANNER, JEEVSQL_VERSION)
    from lib.parse.cmdline import cmdLineParser
    from lib.utils.crawler import crawl

except KeyboardInterrupt:
    print("\n  Aborted."); sys.exit(0)


# ── Safe module importer ──────────────────────────────────────────────────────
def _safe_import(mod, attr=None):
    try:
        m = __import__(mod, fromlist=[attr] if attr else [])
        return getattr(m, attr) if attr else m
    except Exception:
        return None

AIPayloadEngine = _safe_import("lib.core.ai_engine",                     "AIPayloadEngine")
AsyncScanEngine = _safe_import("lib.core.async_engine",                  "AsyncScanEngine")
AIWAFBypass     = _safe_import("lib.evasion.ai_waf_bypass",              "AIWAFBypass")
EncoderChain    = _safe_import("lib.evasion.encoder_chain",              "EncoderChain")
GraphQLInj      = _safe_import("lib.techniques.graphql.advanced_inject", "GraphQLInjector")
NoSQLInj        = _safe_import("lib.techniques.nosql.mongodb_inject",    "NoSQLInjector")
JWTAttacker     = _safe_import("lib.techniques.auth.jwt_advanced",       "JWTAttacker")
RESTInj         = _safe_import("lib.techniques.api.rest_inject",         "RESTAPIInjector")
GRPCInj         = _safe_import("lib.techniques.api.grpc_inject",         "GRPCInjector")
CloudInj        = _safe_import("lib.techniques.cloud.lambda_inject",     "CloudInjector")
AdvSSTI         = _safe_import("lib.techniques.ssti.advanced_ssti",      "AdvancedSSTI")
DeepRecon       = _safe_import("lib.recon.deep_recon",                   "DeepRecon")
ParamMiner      = _safe_import("lib.recon.param_miner",                  "ParamMiner")
ExploitChain    = _safe_import("lib.exploit.chain",                      "ExploitChain")
OOBExfil        = _safe_import("lib.exploit.oob",                        "OOBExfiltrator")
ReportEngine    = _safe_import("lib.report.report_engine",               "ReportEngine")
HTTPBypass      = _safe_import("lib.techniques.bypass.http_error_bypass","HTTPErrorBypass")
AdvDumpEngine   = _safe_import("lib.techniques.dump.advanced_dump",      "AdvancedDumpEngine")
SmartTamper     = _safe_import("lib.techniques.bypass.smart_tamper",     "SmartTamper")
HashIdentifier  = _safe_import("lib.techniques.dump.hash_cracker",       "HashIdentifier")

_MODULES = {
    "ai_engine":    AIPayloadEngine,  "async_engine":   AsyncScanEngine,
    "ai_waf_bypass":AIWAFBypass,      "encoder_chain":  EncoderChain,
    "graphql":      GraphQLInj,       "nosql":          NoSQLInj,
    "jwt":          JWTAttacker,      "rest_api":       RESTInj,
    "grpc":         GRPCInj,          "cloud":          CloudInj,
    "ssti":         AdvSSTI,          "recon":          DeepRecon,
    "param_mine":   ParamMiner,       "exploit_chain":  ExploitChain,
    "oob_exfil":    OOBExfil,         "reporting":      ReportEngine,
    "http_bypass":  HTTPBypass,       "adv_dump":       AdvDumpEngine,
    "smart_tamper": SmartTamper,      "hash_id":        HashIdentifier,
}
FEATURES = {k: v is not None for k, v in _MODULES.items()}


# ── Path helper ───────────────────────────────────────────────────────────────
def modulePath():
    try: _ = sys.executable if weAreFrozen() else __file__
    except NameError: _ = inspect.getsourcefile(modulePath)
    return getUnicode(os.path.dirname(os.path.realpath(_)),
                      encoding=sys.getfilesystemencoding() or UNICODE_ENCODING)

def checkEnvironment():
    try: os.path.isdir(modulePath())
    except UnicodeEncodeError:
        fatal("Non-ASCII path detected — move GenSQL to a plain ASCII directory")
        raise SystemExit


# ── Banner ────────────────────────────────────────────────────────────────────
def printBanner(no_banner=False):
    if no_banner:
        return
    raw = JEEVSQL_BANNER
    raw = re.sub(r"(?im).*built on sqlmap.*\n?", "", raw)
    dataToStdout(raw, forceOutput=True)

    loaded  = [k for k, v in FEATURES.items() if v]
    missing = [k for k, v in FEATURES.items() if not v]

    dataToStdout(
        C.GREEN + "  [+] " + C.GRAY + "Loaded  : " + C.GREEN
        + ", ".join(loaded) + C.RESET + "\n", forceOutput=True)
    if missing:
        dataToStdout(
            C.YELLOW + "  [-] " + C.GRAY + "Optional: " + C.YELLOW
            + ", ".join(missing) + C.RESET + "\n", forceOutput=True)
    dataToStdout("\n", forceOutput=True)


# ─────────────────────────────────────────────────────────────────────────────
# SUBCOMMAND: scan
# ─────────────────────────────────────────────────────────────────────────────
SCAN_HELP = """
  EXAMPLES
  ─────────────────────────────────────────────────────────
  Basic scan:
    gensql scan -t https://site.com/page?id=1

  Detect injection with WAF evasion:
    gensql scan -t https://site.com/page?id=1 --evade --level 3

  POST parameter scan:
    gensql scan -t https://site.com/login -f "user=admin&pass=x"

  Scan with tamper chain:
    gensql scan -t https://site.com/page?id=1 --tamper hex,space

  Scan all parameters:
    gensql scan -t https://site.com/page?id=1&cat=2 --all-params
"""

DUMP_HELP = """
  EXAMPLES
  ─────────────────────────────────────────────────────────
  Auto dump everything:
    gensql dump -t https://site.com/page?id=1

  Dump specific table:
    gensql dump -t https://site.com/page?id=1 --table users

  Dump with hex encoding (bypass string WAF):
    gensql dump -t https://site.com/page?id=1 --hex

  Dump credentials only:
    gensql dump -t https://site.com/page?id=1 --creds

  Parallel dump (fastest):
    gensql dump -t https://site.com/page?id=1 --parallel --threads 8

  Export to HTML:
    gensql dump -t https://site.com/page?id=1 --out dump.html
"""

BYPASS_HELP = """
  EXAMPLES
  ─────────────────────────────────────────────────────────
  Test all bypass techniques on a 403:
    gensql bypass -t https://site.com/admin

  Bypass a 429 rate limit:
    gensql bypass -t https://site.com/api --code 429

  Run bypass then scan:
    gensql bypass -t https://site.com/admin --then-scan
"""

RECON_HELP = """
  EXAMPLES
  ─────────────────────────────────────────────────────────
  Full OSINT recon:
    gensql recon -t https://site.com

  Mine parameters from Wayback Machine:
    gensql recon -t https://site.com --wayback

  Enumerate subdomains + endpoints:
    gensql recon -t https://site.com --subdomains --js
"""


# ── Argument parser ───────────────────────────────────────────────────────────
def _build_parser():
    """Build the GenSQL argument parser — completely different from sqlmap."""

    p = argparse.ArgumentParser(
        prog="gensql",
        description=(
            C.CYAN + C.BOLD + "GenSQL v2.0.0" + C.RESET
            + " — Next-Generation Web Security Assessment Framework\n"
            + "  by Jeevraj\n\n"
            + "  Use a subcommand or pass flags directly:\n"
            + C.YELLOW + "    gensql scan    " + C.GRAY + "— inject & enumerate\n" + C.RESET
            + C.YELLOW + "    gensql dump    " + C.GRAY + "— extract database data\n" + C.RESET
            + C.YELLOW + "    gensql bypass  " + C.GRAY + "— bypass 403/404/429/503\n" + C.RESET
            + C.YELLOW + "    gensql recon   " + C.GRAY + "— OSINT & discovery\n" + C.RESET
            + C.YELLOW + "    gensql wizard  " + C.GRAY + "— interactive guided mode\n" + C.RESET
        ),
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # ── Target ───────────────────────────────────────────────────────────────
    g_tgt = p.add_argument_group(C.BOLD + "TARGET" + C.RESET)
    g_tgt.add_argument("-t", "--target", dest="target", metavar="URL",
        help="Target URL  (e.g. https://site.com/page?id=1)")
    g_tgt.add_argument("-u",             dest="target",  # keep -u as alias
        help=argparse.SUPPRESS)
    g_tgt.add_argument("-f", "--form-data", dest="form_data", metavar="DATA",
        help="POST form data  (e.g. 'user=x&pass=y')")
    g_tgt.add_argument("-H", "--header", dest="extra_headers", action="append",
        metavar="HEADER", help="Extra HTTP header  (can repeat)")
    g_tgt.add_argument("--cookie",       dest="cookie", metavar="COOKIE",
        help="Cookie string")
    g_tgt.add_argument("--proxy",        dest="proxy",  metavar="PROXY",
        help="HTTP/SOCKS proxy  (e.g. http://127.0.0.1:8080)")

    # ── Scan behaviour ────────────────────────────────────────────────────────
    g_scan = p.add_argument_group(C.BOLD + "SCAN BEHAVIOUR" + C.RESET)
    g_scan.add_argument("--level",     type=int, default=1, choices=range(1, 6),
        metavar="1-5",  help="Test depth  1=basic  5=exhaustive  (default: 1)")
    g_scan.add_argument("--risk",      type=int, default=1, choices=range(1, 4),
        metavar="1-3",  help="Risk level  1=safe  3=heavy  (default: 1)")
    g_scan.add_argument("--speed",     choices=["slow", "normal", "fast", "turbo"],
        default="normal", help="Request speed preset  (default: normal)")
    g_scan.add_argument("--all-params",  action="store_true",
        help="Test every parameter in the URL")
    g_scan.add_argument("-p", "--param", dest="param", metavar="PARAM",
        help="Force-test this parameter")
    g_scan.add_argument("--dbms",      dest="dbms",   metavar="DBMS",
        help="Force DBMS  (mysql/pgsql/mssql/oracle/sqlite)")
    g_scan.add_argument("--technique", dest="technique", metavar="BEUQT",
        help="Injection techniques  (B=blind E=error U=union Q=stacked T=time)")
    g_scan.add_argument("--tamper",    dest="tamper", metavar="LIST",
        help="Tamper scripts  e.g. hex,space,rand  (or 'auto' for AI selection)")

    # ── WAF & Bypass ─────────────────────────────────────────────────────────
    g_waf = p.add_argument_group(C.BOLD + "WAF & BYPASS" + C.RESET)
    g_waf.add_argument("--evade",         action="store_true",
        help="Full WAF evasion mode  (auto-selects best tampers)")
    g_waf.add_argument("--auto-bypass",   action="store_true",
        help="Auto-bypass HTTP 403/404/429/503 before scanning")
    g_waf.add_argument("--bypass-code",   type=int, metavar="CODE",
        help="Specific HTTP error code to bypass")
    g_waf.add_argument("--ai-evade",      action="store_true",
        help="AI-powered evasion  (offline, no API)")
    g_waf.add_argument("--rotate-id",     type=int, default=0, metavar="N",
        help="Rotate identity every N requests")
    g_waf.add_argument("--encode",        dest="encoder_chain", metavar="CHAIN",
        help="Encoder chain  e.g. url,base64,hex")

    # ── Dump ─────────────────────────────────────────────────────────────────
    g_dump = p.add_argument_group(C.BOLD + "DUMP" + C.RESET)
    g_dump.add_argument("--dump",        action="store_true",
        help="Dump the entire database (auto technique)")
    g_dump.add_argument("--creds",       action="store_true",
        help="Dump credential tables  (users/passwords/hashes)")
    g_dump.add_argument("--table",       metavar="TABLE",
        help="Dump a specific table")
    g_dump.add_argument("--columns",     metavar="COLS",
        help="Comma-separated columns to dump")
    g_dump.add_argument("--hex",         action="store_true",
        help="Hex-encode dump  (bypass string WAF filters)")
    g_dump.add_argument("--blind",       action="store_true",
        help="Binary-search blind extraction  (50%% fewer requests)")
    g_dump.add_argument("--bitwise",     action="store_true",
        help="Bitwise extraction  (8 requests/char, fastest blind)")
    g_dump.add_argument("--parallel",    action="store_true",
        help="Dump multiple tables in parallel")
    g_dump.add_argument("--threads",     type=int, default=4, metavar="N",
        help="Parallel dump threads  (default: 4)")
    g_dump.add_argument("--chunk",       type=int, default=50, metavar="N",
        help="Rows per chunk  (default: 50)")
    g_dump.add_argument("--resume",      action="store_true",
        help="Resume an interrupted dump")
    g_dump.add_argument("--out",         metavar="FILE",
        help="Export to file  (.html/.json/.csv/.sql auto-detected)")
    g_dump.add_argument("--force-dump",  action="store_true",
        help="Dump without waiting for injection confirmation")

    # ── Modern injection surfaces ──────────────────────────────────────────────
    g_mod = p.add_argument_group(C.BOLD + "MODERN SURFACES" + C.RESET)
    g_mod.add_argument("--graphql",    action="store_true",
        help="GraphQL injection  (batch/alias/introspect/fragment)")
    g_mod.add_argument("--nosql",      action="store_true",
        help="NoSQL injection  (MongoDB/CouchDB/Redis)")
    g_mod.add_argument("--nosql-type", default="mongodb", metavar="TYPE")
    g_mod.add_argument("--jwt",        action="store_true",
        help="JWT attacks  (alg:none/RS256-HS256/kid-SQLi/bruteforce)")
    g_mod.add_argument("--grpc",       action="store_true",
        help="gRPC-Web proto field injection")
    g_mod.add_argument("--ssti",       action="store_true",
        help="SSTI detection + auto RCE chain")
    g_mod.add_argument("--idor",       action="store_true",
        help="IDOR/BOLA enumeration")
    g_mod.add_argument("--idor-range", default="1-1000", metavar="RANGE")
    g_mod.add_argument("--api",        dest="swagger_url", metavar="SPEC",
        help="Swagger/OpenAPI spec URL for guided API scan")

    # ── Cloud ─────────────────────────────────────────────────────────────────
    g_cloud = p.add_argument_group(C.BOLD + "CLOUD" + C.RESET)
    g_cloud.add_argument("--cloud",    action="store_true",
        help="Cloud/serverless injection  (AWS/Azure/GCP)")
    g_cloud.add_argument("--provider", default="auto", metavar="PROVIDER")
    g_cloud.add_argument("--ssrf-meta",action="store_true",
        help="SSRF → cloud metadata  (169.254.169.254)")

    # ── Recon ─────────────────────────────────────────────────────────────────
    g_recon = p.add_argument_group(C.BOLD + "RECON" + C.RESET)
    g_recon.add_argument("--recon",      action="store_true",
        help="Deep OSINT recon  (crt.sh / Wayback / JS analysis)")
    g_recon.add_argument("--wayback",    action="store_true",
        help="Mine params from Wayback Machine")
    g_recon.add_argument("--js",         action="store_true",
        help="Extract endpoints from JavaScript files")
    g_recon.add_argument("--subdomains", action="store_true",
        help="Enumerate subdomains via certificate transparency")
    g_recon.add_argument("--mine",       action="store_true",
        help="Parameter mining  (1000+ built-in names)")
    g_recon.add_argument("--shodan",     metavar="KEY",
        help="Shodan API key for extended recon")

    # ── Post-Exploit ──────────────────────────────────────────────────────────
    g_post = p.add_argument_group(C.BOLD + "POST-EXPLOITATION" + C.RESET)
    g_post.add_argument("--exploit",   action="store_true",
        help="SQLi → file read → webshell → OS command chain")
    g_post.add_argument("--harvest",   action="store_true",
        help="Extract and identify credential hashes")
    g_post.add_argument("--privesc",   action="store_true",
        help="Check DB privilege escalation paths")
    g_post.add_argument("--oob",       action="store_true",
        help="Out-of-band DNS/HTTP data exfiltration")
    g_post.add_argument("--oob-host",  metavar="DOMAIN")
    g_post.add_argument("--oob-port",  type=int, default=0, metavar="PORT")

    # ── Reports ───────────────────────────────────────────────────────────────
    g_rep = p.add_argument_group(C.BOLD + "REPORTS" + C.RESET)
    g_rep.add_argument("--report",  metavar="FILE",
        help="Save HTML report  (dark theme, CVSS 4.0)")
    g_rep.add_argument("--report-json", metavar="FILE",
        help="Save JSON report")
    g_rep.add_argument("--cvss",    action="store_true",
        help="Include CVSS 4.0 scores")
    g_rep.add_argument("--live",    action="store_true",
        help="Real-time web dashboard  (http://localhost:7474)")
    g_rep.add_argument("--live-port", type=int, default=7474, metavar="PORT")

    # ── Profiles ──────────────────────────────────────────────────────────────
    g_prof = p.add_argument_group(C.BOLD + "PROFILES & MODE" + C.RESET)
    g_prof.add_argument("--profile", metavar="PROFILE",
        help="Preset: stealth|api|cloud|pentest|aggressive|dump")
    g_prof.add_argument("--wizard",  action="store_true",
        help="Interactive guided wizard")
    g_prof.add_argument("--batch",   action="store_true",
        help="Non-interactive  (auto-answer all prompts)")
    g_prof.add_argument("--verbose", "-v", action="store_true",
        help="Verbose output")
    g_prof.add_argument("--no-banner", action="store_true",
        help="Skip the ASCII banner")
    g_prof.add_argument("--version",   action="store_true",
        help="Show version and exit")
    g_prof.add_argument("-h", "--help", action="help",
        help="Show this help and exit")

    return p


def _parse_args(argv=None):
    """Parse GenSQL arguments."""
    p = _build_parser()
    a, _ = p.parse_known_args(argv)
    return a, p


# ── Profile presets ───────────────────────────────────────────────────────────
def _apply_profile(name, o):
    profiles = {
        "stealth": dict(evade=True, rotate_id=5, ai_evade=True,
                        speed="slow", level=2, risk=1),
        "api":     dict(graphql=True, nosql=True, jwt=True, grpc=True,
                        idor=True, mine=True, ai_evade=True),
        "cloud":   dict(cloud=True, ssrf_meta=True, recon=True, ai_evade=True),
        "pentest": dict(ai_evade=True, evade=True, recon=True, graphql=True,
                        nosql=True, jwt=True, ssti=True, exploit=True,
                        harvest=True, privesc=True, cvss=True,
                        auto_bypass=True, dump=True,
                        report="gensql_report.html", report_json="gensql_report.json",
                        level=4, risk=2),
        "aggressive": dict(ai_evade=True, evade=True, graphql=True, nosql=True,
                           jwt=True, ssti=True, exploit=True, harvest=True,
                           oob=True, auto_bypass=True, dump=True,
                           hex=True, parallel=True, level=5, risk=3,
                           speed="turbo"),
        "dump":    dict(dump=True, creds=True, hex=True, parallel=True,
                        auto_bypass=True, ai_evade=True,
                        out="gensql_dump.html"),
    }
    p = profiles.get(name.lower(), {})
    if not p:
        warn("Unknown profile %r — use: stealth|api|cloud|pentest|aggressive|dump" % name)
        return
    for k, v in p.items():
        setattr(o, k, v)
    info("Profile [%s] loaded — %d settings applied" % (name, len(p)))


# ── Subcommand router ─────────────────────────────────────────────────────────
def _subcommand_translate(argv):
    """
    Detect if first arg is a GenSQL subcommand and translate it to flags.
    gensql scan -t URL  →  gensql.py -t URL
    gensql dump -t URL  →  gensql.py -t URL --dump
    gensql bypass -t URL  →  gensql.py -t URL --auto-bypass --bypass-url URL
    gensql recon -t URL  →  gensql.py -t URL --recon --mine --wayback
    gensql wizard       →  gensql.py --wizard
    """
    if len(argv) < 2:
        return argv

    sub = argv[1].lower()
    rest = argv[2:]

    # Handle -t / --target → -u translation
    def _remap(args):
        new = []
        i = 0
        while i < len(args):
            if args[i] in ("-t", "--target") and i + 1 < len(args):
                new += ["-u", args[i + 1]]
                i += 2
            elif args[i].startswith("--target="):
                new += ["-u", args[i].split("=", 1)[1]]
                i += 1
            else:
                new.append(args[i])
                i += 1
        return new

    SUBCMDS = {
        "scan":   [],
        "dump":   ["--adv-dump", "--dump-creds"],
        "bypass": ["--auto-bypass"],
        "recon":  ["--deep-recon", "--wayback", "--js-analysis", "--param-mine"],
        "wizard": ["--wizard"],
        "help":   ["-h"],
    }

    if sub in SUBCMDS:
        return [argv[0]] + SUBCMDS[sub] + _remap(rest)

    # Not a subcommand — but still remap -t → -u
    return [argv[0]] + _remap(argv[1:])


# ── Interactive wizard ────────────────────────────────────────────────────────
def _wizard():
    print()
    banner_line("GenSQL Wizard")
    print()

    try:
        target = input(C.YELLOW + "  Target URL" + C.GRAY + "  : " + C.WHITE).strip()
        print(C.RESET, end="")
    except (EOFError, KeyboardInterrupt):
        print(); return None

    if not target:
        warn("No URL provided"); return None
    if not re.match(r"(?i)https?://", target):
        target = "http://" + target

    print()
    print(C.GRAY + "  " + "─" * 50)
    print(C.BOLD + "  Scan goal:" + C.RESET)
    goals = [
        ("1", "dump",       "Extract all database data  [fastest]"),
        ("2", "pentest",    "Full pentest  (scan + exploit + report)  [default]"),
        ("3", "stealth",    "Stealth  (evade WAF/IDS, slow)"),
        ("4", "api",        "API targets  (REST/GraphQL/JWT/gRPC)"),
        ("5", "cloud",      "Cloud/Serverless  (AWS/Azure/GCP)"),
        ("6", "aggressive", "Aggressive  (everything at full speed)"),
    ]
    for n, _, desc in goals:
        print(C.YELLOW + "    %s" % n + C.GRAY + ")  " + C.WHITE + desc + C.RESET)
    print()

    try:
        c = input(C.YELLOW + "  Goal [1-6, default=2]: " + C.WHITE).strip() or "2"
        print(C.RESET, end="")
    except (EOFError, KeyboardInterrupt):
        print(); return None

    prof = dict((n, p) for n, p, _ in goals).get(c, "pentest")

    print()
    opts = []
    try:
        for question, flag in [
            ("Bypass WAF / firewalls?   [Y/n]: ", "--auto-bypass"),
            ("Use AI evasion?           [Y/n]: ", "--ai-evade"),
            ("Generate HTML report?     [Y/n]: ", "--report gensql_report.html"),
            ("Start live dashboard?     [y/N]: ", None),
        ]:
            ans = input(C.GRAY + "  " + question + C.WHITE).strip().lower()
            print(C.RESET, end="")
            if flag and ans not in ("n", "no", ""):
                opts += flag.split()
            elif flag is None and ans in ("y", "yes"):
                opts.append("--live")
    except (EOFError, KeyboardInterrupt):
        print()

    extra = ["-u", target, "--profile", prof, "--batch"] + opts
    print()
    info("Launching: %s  profile=%s" % (target, prof))
    return extra


# ── Map GenSQL args → core engine flags ───────────────────────────────────────
def _map_to_core_flags(o):
    """
    Translate GenSQL parsed args into sys.argv flags that the core engine
    understands, appended to sys.argv before _strip_gensql_args runs.
    """
    extras = []

    # Speed presets → delay + concurrent
    speed_map = {"slow": ("3", "5"), "normal": ("0", "20"),
                 "fast": ("0", "50"), "turbo": ("0", "100")}
    if hasattr(o, "speed") and o.speed in speed_map:
        delay, thr = speed_map[o.speed]
        if delay != "0":
            extras += ["--delay", delay]
        extras += ["--threads", thr]

    # level/risk
    if getattr(o, "level", 1) > 1:
        extras += ["--level", str(o.level)]
    if getattr(o, "risk", 1) > 1:
        extras += ["--risk", str(o.risk)]

    # Param
    if getattr(o, "param", None):
        extras += ["-p", o.param]

    # DBMS override
    if getattr(o, "dbms", None):
        extras += ["--dbms", o.dbms]

    # Technique
    if getattr(o, "technique", None):
        extras += ["--technique", o.technique]

    # Tamper — translate 'hex,space,rand' → actual script names
    tamper_aliases = {
        "hex":    "charencode",
        "space":  "space2comment",
        "rand":   "randomcase",
        "case":   "randomcase",
        "base64": "base64encode",
        "plus":   "plus2concat",
    }
    if getattr(o, "tamper", None):
        if o.tamper == "auto":
            pass  # handled by SmartTamper
        else:
            scripts = []
            for t in o.tamper.split(","):
                scripts.append(tamper_aliases.get(t.strip().lower(), t.strip()))
            extras += ["--tamper", ",".join(scripts)]
    elif getattr(o, "evade", False):
        # Default evasion chain
        extras += ["--tamper", "space2comment,randomcase,charencode,between"]

    # Form data → -d
    if getattr(o, "form_data", None):
        extras += ["-d", o.form_data]

    # Cookie
    if getattr(o, "cookie", None):
        extras += ["--cookie", o.cookie]

    # Proxy
    if getattr(o, "proxy", None):
        extras += ["--proxy", o.proxy]

    # Extra headers
    for hdr in (getattr(o, "extra_headers", None) or []):
        extras += ["-H", hdr]

    # Random-agent when evading
    if getattr(o, "evade", False) or getattr(o, "ai_evade", False):
        extras += ["--random-agent"]

    # batch
    if getattr(o, "batch", False):
        extras += ["--batch"]

    # verbose
    if getattr(o, "verbose", False):
        extras += ["-v", "3"]

    # target -u
    if getattr(o, "target", None) and "-u" not in sys.argv:
        extras += ["-u", o.target]

    return extras


# ── Bypass standalone mode ────────────────────────────────────────────────────
def _run_standalone_bypass(o):
    """Run bypass engine standalone when no scan target is needed."""
    if not HTTPBypass:
        warn("HTTP bypass module not loaded"); return

    target = getattr(o, "target", None)
    if not target:
        warn("Specify --target URL"); return

    banner_line("HTTP Error Bypass")
    info("Target: " + target)

    code = getattr(o, "bypass_code", None)
    engine = HTTPBypass(verbose=True)
    result = engine.auto_bypass(target, error_code=code)

    bypasses = result.get("bypasses", [])
    print()
    if bypasses:
        success("%d bypass technique(s) worked:" % len(bypasses))
        for b in bypasses:
            print(C.GRAY + "    %-30s" % b.get("technique", "?")
                  + C.CYAN + "HTTP " + str(b.get("status", "?"))
                  + C.GRAY + "  " + str(b.get("variant") or b.get("header") or "")
                  + C.RESET)
    else:
        error("No bypasses found for HTTP %d" % result.get("original_status", 0))

    stats = engine.get_stats()
    info("Attempts: %d  |  Succeeded: %d" % (stats["attempts"], stats["bypassed"]))


# ── Module initialisation ─────────────────────────────────────────────────────
def _init_modules(o):
    if getattr(o, "ai_evade", False) and AIPayloadEngine:
        conf.aiEngine = AIPayloadEngine(offline=True, dbms=getattr(conf, "dbms", None))
        info("AI evasion engine active  (offline)")

    if AsyncScanEngine and getattr(o, "speed", "normal") == "turbo":
        conf.asyncEngine = AsyncScanEngine(max_concurrent=100)
        info("Async turbo engine active")

    if getattr(o, "evade", False) or getattr(o, "ai_evade", False):
        if AIWAFBypass:
            conf.aiwafBypass = AIWAFBypass()
            info("AI WAF bypass active")

    if getattr(o, "auto_bypass", False) and HTTPBypass:
        conf.httpBypass = HTTPBypass(verbose=False)
        info("HTTP error bypass active  (403/404/429/503)")

    if getattr(o, "encoder_chain", None) and EncoderChain:
        conf.encoderChain = EncoderChain(o.encoder_chain.split(","))

    if getattr(o, "graphql", False) and GraphQLInj:
        conf.graphqlInj = GraphQLInj()
        info("GraphQL injector active")

    if getattr(o, "nosql", False) and NoSQLInj:
        conf.nosqlInj = NoSQLInj(db_type=getattr(o, "nosql_type", "mongodb"))
        info("NoSQL injector active")

    if getattr(o, "jwt", False) and JWTAttacker:
        conf.jwtAttacker = JWTAttacker()
        info("JWT attack suite active")

    if getattr(o, "grpc", False) and GRPCInj:
        conf.grpcInj = GRPCInj()
        info("gRPC injector active")

    if getattr(o, "ssti", False) and AdvSSTI:
        conf.sstiScanner = AdvSSTI()
        info("SSTI scanner active")

    if getattr(o, "cloud", False) and CloudInj:
        conf.cloudInj = CloudInj(provider=getattr(o, "provider", "auto"),
                                  ssrf_metadata=getattr(o, "ssrf_meta", False))
        info("Cloud injector active")

    if getattr(o, "recon", False) and DeepRecon:
        conf.deepRecon = DeepRecon(
            wayback=getattr(o, "wayback", False),
            js_analysis=getattr(o, "js", False),
            subdomain_enum=getattr(o, "subdomains", False))
        info("Deep recon active")

    if getattr(o, "mine", False) and ParamMiner:
        conf.paramMiner = ParamMiner(swagger_url=getattr(o, "swagger_url", None))
        info("Param miner active")

    if getattr(o, "exploit", False) and ExploitChain:
        conf.exploitChain = ExploitChain(
            harvest_creds=getattr(o, "harvest", False),
            privesc=getattr(o, "privesc", False))
        info("Exploit chain active")

    if getattr(o, "oob", False) and OOBExfil:
        conf.oobExfil = OOBExfil(
            domain=getattr(o, "oob_host", None),
            listen_port=getattr(o, "oob_port", 0))
        info("OOB exfiltration active")

    if getattr(o, "report", None) and ReportEngine:
        conf.reportEngine = ReportEngine(
            html_path=o.report,
            json_path=getattr(o, "report_json", None),
            cvss4=getattr(o, "cvss", False))
        info("Report engine active → %s" % o.report)

    if getattr(o, "live", False):
        try:
            from lib.report.dashboard import Dashboard
            conf.dashboard = Dashboard(port=getattr(o, "live_port", 7474))
            conf.dashboard.start()
            info("Live dashboard → http://127.0.0.1:%d" % getattr(o, "live_port", 7474))
        except Exception as ex:
            warn("Dashboard unavailable: %s" % str(ex)[:60])


# ── Advanced dump runner ──────────────────────────────────────────────────────
def _run_adv_dump(o):
    """Run the advanced dump engine after a confirmed injection scan."""
    if not AdvDumpEngine:
        warn("Advanced dump engine not available"); return

    url = getattr(conf, "url", None)
    if not url:
        return

    # Guard: only dump after confirmed injection
    if not getattr(o, "force_dump", False):
        try:
            from lib.core.data import kb as _kb
            injections = list(_kb.get("injections") or [])
            if not injections:
                warn("No injection confirmed — skipping dump  (use --force-dump to override)")
                return
            success("%d injection vector(s) confirmed — starting advanced dump" % len(injections))
        except Exception:
            pass

    # Technique selection
    technique = "auto"
    if getattr(o, "blind",   False): technique = "blind"
    if getattr(o, "bitwise", False): technique = "bitwise"
    if getattr(o, "dump",    False) and not technique: technique = "auto"

    dbms = (getattr(conf, "dbms", None) or "mysql").lower().split()[0]
    checkpoint = "gensql_dump.checkpoint" if getattr(o, "resume", False) else None

    dump = AdvDumpEngine(
        dbms=dbms,
        threads=getattr(o, "threads", 4),
        chunk_size=getattr(o, "chunk", 50),
        delay=getattr(conf, "timeSec", 0) or 0,
        verbose=True,
        checkpoint_file=checkpoint,
    )

    # Build requester from real URL + session cookies
    def _make_req(base_url):
        import urllib.request, urllib.error, urllib.parse, ssl, socket

        parsed = urllib.parse.urlparse(base_url)
        qs     = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        param  = list(qs.keys())[0] if qs else "id"

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try: ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except Exception: pass

        cookie_hdr = ""
        try:
            for src in (getattr(conf, "httpHeaders", {}),
                        {"Cookie": getattr(conf, "cookie", "")}):
                c = src.get("Cookie", "") or src.get("cookie", "")
                if c: cookie_hdr = c; break
        except Exception: pass

        ua = "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0"

        def req(payload):
            nq = {k: v[0] for k, v in qs.items()}
            nq[param] = payload
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(nq)))
            r = urllib.request.Request(test_url)
            r.add_header("User-Agent", ua)
            r.add_header("Accept", "text/html,*/*")
            if cookie_hdr: r.add_header("Cookie", cookie_hdr)
            old = socket.getdefaulttimeout()
            socket.setdefaulttimeout(8)
            try:
                with urllib.request.urlopen(r, context=ctx, timeout=8) as resp:
                    return resp.status, resp.read(512000).decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e:
                return e.code, ""
            except Exception:
                return 0, ""
            finally:
                socket.setdefaulttimeout(old)
        return req, param

    req_fn, param = _make_req(url)
    info("Dump param: %r | DBMS: %s | Technique: %s" % (param, dbms, technique))
    dump.set_requester(req_fn)

    # Wrap with bypass if requested
    if getattr(o, "auto_bypass", False) and HTTPBypass:
        bp = HTTPBypass(verbose=False)
        orig = dump.requester
        def _bp_req(p):
            code, body = orig(p)
            if code in (403, 404, 429, 503):
                info("HTTP %d during dump — trying bypass..." % code)
                r = bp.best_bypass(url, error_code=code)
                if r: info("Bypass: " + r.get("technique", "?"))
            return code, body
        dump.set_requester(_bp_req)

    # Run
    if getattr(o, "creds", False):
        info("Targeting credential tables...")
        creds = dump.dump_credentials()
        info("Credential entries found: %d" % len(creds))

    tbl  = getattr(o, "table", None)
    cols = ([c.strip() for c in o.columns.split(",")]
            if getattr(o, "columns", None) else None)

    if tbl:
        dump.dump_table(tbl, cols, technique=technique, hex_encode=getattr(o, "hex", False))
    elif getattr(o, "dump", False):
        tables = dump.get_tables()
        if tables:
            info("Tables found: %s" % ", ".join(tables))
            tbl_cols = {t: dump.get_columns(t) or ["*"] for t in tables}
            if getattr(o, "parallel", False):
                dump.dump_all_tables(tbl_cols, technique=technique)
            else:
                for t, c in tbl_cols.items():
                    dump.dump_table(t, c, technique=technique,
                                    hex_encode=getattr(o, "hex", False))
        else:
            warn("Could not enumerate tables — try --table users")

    dump.print_summary()

    out = getattr(o, "out", None)
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
            success("Dump saved → %s" % path_out)

    # Hash identification on found data
    if HashIdentifier and dump._results:
        hid = HashIdentifier()
        for tbl_name, rows in dump._results.items():
            for row in rows:
                for k, v in row.items():
                    if k.startswith("__"): continue
                    found = hid.identify_all(str(v))
                    for h in found:
                        if h["confidence"] >= 75:
                            info("Hash detected in %s.%s : %s  [%s, %d%% confidence]"
                                 % (tbl_name, k, h["hash"][:20] + "...",
                                    h["type"], h["confidence"]))


# ── Finalise ──────────────────────────────────────────────────────────────────
def _finalize(o):
    # Run advanced dump after scan
    if getattr(o, "dump", False) or getattr(o, "creds", False) or getattr(o, "table", None):
        try: _run_adv_dump(o)
        except Exception as ex: warn("Dump error: %s" % str(ex)[:80])

    if hasattr(conf, "reportEngine"):
        try: conf.reportEngine.finalize(); success("Reports written")
        except Exception: pass

    if hasattr(conf, "dashboard"):
        try: conf.dashboard.stop()
        except Exception: pass


# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    """GenSQL v2.0.0 — by Jeevraj"""

    # 0. Route subcommands and remap -t → -u
    sys.argv = _subcommand_translate(sys.argv)

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

    # 2. Parse GenSQL args
    o, _parser = _parse_args()

    # Show version
    if getattr(o, "version", False):
        print("GenSQL v2.0.0 by Jeevraj"); sys.exit(0)

    # 3. Apply profile
    if getattr(o, "profile", None):
        _apply_profile(o.profile, o)

    # 4. Standalone bypass (no scan needed)
    if getattr(o, "target", None) and "--adv-dump" not in sys.argv:
        bypass_only = any(getattr(o, f, False)
                          for f in ("auto_bypass", "bypass_code"))
        if bypass_only and not any(f in sys.argv for f in
                                    ("-u","--target","--dump","--level")):
            _run_standalone_bypass(o); return

    # 5. Translate GenSQL flags → core engine argv
    extra_core = _map_to_core_flags(o)
    for flag in extra_core:
        if flag not in sys.argv:
            sys.argv.append(flag)

    # 6. Strip GenSQL flags from argv before core parser runs
    sys.argv = _strip_gensql_args(sys.argv)

    try:
        dirtyPatches()
        resolveCrossReferences()
        checkEnvironment()
        setPaths(modulePath())

        printBanner(no_banner=getattr(o, "no_banner", False))

        args = cmdLineParser()
        cmdLineOptions.update(args.__dict__ if hasattr(args, "__dict__") else args)
        initOptions(cmdLineOptions)

        if checkPipedInput():
            conf.batch = True

        if conf.get("api"):
            from lib.utils.api import StdDbOut, setRestAPILog
            sys.stdout = StdDbOut(conf.taskid, messagetype="stdout")
            sys.stderr = StdDbOut(conf.taskid, messagetype="stderr")
            setRestAPILog()

        # Disable SSL cert verification globally
        try:
            import ssl as _ssl
            _ssl._create_default_https_context = _ssl._create_unverified_context
        except Exception:
            pass

        # Auto-accept cookies in batch mode
        try:
            if conf.get("batch") or "--batch" in sys.argv:
                conf.getCookies = True
        except Exception:
            pass

        conf.showTime = True

        # GenSQL legal notice (shorter, different from sqlmap)
        dataToStdout(
            C.GRAY + "\n  [" + C.YELLOW + "LEGAL" + C.GRAY + "] "
            + C.WHITE + LEGAL_DISCLAIMER + C.RESET + "\n\n",
            forceOutput=True)

        dataToStdout(
            C.GRAY + "  [" + C.CYAN + "START" + C.GRAY + "] "
            + C.WHITE + time.strftime("%Y-%m-%d %H:%M:%S") + C.RESET + "\n\n",
            forceOutput=True)

        init()
        _init_modules(o)

        # Recon phase
        if getattr(o, "recon", False) and hasattr(conf, "deepRecon"):
            url = getattr(conf, "url", None)
            if url:
                m = re.search(r"https?://([^/]+)", url)
                if m:
                    try:
                        findings = conf.deepRecon.generate_recon_report(m.group(1))
                        for key, label in [
                            ("technologies", "Tech"),
                            ("subdomains",   "Subdomains"),
                            ("api_endpoints","API endpoints"),
                        ]:
                            v = findings.get(key)
                            if v:
                                info("%s: %s" % (
                                    label,
                                    ", ".join(v) if isinstance(v, list) else str(v)))
                    except Exception as ex:
                        warn("Recon: %s" % str(ex)[:60])

        if not conf.updateAll:
            if conf.smokeTest:
                from lib.core.testing import smokeTest
                os._exitcode = 1 - (smokeTest() or 0)
            elif conf.vulnTest:
                from lib.core.testing import vulnTest
                os._exitcode = 1 - (vulnTest() or 0)
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
                                    info("Crawling (%d): %r" % (i + 1, tgt))
                                    crawl(tgt)
                                except Exception as ex:
                                    if not isinstance(ex, SqlmapUserQuitException):
                                        error("Crawl: %s" % getSafeExString(ex))
                                    else: raise
                                else:
                                    if kb.targets: start()
                        else:
                            start()
                    except Exception as ex:
                        os._exitcode = 1
                        if "can't start new thread" in getSafeExString(ex):
                            fatal("Cannot start threads"); raise SystemExit
                        else: raise

    except SqlmapUserQuitException:
        if not conf.batch: warn("Scan aborted by user")
    except (SqlmapSilentQuitException, bdb.BdbQuit): pass
    except SqlmapShellQuitException: cmdLineOptions.sqlmapShell = False
    except SqlmapBaseException as ex:
        fatal(getSafeExString(ex)); os._exitcode = 1; raise SystemExit
    except KeyboardInterrupt:
        try: print()
        except IOError: pass
    except EOFError:
        print(); warn("EOF — exiting")
    except SystemExit as ex:
        os._exitcode = ex.code or 0
    except Exception:
        print()
        errMsg = unhandledExceptionMessage()
        excMsg = traceback.format_exc()
        os._exitcode = 255
        errMsg = maskSensitiveData(errMsg)
        excMsg = maskSensitiveData(excMsg)
        fatal(errMsg)
        dataToStdout(setColor(excMsg.strip(), level=logging.CRITICAL) + "\n")
        if not codeIsModified():
            createGithubIssue(errMsg, excMsg)
    finally:
        kb.threadContinue = False
        try: _finalize(o)
        except Exception: pass
        if (getDaysFromLastUpdate() or 0) > LAST_UPDATE_NAGGING_DAYS:
            warn("GenSQL update available — git pull")
        if conf.get("reportCollector") is not None:
            try:
                from lib.utils.api import writeReportJson
                writeReportJson(conf.reportCollector, conf.reportJson)
            except Exception: pass
            finally:
                try: conf.reportCollector.disconnect()
                except Exception: pass
        if conf.get("showTime"):
            dataToStdout(
                C.GRAY + "\n  [" + C.CYAN + "DONE" + C.GRAY + "]  "
                + C.WHITE + time.strftime("%Y-%m-%d %H:%M:%S")
                + C.RESET + "\n\n",
                forceOutput=True)
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
                    json.dump(conf.httpCollector.obtain(), fp=f, indent=4,
                              separators=(",", ": "))
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
    try:
        main()
    except KeyboardInterrupt:
        pass
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
    finally:
        if threading.active_count() > 1:
            os._exit(getattr(os, "_exitcode", 0))
        else:
            sys.exit(getattr(os, "_exitcode", 0))
else:
    __import__("lib.controller.controller")
    from lib.utils.library import scan, scanFromRequest, SqlmapError

__all__ = ["scan", "scanFromRequest", "SqlmapError"]
