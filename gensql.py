#!/usr/bin/env python
"""
GenSQL - Next-Generation Web Security Assessment Framework
Version : 2.0.0
Author  : Jeevraj

Capabilities:
  - Offline AI payload mutation engine
  - Async HTTP/2 concurrent scan engine
  - AI-powered WAF bypass (Cloudflare, Akamai, Imperva, AWS WAF, F5...)
  - GraphQL / NoSQL / JWT / gRPC / SSTI / Cloud injection
  - 100+ tamper scripts for modern WAFs
  - Deep OSINT recon (crt.sh, Wayback Machine, JS analysis)
  - Exploit chain: SQLi to RCE to lateral movement
  - OOB exfiltration via DNS / HTTP
  - CVSS 4.0 HTML/JSON/Markdown reports
  - Real-time web dashboard
  - Scan profiles: stealth / pentest / api / cloud / aggressive
"""
from __future__ import print_function

# ── GenSQL-specific flags that must be stripped before the core parser runs ──
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
}
_GENSQL_VALUE_FLAGS = {
    "--nosql-type", "--cloud-provider", "--encoder-chain", "--swagger-url",
    "--shodan-key", "--oob-domain", "--oob-http", "--report-html",
    "--report-json", "--report-md", "--profile", "--idor-range",
    "--max-concurrent", "--ai-top-payloads", "--oob-listen",
    "--rotate-identity", "--dashboard-port",
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
            i += 2   # skip flag + its value
            continue
        # handle --flag=value form
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

AIPayloadEngine = _safe_import("lib.core.ai_engine",                    "AIPayloadEngine")
AsyncScanEngine = _safe_import("lib.core.async_engine",                 "AsyncScanEngine")
AIWAFBypass     = _safe_import("lib.evasion.ai_waf_bypass",             "AIWAFBypass")
EncoderChain    = _safe_import("lib.evasion.encoder_chain",             "EncoderChain")
GraphQLInj      = _safe_import("lib.techniques.graphql.advanced_inject","GraphQLInjector")
NoSQLInj        = _safe_import("lib.techniques.nosql.mongodb_inject",   "NoSQLInjector")
JWTAttacker     = _safe_import("lib.techniques.auth.jwt_advanced",      "JWTAttacker")
RESTInj         = _safe_import("lib.techniques.api.rest_inject",        "RESTAPIInjector")
GRPCInj         = _safe_import("lib.techniques.api.grpc_inject",       "GRPCInjector")
CloudInj        = _safe_import("lib.techniques.cloud.lambda_inject",    "CloudInjector")
AdvSSTI         = _safe_import("lib.techniques.ssti.advanced_ssti",     "AdvancedSSTI")
DeepRecon       = _safe_import("lib.recon.deep_recon",                  "DeepRecon")
ParamMiner      = _safe_import("lib.recon.param_miner",                 "ParamMiner")
ExploitChain    = _safe_import("lib.exploit.chain",                     "ExploitChain")
OOBExfil        = _safe_import("lib.exploit.oob",                       "OOBExfiltrator")
ReportEngine    = _safe_import("lib.report.report_engine",              "ReportEngine")

_MODS = {
    "ai_engine":     AIPayloadEngine, "async_engine":  AsyncScanEngine,
    "ai_waf_bypass": AIWAFBypass,     "encoder_chain": EncoderChain,
    "graphql_inject":GraphQLInj,      "nosql_inject":  NoSQLInj,
    "jwt_attack":    JWTAttacker,     "rest_inject":   RESTInj,
    "grpc_inject":   GRPCInj,         "cloud_scan":    CloudInj,
    "ssti_advanced": AdvSSTI,         "deep_recon":    DeepRecon,
    "param_miner":   ParamMiner,      "exploit_chain": ExploitChain,
    "oob_exfil":     OOBExfil,        "reporting":     ReportEngine,
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
        logger.critical("non-ASCII path — move GenSQL to a plain-ASCII directory"); raise SystemExit
    if LooseVersion(VERSION) < LooseVersion("1.0"):
        logger.critical("broken runtime environment"); raise SystemExit
    if "sqlmap.sqlmap" in sys.modules:
        for _ in ("cmdLineOptions", "conf", "kb"):
            globals()[_] = getattr(sys.modules["lib.core.data"], _)
        for _ in ("SqlmapBaseException", "SqlmapShellQuitException",
                  "SqlmapSilentQuitException", "SqlmapUserQuitException"):
            globals()[_] = getattr(sys.modules["lib.core.exception"], _)

def printBanner():
    # Replace any remaining "sqlmap" reference in the banner at display time
    raw = JEEVSQL_BANNER
    # Remove "Built on sqlmap..." line if it slipped through
    raw = re.sub(r"(?im).*built on sqlmap.*\n?", "", raw)
    dataToStdout(raw, forceOutput=True)
    loaded  = [k for k, v in FEATURES.items() if v]
    missing = [k for k, v in FEATURES.items() if not v]
    if loaded:
        dataToStdout("\033[01;32m  [+] Loaded  : %s\033[0m\n" % ", ".join(loaded), forceOutput=True)
    if missing:
        dataToStdout("\033[01;33m  [~] Optional: %s\033[0m\n" % ", ".join(missing), forceOutput=True)
    dataToStdout("\n", forceOutput=True)


# ── Argument parser (GenSQL-only flags) ───────────────────────────────────────
def _args(argv=None):
    import argparse
    p = argparse.ArgumentParser(
        prog="gensql",
        description="GenSQL v2.0.0 - Next-Generation Web Security Assessment Framework by Jeevraj",
        add_help=False,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    g1 = p.add_argument_group("GenSQL AI & Engine")
    g1.add_argument("--ai-assist",      action="store_true", help="Offline AI payload mutation engine")
    g1.add_argument("--ai-learn",       action="store_true", help="Adaptive learning from responses")
    g1.add_argument("--async-engine",   action="store_true", help="HTTP/2 async concurrent engine")
    g1.add_argument("--http2",          action="store_true", help="Force HTTP/2 protocol")
    g1.add_argument("--max-concurrent", type=int, default=50, metavar="N", help="Max concurrent requests (default: 50)")
    g1.add_argument("--ai-top-payloads",type=int, default=0,  metavar="N", help="Print top N AI-scored payloads after scan")

    g2 = p.add_argument_group("GenSQL WAF Evasion")
    g2.add_argument("--ai-waf-bypass",  action="store_true", help="AI-powered WAF evasion (Cloudflare/Akamai/Imperva/AWS)")
    g2.add_argument("--humanize",       action="store_true", help="Humanise request timing and behaviour")
    g2.add_argument("--chunked-bypass", action="store_true", help="Chunked transfer encoding bypass")
    g2.add_argument("--rotate-identity",type=int, default=0,  metavar="N", help="Rotate identity every N requests")
    g2.add_argument("--encoder-chain",  default=None, metavar="CHAIN",
                    help="Comma-separated encoder chain e.g. url,base64,hex")

    g3 = p.add_argument_group("GenSQL Injection Techniques")
    g3.add_argument("--graphql-inject",    action="store_true", help="GraphQL injection (introspection/batch/alias/fragment)")
    g3.add_argument("--graphql-introspect",action="store_true", help="Run full GraphQL introspection first")
    g3.add_argument("--nosql-inject",      action="store_true", help="NoSQL injection (MongoDB/CouchDB/Redis)")
    g3.add_argument("--nosql-type",        default="mongodb",   metavar="TYPE", help="NoSQL DB type (default: mongodb)")
    g3.add_argument("--jwt-attack",        action="store_true", help="JWT attack suite (alg:none/RS256-HS256/kid-SQLi)")
    g3.add_argument("--jwt-bruteforce",    action="store_true", help="Bruteforce JWT weak secrets")
    g3.add_argument("--grpc-inject",       action="store_true", help="gRPC-Web proto field injection")
    g3.add_argument("--ssti-inject",       action="store_true", help="SSTI detection + auto RCE chain")
    g3.add_argument("--idor-scan",         action="store_true", help="IDOR/BOLA parameter scan")
    g3.add_argument("--idor-range",        default="1-1000",    metavar="RANGE", help="IDOR ID range (default: 1-1000)")

    g4 = p.add_argument_group("GenSQL Cloud & API")
    g4.add_argument("--cloud-scan",       action="store_true", help="Cloud/serverless injection (AWS Lambda/Azure/GCP)")
    g4.add_argument("--cloud-provider",   default="auto",      metavar="PROVIDER", help="Cloud provider: aws/azure/gcp/auto")
    g4.add_argument("--lambda-cold-start",action="store_true", help="Lambda cold-start timing attack")
    g4.add_argument("--ssrf-metadata",    action="store_true", help="SSRF to cloud metadata service (169.254.169.254)")
    g4.add_argument("--swagger-url",      default=None,        metavar="URL", help="Swagger/OpenAPI spec URL for guided scan")

    g5 = p.add_argument_group("GenSQL Recon")
    g5.add_argument("--deep-recon",      action="store_true", help="OSINT recon (crt.sh / Wayback / JS endpoints)")
    g5.add_argument("--wayback",         action="store_true", help="Mine parameters from Wayback Machine")
    g5.add_argument("--js-analysis",     action="store_true", help="Extract endpoints and params from JavaScript files")
    g5.add_argument("--subdomain-enum",  action="store_true", help="Passive subdomain enumeration via crt.sh")
    g5.add_argument("--param-mine",      action="store_true", help="Parameter mining (1000+ built-in names)")
    g5.add_argument("--shodan-key",      default=None,        metavar="KEY", help="Shodan API key for extended recon")

    g6 = p.add_argument_group("GenSQL Post-Exploitation")
    g6.add_argument("--exploit-chain",  action="store_true", help="SQLi -> file read -> webshell -> OS cmd chain")
    g6.add_argument("--harvest-creds",  action="store_true", help="Extract credentials from DB dumps")
    g6.add_argument("--privesc-check",  action="store_true", help="Check DB privilege escalation paths")
    g6.add_argument("--lateral-move",   action="store_true", help="Generate lateral movement payloads")
    g6.add_argument("--oob-exfil",      action="store_true", help="Out-of-band DNS/HTTP exfiltration")
    g6.add_argument("--oob-domain",     default=None,        metavar="DOMAIN", help="Callback domain for OOB exfiltration")
    g6.add_argument("--oob-http",       default=None,        metavar="URL",    help="HTTP callback URL for OOB")
    g6.add_argument("--oob-listen",     type=int, default=0, metavar="PORT",   help="Start built-in OOB HTTP listener on port")

    g7 = p.add_argument_group("GenSQL Reporting")
    g7.add_argument("--report-html",  default=None, metavar="FILE", help="Write HTML report with CVSS 4.0 scoring")
    g7.add_argument("--report-json",  default=None, metavar="FILE", help="Write JSON report")
    g7.add_argument("--report-md",    default=None, metavar="FILE", help="Write Markdown report")
    g7.add_argument("--cvss4",        action="store_true",          help="Include CVSS 4.0 scores in report")
    g7.add_argument("--dashboard",    action="store_true",          help="Start real-time web dashboard")
    g7.add_argument("--dashboard-port",type=int, default=7474, metavar="PORT", help="Dashboard port (default: 7474)")

    g8 = p.add_argument_group("GenSQL Profiles & Wizard")
    g8.add_argument("--profile", default=None, metavar="PROFILE",
                    help="Scan profile: stealth | api | cloud | pentest | aggressive")
    g8.add_argument("--wizard",  action="store_true", help="Interactive guided wizard (easiest way to start)")

    # parse only the flags we know; pass the rest to the core engine
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
            "privesc_check": True, "cvss4": True,
            "report_html": "gensql_report.html", "report_json": "gensql_report.json",
        },
        "aggressive": {
            "ai_assist": True, "async_engine": True, "ai_waf_bypass": True,
            "graphql_inject": True, "nosql_inject": True, "jwt_attack": True,
            "ssti_inject": True, "exploit_chain": True, "harvest_creds": True,
            "oob_exfil": True,
        },
    }
    p = profiles.get(name.lower(), {})
    if not p:
        logger.warning("Unknown profile %r — valid: stealth, api, cloud, pentest, aggressive" % name)
        return
    for k, v in p.items():
        setattr(o, k, v)
    logger.info("Profile [%s] applied — %d options enabled" % (name, len(p)))


# ── Interactive wizard ─────────────────────────────────────────────────────────
def _wizard():
    print("\n\033[01;36m╔══════════════════════════════════════════╗")
    print("║     GenSQL Wizard  -  by Jeevraj         ║")
    print("╚══════════════════════════════════════════╝\033[0m\n")

    url = input("  \033[01;33mTarget URL\033[0m  : ").strip()
    if not url:
        print("  [!] No URL provided. Exiting wizard.")
        return None
    if not re.match(r"(?i)https?://", url):
        url = "http://" + url

    print("\n  \033[01;33mScan Profile\033[0m:")
    print("    1) Stealth     — slow, evasive, WAF bypass")
    print("    2) API         — GraphQL / NoSQL / JWT / gRPC")
    print("    3) Pentest     — full scan + exploit chain + HTML report  [default]")
    print("    4) Aggressive  — everything + OOB exfiltration")
    print("    5) Cloud       — AWS Lambda / Azure / GCP / SSRF metadata")
    c = input("  Profile [1-5, default=3]: ").strip() or "3"
    pm = {"1": "stealth", "2": "api", "3": "pentest", "4": "aggressive", "5": "cloud"}
    prof = pm.get(c, "pentest")

    print("\n  \033[01;33mExtra options\033[0m:")
    ai  = input("  Enable AI payload mutation? [Y/n]: ").strip().lower()
    waf = input("  Enable AI WAF bypass?       [Y/n]: ").strip().lower()
    rep = input("  Generate HTML report?       [Y/n]: ").strip().lower()
    dash= input("  Start live dashboard?       [y/N]: ").strip().lower()

    extra = ["-u", url, "--profile", prof]
    if ai  not in ("n", "no"):  extra.append("--ai-assist")
    if waf not in ("n", "no"):  extra.append("--ai-waf-bypass")
    if rep not in ("n", "no"):  extra += ["--report-html", "gensql_report.html"]
    if dash in ("y", "yes"):    extra.append("--dashboard")

    print("\n  \033[01;32m[*] Starting scan with profile: %s\033[0m\n" % prof)
    return extra


# ── Module initialisation ──────────────────────────────────────────────────────
def _init(o):
    if getattr(o, "ai_assist", False) and AIPayloadEngine:
        conf.aiEngine = AIPayloadEngine(offline=True, dbms=getattr(conf, "dbms", None))
        logger.info("AI engine active (fully offline)")

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


# ── Post-scan recon ────────────────────────────────────────────────────────────
def _recon(o):
    if not (getattr(o, "deep_recon", False) and hasattr(conf, "deepRecon")):
        return
    url = getattr(conf, "url", None)
    if not url:
        return
    m = re.search(r"https?://([^/]+)", url)
    if not m:
        return
    try:
        findings = conf.deepRecon.generate_recon_report(m.group(1))
        for key, label in [("technologies", "Tech"), ("cloud_provider", "Cloud"),
                            ("subdomains", "Subdomains"), ("api_endpoints", "API endpoints")]:
            v = findings.get(key)
            if v:
                logger.info("%s: %s" % (label, ", ".join(v) if isinstance(v, list) else str(v)))
        kb.genReconFindings = findings
    except Exception as ex:
        logger.warning("Recon error: %s" % getSafeExString(ex))


# ── Finalise ───────────────────────────────────────────────────────────────────
def _finalize(o):
    if hasattr(conf, "reportEngine"):
        try:
            conf.reportEngine.finalize()
            logger.info("Reports written")
        except Exception as ex:
            logger.warning("Report error: %s" % getSafeExString(ex))

    top_n = getattr(o, "ai_top_payloads", 0)
    if top_n > 0 and hasattr(conf, "aiEngine"):
        try:
            top = conf.aiEngine.get_best_payloads(count=top_n)
            if top:
                dataToStdout("\n\033[01;36m[*] Top AI payloads:\033[0m\n", forceOutput=True)
                for i, (pl, sc) in enumerate(top, 1):
                    dataToStdout("  %2d. [%.3f] %s\n" % (i, sc, pl), forceOutput=True)
        except Exception:
            pass

    if hasattr(conf, "dashboard"):
        try: conf.dashboard.stop()
        except Exception: pass


# ── Main ───────────────────────────────────────────────────────────────────────
def main():
    """GenSQL v2.0.0 — by Jeevraj"""

    # 1. Handle --wizard before anything else
    if "--wizard" in sys.argv:
        try:
            extra = _wizard()
            if extra:
                # Remove --wizard, inject wizard output
                sys.argv = [sys.argv[0]] + extra + [
                    a for a in sys.argv[1:] if a != "--wizard"]
            else:
                sys.exit(0)
        except (KeyboardInterrupt, EOFError):
            print()
            sys.exit(0)

    # 2. Parse GenSQL-specific args (parse_known_args — leaves core flags alone)
    o, _parser = _args()

    # 3. Apply profile early so it can influence _strip_gensql_args
    if getattr(o, "profile", None):
        _profile(o.profile, o)

    # 4. CRITICAL: strip ALL GenSQL flags from sys.argv before the core parser
    sys.argv = _strip_gensql_args(sys.argv)

    try:
        dirtyPatches()
        resolveCrossReferences()
        checkEnvironment()
        setPaths(modulePath())
        printBanner()

        # 5. Run the core argument parser (now only sees standard flags)
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

        conf.showTime = True
        dataToStdout("[!] legal disclaimer: %s\n\n" % LEGAL_DISCLAIMER, forceOutput=True)
        dataToStdout("[*] starting @ %s\n\n" % time.strftime("%X /%Y-%m-%d/"), forceOutput=True)

        init()

        # 6. Initialise all GenSQL modules
        _init(o)

        # 7. Pre-scan recon
        _recon(o)

        # 8. Run the scan
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
                                    else:
                                        raise
                                else:
                                    if kb.targets:
                                        start()
                        else:
                            start()
                    except Exception as ex:
                        os._exitcode = 1
                        if "can't start new thread" in getSafeExString(ex):
                            logger.critical("unable to start new threads"); raise SystemExit
                        else:
                            raise

    except SqlmapUserQuitException:
        if not conf.batch: logger.error("user quit")
    except (SqlmapSilentQuitException, bdb.BdbQuit):
        pass
    except SqlmapShellQuitException:
        cmdLineOptions.sqlmapShell = False
    except SqlmapBaseException as ex:
        logger.critical(getSafeExString(ex)); os._exitcode = 1; raise SystemExit
    except KeyboardInterrupt:
        try: print()
        except IOError: pass
    except EOFError:
        print(); logger.error("exit")
    except SystemExit as ex:
        os._exitcode = ex.code or 0
    except Exception:
        print()
        errMsg = unhandledExceptionMessage()
        excMsg = traceback.format_exc()
        os._exitcode = 255
        errMsg = maskSensitiveData(errMsg)
        excMsg = maskSensitiveData(excMsg)
        logger.critical(errMsg)
        dataToStdout("%s\n" % setColor(excMsg.strip(), level=logging.CRITICAL))
        if not codeIsModified():
            createGithubIssue(errMsg, excMsg)
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
            except Exception:
                pass
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

        if conf.get("hashDB"):
            conf.hashDB.flush(); conf.hashDB.close()

        if conf.get("harFile"):
            try:
                with openFile(conf.harFile, "w+") as f:
                    json.dump(conf.httpCollector.obtain(), fp=f, indent=4, separators=(",", ": "))
            except SqlmapBaseException:
                pass

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
