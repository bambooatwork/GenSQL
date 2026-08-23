#!/usr/bin/env python
"""
GenSQL - Next-Generation SQL Injection & Web Security Assessment Framework
Tool    : GenSQL
Author  : Jeevraj
Version : 2.0.0
Built on: sqlmap v1.10.8

Superior to sqlmap in every way:
  - Offline AI payload mutation engine
  - Async HTTP/2 scan engine
  - GraphQL / NoSQL / JWT / gRPC / SSTI / Cloud injection
  - 60+ new tamper scripts for modern WAFs
  - Deep OSINT recon (crt.sh, Wayback, JS analysis)
  - Exploit chain: SQLi to RCE to lateral movement
  - OOB exfiltration via DNS / HTTP / FTP
  - CVSS 4.0 HTML/JSON/Markdown reports
  - Scan profiles: stealth / pentest / api / cloud / aggressive
"""
from __future__ import print_function

try:
    import sys, os
    sys.dont_write_bytecode = True
    try:
        __import__("lib.utils.versioncheck")
    except ImportError:
        sys.exit("[!] wrong installation - visit https://github.com/sqlmapproject/sqlmap/#installation")

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
GRPCInj         = _safe_import("lib.techniques.api.grpc_inject",        "GRPCInjector")
CloudInj        = _safe_import("lib.techniques.cloud.lambda_inject",    "CloudInjector")
AdvSSTI         = _safe_import("lib.techniques.ssti.advanced_ssti",     "AdvancedSSTI")
DeepRecon       = _safe_import("lib.recon.deep_recon",                  "DeepRecon")
ParamMiner      = _safe_import("lib.recon.param_miner",                 "ParamMiner")
ExploitChain    = _safe_import("lib.exploit.chain",                     "ExploitChain")
OOBExfil        = _safe_import("lib.exploit.oob",                       "OOBExfiltrator")
ReportEngine    = _safe_import("lib.report.report_engine",              "ReportEngine")

_MODS = {"ai_engine": AIPayloadEngine, "async_engine": AsyncScanEngine,
         "ai_waf_bypass": AIWAFBypass, "encoder_chain": EncoderChain,
         "graphql_inject": GraphQLInj, "nosql_inject": NoSQLInj,
         "jwt_attack": JWTAttacker, "rest_inject": RESTInj,
         "grpc_inject": GRPCInj, "cloud_scan": CloudInj,
         "ssti_advanced": AdvSSTI, "deep_recon": DeepRecon,
         "param_miner": ParamMiner, "exploit_chain": ExploitChain,
         "oob_exfil": OOBExfil, "reporting": ReportEngine}
FEATURES = {k: v is not None for k, v in _MODS.items()}


def modulePath():
    try: _ = sys.executable if weAreFrozen() else __file__
    except NameError: _ = inspect.getsourcefile(modulePath)
    return getUnicode(os.path.dirname(os.path.realpath(_)),
                      encoding=sys.getfilesystemencoding() or UNICODE_ENCODING)

def checkEnvironment():
    try: os.path.isdir(modulePath())
    except UnicodeEncodeError:
        logger.critical("non-ASCII path - move gensql to another location"); raise SystemExit
    if LooseVersion(VERSION) < LooseVersion("1.0"):
        logger.critical("broken runtime environment"); raise SystemExit
    if "sqlmap.sqlmap" in sys.modules:
        for _ in ("cmdLineOptions","conf","kb"):
            globals()[_] = getattr(sys.modules["lib.core.data"], _)
        for _ in ("SqlmapBaseException","SqlmapShellQuitException",
                  "SqlmapSilentQuitException","SqlmapUserQuitException"):
            globals()[_] = getattr(sys.modules["lib.core.exception"], _)

def printBanner():
    dataToStdout(JEEVSQL_BANNER, forceOutput=True)
    loaded  = [k for k,v in FEATURES.items() if v]
    missing = [k for k,v in FEATURES.items() if not v]
    if loaded:
        dataToStdout("\033[01;32m  [+] Loaded  : %s\033[0m\n" % ", ".join(loaded), forceOutput=True)
    if missing:
        dataToStdout("\033[01;33m  [~] Optional: %s\033[0m\n" % ", ".join(missing), forceOutput=True)
    dataToStdout("\n", forceOutput=True)

def _args():
    import argparse
    p = argparse.ArgumentParser(add_help=False)
    for flag in ("--ai-assist","--ai-learn","--async-engine","--http2","--graphql-inject",
                 "--graphql-introspect","--nosql-inject","--jwt-attack","--jwt-bruteforce",
                 "--grpc-inject","--ssti-inject","--idor-scan","--cloud-scan",
                 "--lambda-cold-start","--ssrf-metadata","--ai-waf-bypass","--humanize",
                 "--chunked-bypass","--deep-recon","--wayback","--js-analysis",
                 "--subdomain-enum","--param-mine","--exploit-chain","--harvest-creds",
                 "--privesc-check","--lateral-move","--oob-exfil","--cvss4",
                 "--dashboard","--wizard"):
        p.add_argument(flag, action="store_true", default=False)
    for flag, default in (("--nosql-type","mongodb"),("--cloud-provider","auto"),
                          ("--encoder-chain",None),("--swagger-url",None),
                          ("--shodan-key",None),("--oob-domain",None),
                          ("--oob-http",None),("--report-html",None),
                          ("--report-json",None),("--report-md",None),
                          ("--profile",None),("--idor-range","1-1000")):
        p.add_argument(flag, default=default)
    for flag, default in (("--max-concurrent",50),("--ai-top-payloads",0),
                          ("--oob-listen",0),("--rotate-identity",0),
                          ("--dashboard-port",7474)):
        p.add_argument(flag, type=int, default=default)
    a,_ = p.parse_known_args()
    return a

def _profile(name, o):
    P = {
        "stealth":    {"humanize":True,"rotate_identity":5,"ai_waf_bypass":True},
        "aggressive": {"ai_assist":True,"async_engine":True,"ai_waf_bypass":True,
                       "graphql_inject":True,"nosql_inject":True,"jwt_attack":True,
                       "ssti_inject":True,"exploit_chain":True,"harvest_creds":True},
        "pentest":    {"ai_assist":True,"ai_waf_bypass":True,"deep_recon":True,
                       "graphql_inject":True,"nosql_inject":True,"jwt_attack":True,
                       "ssti_inject":True,"exploit_chain":True,"harvest_creds":True,
                       "privesc_check":True,"report_html":"gensql_report.html",
                       "report_json":"gensql_report.json","cvss4":True},
        "api":        {"graphql_inject":True,"nosql_inject":True,"jwt_attack":True,
                       "grpc_inject":True,"idor_scan":True,"param_mine":True,"ai_assist":True},
        "cloud":      {"cloud_scan":True,"ssrf_metadata":True,"lambda_cold_start":True,
                       "ai_assist":True,"deep_recon":True},
    }
    for k,v in P.get(name,{}).items(): setattr(o,k,v)
    logger.info("Profile %r applied" % name)

def _wizard():
    print("\n\033[01;36m[*] GenSQL Wizard - by Jeevraj\033[0m")
    url = input("  Target URL: ").strip()
    if not url: return None
    print("  1) Stealth  2) API  3) Pentest  4) Aggressive")
    c = input("  Profile [1-4, default=3]: ").strip() or "3"
    pm = {"1":"stealth","2":"api","3":"pentest","4":"aggressive"}
    prof = pm.get(c,"pentest")
    extra = ["-u",url,"--profile",prof,"--ai-assist","--ai-waf-bypass"]
    if input("  HTML report? [Y/n]: ").strip().lower() not in ("n","no"):
        extra += ["--report-html","gensql_report.html"]
    return extra

def _init(o):
    if o.ai_assist and AIPayloadEngine:
        conf.aiEngine = AIPayloadEngine(offline=True, dbms=getattr(conf,"dbms",None))
        logger.info("AI engine loaded (offline)")
    if o.async_engine and AsyncScanEngine:
        conf.asyncEngine = AsyncScanEngine(max_concurrent=o.max_concurrent,
                                           http_version="http2" if o.http2 else "auto")
        logger.info("Async engine loaded")
    if o.ai_waf_bypass and AIWAFBypass:
        conf.aiwafBypass = AIWAFBypass()
        if o.humanize: conf.aiwafBypass.enable_humanization()
        logger.info("AI WAF bypass loaded")
    if o.encoder_chain and EncoderChain:
        conf.encoderChain = EncoderChain(o.encoder_chain.split(","))
    if o.graphql_inject and GraphQLInj:
        conf.graphqlInjector = GraphQLInj(do_introspect=o.graphql_introspect)
        logger.info("GraphQL injector loaded")
    if o.nosql_inject and NoSQLInj:
        conf.nosqlInjector = NoSQLInj(db_type=o.nosql_type); logger.info("NoSQL injector loaded")
    if o.jwt_attack and JWTAttacker:
        conf.jwtAttacker = JWTAttacker(bruteforce=o.jwt_bruteforce); logger.info("JWT attacker loaded")
    if o.grpc_inject and GRPCInj:
        conf.grpcInjector = GRPCInj(); logger.info("gRPC injector loaded")
    if o.ssti_inject and AdvSSTI:
        conf.sstiScanner = AdvSSTI(); logger.info("SSTI scanner loaded")
    if o.cloud_scan and CloudInj:
        conf.cloudInjector = CloudInj(provider=o.cloud_provider, ssrf_metadata=o.ssrf_metadata)
        logger.info("Cloud injector loaded")
    if o.deep_recon and DeepRecon:
        conf.deepRecon = DeepRecon(wayback=o.wayback, js_analysis=o.js_analysis,
                                    subdomain_enum=o.subdomain_enum, shodan_key=o.shodan_key)
        logger.info("Deep recon loaded")
    if o.param_mine and ParamMiner:
        conf.paramMiner = ParamMiner(swagger_url=o.swagger_url); logger.info("Param miner loaded")
    if o.exploit_chain and ExploitChain:
        conf.exploitChain = ExploitChain(harvest_creds=o.harvest_creds,
                                          privesc=o.privesc_check, lateral=o.lateral_move)
        logger.info("Exploit chain loaded")
    if o.oob_exfil and OOBExfil:
        conf.oobExfil = OOBExfil(domain=o.oob_domain, http_callback=o.oob_http,
                                   listen_port=o.oob_listen); logger.info("OOB exfil loaded")
    if (o.report_html or o.report_json or o.report_md) and ReportEngine:
        conf.reportEngine = ReportEngine(html_path=o.report_html, json_path=o.report_json,
                                          md_path=o.report_md, cvss4=o.cvss4)
        logger.info("Report engine loaded")
    if o.dashboard:
        try:
            from lib.report.dashboard import Dashboard
            conf.dashboard = Dashboard(port=o.dashboard_port)
            conf.dashboard.start()
            logger.info("Dashboard @ http://127.0.0.1:%d" % o.dashboard_port)
        except Exception as ex: logger.warning("Dashboard unavailable: %s" % getSafeExString(ex))
    if o.idor_scan and RESTInj:
        try: s,e = map(int,o.idor_range.split("-"))
        except: s,e = 1,1000
        conf.idorScanner = RESTInj(idor_start=s, idor_end=e); logger.info("IDOR scanner loaded")

def _recon(o):
    if not (o.deep_recon and hasattr(conf,"deepRecon")): return
    url = getattr(conf,"url",None)
    if not url: return
    m = re.search(r"https?://([^/]+)", url)
    if not m: return
    try:
        F = conf.deepRecon.generate_recon_report(m.group(1))
        for k,lbl in [("technologies","Tech"),("cloud_provider","Cloud"),
                      ("subdomains","Subdomains"),("api_endpoints","APIs")]:
            v = F.get(k)
            if v: logger.info("%s: %s" % (lbl, ", ".join(v) if isinstance(v,list) else str(v)))
        kb.jeevReconFindings = F
    except Exception as ex: logger.warning("Recon error: %s" % getSafeExString(ex))

def _finalize(o):
    if hasattr(conf,"reportEngine"):
        try: conf.reportEngine.finalize(); logger.info("Reports written")
        except Exception as ex: logger.warning("Report error: %s" % getSafeExString(ex))
    if o.ai_top_payloads > 0 and hasattr(conf,"aiEngine"):
        try:
            top = conf.aiEngine.get_best_payloads(count=o.ai_top_payloads)
            if top:
                dataToStdout("\n\033[01;36m[*] Top AI payloads:\033[0m\n", forceOutput=True)
                for i,(pl,sc) in enumerate(top,1):
                    dataToStdout("  %2d. [%.3f] %s\n" % (i,sc,pl), forceOutput=True)
        except: pass
    if hasattr(conf,"dashboard"):
        try: conf.dashboard.stop()
        except: pass

def main():
    """GenSQL - by Jeevraj"""
    if "--wizard" in sys.argv:
        try:
            extra = _wizard()
            if extra:
                sys.argv = [sys.argv[0]] + extra + [a for a in sys.argv[1:] if a != "--wizard"]
        except (KeyboardInterrupt, EOFError): print(); sys.exit(0)

    o = _args()
    try:
        dirtyPatches(); resolveCrossReferences(); checkEnvironment(); setPaths(modulePath())
        printBanner()
        args = cmdLineParser()
        cmdLineOptions.update(args.__dict__ if hasattr(args,"__dict__") else args)
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
        if o.profile: _profile(o.profile, o)
        _init(o)
        if conf.get("reportJson"):
            from lib.utils.api import setupReportCollector
            conf.reportCollector = setupReportCollector()
        _recon(o)
        if not conf.updateAll:
            if conf.smokeTest:
                from lib.core.testing import smokeTest; os._exitcode=1-(smokeTest() or 0)
            elif conf.vulnTest:
                from lib.core.testing import vulnTest; os._exitcode=1-(vulnTest() or 0)
            elif conf.fpTest:
                from lib.core.testing import fpTest; os._exitcode=1-(fpTest() or 0)
            elif conf.payloadLint:
                from lib.core.testing import payloadLintTest; os._exitcode=1-(payloadLintTest() or 0)
            elif conf.apiTest:
                from lib.core.testing import apiTest; os._exitcode=1-(apiTest() or 0)
            else:
                from lib.controller.controller import start
                if conf.profile:
                    from lib.core.profiling import profile; profile()
                else:
                    try:
                        if conf.crawlDepth and conf.bulkFile:
                            for i,tgt in enumerate(getFileItems(conf.bulkFile)):
                                try:
                                    kb.targets = OrderedSet()
                                    if not re.search(r"(?i)\Ahttp[s]*://",tgt): tgt="https://"+tgt
                                    logger.info("crawling %r (%d)" % (tgt,i+1)); crawl(tgt)
                                except Exception as ex:
                                    if not isinstance(ex,SqlmapUserQuitException):
                                        logger.error("crawl error: %s" % getSafeExString(ex))
                                    else: raise
                                else:
                                    if kb.targets: start()
                        else: start()
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
        logger.critical(getSafeExString(ex)); os._exitcode=1; raise SystemExit
    except KeyboardInterrupt:
        try: print()
        except IOError: pass
    except EOFError: print(); logger.error("exit")
    except SystemExit as ex: os._exitcode = ex.code or 0
    except Exception:
        print()
        errMsg = unhandledExceptionMessage(); excMsg = traceback.format_exc()
        os._exitcode = 255
        errMsg = maskSensitiveData(errMsg); excMsg = maskSensitiveData(excMsg)
        logger.critical(errMsg)
        dataToStdout("%s\n" % setColor(excMsg.strip(), level=logging.CRITICAL))
        if not codeIsModified(): createGithubIssue(errMsg, excMsg)
    finally:
        kb.threadContinue = False
        try: _finalize(o)
        except: pass
        if (getDaysFromLastUpdate() or 0) > LAST_UPDATE_NAGGING_DAYS:
            logger.warning("GenSQL version is outdated")
        if conf.get("reportCollector") is not None:
            try:
                from lib.utils.api import writeReportJson
                writeReportJson(conf.reportCollector, conf.reportJson)
            except: pass
            finally:
                try: conf.reportCollector.disconnect()
                except: pass
        if conf.get("showTime"):
            dataToStdout("\n[*] ending @ %s\n\n" % time.strftime("%X /%Y-%m-%d/"), forceOutput=True)
        kb.threadException = True
        for tmpDir in conf.get("tempDirs",[]):
            for pfx in (MKSTEMP_PREFIX.IPC, MKSTEMP_PREFIX.TESTING,
                        MKSTEMP_PREFIX.COOKIE_JAR, MKSTEMP_PREFIX.BIG_ARRAY):
                for fp in glob.glob(os.path.join(tmpDir,"%s*"%pfx)):
                    try: os.remove(fp)
                    except OSError: pass
        if conf.get("hashDB"): conf.hashDB.flush(); conf.hashDB.close()
        if conf.get("harFile"):
            try:
                with openFile(conf.harFile,"w+") as f:
                    json.dump(conf.httpCollector.obtain(),fp=f,indent=4,separators=(",",": "))
            except SqlmapBaseException: pass
        if conf.get("api"): conf.databaseCursor.disconnect()
        if conf.get("dumper"): conf.dumper.flush()
        _ = time.time()
        while threading.active_count()>1 and (time.time()-_)<THREAD_FINALIZATION_TIMEOUT:
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
        if threading.active_count()>1: os._exit(getattr(os,"_exitcode",0))
        else: sys.exit(getattr(os,"_exitcode",0))
else:
    __import__("lib.controller.controller")
    from lib.utils.library import scan, scanFromRequest, SqlmapError

__all__ = ["scan","scanFromRequest","SqlmapError"]
