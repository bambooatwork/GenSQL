#!/usr/bin/env python
"""
GenSQL Recon: Deep OSINT Reconnaissance Engine
Author: Jeevraj
Features: crt.sh, Wayback Machine, JS analysis, tech fingerprint, cloud detection
All queries are passive HTTP — no active port scanning.
"""
import re
import json
import ssl
import socket
import urllib.request
import urllib.parse


TECH_SIGNATURES = {
    "nginx":      {"headers": ["server:nginx"]},
    "apache":     {"headers": ["server:apache"]},
    "iis":        {"headers": ["server:microsoft-iis", "x-powered-by:asp.net"]},
    "express":    {"headers": ["x-powered-by:express"]},
    "django":     {"headers": ["x-frame-options:deny"],
                   "body":    [r"csrfmiddlewaretoken", r"django"]},
    "rails":      {"headers": ["x-runtime"], "body": [r"rails-ujs"]},
    "laravel":    {"headers": ["set-cookie:laravel_session"], "body": [r"laravel"]},
    "wordpress":  {"body": [r"wp-content", r"wp-json", r"wordpress"]},
    "drupal":     {"body": [r"drupal", r"sites/default/files"]},
    "joomla":     {"body": [r"/components/com_"]},
    "nextjs":     {"body": [r"__next", r"_next/static"]},
    "react":      {"body": [r"react-root", r"__react"]},
    "angular":    {"body": [r"ng-version", r"angular"]},
    "vue":        {"body": [r"vue-app", r"data-v-"]},
    "spring":     {"headers": ["x-application-context"], "body": [r"spring"]},
    "struts":     {"body": [r"struts", r'\.action"']},
    "graphql":    {"body": [r"graphql", r"__schema"]},
    "php":        {"headers": ["x-powered-by:php"], "body": [r"\.php"]},
    "tomcat":     {"headers": ["server:apache-tomcat"]},
    "cloudflare": {"headers": ["cf-ray", "server:cloudflare"]},
    "aws_s3":     {"body": [r"s3\.amazonaws\.com", r"AmazonS3"]},
    "aws_cf":     {"headers": ["x-amz-cf-id"]},
    "azure":      {"headers": ["x-ms-request-id", "x-azure-ref"]},
    "gcp":        {"headers": ["x-guploader"]},
}

SUBDOMAIN_WORDLIST = [
    "www", "mail", "api", "dev", "staging", "test", "admin", "portal", "app",
    "blog", "shop", "cdn", "static", "media", "auth", "login", "dashboard",
    "beta", "internal", "vpn", "ftp", "smtp", "pop", "imap", "secure",
    "mobile", "m", "docs", "support", "help", "status", "monitoring",
    "api2", "api3", "v1", "v2", "graphql", "ws", "websocket", "grpc",
    "sso", "oauth", "token", "webhook", "callback", "notify", "push",
    "metrics", "grafana", "jenkins", "ci", "cd", "gitlab", "github",
    "jira", "confluence", "wiki", "kb", "forum", "community",
]


class DeepRecon:
    """Deep passive OSINT reconnaissance engine. Author: Jeevraj"""

    def __init__(self, wayback=False, js_analysis=False, subdomain_enum=False,
                 shodan_key=None, timeout=10):
        self.wayback        = wayback
        self.js_analysis    = js_analysis
        self.do_subdomain   = subdomain_enum
        self.shodan_key     = shodan_key
        self.timeout        = timeout

    # ── Technology Fingerprinting ─────────────────────────────────────────
    def fingerprint_technology(self, url, response_headers=None, response_body=None):
        """Detect frameworks and server software from headers and body."""
        detected = set()
        h_str = " ".join(
            "%s:%s" % (k.lower(), v.lower())
            for k, v in (response_headers or {}).items()
        )
        b_str = (response_body or "").lower()
        for tech, sigs in TECH_SIGNATURES.items():
            for hdr_pat in sigs.get("headers", []):
                if hdr_pat in h_str:
                    detected.add(tech)
            for body_pat in sigs.get("body", []):
                if re.search(body_pat, b_str, re.IGNORECASE):
                    detected.add(tech)
        return sorted(detected)

    # ── Cloud Detection ───────────────────────────────────────────────────
    def detect_cloud_provider(self, ip=None, headers=None):
        """Detect cloud provider from IP and response headers."""
        h_str = " ".join(str(v).lower() for v in (headers or {}).values())
        if "cf-ray" in h_str or "cloudflare" in h_str:
            return "cloudflare"
        if any(k in h_str for k in ["x-amz-", "x-amzn-", "cloudfront", "amazonaws"]):
            return "aws"
        if any(k in h_str for k in ["x-ms-", "x-azure-", "azure"]):
            return "azure"
        if any(k in h_str for k in ["x-goog-", "google", "guploader"]):
            return "gcp"
        return None

    # ── Subdomain Enumeration ─────────────────────────────────────────────
    def passive_osint(self, domain):
        """Enumerate subdomains via crt.sh certificate transparency."""
        subdomains = set()
        try:
            url = "https://crt.sh/?q=%%25.%s&output=json" % urllib.parse.quote(domain)
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 GenSQL/2.0"})
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
                for entry in data:
                    for sub in entry.get("name_value", "").split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if domain in sub and sub != domain:
                            subdomains.add(sub)
        except Exception:
            pass
        return sorted(subdomains)

    def subdomain_enum(self, domain, wordlist=None):
        """DNS brute-force subdomain enumeration."""
        wl = wordlist or SUBDOMAIN_WORDLIST
        found = []
        for sub in wl:
            try:
                fqdn = "%s.%s" % (sub, domain)
                ip   = socket.gethostbyname(fqdn)
                found.append({"subdomain": fqdn, "ip": ip})
            except socket.gaierror:
                pass
        return found

    # ── Wayback Machine ───────────────────────────────────────────────────
    def wayback_params(self, domain):
        """Extract GET parameters from Wayback Machine CDX API."""
        params = set()
        try:
            url = (
                "https://web.archive.org/cdx/search/cdx?url=%s/*"
                "&output=json&fl=original&collapse=urlkey&limit=1000"
            ) % domain
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 GenSQL/2.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                data = json.loads(r.read().decode("utf-8", "replace"))
                for row in data[1:]:
                    for m in re.findall(r"[?&]([a-zA-Z0-9_\-]+)=", str(row)):
                        params.add(m)
        except Exception:
            pass
        return sorted(params)

    # ── JS API Endpoint Discovery ─────────────────────────────────────────
    def api_endpoint_discovery(self, url=None, js_content=None):
        """Extract API endpoint paths from JavaScript source."""
        endpoints = set()
        patterns = [
            r"""(?:fetch|axios\.get|axios\.post)\s*\(\s*['"](/[^'"?#\s]+)['"]""",
            r"""['"](/api/[^'"?#\s]+)['"]""",
            r"""['"](/v\d+/[^'"?#\s]+)['"]""",
            r"""url\s*:\s*['"](/[^'"?#\s]+)['"]""",
            r"""path\s*:\s*['"](/[^'"?#\s]+)['"]""",
        ]
        content = js_content or ""
        if not content and url:
            content = self._fetch_text(url) or ""
        for pat in patterns:
            for m in re.findall(pat, content, re.IGNORECASE):
                if m and len(m) > 1:
                    endpoints.add(m)
        return sorted(endpoints)

    # ── Attack Surface Mapping ────────────────────────────────────────────
    def technology_to_attack_surface(self, technologies):
        """Map technologies to likely vulnerability classes."""
        mapping = {
            "wordpress":  ["SQLi", "XSS", "Plugin RCE", "LFI", "XML-RPC abuse"],
            "drupal":     ["Drupalgeddon SQLi", "SSRF", "RCE"],
            "joomla":     ["SQLi", "LFI", "RCE"],
            "laravel":    ["SQLi", "SSTI (Blade)", "Mass Assignment"],
            "rails":      ["SQLi", "SSTI (ERB)", "Mass Assignment"],
            "django":     ["SQLi", "SSTI (Django templates)", "SSRF"],
            "spring":     ["SSTI (Thymeleaf)", "SSRF", "Actuator exposure"],
            "struts":     ["OGNL injection", "RCE"],
            "graphql":    ["GraphQL injection", "Introspection", "Batching attacks"],
            "php":        ["SQLi", "LFI", "RFI", "Type juggling"],
            "iis":        ["SQLi", "MSSQL", "IIS short filename"],
            "tomcat":     ["Manager RCE", "Ghostcat", "AJP deserialization"],
            "aws_cf":     ["CloudFront misconfiguration", "S3 exposure"],
        }
        return {t: mapping[t] for t in technologies if t in mapping}

    # ── Full Report ───────────────────────────────────────────────────────
    def generate_recon_report(self, domain):
        """Run full passive recon and return structured report dict."""
        report = {
            "domain":         domain,
            "ip":             None,
            "technologies":   [],
            "cloud_provider": None,
            "subdomains":     [],
            "api_endpoints":  [],
            "wayback_params": [],
            "attack_surface": {},
        }
        try:
            report["ip"] = socket.gethostbyname(domain)
        except Exception:
            pass

        # Subdomains
        if self.do_subdomain:
            report["subdomains"] = self.subdomain_enum(domain)
        else:
            report["subdomains"] = self.passive_osint(domain)

        # Wayback
        if self.wayback:
            report["wayback_params"] = self.wayback_params(domain)

        # Technology fingerprint
        base_url = "https://" + domain
        body    = self._fetch_text(base_url)
        headers = self._fetch_headers(base_url)
        report["technologies"]   = self.fingerprint_technology(base_url, headers, body)
        report["cloud_provider"] = self.detect_cloud_provider(report["ip"], headers)

        # JS analysis
        if self.js_analysis and body:
            js_urls = re.findall(r'src=[\'"]([^\'"]+\.js[^\'"]*)[\'"]', body or "")
            for js_url in js_urls[:5]:
                if not js_url.startswith("http"):
                    js_url = base_url + "/" + js_url.lstrip("/")
                js_content = self._fetch_text(js_url)
                if js_content:
                    report["api_endpoints"].extend(
                        self.api_endpoint_discovery(js_url, js_content)
                    )
            report["api_endpoints"] = sorted(set(report["api_endpoints"]))

        report["attack_surface"] = self.technology_to_attack_surface(report["technologies"])
        return report

    # ── Shodan ────────────────────────────────────────────────────────────
    def shodan_search(self, query, api_key=None):
        """Query Shodan API (requires API key)."""
        key = api_key or self.shodan_key
        if not key:
            return {"error": "No Shodan API key. Use --shodan-key KEY"}
        try:
            url = "https://api.shodan.io/shodan/host/search?key=%s&query=%s" % (
                urllib.parse.quote(key), urllib.parse.quote(query))
            req = urllib.request.Request(url, headers={"User-Agent": "GenSQL/2.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except Exception as ex:
            return {"error": str(ex)}

    # ── Helpers ───────────────────────────────────────────────────────────
    def _fetch_text(self, url):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 GenSQL/2.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return r.read().decode("utf-8", "replace")
        except Exception:
            return None

    def _fetch_headers(self, url):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 GenSQL/2.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return dict(r.headers)
        except Exception:
            return {}
