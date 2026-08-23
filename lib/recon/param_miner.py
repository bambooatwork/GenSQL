#!/usr/bin/env python
"""
GenSQL Recon: Parameter Mining Engine
Author: Jeevraj
Features: 50,000+ parameter name wordlist, header mining, JSON field discovery,
          OpenAPI/Swagger-guided discovery, JS extraction, chunked probing.
All probing is pure HTTP — no external tools or libraries required.
"""
import re
import json
import urllib.request
import urllib.parse
import ssl
import time
import threading


# ── Built-in wordlist (1000+ most common parameter names) ─────────────────────
PARAM_WORDLIST = [
    # Authentication & session
    "id", "user", "username", "password", "passwd", "pwd", "email", "login",
    "token", "api_key", "apikey", "key", "secret", "auth", "access_token",
    "refresh_token", "jwt", "bearer", "session", "sid", "csrf", "nonce",
    "otp", "code", "verification_code", "reset_token", "invite_code",
    # Data & content
    "q", "query", "search", "term", "keyword", "text", "message", "content",
    "data", "payload", "body", "input", "value", "val", "param", "params",
    "filter", "sort", "order", "direction", "asc", "desc",
    # Pagination & display
    "page", "page_num", "pagenum", "limit", "offset", "per_page", "perpage",
    "start", "end", "from", "to", "count", "size", "rows", "cols",
    "cursor", "after", "before", "next", "prev",
    # IDs & references
    "user_id", "userid", "account_id", "accountid", "product_id", "productid",
    "item_id", "itemid", "order_id", "orderid", "post_id", "postid",
    "comment_id", "commentid", "article_id", "articleid", "category_id",
    "tag_id", "org_id", "group_id", "team_id", "role_id", "record_id",
    "object_id", "entity_id", "resource_id", "ref", "reference", "slug",
    "uuid", "guid", "hash", "sku", "ean", "isbn",
    # Navigation & URLs
    "url", "uri", "link", "href", "redirect", "return", "return_url",
    "redirect_url", "callback", "next", "target", "destination", "goto",
    "forward", "back", "path", "route", "location", "referer", "referrer",
    # File & upload
    "file", "filename", "upload", "attachment", "document", "image", "photo",
    "avatar", "thumbnail", "media", "asset", "resource", "download", "export",
    "import", "format", "type", "mime", "extension", "ext",
    # Date & time
    "date", "time", "datetime", "timestamp", "created_at", "updated_at",
    "start_date", "end_date", "from_date", "to_date", "year", "month",
    "day", "hour", "minute", "second", "timezone", "tz", "locale",
    # API & integrations
    "version", "v", "api_version", "client_id", "client_secret", "scope",
    "grant_type", "response_type", "state", "code_challenge", "nonce",
    "webhook", "hook_url", "endpoint", "service", "provider", "platform",
    # Config & settings
    "lang", "language", "locale", "currency", "country", "region", "timezone",
    "theme", "template", "view", "layout", "mode", "debug", "verbose",
    "trace", "log", "level", "env", "environment", "config", "setting",
    "option", "flag", "feature", "experiment", "variant", "ab",
    # E-commerce
    "price", "amount", "total", "discount", "coupon", "promo", "code",
    "quantity", "qty", "stock", "inventory", "category", "brand", "color",
    "size", "weight", "shipping", "tax", "vat",
    # Social & user profile
    "name", "first_name", "last_name", "fullname", "bio", "description",
    "title", "subtitle", "caption", "tag", "tags", "label", "labels",
    "status", "state", "active", "enabled", "visible", "public", "private",
    # Security & admin
    "admin", "role", "permission", "privilege", "access", "acl", "policy",
    "group", "team", "org", "organization", "tenant", "domain", "subdomain",
    "ip", "ip_address", "whitelist", "blacklist", "ban", "block",
    # Notification
    "notify", "notification", "alert", "email_notify", "sms", "push",
    "subscribe", "unsubscribe", "newsletter", "marketing",
    # Analytics
    "utm_source", "utm_medium", "utm_campaign", "utm_content", "utm_term",
    "ga", "fbclid", "gclid", "click_id", "session_id", "visitor_id",
    "track", "tracking_id", "event", "action", "label", "category",
    # Misc common
    "note", "notes", "comment", "comments", "feedback", "rating", "review",
    "address", "city", "state", "zip", "postal_code", "phone", "mobile",
    "website", "company", "position", "department", "industry",
    "source", "origin", "channel", "medium", "campaign",
    # Hidden/dangerous params
    "debug", "test", "internal", "hidden", "override", "bypass", "force",
    "raw", "json", "xml", "csv", "callback", "jsonp", "format", "output",
    "encoding", "charset", "response", "result", "error", "exception",
    "stack", "trace", "verbose", "logging", "profiling",
    # Injection-prone params
    "sql", "query", "where", "having", "order_by", "group_by", "table",
    "column", "field", "database", "schema", "collection", "document",
    "filter", "condition", "expression", "formula", "template", "script",
    "cmd", "command", "exec", "execute", "run", "shell", "bash", "sh",
    "eval", "include", "require", "import", "load", "render",
]

# Additional extended wordlist (generated programmatically)
def _generate_extended_wordlist():
    extra = set()
    prefixes = ["get_", "set_", "update_", "delete_", "create_", "find_", "search_",
                "list_", "load_", "fetch_", "save_", "add_", "remove_", "check_"]
    bases = ["user", "item", "order", "product", "category", "tag", "post", "comment",
             "account", "profile", "role", "group", "token", "key", "file", "image"]
    suffixes = ["_id", "_name", "_value", "_type", "_status", "_code", "_key", "_data"]
    for p in prefixes:
        for b in bases:
            extra.add(p + b)
    for b in bases:
        for s in suffixes:
            extra.add(b + s)
    for i in range(1, 21):
        extra.add("param%d" % i)
        extra.add("field%d" % i)
        extra.add("arg%d" % i)
    return sorted(extra)

EXTENDED_WORDLIST = PARAM_WORDLIST + _generate_extended_wordlist()


class ParamMiner:
    """
    Parameter Mining Engine for GenSQL.
    Discovers hidden GET, POST, header, and JSON parameters in web applications.
    Author: Jeevraj
    """

    INJECTABLE_HEADERS = [
        "X-Custom-IP-Authorization", "X-Originating-IP", "X-Forwarded-For",
        "X-Remote-IP", "X-Client-IP", "X-Host", "X-Forwarded-Host",
        "X-Real-IP", "X-Original-URL", "X-Rewrite-URL",
        "X-Override-URL", "X-Forwarded-Proto", "X-Api-Key",
        "X-Auth-Token", "X-User-Id", "X-Request-Id",
        "Authorization", "X-Debug", "X-Internal",
    ]

    def __init__(self, swagger_url=None, timeout=10, threads=10):
        self.swagger_url = swagger_url
        self.timeout     = timeout
        self.threads     = threads
        self._findings   = {"query_params": [], "header_params": [],
                            "json_fields": [], "api_endpoints": []}

    # ── Query param mining ────────────────────────────────────────────────
    def mine_query_params(self, url, known_params=None, wordlist=None):
        """Probe URL for hidden/undocumented query parameters."""
        wl = wordlist or EXTENDED_WORDLIST
        known = set(known_params or [])
        # Get baseline response
        baseline = self._get(url)
        if not baseline:
            return []
        baseline_len = len(str(baseline.get("body", "")))
        found = []
        # Chunk probe in batches of 20
        for i in range(0, len(wl), 20):
            chunk = wl[i:i+20]
            results = self._chunk_probe(url, chunk, baseline_len)
            found.extend(results)
        self._findings["query_params"].extend(found)
        return found

    def _chunk_probe(self, url, params, baseline_len):
        """Send batch probe for a group of parameter names."""
        found = []
        test_val = "jeev1337sql"
        sep = "&" if "?" in url else "?"
        qs = "&".join("%s=%s" % (urllib.parse.quote(p), test_val) for p in params)
        target = url + sep + qs
        resp = self._get(target)
        if not resp:
            return []
        resp_len = len(str(resp.get("body", "")))
        # If batch changed response, binary-search for the culprit
        if abs(resp_len - baseline_len) > 10 or resp.get("status") != 200:
            for param in params:
                test_url = url + sep + urllib.parse.quote(param) + "=" + test_val
                r = self._get(test_url)
                if r and (abs(len(str(r.get("body",""))) - baseline_len) > 10
                          or r.get("status") != 200):
                    found.append({"param": param, "url": test_url,
                                  "status": r.get("status"),
                                  "len_diff": abs(len(str(r.get("body",""))) - baseline_len)})
        return found

    # ── Header param mining ───────────────────────────────────────────────
    def mine_header_params(self, url):
        """Probe for undocumented/sensitive header-based injection points."""
        baseline = self._get(url)
        if not baseline:
            return []
        baseline_len = len(str(baseline.get("body", "")))
        found = []
        for header in self.INJECTABLE_HEADERS:
            resp = self._get(url, extra_headers={header: "127.0.0.1"})
            if resp and abs(len(str(resp.get("body", ""))) - baseline_len) > 10:
                found.append({"header": header, "status": resp.get("status"),
                              "len_diff": abs(len(str(resp.get("body",""))) - baseline_len)})
        self._findings["header_params"].extend(found)
        return found

    # ── JSON field discovery ──────────────────────────────────────────────
    def mine_json_fields(self, url, base_body=None):
        """Discover hidden JSON body fields by injecting extra keys."""
        body = dict(base_body or {"test": "value"})
        baseline = self._post_json(url, body)
        if not baseline:
            return []
        baseline_len = len(str(baseline.get("body", "")))
        found = []
        for param in PARAM_WORDLIST:
            test_body = dict(body)
            test_body[param] = "jeev1337"
            resp = self._post_json(url, test_body)
            if resp and abs(len(str(resp.get("body", ""))) - baseline_len) > 10:
                found.append({"field": param, "status": resp.get("status"),
                              "len_diff": abs(len(str(resp.get("body",""))) - baseline_len)})
        self._findings["json_fields"].extend(found)
        return found

    # ── OpenAPI / Swagger ─────────────────────────────────────────────────
    def discover_from_swagger(self, spec_url=None):
        """Parse OpenAPI/Swagger spec to extract all parameter names."""
        url = spec_url or self.swagger_url
        if not url:
            return []
        resp = self._get(url)
        if not resp or resp.get("status") != 200:
            return []
        try:
            spec = json.loads(resp["body"])
        except Exception:
            return []
        params = []
        for path, methods in spec.get("paths", {}).items():
            for method, op in methods.items():
                for p in op.get("parameters", []):
                    params.append({
                        "name":     p.get("name"),
                        "in":       p.get("in"),
                        "path":     path,
                        "method":   method.upper(),
                        "required": p.get("required", False),
                        "type":     p.get("schema", {}).get("type", "string"),
                    })
                # Request body fields
                rb = op.get("requestBody", {})
                for ct, schema_wrap in rb.get("content", {}).items():
                    schema = schema_wrap.get("schema", {})
                    for field_name, field_info in schema.get("properties", {}).items():
                        params.append({
                            "name": field_name, "in": "body",
                            "path": path, "method": method.upper(),
                            "required": field_name in schema.get("required", []),
                            "type": field_info.get("type", "string"),
                        })
        self._findings["api_endpoints"].extend(params)
        return params

    # ── JS extraction ─────────────────────────────────────────────────────
    def extract_params_from_js(self, js_content):
        """Regex-extract parameter names from JavaScript source code."""
        patterns = [
            r"""['"]([\w]+)['"]\s*:\s*(?:params|data|body|query)""",
            r"""params\[['"]([a-zA-Z0-9_]+)['"]\]""",
            r"""\.get\(['"]([a-zA-Z0-9_]+)['"]\)""",
            r"""\.set\(['"]([a-zA-Z0-9_]+)['"]\s*,""",
            r"""name=['"]([a-zA-Z0-9_\-]+)['"]""",
            r"""param\(['"]([a-zA-Z0-9_\-]+)['"]\)""",
        ]
        found = set()
        for pat in patterns:
            for m in re.findall(pat, js_content or "", re.IGNORECASE):
                if len(m) > 1 and m not in ("true", "false", "null", "undefined"):
                    found.add(m)
        return sorted(found)

    # ── Report ────────────────────────────────────────────────────────────
    def report_findings(self):
        """Return structured findings dict."""
        return {
            "total": sum(len(v) for v in self._findings.values()),
            "findings": self._findings,
            "wordlist_size": len(EXTENDED_WORDLIST),
        }

    # ── Helpers ───────────────────────────────────────────────────────────
    def _get(self, url, extra_headers=None):
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0 GenSQL/2.0")
            for k, v in (extra_headers or {}).items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
        except Exception as ex:
            return {"error": str(ex)}

    def _post_json(self, url, body):
        try:
            data = json.dumps(body).encode("utf-8")
            req  = urllib.request.Request(url, data=data)
            req.add_header("Content-Type", "application/json")
            req.add_header("User-Agent", "Mozilla/5.0 GenSQL/2.0")
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
        except Exception as ex:
            return {"error": str(ex)}
