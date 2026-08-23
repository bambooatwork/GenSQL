#!/usr/bin/env python
"""GenSQL Evasion: EncoderChain - multi-layer payload encoding. Author: Jeevraj"""
import base64, binascii, re, html, urllib.parse, codecs, random

class EncoderChain:
    """Apply a chain of encoding transformations to bypass WAF body/param inspection."""
    ENCODERS = {
        "base64":     ("_enc_b64",   "_dec_b64"),
        "url":        ("_enc_url",   "_dec_url"),
        "double_url": ("_enc_durl",  "_dec_durl"),
        "hex":        ("_enc_hex",   "_dec_hex"),
        "html":       ("_enc_html",  "_dec_html"),
        "unicode":    ("_enc_uni",   "_dec_uni"),
        "rot13":      ("_enc_rot13", "_enc_rot13"),
        "binary":     ("_enc_bin",   "_dec_bin"),
        "octal":      ("_enc_oct",   "_dec_oct"),
    }
    WAF_CHAINS = {
        "cloudflare": ["url","base64"],
        "akamai":     ["double_url","html"],
        "imperva":    ["unicode","url"],
        "modsecurity":["hex","url"],
        "aws_waf":    ["base64","url"],
        "default":    ["url"],
    }
    def __init__(self, chain=None):
        self.chain = chain or ["url"]
        for enc in self.chain:
            if enc not in self.ENCODERS:
                raise ValueError("Unknown encoder: %s. Valid: %s" % (enc, list(self.ENCODERS)))

    # ── encode/decode dispatch ──────────────────────────────────────────
    def encode(self, payload):
        result = payload
        for enc in self.chain:
            fn = getattr(self, self.ENCODERS[enc][0])
            result = fn(result)
        return result

    def decode(self, text):
        result = text
        for enc in reversed(self.chain):
            fn = getattr(self, self.ENCODERS[enc][1])
            result = fn(result)
        return result

    # ── individual encoders ─────────────────────────────────────────────
    def _enc_b64(self, s):
        b = s.encode("utf-8") if isinstance(s,str) else s
        return base64.b64encode(b).decode("ascii")
    def _dec_b64(self, s):
        return base64.b64decode(s).decode("utf-8","replace")

    def _enc_url(self, s):
        return urllib.parse.quote(str(s), safe="")
    def _dec_url(self, s):
        return urllib.parse.unquote(str(s))

    def _enc_durl(self, s):
        return urllib.parse.quote(urllib.parse.quote(str(s), safe=""), safe="")
    def _dec_durl(self, s):
        return urllib.parse.unquote(urllib.parse.unquote(str(s)))

    def _enc_hex(self, s):
        return "".join("%%%.2X" % ord(c) for c in str(s))
    def _dec_hex(self, s):
        return urllib.parse.unquote(s)

    def _enc_html(self, s):
        return html.escape(str(s))
    def _dec_html(self, s):
        return html.unescape(str(s))

    def _enc_uni(self, s):
        return "".join(("\\u%04x" % ord(c)) if ord(c) > 127 else c for c in str(s))
    def _dec_uni(self, s):
        return s.encode("utf-8").decode("unicode_escape")

    def _enc_rot13(self, s):
        return codecs.encode(str(s),"rot_13")

    def _enc_bin(self, s):
        return " ".join(format(ord(c),"08b") for c in str(s))
    def _dec_bin(self, s):
        return "".join(chr(int(b,2)) for b in s.split())

    def _enc_oct(self, s):
        return "".join(("\\%03o" % ord(c)) for c in str(s))

    def _dec_oct(self, s):
        return re.sub(r"\\([0-7]{3})", lambda m: chr(int(m.group(1), 8)), s)

    # ── utilities ───────────────────────────────────────────────────────
    def get_all_chains(self, payload, max_depth=2):
        """Return all encoding chain results up to max_depth layers."""
        results = []
        enc_names = list(self.ENCODERS.keys())
        for d in range(1, max_depth+1):
            from itertools import combinations
            for combo in combinations(enc_names, d):
                try:
                    chain = EncoderChain(list(combo))
                    results.append((list(combo), chain.encode(payload)))
                except Exception:
                    pass
        return results

    @classmethod
    def suggest_chain_for_waf(cls, waf_type):
        """Return recommended encoding chain for a known WAF type."""
        return cls.WAF_CHAINS.get((waf_type or "").lower(), cls.WAF_CHAINS["default"])

    def __repr__(self):
        return "EncoderChain(%r)" % self.chain
