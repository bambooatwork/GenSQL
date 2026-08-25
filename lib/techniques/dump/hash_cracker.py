#!/usr/bin/env python
"""
GenSQL - Hash Identification Module
Author  : Jeevraj
Version : 2.0.0

Identifies the hash algorithm used for database password fields.
Supports: MD5, SHA1, SHA256, SHA512, bcrypt, NTLM, MySQL323, MySQL4.1+,
          MSSQL, Oracle, PostgreSQL password hashes.
Pure Python stdlib only.
"""

import re
import hashlib
import binascii
import struct
import threading
from queue import Queue


# ── Hash computation helpers ──────────────────────────────────────────────────

def _md5(s):
    if isinstance(s, str): s = s.encode('utf-8')
    return hashlib.md5(s).hexdigest()

def _sha1(s):
    if isinstance(s, str): s = s.encode('utf-8')
    return hashlib.sha1(s).hexdigest()

def _sha256(s):
    if isinstance(s, str): s = s.encode('utf-8')
    return hashlib.sha256(s).hexdigest()

def _sha512(s):
    if isinstance(s, str): s = s.encode('utf-8')
    return hashlib.sha512(s).hexdigest()

def _mysql323(s):
    """MySQL OLD_PASSWORD() algorithm (pre-4.1) — pure Python."""
    if isinstance(s, str): s = s.encode('latin-1', errors='replace')
    nr = 1345345333
    add = 7
    nr2 = 0x12345671
    for byte in s:
        if byte in (32, 9):  # skip spaces and tabs
            continue
        tmp = (nr & 0x3F) + add
        nr = nr ^ ((((tmp) & 0xFFFFFFFF) * byte + nr) & 0xFFFFFFFF)
        nr2 = (nr2 + ((nr2 << 8) ^ nr)) & 0xFFFFFFFF
        add = (add + byte) & 0xFFFFFFFF
    r1 = nr & ((1 << 31) - 1)
    r2 = nr2 & ((1 << 31) - 1)
    return '%08lx%08lx' % (r1, r2)

def _mysql41(s):
    """MySQL 4.1+ PASSWORD() = *SHA1(SHA1(password)) uppercase."""
    if isinstance(s, str): s = s.encode('utf-8')
    h1 = hashlib.sha1(s).digest()
    h2 = hashlib.sha1(h1).hexdigest().upper()
    return '*' + h2

def _ntlm(s):
    """NTLM hash = MD4(UTF-16-LE password) — MD4 implemented in pure Python."""
    if isinstance(s, str):
        s = s.encode('utf-16-le')
    return _md4(s)

def _md4(data):
    """Pure Python MD4 implementation (for NTLM)."""
    def _f(x, y, z): return (x & y) | (~x & z)
    def _g(x, y, z): return (x & y) | (x & z) | (y & z)
    def _h(x, y, z): return x ^ y ^ z
    def _rotl(x, n): return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    def _add(*args): return sum(args) & 0xFFFFFFFF

    msg = bytearray(data)
    orig_len = len(data) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack('<Q', orig_len)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for i in range(0, len(msg), 64):
        chunk = msg[i:i+64]
        X = list(struct.unpack('<16I', chunk))
        aa, bb, cc, dd = a, b, c, d

        # Round 1
        s1 = [3, 7, 11, 19]
        for j in range(16):
            k = j
            i_s = s1[j % 4]
            a = _rotl(_add(a, _f(b, c, d), X[k]), i_s)
            a, b, c, d = d, a, b, c

        # Round 2
        s2 = [3, 5, 9, 13]
        for j in range(16):
            k = (j % 4) * 4 + j // 4
            i_s = s2[j % 4]
            a = _rotl(_add(a, _g(b, c, d), X[k], 0x5A827999), i_s)
            a, b, c, d = d, a, b, c

        # Round 3
        s3 = [3, 9, 11, 15]
        r3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for j in range(16):
            k = r3[j]
            i_s = s3[j % 4]
            a = _rotl(_add(a, _h(b, c, d), X[k], 0x6ED9EBA1), i_s)
            a, b, c, d = d, a, b, c

        a = _add(a, aa); b = _add(b, bb)
        c = _add(c, cc); d = _add(d, dd)

    return struct.pack('<4I', a, b, c, d).hex()


# ── Hash identification ───────────────────────────────────────────────────────

HASH_PATTERNS = [
    # (name, confidence, regex_or_condition)
    ('bcrypt',      95,  re.compile(r'^\$2[aby]?\$\d{2}\$.{53}$')),
    ('sha512_crypt',90,  re.compile(r'^\$6\$.{8,16}\$.{86}$')),
    ('sha256_crypt',90,  re.compile(r'^\$5\$.{8,16}\$.{43}$')),
    ('mysql41',     95,  re.compile(r'^\*[0-9A-F]{40}$')),
    ('mssql2012',   90,  re.compile(r'^0x0200[0-9A-F]{136}$', re.I)),
    ('mssql2000',   90,  re.compile(r'^0x0100[0-9A-F]{88}$', re.I)),
    ('oracle11g',   90,  re.compile(r'^S:[0-9A-F]{60}$', re.I)),
    ('sha512',      85,  re.compile(r'^[0-9a-f]{128}$', re.I)),
    ('sha256',      85,  re.compile(r'^[0-9a-f]{64}$', re.I)),
    ('sha1',        80,  re.compile(r'^[0-9a-f]{40}$', re.I)),
    ('mysql323',    75,  re.compile(r'^[0-9a-f]{16}$', re.I)),
    ('ntlm',        75,  re.compile(r'^[0-9A-F]{32}$')),   # uppercase
    ('md5',         75,  re.compile(r'^[0-9a-f]{32}$')),   # lowercase
    ('md5_upper',   70,  re.compile(r'^[0-9A-F]{32}$')),
]

# Regex patterns for scanning text blocks
TEXT_HASH_PATTERNS = {
    'md5':        re.compile(r'\b[0-9a-f]{32}\b', re.I),
    'sha1':       re.compile(r'\b[0-9a-f]{40}\b', re.I),
    'sha256':     re.compile(r'\b[0-9a-f]{64}\b', re.I),
    'sha512':     re.compile(r'\b[0-9a-f]{128}\b', re.I),
    'bcrypt':     re.compile(r'\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}'),
    'mysql41':    re.compile(r'\*[0-9A-F]{40}'),
    'ntlm':       re.compile(r'\b[0-9A-F]{32}\b'),
    'mssql':      re.compile(r'0x0[12]00[0-9A-Fa-f]{88,136}'),
}


class HashCracker:
    """
    Offline hash identification engine for GenSQL.
    Identifies hash algorithms found in database dumps.
    """

    def identify(self, hash_str):
        """
        Identify the hash algorithm from the hash string.

        Returns:
            dict: {'type': str, 'confidence': int, 'possible': [str]}
        """
        if not hash_str or not isinstance(hash_str, str):
            return {'type': 'unknown', 'confidence': 0, 'possible': []}

        h = hash_str.strip()
        matches = []

        for name, conf, pat in HASH_PATTERNS:
            if isinstance(pat, re.Pattern):
                if pat.match(h):
                    matches.append((name, conf))
            elif callable(pat):
                if pat(h):
                    matches.append((name, conf))

        if not matches:
            return {'type': 'unknown', 'confidence': 0, 'possible': []}

        matches.sort(key=lambda x: -x[1])
        return {
            'type': matches[0][0],
            'confidence': matches[0][1],
            'possible': [m[0] for m in matches],
        }

    def verify(self, password, hash_str, hash_type):
        """
        Verify if a password matches a given hash.

        Returns:
            bool
        """
        h = hash_str.strip()
        try:
            ht = hash_type.lower()
            if ht == 'md5':
                return _md5(password) == h.lower()
            elif ht == 'sha1':
                return _sha1(password) == h.lower()
            elif ht == 'sha256':
                return _sha256(password) == h.lower()
            elif ht == 'sha512':
                return _sha512(password) == h.lower()
            elif ht == 'ntlm':
                return _ntlm(password).upper() == h.upper()
            elif ht == 'mysql323':
                return _mysql323(password) == h.lower()
            elif ht == 'mysql41':
                return _mysql41(password) == h.upper()
            elif ht == 'bcrypt':
                try:
                    import bcrypt
                    return bcrypt.checkpw(password.encode(), h.encode())
                except ImportError:
                    return False
        except Exception:
            pass
        return False

    def get_all_hash_types(self):
        """Return list of all supported hash type names."""
        return [name for name, _, _ in HASH_PATTERNS]


class HashIdentifier:
    """
    Scan text blocks (DB dumps, responses) and identify all hashes found.
    """

    def __init__(self):
        self._cracker = HashCracker()

    def identify_all(self, text):
        """
        Scan text and return all identified hashes.

        Args:
            text : String to scan (e.g. database dump output)

        Returns:
            List of dicts: [{'hash': str, 'type': str, 'confidence': int, 'position': int}]
        """
        if not text:
            return []

        results = []
        seen = set()

        for hash_type, pattern in TEXT_HASH_PATTERNS.items():
            for m in pattern.finditer(text):
                h = m.group(0)
                if h in seen:
                    continue
                seen.add(h)
                id_result = self._cracker.identify(h)
                results.append({
                    'hash': h,
                    'type': id_result['type'],
                    'confidence': id_result['confidence'],
                    'possible': id_result['possible'],
                    'position': m.start(),
                })

        # Sort by position in text
        results.sort(key=lambda x: x['position'])
        return results

    def summary(self, text):
        """Return a grouped summary of hash types found in text."""
        found = self.identify_all(text)
        groups = {}
        for item in found:
            t = item['type']
            if t not in groups:
                groups[t] = []
            groups[t].append(item['hash'])
        return groups


# ── Convenience functions ─────────────────────────────────────────────────────

def identify_hash(hash_str):
    """Quick-identify a single hash string. Returns type string."""
    return HashCracker().identify(hash_str)['type']

def scan_for_hashes(text):
    """Scan a text block and return all hashes found with their types."""
    return HashIdentifier().identify_all(text)
