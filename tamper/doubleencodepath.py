#!/usr/bin/env python
# JeevSQL Tamper: doubleencodepath - by Jeevraj
# Double URL-encodes payload for path-based injection points.
from lib.core.enums import PRIORITY
import urllib.parse

__priority__ = PRIORITY.NORMAL

def dependencies(): pass

def tamper(payload, **kwargs):
    if not payload:
        return payload
    # First encode
    encoded = urllib.parse.quote(payload, safe='')
    # Double encode the percent signs
    double = encoded.replace('%', '%25')
    return double
