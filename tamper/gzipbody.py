#!/usr/bin/env python
# JeevSQL Tamper: gzipbody - by Jeevraj
# Gzip-encodes the payload. Caller must set Content-Encoding: gzip header.
from lib.core.enums import PRIORITY
import gzip, base64

__priority__ = PRIORITY.NORMAL

def dependencies(): pass

def tamper(payload, **kwargs):
    if not payload:
        return payload
    data = payload.encode('utf-8') if isinstance(payload, str) else payload
    compressed = gzip.compress(data)
    return base64.b64encode(compressed).decode('ascii')
