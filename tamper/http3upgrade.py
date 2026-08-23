#!/usr/bin/env python
# JeevSQL Tamper: http3upgrade - by Jeevraj
# Adds HTTP/3 upgrade headers alongside payload to trigger protocol confusion in proxies.
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies(): pass

def tamper(payload, **kwargs):
    headers = kwargs.get('headers', {})
    if isinstance(headers, dict):
        headers['Alt-Svc'] = 'h3=":443"; ma=86400'
        headers['Upgrade-Insecure-Requests'] = '1'
        headers['Connection'] = 'Upgrade, HTTP2-Settings'
    return payload
