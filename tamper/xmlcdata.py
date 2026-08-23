#!/usr/bin/env python
# JeevSQL Tamper: xmlcdata - by Jeevraj
# Wraps SQL payload in XML CDATA sections for XML-processing endpoints.
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies(): pass

def tamper(payload, **kwargs):
    if not payload:
        return payload
    # XML CDATA escape
    safe = payload.replace(']]>', ']]]]><![CDATA[>')
    return '<![CDATA[%s]]>' % safe
