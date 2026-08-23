#!/usr/bin/env python
# JeevSQL Tamper: svginjection - by Jeevraj
# Wraps SQL payload inside SVG/XML entities for SVG-processing endpoints.
from lib.core.enums import PRIORITY

__priority__ = PRIORITY.NORMAL

def dependencies(): pass

def tamper(payload, **kwargs):
    if not payload:
        return payload
    encoded = ''
    for ch in payload:
        if ch in '<>&"':
            encoded += '&#x%x;' % ord(ch)
        elif ord(ch) > 127:
            encoded += '&#x%x;' % ord(ch)
        else:
            encoded += ch
    return '<svg xmlns="http://www.w3.org/2000/svg"><script>%s</script></svg>' % encoded
