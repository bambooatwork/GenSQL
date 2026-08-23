#!/usr/bin/env python
# JeevSQL Tamper: multipartmix - by Jeevraj
# Converts payload to multipart/form-data with boundary pollution.
from lib.core.enums import PRIORITY
import random, string

__priority__ = PRIORITY.NORMAL

def dependencies(): pass

def tamper(payload, **kwargs):
    if not payload:
        return payload
    boundary = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    return ('--%(b)s\r\nContent-Disposition: form-data; name="data"\r\n\r\n%(p)s\r\n--%(b)s--' 
            % {'b': boundary, 'p': payload})
