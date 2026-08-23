#!/usr/bin/env python
# JeevSQL Tamper: casefuzz - by Jeevraj
# Advanced case fuzzing with Unicode look-alike characters.
from lib.core.enums import PRIORITY
import random, re

__priority__ = PRIORITY.NORMAL

LOOKALIKES = {
    'a': [u'\u0430', u'\u0251', 'a', 'A'],
    'e': [u'\u0435', u'\u03b5', 'e', 'E'],
    'o': [u'\u043e', u'\u03bf', 'o', 'O'],
    'c': [u'\u0441', u'\u03c2', 'c', 'C'],
    'p': [u'\u0440', 'p', 'P'],
    'x': [u'\u0445', 'x', 'X'],
}

def dependencies(): pass

def tamper(payload, **kwargs):
    if not payload:
        return payload
    result = []
    for ch in payload:
        low = ch.lower()
        if low in LOOKALIKES and random.random() < 0.25:
            result.append(random.choice(LOOKALIKES[low]))
        elif ch.isalpha() and random.random() < 0.4:
            result.append(ch.upper() if ch.islower() else ch.lower())
        else:
            result.append(ch)
    return ''.join(result)
