#!/usr/bin/env python
# JeevSQL Tamper: ai_mutate - by Jeevraj
# Meta-tamper that chains multiple random tampers and applies grammar-based mutation.
# Fully offline - no external AI API calls.
from lib.core.enums import PRIORITY
import random, re, importlib, os, sys

__priority__ = PRIORITY.NORMAL

CHAIN_TAMPERS = [
    'charencode', 'randomcase', 'space2comment', 'between', 'greatest',
    'equaltolike', 'casefuzz', 'nullbytemid', 'doubleencodepath',
]

COMMENT_VARIANTS = ['/**/', '/*!*/', '/*--*/', '/*+*/', '/*!50000*/', '%0a', '%09']
NUMBER_FUNCS = {
    '0': 'ABS(0)', '1': 'ABS(1)', '2': 'ABS(2)',
}

def dependencies(): pass

def _try_tamper(name, payload):
    try:
        tamper_path = os.path.join(os.path.dirname(__file__))
        if tamper_path not in sys.path:
            sys.path.insert(0, tamper_path)
        mod = importlib.import_module(name)
        return mod.tamper(payload)
    except Exception:
        return payload

def tamper(payload, **kwargs):
    if not payload:
        return payload
    result = payload
    # Chain 2-3 random tampers
    chosen = random.sample([t for t in CHAIN_TAMPERS if t != 'ai_mutate'], min(3, len(CHAIN_TAMPERS)))
    for t in chosen:
        try:
            result = _try_tamper(t, result)
        except Exception:
            pass
    # Random comment insertion between keywords
    result = re.sub(r' +', lambda m: random.choice(COMMENT_VARIANTS), result, count=2)
    # Random number substitution
    for digit, func in NUMBER_FUNCS.items():
        if random.random() < 0.3:
            result = result.replace(digit, func, 1)
    return result
