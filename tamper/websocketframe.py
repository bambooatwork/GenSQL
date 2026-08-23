#!/usr/bin/env python
# JeevSQL Tamper: websocketframe - by Jeevraj
# Encodes payload as WebSocket frame format for WS-based injection points.
from lib.core.enums import PRIORITY
import struct, os

__priority__ = PRIORITY.NORMAL

def dependencies(): pass

def tamper(payload, **kwargs):
    if not payload:
        return payload
    data = payload.encode('utf-8') if isinstance(payload, str) else payload
    length = len(data)
    mask = os.urandom(4)
    masked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    if length < 126:
        header = struct.pack('!BB', 0x81, 0x80 | length)
    elif length < 65536:
        header = struct.pack('!BBH', 0x81, 0xFE, length)
    else:
        header = struct.pack('!BBQ', 0x81, 0xFF, length)
    frame = header + mask + masked
    return frame.hex()
