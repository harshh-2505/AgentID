"""Encoding helpers that produce byte-for-byte the same output as core/encoding.js."""

import base64
import hashlib
import math
import os
import time
from decimal import Decimal

_SAFE_INT = 2 ** 53
_ESCAPES = {'"': '\\"', '\\': '\\\\', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t'}


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))


def random_id(prefix: str) -> str:
    return prefix + '_' + b64u(os.urandom(9))


def now_sec() -> int:
    return int(time.time())


def sha256(data) -> str:
    return hashlib.sha256(data.encode('utf-8') if isinstance(data, str) else data).hexdigest()


def hash_object(obj) -> str:
    return sha256(canonical(obj))


def _number(x) -> str:
    # JSON.stringify(Number): ints beyond 2^53 become doubles in JS, so format them as doubles too.
    if isinstance(x, int):
        if -_SAFE_INT < x < _SAFE_INT:
            return str(x)
        try:
            x = float(x)
        except OverflowError:
            return 'null'
    if math.isnan(x) or math.isinf(x):
        return 'null'
    if x == 0:
        return '0'
    sign = '-' if x < 0 else ''
    # repr() gives the shortest round-tripping digits, as ECMAScript Number::toString does;
    # only the layout rules differ.
    t = Decimal(repr(abs(x))).normalize().as_tuple()
    s = ''.join(map(str, t.digits))
    k = len(s)
    n = t.exponent + k
    if k <= n <= 21:
        out = s + '0' * (n - k)
    elif 0 < n <= 21:
        out = s[:n] + '.' + s[n:]
    elif -6 < n <= 0:
        out = '0.' + '0' * -n + s
    else:
        e = n - 1
        out = (s if k == 1 else s[0] + '.' + s[1:]) + 'e' + ('+' if e >= 0 else '-') + str(abs(e))
    return sign + out


def _string(s: str) -> str:
    out = ['"']
    i, n = 0, len(s)
    while i < n:
        c = s[i]
        o = ord(c)
        if c in _ESCAPES:
            out.append(_ESCAPES[c])
        elif o < 0x20:
            out.append('\\u%04x' % o)
        elif 0xD800 <= o <= 0xDFFF:
            # A surrogate pair is one character to JS; a lone surrogate is escaped (well-formed JSON.stringify).
            if o <= 0xDBFF and i + 1 < n and 0xDC00 <= ord(s[i + 1]) <= 0xDFFF:
                out.append(chr(0x10000 + ((o - 0xD800) << 10) + (ord(s[i + 1]) - 0xDC00)))
                i += 1
            else:
                out.append('\\u%04x' % o)
        else:
            out.append(c)
        i += 1
    out.append('"')
    return ''.join(out)


def _utf16_key(k: str) -> bytes:
    # JS sorts strings by UTF-16 code unit, Python by code point; they differ above U+FFFF.
    return k.encode('utf-16-be', 'surrogatepass')


def canonical(value) -> str:
    """Deterministic JSON: sorted keys, no whitespace, JSON.stringify number and string rules.

    None is JSON null (JS keeps null and drops only undefined, which Python has no equivalent of).
    """
    if value is None:
        return 'null'
    if value is True:
        return 'true'
    if value is False:
        return 'false'
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (list, tuple)):
        return '[' + ','.join(canonical(v) for v in value) + ']'
    if isinstance(value, dict):
        keys = sorted((str(k) for k in value), key=_utf16_key)
        lookup = {str(k): v for k, v in value.items()}
        return '{' + ','.join(_string(k) + ':' + canonical(lookup[k]) for k in keys) + '}'
    raise TypeError(f'cannot canonicalize {type(value).__name__}')
