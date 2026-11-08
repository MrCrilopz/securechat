"""Valida usuario y contraseña con reglas propias, aparte de la red y el disco."""
import re

def username(value):
    if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9_]{3,32}', value):
        raise ValueError('Username must contain 3–32 ASCII letters, numbers or underscores')
    return value

def password(value):
    if not isinstance(value, str) or len(value) < 12 or len(value) > 256:
        raise ValueError('Password must contain 12–256 characters')
    return value
