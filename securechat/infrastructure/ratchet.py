"""Avanza la clave simétrica de cada mensaje con HMAC-SHA256 para no reutilizarla."""
from .hashing import hmac_sha256

def advance(key):
    return hmac_sha256(key, b'message'), hmac_sha256(key, b'next')
