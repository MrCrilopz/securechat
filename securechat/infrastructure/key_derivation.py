"""Deriva las claves de envío y de recepción de la sesión con HKDF-SHA256."""
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .encoding import canonical

def derive(dhs, header, sender, recipient):
    info = b'securechat exchange v1\0' + canonical({'header': header, 'sender': sender, 'recipient': recipient})
    output = HKDF(algorithm=hashes.SHA256(), length=64, salt=None, info=info).derive(b''.join(dhs))
    return output[:32], output[32:]

