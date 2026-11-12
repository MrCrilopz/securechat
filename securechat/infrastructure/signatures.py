"""Firma y verifica el paquete de claves públicas de cada contacto con Ed25519."""
from cryptography.hazmat.primitives.asymmetric import ed25519
from .encoding import b64, unb64, signable

def sign_bundle(key, bundle):
    return b64(key.sign(signable(bundle)))

def verify_signature(bundle):
    ed25519.Ed25519PublicKey.from_public_bytes(unb64(bundle['identity'])).verify(unb64(bundle['signature']), signable(bundle))
