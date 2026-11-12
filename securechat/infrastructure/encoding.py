"""Codifica claves y sobres en Base64 y JSON canónico para firmar y cifrar."""
import base64, json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519

def b64(data): return base64.urlsafe_b64encode(data).decode('ascii')
def unb64(data): return base64.b64decode(data.encode('ascii'), altchars=b'-_', validate=True)
def public(key): return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
def private(key): return key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
def xpub(data): return x25519.X25519PublicKey.from_public_bytes(unb64(data))
def canonical(value): return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()
def signable(bundle): return canonical({k: bundle[k] for k in ('username', 'identity', 'agreement', 'prekey')})

