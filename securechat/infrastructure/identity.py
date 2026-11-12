"""Genera identidades, verifica el paquete de claves y calcula la huella compartida."""
from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from .encoding import b64, unb64, public, private, xpub, canonical, signable
from .signatures import verify_signature, sign_bundle
from .hashing import sha256

def verify_bundle(bundle):
    verify_signature(bundle)
    xpub(bundle['agreement']); xpub(bundle['prekey'])

def fingerprint(first, second):
    keys = sorted([canonical({k: first[k] for k in ('username', 'identity', 'agreement')}), canonical({k: second[k] for k in ('username', 'identity', 'agreement')})])
    return sha256(b'securechat safety v1\0' + keys[0] + b'\0' + keys[1]).hex()

@dataclass
class Identity:
    username: str
    signing: object
    agreement: object
    prekey: object
    @classmethod
    def generate(cls, username): return cls(username, ed25519.Ed25519PrivateKey.generate(), x25519.X25519PrivateKey.generate(), x25519.X25519PrivateKey.generate())
    def bundle(self):
        bundle = {'username': self.username, 'identity': b64(public(self.signing)), 'agreement': b64(public(self.agreement)), 'prekey': b64(public(self.prekey))}
        bundle['signature'] = sign_bundle(self.signing, bundle); return bundle
    def serialize(self): return {'username': self.username, 'signing': b64(private(self.signing)), 'agreement': b64(private(self.agreement)), 'prekey': b64(private(self.prekey))}
    @classmethod
    def restore(cls, obj): return cls(obj['username'], ed25519.Ed25519PrivateKey.from_private_bytes(unb64(obj['signing'])), x25519.X25519PrivateKey.from_private_bytes(unb64(obj['agreement'])), x25519.X25519PrivateKey.from_private_bytes(unb64(obj['prekey'])))

