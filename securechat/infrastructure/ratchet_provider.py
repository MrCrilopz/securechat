"""Primitivas del prototipo aislado; no conectadas al cliente de mensajería."""
import os

from securechat.application.double_ratchet import InvalidRatchetPublicKey

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


class CryptographyRatchet:
    def generate_dh(self):
        return X25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
            serialization.NoEncryption())

    def dh_public(self, private):
        return X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def dh(self, private, public):
        private_key = X25519PrivateKey.from_private_bytes(private)
        public_key = X25519PublicKey.from_public_bytes(public)
        try:
            return private_key.exchange(public_key)
        except ValueError as exc:
            raise InvalidRatchetPublicKey('Invalid X25519 ratchet public key') from exc

    def root_step(self, root, secret):
        material = HKDF(algorithm=hashes.SHA256(), length=64, salt=root,
                        info=b'ProyectoCriptologia/experimental/DR/root/v1').derive(secret)
        return material[:32], material[32:]

    def chain_step(self, chain):
        def mac(value):
            ctx = hmac.HMAC(chain, hashes.SHA256())
            ctx.update(value)
            return ctx.finalize()
        return mac(b'\x02'), mac(b'\x01')

    def nonce(self):
        return os.urandom(12)

    def seal(self, key, nonce, plaintext, aad):
        return AESGCM(key).encrypt(nonce, plaintext, aad)

    def open(self, key, nonce, ciphertext, aad):
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
