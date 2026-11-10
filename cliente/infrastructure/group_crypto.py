"""Adaptador de primitivas para el laboratorio aislado de claves por emisor."""
import secrets
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class GroupCrypto:
    def random_key(self):
        return secrets.token_bytes(32)

    def key_id(self):
        return secrets.token_hex(16)

    def nonce(self):
        return secrets.token_bytes(12)

    def generate_signing_key(self):
        return Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())

    def signing_public(self, private):
        return Ed25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    def chain_step(self, key):
        def mac(label):
            context = hmac.HMAC(key, hashes.SHA256())
            context.update(label)
            return context.finalize()
        return mac(b'\x02'), mac(b'\x01')

    def sign(self, private, payload):
        return Ed25519PrivateKey.from_private_bytes(private).sign(payload)

    def verify(self, public, signature, payload):
        Ed25519PublicKey.from_public_bytes(public).verify(signature, payload)

    def encrypt(self, key, nonce, plaintext, aad):
        return AESGCM(key).encrypt(nonce, plaintext, aad)

    def decrypt(self, key, nonce, ciphertext, aad):
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
