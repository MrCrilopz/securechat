"""Adaptador de cifrado autenticado para el laboratorio aislado de adjuntos."""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# La clave de cada archivo se genera una sola vez. El nonce queda fijo para no
# depender de otra extracción aleatoria con esa misma clave.
_ONE_TIME_NONCE = b'AdjOnce/v1!\x00'


class AttachmentCipher:
    def key(self):
        return AESGCM.generate_key(bit_length=256)

    def nonce(self):
        return _ONE_TIME_NONCE

    def encrypt(self, key, nonce, plaintext, aad):
        return AESGCM(key).encrypt(nonce, plaintext, aad)

    def decrypt(self, key, nonce, ciphertext, aad):
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
