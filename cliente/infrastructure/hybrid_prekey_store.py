"""Almacén aislado e inmutable de preclaves híbridas, aún no integrado al chat."""
import json
import secrets
import sqlite3
from contextlib import closing

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from securechat.infrastructure.encoding import canonical
from securechat.infrastructure.hashing import sha256

_AAD = b'ProyectoCriptologia/experimental/hybrid-prekey/v1\x00'


class HybridPrekeyStorageError(RuntimeError):
    """No fue posible confirmar el estado durable de la preclave."""


class HybridPrekeyStore:
    def __init__(self, path, key, codec):
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError('La clave del almacén debe contener 32 bytes')
        self.path, self.key, self.codec = path, key, codec
        try:
            with closing(self._connect()) as db:
                db.execute('CREATE TABLE IF NOT EXISTS prekeys (identity BLOB PRIMARY KEY, nonce BLOB NOT NULL, ciphertext BLOB NOT NULL)')
                db.commit()
        except (sqlite3.Error, OSError) as exc:
            raise HybridPrekeyStorageError('No fue posible preparar el almacén de preclaves') from exc

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            db.execute('PRAGMA synchronous=FULL')
            return db
        except Exception:
            db.close()
            raise

    @staticmethod
    def _identity(identity):
        return sha256(canonical(identity.bundle()))

    def _open(self, identity, digest, row):
        plaintext = AESGCM(self.key).decrypt(row[0], row[1], _AAD + digest)
        try:
            stored = json.loads(plaintext)
        except (ValueError, UnicodeError) as exc:
            raise HybridPrekeyStorageError('Registro de preclave inválido') from exc
        private = self.codec.restore(identity, stored)
        public = self.codec.public(identity, stored)
        return private, public

    def ensure(self, identity):
        """Retorna la misma preclave pública mientras el registro exista intacto."""
        digest = self._identity(identity)
        try:
            with closing(self._connect()) as db:
                db.execute('BEGIN IMMEDIATE')
                row = db.execute('SELECT nonce, ciphertext FROM prekeys WHERE identity=?', (digest,)).fetchone()
                if row is None:
                    stored = self.codec.create(identity)
                    public = self.codec.public(identity, stored)
                    plaintext = json.dumps(stored, sort_keys=True, separators=(',', ':')).encode('utf-8')
                    nonce = secrets.token_bytes(12)
                    ciphertext = AESGCM(self.key).encrypt(nonce, plaintext, _AAD + digest)
                    db.execute('INSERT INTO prekeys (identity, nonce, ciphertext) VALUES (?, ?, ?)',
                               (digest, nonce, ciphertext))
                else:
                    _, public = self._open(identity, digest, row)
                db.commit()
                return public
        except (sqlite3.Error, OSError) as exc:
            raise HybridPrekeyStorageError('Resultado de guardado incierto; vuelva a consultar el almacén') from exc

    def restore(self, identity):
        """Recupera la clave privada validada o None si no existe registro."""
        digest = self._identity(identity)
        try:
            with closing(self._connect()) as db:
                row = db.execute('SELECT nonce, ciphertext FROM prekeys WHERE identity=?', (digest,)).fetchone()
            if row is None:
                return None
            private, _ = self._open(identity, digest, row)
            return private
        except (sqlite3.Error, OSError) as exc:
            raise HybridPrekeyStorageError('No fue posible recuperar la preclave') from exc
