"""Almacén local aislado: transcripción y estado cifrado en una transacción."""
import base64
import json
import secrets
import sqlite3
from contextlib import closing

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from cliente.application.hybrid_acceptance import HybridPersistenceError, HybridReplayError

_AAD = b'ProyectoCriptologia/experimental/hybrid-store/v1\x00'


class HybridStateStore:
    def __init__(self, path, key):
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError('La clave del almacén debe contener 32 bytes')
        self.path, self.key = path, key
        try:
            with closing(self._connect()) as db:
                db.execute('CREATE TABLE IF NOT EXISTS accepted (digest BLOB PRIMARY KEY, nonce BLOB NOT NULL, payload BLOB NOT NULL)')
                db.commit()
        except sqlite3.Error as exc:
            raise HybridPersistenceError('No se pudo preparar el almacén local') from exc

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            db.execute('PRAGMA synchronous=FULL')
            return db
        except Exception:
            db.close()
            raise

    @staticmethod
    def _digest(digest):
        if not isinstance(digest, bytes) or len(digest) != 32:
            raise ValueError('Identificador de transcripción inválido')
        return digest

    def save_once(self, digest, state, plaintext):
        self._digest(digest)
        if not isinstance(state, dict) or not isinstance(plaintext, bytes):
            raise ValueError('Estado de aceptación inválido')
        try:
            payload = json.dumps({'state': state, 'plaintext': base64.b64encode(plaintext).decode('ascii')},
                                 sort_keys=True, separators=(',', ':')).encode('utf-8')
            nonce = secrets.token_bytes(12)
            sealed = AESGCM(self.key).encrypt(nonce, payload, _AAD + digest)
            with closing(self._connect()) as db:
                db.execute('BEGIN IMMEDIATE')
                try:
                    db.execute('INSERT INTO accepted (digest, nonce, payload) VALUES (?, ?, ?)',
                               (digest, nonce, sealed))
                except sqlite3.IntegrityError as exc:
                    db.rollback()
                    raise HybridReplayError('La transcripción ya fue aceptada') from exc
                db.commit()
        except HybridReplayError:
            raise
        except (sqlite3.Error, OSError, TypeError, ValueError) as exc:
            raise HybridPersistenceError('Resultado de guardado incierto; consultar el almacén antes de reintentar') from exc

    def load(self, digest):
        self._digest(digest)
        try:
            with closing(self._connect()) as db:
                row = db.execute('SELECT nonce, payload FROM accepted WHERE digest=?', (digest,)).fetchone()
            if row is None:
                return None
            data = AESGCM(self.key).decrypt(row[0], row[1], _AAD + digest)
            record = json.loads(data)
            if not isinstance(record, dict) or set(record) != {'state', 'plaintext'} or not isinstance(record['state'], dict):
                raise ValueError('Estado cifrado inválido')
            return record['state'], base64.b64decode(record['plaintext'], validate=True)
        except (sqlite3.Error, OSError, TypeError, ValueError, InvalidTag) as exc:
            raise HybridPersistenceError('No se pudo recuperar el estado híbrido') from exc
