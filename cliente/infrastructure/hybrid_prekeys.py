"""Preclave ML-KEM experimental para incluir en el estado local cifrado.

No publica la clave ni participa en las conversaciones reales. No debe usarse
para distribución hasta coordinar concurrencia, rotación y recuperación.
"""
import copy
import secrets
from cryptography.exceptions import UnsupportedAlgorithm
from securechat.infrastructure import hybrid_handshake
from securechat.infrastructure.encoding import b64, unb64


class HybridPrekeyCodec:
    def __init__(self, provider):
        self.provider = provider

    def create(self, identity):
        private, public = hybrid_handshake.generate_prekey(self.provider, identity)
        record = {'seed': b64(private.private_bytes_raw()), 'record': public}
        self.restore(identity, record)
        return record

    def restore(self, identity, stored):
        if not isinstance(stored, dict) or set(stored) != {'seed', 'record'}:
            raise ValueError('Invalid stored hybrid prekey')
        bundle, public_key = hybrid_handshake._validate_prekey(self.provider, stored['record'], identity.bundle())
        if bundle != identity.bundle():
            raise ValueError('Hybrid prekey identity does not match local identity')
        seed = unb64(stored['seed'])
        if len(seed) != 64:
            raise ValueError('Invalid hybrid prekey seed')
        try:
            private = hybrid_handshake._require_kem().MLKEM768PrivateKey.from_seed_bytes(seed)
            if not secrets.compare_digest(private.public_key().public_bytes_raw(), public_key):
                raise ValueError('Hybrid prekey seed does not match the signed public key')
            return private
        except UnsupportedAlgorithm as exc:
            raise hybrid_handshake.HybridUnavailable('Backend does not support ML-KEM-768') from exc

    def public(self, identity, stored):
        self.restore(identity, stored)
        return copy.deepcopy(stored['record'])
