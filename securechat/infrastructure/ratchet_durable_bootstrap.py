"""Recepción inicial experimental con registro durable; no integra el chat.

El almacén y la clave deben ser estables y protegidos por el llamador. La
restauración de una copia anterior o el borrado de la base permite replay.
"""
import copy

from cliente.application.hybrid_acceptance import HybridPersistenceError
from securechat.application.ratchet_state_codec import encode_state, decode_state
from securechat.infrastructure.encoding import canonical
from securechat.infrastructure.hashing import sha256
from securechat.infrastructure.ratchet_bootstrap import accept, _TRANSCRIPT_FIELDS

_TRANSCRIPT_DOMAIN = b'ProyectoCriptologia/experimental/dr-acceptance/v1\x00'
_PACKET_DOMAIN = b'ProyectoCriptologia/experimental/dr-packet/v1\x00'


class DurableBootstrap:
    """La escritura única guarda estado, texto y huella del paquete conjuntamente."""

    def __init__(self, provider, recipient, trusted_sender, store):
        self.provider, self.recipient = provider, recipient
        self.trusted_sender, self.store = copy.deepcopy(trusted_sender), store

    @staticmethod
    def _digests(packet):
        transcript = {name: packet[name] for name in _TRANSCRIPT_FIELDS}
        return (sha256(_TRANSCRIPT_DOMAIN + canonical(transcript)),
                sha256(_PACKET_DOMAIN + canonical(packet)).hex())

    def accept(self, packet):
        packet = copy.deepcopy(packet)
        state, plaintext = accept(self.provider, self.recipient, self.trusted_sender, packet)
        digest, packet_digest = self._digests(packet)
        record = {'version': 1, 'packet_digest': packet_digest, 'ratchet': encode_state(state)}
        self.store.save_once(digest, record, plaintext)
        return state, plaintext

    def recover(self, packet):
        packet = copy.deepcopy(packet)
        # Authenticating again avoids using an untrusted identifier to obtain secrets.
        _, plaintext = accept(self.provider, self.recipient, self.trusted_sender, packet)
        digest, packet_digest = self._digests(packet)
        result = self.store.load(digest)
        if result is None:
            return None
        record, stored_plaintext = result
        if (type(record) is not dict or set(record) != {'version', 'packet_digest', 'ratchet'}
                or type(record['version']) is not int or record['version'] != 1
                or record['packet_digest'] != packet_digest or stored_plaintext != plaintext):
            raise HybridPersistenceError('El paquete no coincide con el estado guardado')
        return decode_state(record['ratchet']), stored_plaintext
