"""Experimento aislado: transición, historial y cola antes de transmitir o ACK.

No es integración al chat: el llamador debe cifrar/autenticar y persistir de
forma atómica todo el agregado, usar exclusión entre procesos y manejar rollback.
"""
import copy
from securechat.application.double_ratchet import encrypt_message, decrypt_message, RatchetError

from securechat.application.ratchet_session_limits import (
    MAX_ACCEPTED, MAX_HISTORY, MAX_MESSAGE_ID_LENGTH, MAX_PLAINTEXT_BYTES,
)

class RatchetSessionInvalidated(RuntimeError):
    """Escritura de resultado incierto; volver a cargar el agregado."""

class TransactionalRatchet:
    def __init__(self, provider, gateway, persist, ratchet, associated_data, snapshot=None):
        self.provider, self.gateway, self.persist, self.aad = provider, gateway, persist, associated_data
        self.state = copy.deepcopy(snapshot) if snapshot is not None else {
            'ratchet': copy.deepcopy(ratchet), 'outbox': [], 'accepted': {}, 'history': []}
        self.invalid = False

    def _valid(self):
        if self.invalid: raise RatchetSessionInvalidated('Reload required')

    def _commit(self, candidate):
        self._valid()
        try: self.persist(candidate)
        except Exception as exc:
            self.invalid = True
            raise RatchetSessionInvalidated('Persistence outcome uncertain; reload required') from exc
        self.state = candidate

    def flush(self):
        self._valid()
        while self.state['outbox']:
            self.gateway.send(copy.deepcopy(self.state['outbox'][0]))
            candidate = copy.deepcopy(self.state); candidate['outbox'].pop(0)
            self._commit(candidate)

    def send(self, plaintext):
        self._valid()
        if type(plaintext) is not bytes or len(plaintext) > MAX_PLAINTEXT_BYTES:
            raise RatchetError('Invalid plaintext')
        if len(self.state['history']) >= MAX_HISTORY: raise RatchetError('History is full')
        self.flush()
        ratchet, packet = encrypt_message(self.provider, self.state['ratchet'], plaintext, self.aad)
        candidate = copy.deepcopy(self.state); candidate['ratchet'] = ratchet
        candidate['outbox'].append(packet); candidate['history'].append(plaintext)
        self._commit(candidate); self.flush()

    def receive(self, message_id, packet):
        self._valid()
        if type(message_id) is not str or not 0 < len(message_id) <= MAX_MESSAGE_ID_LENGTH: raise RatchetError('Invalid message id')
        accepted = self.state['accepted']
        if message_id in accepted:
            if accepted[message_id] != packet: raise RatchetError('Reused message id')
            self.gateway.acknowledge(message_id); return None
        if packet in accepted.values():
            self.gateway.acknowledge(message_id); return None
        if len(accepted) >= MAX_ACCEPTED: raise RatchetError('Accepted packet cache is full')
        if len(self.state['history']) >= MAX_HISTORY: raise RatchetError('History is full')
        ratchet, plaintext = decrypt_message(self.provider, self.state['ratchet'], packet, self.aad)
        if len(plaintext) > MAX_PLAINTEXT_BYTES: raise RatchetError('Invalid plaintext')
        candidate = copy.deepcopy(self.state); candidate['ratchet'] = ratchet
        candidate['accepted'][message_id] = copy.deepcopy(packet); candidate['history'].append(plaintext)
        self._commit(candidate); self.gateway.acknowledge(message_id)
        return plaintext
