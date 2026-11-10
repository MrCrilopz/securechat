"""Adaptador criptográfico de la sesión DR explícita de la aplicación.

La sesión todavía requiere revisión y una política de transición; no realiza
migración ni convierte automáticamente sesiones clásicas existentes.
"""
from securechat.application import double_ratchet as dr
from securechat.application.ratchet_state_codec import encode_state, decode_state
from securechat.application.ratchet_transport import context, wrap, unwrap
from securechat.application.ratchet_transport import RatchetTransportError
from securechat.domain.errors import RatchetPacketRejected
from cryptography.exceptions import InvalidTag
from securechat.infrastructure import ratchet_bootstrap
from securechat.infrastructure.encoding import unb64, canonical
from securechat.infrastructure.hashing import sha256
from securechat.infrastructure.ratchet_provider import CryptographyRatchet


class DoubleRatchetChat:
    def __init__(self): self.provider = CryptographyRatchet()

    @staticmethod
    def _aad(sender, recipient, sid):
        # Bind the direction separately: transport context sorts the peers.
        return context(sender, recipient, sid) + b'\x00sender\x00' + sender.encode('ascii')

    def initiate(self, identity, peer, text):
        state, initial = ratchet_bootstrap.initiate(self.provider, identity, peer, peer, text.encode('utf8'))
        sid = unb64(initial['session']).hex()
        envelope = {'message': {'sender':identity.username, 'recipient':peer['username'],
                                'protocol':'dr-bootstrap-v1', 'payload':initial}}
        return sid, encode_state(state), envelope

    def accept(self, identity, peer, envelope):
        msg = envelope['message']
        if (set(envelope) != {'message'} or set(msg) != {'sender','recipient','protocol','payload'}
                or msg['sender'] != peer['username'] or msg['recipient'] != identity.username
                or msg['protocol'] != 'dr-bootstrap-v1'):
            raise RatchetPacketRejected('Invalid DR bootstrap envelope')
        try:
            state, text = ratchet_bootstrap.accept(self.provider, identity, peer, msg['payload'])
        except ratchet_bootstrap.BootstrapError as exc:
            raise RatchetPacketRejected('DR bootstrap rejected') from exc
        return unb64(msg['payload']['session']).hex(), encode_state(state), text.decode('utf8')

    def next_send(self, encoded_state):
        dh, number = dr.next_send_slot(self.provider, decode_state(encoded_state))
        return dh.hex(), number

    def encrypt(self, encoded_state, sender, recipient, sid, text):
        state, packet = dr.encrypt_message(self.provider, decode_state(encoded_state), text.encode('utf8'),
                                           self._aad(sender, recipient, sid))
        return encode_state(state), wrap(sender, recipient, sid, packet)

    def decrypt(self, encoded_state, sender, recipient, sid, envelope):
        # Local state codec errors are not packet errors and must propagate.
        state = decode_state(encoded_state)
        try:
            packet = unwrap(envelope, sender, recipient, sid)
            state, text = dr.decrypt_message(self.provider, state, packet,
                                             self._aad(sender, recipient, sid))
        except (RatchetTransportError, dr.RatchetError, InvalidTag) as exc:
            raise RatchetPacketRejected('DR packet rejected or security limit reached') from exc
        return encode_state(state), text.decode('utf8')

    @staticmethod
    def digest(envelope): return sha256(canonical(envelope)).hex()
