"""Inicialización aislada: aún no sustituye el acuerdo del chat."""
import copy
import json
from securechat.infrastructure.encoding import b64, unb64, canonical
import unittest
from securechat.infrastructure.identity import Identity
from securechat.infrastructure.ratchet_provider import CryptographyRatchet
from securechat.infrastructure.ratchet_bootstrap import initiate, accept, BootstrapError, _SIGN_DOMAIN, _TRANSCRIPT_FIELDS
from securechat.application.double_ratchet import encrypt_message, decrypt_message


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.p = CryptographyRatchet()
        self.alice = Identity.generate('alice')
        self.bob = Identity.generate('bob')
        self.a = self.alice.bundle(); self.b = self.bob.bundle()

    def test_initial_and_reply_messages_use_same_session(self):
        state_a, packet = initiate(self.p, self.alice, self.b, self.b, b'hello')
        packet = json.loads(json.dumps(packet))
        state_b, message = accept(self.p, self.bob, self.a, packet)
        self.assertEqual(message, b'hello')
        state_b, reply = encrypt_message(self.p, state_b, b'world', b'context')
        _, text = decrypt_message(self.p, state_a, reply, b'context')
        self.assertEqual(text, b'world')

    def test_tampering_and_untrusted_identity_are_rejected(self):
        _, packet = initiate(self.p, self.alice, self.b, self.b, b'hello')
        for key in ('session', 'suite', 'sender', 'recipient', 'ephemeral', 'signature', 'ciphertext'):
            altered = copy.deepcopy(packet)
            if key in ('sender', 'recipient'): altered[key]['username'] = 'mallory'
            else: altered[key] = altered[key] + 'A'
            with self.subTest(key=key), self.assertRaises(BootstrapError):
                accept(self.p, self.bob, self.a, altered)
        other = Identity.generate('alice').bundle()
        with self.assertRaises(BootstrapError): accept(self.p, self.bob, other, packet)
        with self.assertRaises(BootstrapError): initiate(self.p, self.alice, self.b, other, b'x')

    def test_tampered_header_and_authenticated_payload_rejected(self):
        _, packet = initiate(self.p, self.alice, self.b, self.b, b'hello')
        for field in ('header', 'nonce', 'ciphertext'):
            altered = copy.deepcopy(packet)
            if field == 'header':
                altered['header']['dh'] = b64(self.p.dh_public(self.p.generate_dh()))
            else:
                raw = bytearray(unb64(altered[field])); raw[0] ^= 1
                altered[field] = b64(raw)
            with self.subTest(field=field), self.assertRaises(BootstrapError):
                accept(self.p, self.bob, self.a, altered)
        _, text = accept(self.p, self.bob, self.a, packet)
        self.assertEqual(text, b'hello')

    def test_signed_low_order_ephemeral_raises_typed_error(self):
        _, packet = initiate(self.p, self.alice, self.b, self.b, b'hello')
        packet['ephemeral'] = b64(bytes(32))
        transcript = {key: packet[key] for key in _TRANSCRIPT_FIELDS}
        packet['signature'] = b64(self.alice.signing.sign(_SIGN_DOMAIN + canonical(transcript)))
        with self.assertRaises(BootstrapError):
            accept(self.p, self.bob, self.a, packet)

    def test_low_order_ratchet_header_without_signing_key_is_typed(self):
        _, packet = initiate(self.p, self.alice, self.b, self.b, b'hello')
        packet['header']['dh'] = b64(bytes(32))
        with self.assertRaises(BootstrapError):
            accept(self.p, self.bob, self.a, packet)

    def test_replay_requires_external_atomic_tracking(self):
        _, packet = initiate(self.p, self.alice, self.b, self.b, b'hello')
        _, first = accept(self.p, self.bob, self.a, packet)
        _, second = accept(self.p, self.bob, self.a, packet)
        self.assertEqual(first, second)

if __name__ == '__main__': unittest.main()
