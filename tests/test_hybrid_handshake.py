"""Tests for the isolated educational X25519 + ML-KEM-768 handshake."""
import copy
import unittest
from unittest.mock import patch
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from securechat.infrastructure import crypto
from securechat.infrastructure.hybrid_handshake import (
    HybridUnavailable, generate_prekey, initiate_hybrid, accept_hybrid,
)


def identity(name, seed):
    return crypto.Identity(name, ed25519.Ed25519PrivateKey.from_private_bytes(bytes([seed])*32),
                           x25519.X25519PrivateKey.from_private_bytes(bytes([seed+1])*32),
                           x25519.X25519PrivateKey.from_private_bytes(bytes([seed+2])*32))

class HybridHandshakeTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = identity('alice', 1), identity('bobby', 5)
        self.private, self.prekey = generate_prekey(crypto, self.b)
        self.a_pin, self.b_pin = self.a.bundle(), self.b.bundle()

    def handshake(self):
        return initiate_hybrid(crypto, self.a, self.prekey, self.b_pin, b'initial message')

    def test_initial_message_round_trip_and_directional_keys(self):
        a_state, packet = self.handshake()
        b_state, plaintext = accept_hybrid(crypto, self.b, self.private, self.a_pin, packet)
        self.assertEqual(plaintext, b'initial message')
        self.assertEqual(a_state['send_key'], b_state['receive_key'])
        self.assertEqual(a_state['receive_key'], b_state['send_key'])
        self.assertNotEqual(a_state['send_key'], a_state['receive_key'])
        self.assertEqual(crypto.decrypt(b_state, crypto.encrypt(a_state, 'follow-up')), 'follow-up')

    def test_unsigned_kem_key_substitution_rejected(self):
        changed = copy.deepcopy(self.prekey)
        changed['kem_public'] = crypto.b64(bytes(1184))
        before = copy.deepcopy(changed)
        with self.assertRaises(InvalidSignature): initiate_hybrid(crypto, self.a, changed, self.b_pin, b'x')
        self.assertEqual(changed, before)

    def test_mutated_kem_ciphertext_rejected_without_input_mutation(self):
        _, packet = self.handshake(); altered = copy.deepcopy(packet)
        raw = bytearray(crypto.unb64(altered['kem_ciphertext'])); raw[0] ^= 1
        altered['kem_ciphertext'] = crypto.b64(raw); prior = copy.deepcopy(altered)
        with self.assertRaises((InvalidTag, ValueError)): accept_hybrid(crypto, self.b, self.private, self.a_pin, altered)
        self.assertEqual(altered, prior)
        _, plaintext = accept_hybrid(crypto, self.b, self.private, self.a_pin, packet)
        self.assertEqual(plaintext, b'initial message')

    def test_pinned_identity_mismatch_and_downgrade_rejected(self):
        wrong_pin = identity('bobby', 12).bundle()
        with self.assertRaises(ValueError): initiate_hybrid(crypto, self.a, self.prekey, wrong_pin, b'x')
        _, packet = self.handshake()
        packet['suite'] = 'classical-only'
        with self.assertRaises(ValueError): accept_hybrid(crypto, self.b, self.private, self.a_pin, packet)

    def test_missing_backend_fails_closed(self):
        with patch('securechat.infrastructure.hybrid_handshake._MLKEM', None):
            with self.assertRaises(HybridUnavailable): generate_prekey(crypto, self.b)
            with self.assertRaises(HybridUnavailable): initiate_hybrid(crypto, self.a, self.prekey, self.b_pin, b'x')

    def test_untrusted_sender_and_recipient_prekey_substitution_fail(self):
        _, packet = self.handshake()
        wrong_sender = identity('alice', 20).bundle()
        with self.assertRaises(ValueError): accept_hybrid(crypto, self.b, self.private, wrong_sender, packet)
        altered = copy.deepcopy(packet)
        _, attacker_prekey = generate_prekey(crypto, identity('bobby', 25))
        altered['recipient_prekey'] = attacker_prekey
        with self.assertRaises(ValueError): accept_hybrid(crypto, self.b, self.private, self.a_pin, altered)

    def test_missing_required_kem_field_cannot_fall_back(self):
        _, packet = self.handshake(); del packet['kem_ciphertext']
        with self.assertRaises(ValueError): accept_hybrid(crypto, self.b, self.private, self.a_pin, packet)
        legacy = copy.deepcopy(self.prekey); legacy['suite'] = 'classical-only'
        with self.assertRaises(ValueError): initiate_hybrid(crypto, self.a, legacy, self.b_pin, b'x')

    def test_backend_unsupported_is_reported_explicitly(self):
        from cryptography.exceptions import UnsupportedAlgorithm
        with patch('securechat.infrastructure.hybrid_handshake._MLKEM.MLKEM768PrivateKey.generate', side_effect=UnsupportedAlgorithm('unavailable')):
            with self.assertRaises(HybridUnavailable): generate_prekey(crypto, self.b)
