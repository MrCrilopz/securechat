"""Comprueba el intercambio, la huella y el rechazo de sustitución, alteración y repetición."""
import unittest
import base64
from securechat.infrastructure.crypto import Identity, initiate, accept, encrypt, decrypt, fingerprint
from cryptography.exceptions import InvalidSignature, InvalidTag

class ProtocolTests(unittest.TestCase):
    def setUp(self):
        self.a, self.b = Identity.generate('alice'), Identity.generate('bob')
        self.a_state, self.header = initiate(self.a, self.b.bundle())
        self.b_state = accept(self.b, self.a.bundle(), self.header)
    def test_round_trip_and_reply(self):
        message = encrypt(self.a_state, 'hello')
        self.assertEqual(decrypt(self.b_state, message), 'hello')
        self.assertEqual(decrypt(self.a_state, encrypt(self.b_state, 'reply')), 'reply')
    def test_modified_ciphertext_rejected_and_state_unchanged(self):
        message = encrypt(self.a_state, 'hello')
        raw = bytearray(base64.urlsafe_b64decode(message['ciphertext'])); raw[0] ^= 1
        modified = dict(message, ciphertext=base64.urlsafe_b64encode(raw).decode())
        with self.assertRaises((InvalidTag, ValueError)): decrypt(self.b_state, modified)
        self.assertEqual(decrypt(self.b_state, message), 'hello')
    def test_replay_rejected(self):
        message = encrypt(self.a_state, 'hello'); decrypt(self.b_state, message)
        with self.assertRaises(ValueError): decrypt(self.b_state, message)
    def test_prekey_substitution_rejected(self):
        bundle = self.b.bundle(); bundle['prekey'] = self.a.bundle()['prekey']
        with self.assertRaises(InvalidSignature): initiate(self.a, bundle)
    def test_safety_number_symmetric_and_changes(self):
        self.assertEqual(fingerprint(self.a.bundle(), self.b.bundle()), fingerprint(self.b.bundle(), self.a.bundle()))
        self.assertNotEqual(fingerprint(self.a.bundle(), self.b.bundle()), fingerprint(self.a.bundle(), Identity.generate('bob').bundle()))

if __name__ == '__main__': unittest.main()
