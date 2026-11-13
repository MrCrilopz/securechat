"""Persistencia experimental: no activa Double Ratchet en el chat."""
import copy
import json
import tempfile
import unittest
from pathlib import Path

from cliente.infrastructure import local_store
from securechat.application.double_ratchet import init_alice, init_bob, encrypt_message, decrypt_message
from securechat.application.ratchet_state_codec import encode_state, decode_state, RatchetStateCodecError
from securechat.infrastructure.ratchet_provider import CryptographyRatchet


class RatchetStateCodecTests(unittest.TestCase):
    def setUp(self):
        self.p = CryptographyRatchet()
        root, private = bytes(range(32)), bytes(range(32, 64))
        self.alice = init_alice(self.p, root, self.p.dh_public(private))
        self.bob = init_bob(self.p, root, private)

    def test_roundtrip_across_encrypted_local_storage_and_skipped_keys(self):
        a, first = encrypt_message(self.p, self.alice, b'first', b'context')
        a, second = encrypt_message(self.p, a, b'second', b'context')
        b, text = decrypt_message(self.p, self.bob, second, b'context')
        self.assertEqual(text, b'second')
        with tempfile.TemporaryDirectory() as temp:
            path = str(Path(temp) / 'state.json')
            encoded = encode_state(b)
            local_store.save(path, 'password-test', {'ratchet': encoded})
            self.assertNotIn(b['root'].hex(), Path(path).read_text())
            restored = decode_state(local_store.load(path, 'password-test')['ratchet'])
            self.assertEqual(restored, b)
            restored, text = decrypt_message(self.p, restored, first, b'context')
            self.assertEqual(text, b'first')
        self.assertEqual(json.loads(json.dumps(encoded)), encoded)

    def test_rejects_invalid_input_and_duplicate_skipped_ids(self):
        a, _ = encrypt_message(self.p, self.alice, b'first', b'context')
        _, second = encrypt_message(self.p, a, b'second', b'context')
        state, _ = decrypt_message(self.p, self.bob, second, b'context')
        good = encode_state(state)
        changes = [lambda d: d.update(version=2), lambda d: d.update(root='0'*63),
                   lambda d: d.update(send_n=True), lambda d: d.update(extra=1),
                   lambda d: d['skipped'].append(copy.deepcopy(d['skipped'][0])),
                   lambda d: d.update(skipped=[d['skipped'][0]]*129)]
        for change in changes:
            altered = copy.deepcopy(good); change(altered)
            with self.subTest(altered=altered), self.assertRaises(RatchetStateCodecError):
                decode_state(altered)

    def test_rejects_uninitialized_chains_with_advanced_counters(self):
        invalid = [dict(self.bob, receive_n=5), dict(self.bob, send_n=10),
                   dict(self.alice, receive_n=1)]
        for state in invalid:
            with self.subTest(state=state), self.assertRaises(RatchetStateCodecError):
                encode_state(state)
        bob_wire = encode_state(self.bob)
        for field, value in [('receive_n', 5), ('send_n', 10)]:
            altered = copy.deepcopy(bob_wire); altered[field] = value
            with self.subTest(field=field), self.assertRaises(RatchetStateCodecError):
                decode_state(altered)
        self.assertEqual(decode_state(encode_state(self.bob)), self.bob)
        self.assertEqual(decode_state(encode_state(self.alice)), self.alice)

    def test_rejects_skipped_key_not_behind_current_receive_counter(self):
        a, first = encrypt_message(self.p, self.alice, b'first', b'context')
        a, second = encrypt_message(self.p, a, b'second', b'context')
        b, _ = decrypt_message(self.p, self.bob, second, b'context')
        encoded = encode_state(b)
        self.assertEqual(decode_state(encoded), b)
        altered = copy.deepcopy(encoded)
        altered['skipped'][0]['n'] = b['receive_n']
        with self.assertRaises(RatchetStateCodecError): decode_state(altered)
        invalid = copy.deepcopy(b)
        old_id = next(iter(invalid['skipped']))
        key = invalid['skipped'].pop(old_id)
        invalid['skipped'][(old_id[0], b['receive_n'])] = key
        with self.assertRaises(RatchetStateCodecError): encode_state(invalid)
        restored, plaintext = decrypt_message(self.p, decode_state(encoded), first, b'context')
        self.assertEqual(plaintext, b'first')

    def test_roundtrip_skipped_key_from_previous_dh_chain(self):
        a, first = encrypt_message(self.p, self.alice, b'first', b'context')
        a, late = encrypt_message(self.p, a, b'late', b'context')
        b, _ = decrypt_message(self.p, self.bob, first, b'context')
        b, reply = encrypt_message(self.p, b, b'reply', b'context')
        a, _ = decrypt_message(self.p, a, reply, b'context')
        a, new_chain = encrypt_message(self.p, a, b'new', b'context')
        b, _ = decrypt_message(self.p, b, new_chain, b'context')
        old_dh, old_counter = next(iter(b['skipped']))
        self.assertNotEqual(old_dh, b['dh_remote'])
        self.assertGreaterEqual(old_counter, b['receive_n'])
        restored = decode_state(encode_state(b))
        _, plain = decrypt_message(self.p, restored, late, b'context')
        self.assertEqual(plain, b'late')

    def test_encoding_rejects_invalid_memory_state(self):
        bad = copy.deepcopy(self.alice); bad['send_n'] = -1
        with self.assertRaises(RatchetStateCodecError): encode_state(bad)

if __name__ == '__main__': unittest.main()
