"""Behaviour of the isolated educational double ratchet prototype."""
import copy
import unittest
from cryptography.exceptions import InvalidTag
from securechat.application.double_ratchet import init_alice, init_bob, encrypt_message, decrypt_message, next_send_slot, RatchetError
from securechat.infrastructure.ratchet_provider import CryptographyRatchet

class DoubleRatchetTests(unittest.TestCase):
    def setUp(self):
        self.p = CryptographyRatchet()
        self.root = bytes(range(32))
        self.bob_private = bytes(range(32,64))
        self.a = init_alice(self.p, self.root, self.p.dh_public(self.bob_private))
        self.b = init_bob(self.p, self.root, self.bob_private)
        self.ad = b'independently-verified-identities'

    def send(self, sender, text): return encrypt_message(self.p, sender, text, self.ad)
    def receive(self, receiver, packet): return decrypt_message(self.p, receiver, packet, self.ad)

    def test_bidirectional_and_multiple_dh_turns(self):
        original_a = copy.deepcopy(self.a)
        a1, p1 = self.send(self.a, b'one')
        self.assertEqual(self.a, original_a)
        b1, plain = self.receive(self.b,p1); self.assertEqual(plain,b'one')
        b2,p2 = self.send(b1,b'two'); a2,plain = self.receive(a1,p2); self.assertEqual(plain,b'two')
        a3,p3 = self.send(a2,b'three'); b3,plain = self.receive(b2,p3); self.assertEqual(plain,b'three')
        self.assertNotEqual(p1['header']['dh'],p3['header']['dh'])

    def test_next_send_slot_matches_the_header_after_a_dh_step(self):
        dh, number = next_send_slot(self.p, self.a)
        a1, first = self.send(self.a, b'one')
        self.assertEqual(first['header']['dh'], dh)
        self.assertEqual(first['header']['n'], number)
        b1, _ = self.receive(self.b, first)
        _, reply = self.send(b1, b'two')
        a2, _ = self.receive(a1, reply)
        dh2, number2 = next_send_slot(self.p, a2)
        _, third = self.send(a2, b'three')
        self.assertEqual(third['header']['dh'], dh2)
        self.assertEqual(third['header']['n'], number2)
        self.assertNotEqual(dh, dh2)

    def test_stolen_send_chain_cannot_read_messages_after_a_dh_step(self):
        from securechat.application.double_ratchet import _aad
        a1, first = self.send(self.a, b'one')
        stolen = a1['send_chain']
        b1, _ = self.receive(self.b, first)
        _, reply = self.send(b1, b'two')
        a2, _ = self.receive(a1, reply)
        self.assertNotEqual(a2['send_chain'], stolen)
        _, third = self.send(a2, b'three')
        _, real_key = self.p.chain_step(a2['send_chain'])
        _, stolen_key = self.p.chain_step(stolen)
        associated = _aad(self.ad, third['header'])
        self.assertEqual(self.p.open(real_key, third['nonce'], third['ciphertext'], associated), b'three')
        with self.assertRaises(InvalidTag):
            self.p.open(stolen_key, third['nonce'], third['ciphertext'], associated)

    def test_out_of_order_and_lost_messages(self):
        a1,p1=self.send(self.a,b'first'); a2,p2=self.send(a1,b'second'); _,p3=self.send(a2,b'third')
        b1,plain=self.receive(self.b,p3);self.assertEqual(plain,b'third')
        b2,plain=self.receive(b1,p1);self.assertEqual(plain,b'first')
        b3,plain=self.receive(b2,p2);self.assertEqual(plain,b'second')
        with self.assertRaises((RatchetError,InvalidTag,ValueError)): self.receive(b3,p1)

    def test_header_nonce_and_ciphertext_tampering_are_transactional(self):
        _,packet=self.send(self.a,b'secret')
        for field in ('header','nonce','ciphertext','aad'):
            with self.subTest(field=field):
                altered=copy.deepcopy(packet); ad=self.ad
                if field=='header': altered['header']['pn']=1
                elif field=='aad': ad=b'wrong-identity'
                else:
                    raw=bytearray(altered[field]);raw[0]^=1;altered[field]=bytes(raw)
                original=copy.deepcopy(self.b)
                with self.assertRaises((RatchetError,InvalidTag,ValueError)): decrypt_message(self.p,self.b,altered,ad)
                self.assertEqual(self.b,original)
        _,plain=self.receive(self.b,packet); self.assertEqual(plain,b'secret')

    def test_replay_and_skip_limit_fail_without_mutation(self):
        a, packet=self.send(self.a,b'once'); b,plain=self.receive(self.b,packet)
        original=copy.deepcopy(b)
        with self.assertRaises((RatchetError,InvalidTag,ValueError)): self.receive(b,packet)
        self.assertEqual(b,original)
        packets=[]
        for i in range(35): a,p=self.send(a,b'x');packets.append(p)
        original=copy.deepcopy(b)
        with self.assertRaises(RatchetError): self.receive(b,packets[-1])
        self.assertEqual(b,original)

    def test_restored_state_requires_external_rollback_protection(self):
        _, packet=self.send(self.a,b'previous')
        stored=copy.deepcopy(self.b)
        advanced,plain=self.receive(self.b,packet);self.assertEqual(plain,b'previous')
        with self.assertRaises((RatchetError,InvalidTag,ValueError)): self.receive(advanced,packet)
        _, replay=self.receive(stored,packet)
        self.assertEqual(replay,b'previous')

    def test_skipped_message_from_previous_dh_chain_survives_ratchet(self):
        a, first = self.send(self.a, b'first')
        a, late = self.send(a, b'late')
        b, _ = self.receive(self.b, first)
        b, reply = self.send(b, b'reply')
        a, _ = self.receive(a, reply)
        a, new_chain = self.send(a, b'new chain')
        b, message = self.receive(b, new_chain)
        self.assertEqual(message, b'new chain')
        b, message = self.receive(b, late)
        self.assertEqual(message, b'late')
        with self.assertRaises((RatchetError, InvalidTag, ValueError)):
            self.receive(b, late)

    def test_skipped_key_not_consumed_by_authentication_failure(self):
        a, first = self.send(self.a, b'first')
        _, second = self.send(a, b'second')
        b, _ = self.receive(self.b, second)
        altered = copy.deepcopy(first)
        altered['ciphertext'] = bytes([first['ciphertext'][0] ^ 1]) + first['ciphertext'][1:]
        original = copy.deepcopy(b)
        with self.assertRaises((RatchetError, InvalidTag, ValueError)):
            self.receive(b, altered)
        self.assertEqual(b, original)
        _, message = self.receive(b, first)
        self.assertEqual(message, b'first')

    def test_invalid_header_values_are_rejected(self):
        _, packet = self.send(self.a, b'test')
        for name, value in [('n', -1), ('pn', True), ('n', 2**64), ('dh', b'bad')]:
            with self.subTest(name=name, value=value):
                altered = copy.deepcopy(packet)
                altered['header'][name] = value
                original = copy.deepcopy(self.b)
                with self.assertRaises((RatchetError, ValueError)):
                    self.receive(self.b, altered)
                self.assertEqual(self.b, original)

    def test_total_skipped_keys_are_bounded_across_ratchet_steps(self):
        from securechat.application.double_ratchet import MAX_SKIPPED_KEYS
        a, b = self.a, self.b
        for turn in range(5):
            for _ in range(31):
                a, _ = self.send(a, b'late')
            a, latest = self.send(a, b'latest')
            if turn == 4:
                original = copy.deepcopy(b)
                with self.assertRaises(RatchetError):
                    self.receive(b, latest)
                self.assertEqual(b, original)
                self.assertLessEqual(len(b['skipped']), MAX_SKIPPED_KEYS)
                break
            b, _ = self.receive(b, latest)
            b, reply = self.send(b, b'reply')
            a, _ = self.receive(a, reply)

    def test_ratchet_public_key_tampering_does_not_advance_state(self):
        _, packet = self.send(self.a, b'secret')
        altered = copy.deepcopy(packet)
        altered['header']['dh'] = self.p.dh_public(self.p.generate_dh())
        original = copy.deepcopy(self.b)
        with self.assertRaises((RatchetError, InvalidTag, ValueError)):
            self.receive(self.b, altered)
        self.assertEqual(self.b, original)
        _, message = self.receive(self.b, packet)
        self.assertEqual(message, b'secret')

    def test_one_dh_transition_can_skip_limit_in_each_chain(self):
        a = self.a
        a, first = self.send(a, b'first')
        for _ in range(32):
            a, _ = self.send(a, b'old delayed')
        b, _ = self.receive(self.b, first)
        b, reply = self.send(b, b'reply')
        a, _ = self.receive(a, reply)
        for _ in range(32):
            a, _ = self.send(a, b'new delayed')
        a, latest = self.send(a, b'latest')
        b, plaintext = self.receive(b, latest)
        self.assertEqual(plaintext, b'latest')
        self.assertEqual(len(b['skipped']), 64)
