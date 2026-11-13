"""Comportamiento del laboratorio aislado de claves por emisor."""
import copy
import unittest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cliente.application.group_sender_keys import (
    GroupError, create_sender, create_receiver, send_group_message, receive_group_message,
)
from cliente.infrastructure.group_crypto import GroupCrypto


class SenderKeyTests(unittest.TestCase):
    def setUp(self):
        self.crypto = GroupCrypto()
        self.sender, self.distribution = create_sender(self.crypto, 'grupo-uno', 1, 'alice')
        self.receiver = create_receiver(self.crypto, self.distribution)
        self.other_receiver = create_receiver(self.crypto, self.distribution)

    def test_sender_key_round_trip_and_independent_receivers(self):
        sender, packet = send_group_message(self.crypto, self.sender, b'mensaje privado')
        self.assertNotIn(b'mensaje privado', repr(packet).encode())
        bob, plaintext = receive_group_message(self.crypto, self.receiver, packet)
        clara, second = receive_group_message(self.crypto, self.other_receiver, packet)
        self.assertEqual((plaintext, second), (b'mensaje privado', b'mensaje privado'))
        self.assertNotEqual(sender, self.sender)
        self.assertNotEqual(bob, self.receiver)
        self.assertNotEqual(clara, self.other_receiver)

    def test_replay_rejected_without_advancing_state(self):
        _, packet = send_group_message(self.crypto, self.sender, b'once')
        receiver, _ = receive_group_message(self.crypto, self.receiver, packet)
        before = copy.deepcopy(receiver)
        with self.assertRaises(GroupError):
            receive_group_message(self.crypto, receiver, packet)
        self.assertEqual(receiver, before)

    def test_out_of_order_and_replay(self):
        sender, one = send_group_message(self.crypto, self.sender, b'one')
        sender, two = send_group_message(self.crypto, sender, b'two')
        _, three = send_group_message(self.crypto, sender, b'three')
        state, plaintext = receive_group_message(self.crypto, self.receiver, three)
        self.assertEqual(plaintext, b'three')
        state, plaintext = receive_group_message(self.crypto, state, one)
        self.assertEqual(plaintext, b'one')
        state, plaintext = receive_group_message(self.crypto, state, two)
        self.assertEqual(plaintext, b'two')
        with self.assertRaises(GroupError):
            receive_group_message(self.crypto, state, one)

    def test_tampering_rejected_without_state_mutation(self):
        _, packet = send_group_message(self.crypto, self.sender, b'private')
        for field in ('ciphertext', 'signature', 'nonce', 'counter', 'group', 'epoch', 'sender', 'key_id'):
            altered = copy.deepcopy(packet)
            if field in ('ciphertext', 'signature', 'nonce'):
                value = bytearray(altered[field]); value[0] ^= 1; altered[field] = bytes(value)
            elif field in ('counter', 'epoch'):
                altered[field] += 1
            else:
                altered[field] += 'x'
            original = copy.deepcopy(self.receiver)
            with self.subTest(field=field), self.assertRaises((GroupError, InvalidTag, InvalidSignature, ValueError)):
                receive_group_message(self.crypto, self.receiver, altered)
            self.assertEqual(self.receiver, original)
        _, plaintext = receive_group_message(self.crypto, self.receiver, packet)
        self.assertEqual(plaintext, b'private')

    def test_skip_limit_and_retained_key_limit(self):
        sender = self.sender
        for _ in range(34):
            sender, packet = send_group_message(self.crypto, sender, b'x')
        with self.assertRaises(GroupError):
            receive_group_message(self.crypto, self.receiver, packet)
        self.assertEqual(self.receiver['counter'], 0)

    def test_epoch_rotation_excludes_old_receiver(self):
        next_sender, distribution = create_sender(self.crypto, 'grupo-uno', 2, 'alice')
        recipient = create_receiver(self.crypto, distribution)
        _, message = send_group_message(self.crypto, next_sender, b'new members only')
        with self.assertRaises((GroupError, InvalidTag, InvalidSignature, ValueError)):
            receive_group_message(self.crypto, self.receiver, message)
        _, plaintext = receive_group_message(self.crypto, recipient, message)
        self.assertEqual(plaintext, b'new members only')
        self.assertNotEqual(self.distribution['chain_key'], distribution['chain_key'])

    def test_malformed_distribution_and_packet_rejected(self):
        for bad in (dict(self.distribution, epoch=True), dict(self.distribution, chain_key=b'a'),
                    dict(self.distribution, sender=''), dict(self.distribution, extra='x')):
            with self.subTest(bad=bad), self.assertRaises(GroupError):
                create_receiver(self.crypto, bad)
        _, packet = send_group_message(self.crypto, self.sender, b'x')
        for bad in (dict(packet, counter=True), dict(packet, counter=-1),
                    dict(packet, counter=2**64), dict(packet, nonce=b'x')):
            with self.subTest(bad=bad), self.assertRaises((GroupError, ValueError)):
                receive_group_message(self.crypto, self.receiver, bad)

    def test_authenticated_but_corrupt_ciphertext_does_not_advance(self):
        from cliente.application.group_sender_keys import _header, _signed
        _, packet = send_group_message(self.crypto, self.sender, b'first')
        altered = copy.deepcopy(packet)
        damaged = bytearray(altered['ciphertext'])
        damaged[0] ^= 1
        altered['ciphertext'] = bytes(damaged)
        altered['signature'] = self.crypto.sign(self.sender['signing_private'],
            _signed(_header(altered), altered['nonce'], altered['ciphertext']))
        before = copy.deepcopy(self.receiver)
        with self.assertRaises(InvalidTag):
            receive_group_message(self.crypto, self.receiver, altered)
        self.assertEqual(self.receiver, before)
        _, plaintext = receive_group_message(self.crypto, self.receiver, packet)
        self.assertEqual(plaintext, b'first')

    def test_saved_skipped_keys_are_bounded_across_multiple_gaps(self):
        sender, receiver = self.sender, self.receiver
        for turn in range(5):
            for _ in range(32):
                sender, _ = send_group_message(self.crypto, sender, b'skipped')
            sender, current = send_group_message(self.crypto, sender, b'current')
            if turn == 4:
                before = copy.deepcopy(receiver)
                with self.assertRaises(GroupError):
                    receive_group_message(self.crypto, receiver, current)
                self.assertEqual(receiver, before)
                break
            receiver, _ = receive_group_message(self.crypto, receiver, current)
        self.assertEqual(len(receiver['skipped']), 128)

    def test_old_state_allows_replay_without_external_rollback_protection(self):
        _, packet = send_group_message(self.crypto, self.sender, b'one')
        advanced, _ = receive_group_message(self.crypto, self.receiver, packet)
        with self.assertRaises(GroupError):
            receive_group_message(self.crypto, advanced, packet)
        _, plaintext = receive_group_message(self.crypto, self.receiver, packet)
        self.assertEqual(plaintext, b'one')
