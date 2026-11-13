"""Persistencia atómica experimental de aceptaciones híbridas."""
import concurrent.futures
import copy
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch
from cryptography.exceptions import InvalidTag
from securechat.infrastructure import crypto
from securechat.infrastructure.hybrid_handshake import generate_prekey, initiate_hybrid, accept_hybrid, transcript_digest
from cliente.application.hybrid_acceptance import HybridAcceptance, HybridReplayError, HybridPersistenceError
from cliente.infrastructure.hybrid_state_store import HybridStateStore
from tests.test_hybrid_handshake import identity


class HybridReplayStorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, 'state.sqlite3')
        self.key = bytes(range(32))
        self.alice = identity('alice', 1)
        self.bob = identity('bobby', 5)
        self.private, self.prekey = generate_prekey(crypto, self.bob)
        _, self.packet = initiate_hybrid(crypto, self.alice, self.prekey, self.bob.bundle(), b'secret hybrid initial')

    def service(self, store=None):
        store = store or HybridStateStore(self.path, self.key)
        return HybridAcceptance(lambda packet: accept_hybrid(crypto, self.bob, self.private,
                                                              self.alice.bundle(), packet),
                                transcript_digest, store)

    def test_replay_after_restart_and_state_recovery(self):
        original = self.service().accept(self.packet)
        self.assertEqual(original[1], b'secret hybrid initial')
        restarted = self.service()
        with self.assertRaises(HybridReplayError):
            restarted.accept(self.packet)
        self.assertEqual(restarted.recover(self.packet), original)
        with open(self.path, 'rb') as stored:
            self.assertNotIn(b'secret hybrid initial', stored.read())

    def test_concurrent_accepts_only_one_commits(self):
        def attempt(_):
            try:
                self.service().accept(self.packet)
                return 'accepted'
            except HybridReplayError:
                return 'replay'
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(attempt, range(2))), ['accepted', 'replay'])

    def test_invalid_packet_does_not_consume_transcript(self):
        broken = copy.deepcopy(self.packet)
        data = bytearray(crypto.unb64(broken['initial_ciphertext']))
        data[0] ^= 1
        broken['initial_ciphertext'] = crypto.b64(data)
        service = self.service()
        with self.assertRaises((InvalidTag, ValueError)):
            service.accept(broken)
        self.assertEqual(service.accept(self.packet)[1], b'secret hybrid initial')

    def test_transcript_claim_is_same_for_modified_ciphertext(self):
        altered = dict(self.packet, initial_ciphertext='different')
        self.assertEqual(transcript_digest(self.packet), transcript_digest(altered))

    def test_storage_failure_returns_no_state_and_retry_works(self):
        class FailedStore:
            def save_once(self, digest, state, plaintext):
                raise HybridPersistenceError('storage failed')
        with self.assertRaises(HybridPersistenceError):
            self.service(FailedStore()).accept(self.packet)
        self.assertEqual(self.service().accept(self.packet)[1], b'secret hybrid initial')

    def test_uncertain_after_commit_can_recover_without_reacceptance(self):
        class FailAfterCommit(sqlite3.Connection):
            def commit(self):
                super().commit()
                raise sqlite3.OperationalError('simulated failure after commit')
        store = HybridStateStore(self.path, self.key)
        real_connect = sqlite3.connect
        def connect(*args, **kwargs):
            return real_connect(*args, **kwargs, factory=FailAfterCommit)
        with patch('cliente.infrastructure.hybrid_state_store.sqlite3.connect', side_effect=connect):
            with self.assertRaises(HybridPersistenceError):
                self.service(store).accept(self.packet)
        restarted = self.service()
        self.assertEqual(restarted.recover(self.packet)[1], b'secret hybrid initial')
        with self.assertRaises(HybridReplayError):
            restarted.accept(self.packet)

    def test_wrong_storage_key_fails_closed(self):
        self.service().accept(self.packet)
        store = HybridStateStore(self.path, b'x' * 32)
        with self.assertRaises(HybridPersistenceError):
            self.service(store).recover(self.packet)

    def test_snapshot_prevents_caller_mutation_during_accept(self):
        original = copy.deepcopy(self.packet)
        def authenticate(packet):
            result = accept_hybrid(crypto, self.bob, self.private, self.alice.bundle(), packet)
            self.packet['nonce'] = crypto.b64(bytes(12))
            return result
        store = HybridStateStore(self.path, self.key)
        service = HybridAcceptance(authenticate, transcript_digest, store)
        accepted = service.accept(self.packet)
        self.assertEqual(service.recover(original), accepted)
        with self.assertRaises(HybridReplayError):
            self.service().accept(original)

    def test_tampered_persisted_ciphertext_is_rejected(self):
        self.service().accept(self.packet)
        import contextlib
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            blob = bytearray(db.execute('SELECT payload FROM accepted').fetchone()[0])
            blob[0] ^= 1
            db.execute('UPDATE accepted SET payload=?', (bytes(blob),))
            db.commit()
        with self.assertRaises(HybridPersistenceError):
            self.service().recover(self.packet)

    def test_failed_commit_does_not_record_acceptance(self):
        class FailBeforeCommit(sqlite3.Connection):
            def commit(self):
                raise sqlite3.OperationalError('simulated before commit')
        store = HybridStateStore(self.path, self.key)
        real_connect = sqlite3.connect
        def connect(*args, **kwargs):
            return real_connect(*args, **kwargs, factory=FailBeforeCommit)
        with patch('cliente.infrastructure.hybrid_state_store.sqlite3.connect', side_effect=connect):
            with self.assertRaises(HybridPersistenceError):
                self.service(store).accept(self.packet)
        restarted = self.service()
        self.assertIsNone(restarted.recover(self.packet))
        self.assertEqual(restarted.accept(self.packet)[1], b'secret hybrid initial')


    def test_recovery_rejects_modified_ciphertext_on_same_transcript(self):
        service = self.service()
        service.accept(self.packet)
        changed = copy.deepcopy(self.packet)
        ciphertext = bytearray(crypto.unb64(changed['initial_ciphertext']))
        ciphertext[0] ^= 1
        changed['initial_ciphertext'] = crypto.b64(ciphertext)
        self.assertEqual(transcript_digest(changed), transcript_digest(self.packet))
        with self.assertRaises((InvalidTag, ValueError)):
            service.recover(changed)
        self.assertEqual(service.recover(self.packet)[1], b'secret hybrid initial')

    def test_recovery_rejects_valid_but_different_authenticated_payload(self):
        store = HybridStateStore(self.path, self.key)
        def authenticate(packet):
            return {'session': 'same'}, packet['initial_ciphertext'].encode()
        service = HybridAcceptance(authenticate, transcript_digest, store)
        service.accept(self.packet)
        changed = dict(self.packet, initial_ciphertext='different-authenticated-value')
        with self.assertRaises(HybridPersistenceError):
            service.recover(changed)
