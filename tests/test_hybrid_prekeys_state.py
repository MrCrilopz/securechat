"""Almacén inmutable aislado de preclave ML-KEM, con procesos independientes."""
import contextlib
import copy
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from cryptography.exceptions import InvalidSignature, InvalidTag
from cliente.infrastructure.hybrid_prekeys import HybridPrekeyCodec
from cliente.infrastructure.hybrid_prekey_store import HybridPrekeyStore, HybridPrekeyStorageError
from securechat.infrastructure import crypto


class HybridPrekeyStateTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = os.path.join(self.directory.name, 'hybrid.sqlite3')
        self.key = bytes(range(32))
        self.identity = crypto.Identity.generate('alice')
        self.codec = HybridPrekeyCodec(crypto)
        self.store = HybridPrekeyStore(self.path, self.key, self.codec)

    def test_creates_signed_key_encrypted_and_reloads(self):
        public = self.store.ensure(self.identity)
        with open(self.path, 'rb') as file:
            raw = file.read()
        self.assertNotIn(self.identity.serialize()['signing'].encode(), raw)
        private = self.store.restore(self.identity)
        self.assertEqual(crypto.b64(private.public_key().public_bytes_raw()), public['kem_public'])
        restarted = HybridPrekeyStore(self.path, self.key, self.codec)
        self.assertEqual(restarted.ensure(self.identity), public)

    def test_seed_not_stored_in_cleartext(self):
        record = self.codec.create(self.identity)
        self.store = HybridPrekeyStore(self.path, self.key, self.codec)
        with patch.object(self.codec, 'create', return_value=record):
            self.store.ensure(self.identity)
        with open(self.path, 'rb') as file:
            self.assertNotIn(record['seed'].encode(), file.read())

    def test_invalid_seed_signature_or_public_is_rejected(self):
        valid = self.codec.create(self.identity)
        for field in ('seed', 'signature', 'public'):
            changed = copy.deepcopy(valid)
            if field == 'seed': changed['seed'] = crypto.b64(bytes(64))
            if field == 'signature': changed['record']['kem_signature'] = crypto.b64(bytes(64))
            if field == 'public': changed['record']['kem_public'] = crypto.b64(bytes(1184))
            with self.subTest(field=field), self.assertRaises((ValueError, InvalidSignature)):
                self.codec.restore(self.identity, changed)

    def test_concurrent_processes_reuse_one_durable_prekey(self):
        script = '''import json, os, time
from cliente.infrastructure.hybrid_prekeys import HybridPrekeyCodec
from cliente.infrastructure.hybrid_prekey_store import HybridPrekeyStore
from securechat.infrastructure import crypto
identity = crypto.Identity.restore(json.loads(os.environ['TEST_IDENTITY']))
class SlowCodec(HybridPrekeyCodec):
    def create(self, identity):
        time.sleep(.3)
        return super().create(identity)
store = HybridPrekeyStore(os.environ['TEST_DB'], bytes(range(32)), SlowCodec(crypto))
open(os.environ['TEST_READY'], 'w').close()
while not os.path.exists(os.environ['TEST_GO']): time.sleep(.005)
print(json.dumps(store.ensure(identity), sort_keys=True), flush=True)
'''
        go = os.path.join(self.directory.name, 'go')
        env = dict(os.environ, TEST_IDENTITY=json.dumps(self.identity.serialize()), TEST_DB=self.path, TEST_GO=go)
        ready = [os.path.join(self.directory.name, f'ready-{index}') for index in range(2)]
        processes = [subprocess.Popen([sys.executable, '-c', script], env=dict(env, TEST_READY=ready[index]),
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for index in range(2)]
        try:
            deadline = time.monotonic() + 15
            while not all(os.path.exists(path) for path in ready):
                if time.monotonic() >= deadline or any(process.poll() is not None for process in processes):
                    self.fail('Los procesos no alcanzaron la barrera de concurrencia')
                time.sleep(.01)
            with open(go, 'w') as f: f.write('start')
            results = []
            for process in processes:
                stdout, stderr = process.communicate(timeout=20)
                self.assertEqual(process.returncode, 0, stderr)
                results.append(json.loads(stdout))
            self.assertEqual(results[0], results[1])
            self.assertEqual(self.store.ensure(self.identity), results[0])
            with contextlib.closing(sqlite3.connect(self.path)) as db:
                self.assertEqual(db.execute('SELECT count(*) FROM prekeys').fetchone()[0], 1)
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill(); process.communicate()

    def test_before_commit_failure_leaves_no_prekey(self):
        class FailBefore(sqlite3.Connection):
            def commit(self): raise sqlite3.OperationalError('before')
        real_connect = sqlite3.connect
        def connect(*args, **kwargs): return real_connect(*args, **kwargs, factory=FailBefore)
        with patch('cliente.infrastructure.hybrid_prekey_store.sqlite3.connect', side_effect=connect):
            with self.assertRaises(HybridPrekeyStorageError): self.store.ensure(self.identity)
        self.assertIsNone(self.store.restore(self.identity))
        self.assertIn('kem_signature', self.store.ensure(self.identity))

    def test_after_commit_failure_can_reload_existing_prekey(self):
        class FailAfter(sqlite3.Connection):
            def commit(self):
                super().commit()
                raise sqlite3.OperationalError('after')
        real_connect = sqlite3.connect
        def connect(*args, **kwargs): return real_connect(*args, **kwargs, factory=FailAfter)
        with patch('cliente.infrastructure.hybrid_prekey_store.sqlite3.connect', side_effect=connect):
            with self.assertRaises(HybridPrekeyStorageError): self.store.ensure(self.identity)
        reloaded = HybridPrekeyStore(self.path, self.key, self.codec)
        first = reloaded.ensure(self.identity)
        self.assertEqual(reloaded.ensure(self.identity), first)
        self.assertEqual(crypto.b64(reloaded.restore(self.identity).public_key().public_bytes_raw()), first['kem_public'])

    def test_wrong_key_and_tampered_ciphertext_fail_closed(self):
        self.store.ensure(self.identity)
        other = HybridPrekeyStore(self.path, bytes(32), self.codec)
        with self.assertRaises(InvalidTag): other.ensure(self.identity)
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            blob = bytearray(db.execute('SELECT ciphertext FROM prekeys').fetchone()[0]); blob[0] ^= 1
            db.execute('UPDATE prekeys SET ciphertext=?', (bytes(blob),)); db.commit()
        with self.assertRaises(InvalidTag): self.store.ensure(self.identity)

    def test_classic_state_file_remains_unchanged(self):
        from cliente.infrastructure import local_store
        legacy_path = os.path.join(self.directory.name, 'alice.json')
        state = {'identity': self.identity.serialize(), 'contacts': {}, 'sessions': {},
                 'history': [{'peer': 'bobby', 'direction': 'out', 'text': 'previous'}], 'outbox': []}
        local_store.save(legacy_path, 'temporary-password-2026', state)
        with open(legacy_path, 'rb') as f:
            before = f.read()
        self.store.ensure(self.identity)
        with open(legacy_path, 'rb') as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(local_store.load(legacy_path, 'temporary-password-2026'), state)

    def test_separate_identities_may_use_distinct_keys_in_same_database(self):
        bob = crypto.Identity.generate('bobby')
        bob_store = HybridPrekeyStore(self.path, b'b' * 32, self.codec)
        alice_public = self.store.ensure(self.identity)
        bob_public = bob_store.ensure(bob)
        self.assertEqual(self.store.ensure(self.identity), alice_public)
        self.assertEqual(bob_store.ensure(bob), bob_public)
        with self.assertRaises(InvalidTag): self.store.ensure(bob)
        with self.assertRaises(InvalidTag): bob_store.ensure(self.identity)
        with contextlib.closing(sqlite3.connect(self.path)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM prekeys').fetchone()[0], 2)
