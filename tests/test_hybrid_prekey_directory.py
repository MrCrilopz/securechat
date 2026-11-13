"""Directorio experimental de preclaves: migración, autorización e integridad."""
import concurrent.futures
import copy
import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
from contextlib import closing

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric import x25519
from cliente.application.hybrid_directory import HybridDirectory
from cliente.application.client import Client
from cliente.infrastructure.hybrid_verifier import HybridPrekeyVerifier
from cliente.infrastructure.http_gateway import HttpGateway
from securechat.infrastructure import crypto
from securechat.infrastructure.hybrid_handshake import generate_prekey, HybridUnavailable, SUITE, _prekey_payload
from servidor.application.service import ChatService
from servidor.infrastructure.server_adapters import SqliteRepository, BundleVerifier


class HybridDirectoryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = os.path.join(self.tmp.name, 'db.sqlite')
        self.repo = SqliteRepository(self.db)
        self.alice = crypto.Identity.generate('alice')
        self.bob = crypto.Identity.generate('bobby')
        self.repo.create_user('alice', 'hash', self.alice.bundle())
        self.repo.create_user('bobby', 'hash', self.bob.bundle())
        self.service = ChatService(self.repo, None, BundleVerifier(), lambda: 0, lambda: 'token')
        _, self.public = generate_prekey(crypto, self.alice)

    def test_publish_idempotent_and_survives_restart(self):
        self.service.publish_hybrid_prekey('alice', self.public)
        self.service.publish_hybrid_prekey('alice', copy.deepcopy(self.public))
        restarted = SqliteRepository(self.db)
        self.assertEqual(restarted.hybrid_prekey('alice'), self.public)

    def test_cannot_publish_on_behalf_of_another_user(self):
        with self.assertRaises((ValueError, InvalidSignature)):
            self.service.publish_hybrid_prekey('bobby', self.public)
        self.assertIsNone(self.repo.hybrid_prekey('bobby'))

    def test_substitution_downgrade_and_private_fields_rejected(self):
        for mode in ('signature', 'key', 'identity', 'suite', 'seed'):
            changed = copy.deepcopy(self.public)
            if mode == 'signature': changed['kem_signature'] = crypto.b64(bytes(64))
            if mode == 'key': changed['kem_public'] = crypto.b64(bytes(1184))
            if mode == 'identity': changed['identity_bundle'] = self.bob.bundle()
            if mode == 'suite': changed['suite'] = 'classical-only'
            if mode == 'seed': changed['seed'] = 'not-public'
            with self.subTest(mode=mode), self.assertRaises((ValueError, InvalidSignature)):
                self.service.publish_hybrid_prekey('alice', changed)
        self.assertIsNone(self.repo.hybrid_prekey('alice'))

    def test_http_reports_unavailable_backend_without_storing_prekey(self):
        from http.server import ThreadingHTTPServer
        from servidor.server import Handler
        self.repo.save_token('test-token', 'alice', 100)
        previous = Handler.service
        Handler.service = self.service
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f'http://127.0.0.1:{server.server_port}/hybrid-prekey'
            def request():
                return urllib.request.Request(url, data=json.dumps({'prekey': self.public}).encode(),
                    headers={'Content-Type': 'application/json', 'Authorization': 'Bearer test-token'})
            with patch('securechat.infrastructure.hybrid_handshake._MLKEM', None):
                with self.assertRaises(urllib.error.HTTPError) as error:
                    urllib.request.urlopen(request())
                self.assertEqual(error.exception.code, 503)
                error.exception.close()
            self.assertIsNone(self.repo.hybrid_prekey('alice'))
            with urllib.request.urlopen(request()) as response:
                self.assertEqual(response.status, 200)
            self.assertEqual(self.repo.hybrid_prekey('alice'), self.public)
        finally:
            server.shutdown(); thread.join(); server.server_close(); Handler.service = previous

    def test_signed_record_with_different_classical_prekey_is_rejected(self):
        altered_identity = crypto.Identity('alice', self.alice.signing, self.alice.agreement,
                                           x25519.X25519PrivateKey.generate())
        _, different = generate_prekey(crypto, altered_identity)
        with self.assertRaises(ValueError):
            self.service.publish_hybrid_prekey('alice', different)
        self.assertIsNone(self.repo.hybrid_prekey('alice'))

    def test_noncanonical_signed_key_does_not_poison_immutable_slot(self):
        invalid = copy.deepcopy(self.public)
        invalid['kem_public'] = crypto.b64(bytes([255]) * 1184)
        invalid['kem_signature'] = crypto.b64(self.alice.signing.sign(
            _prekey_payload(SUITE, invalid['identity_bundle'], invalid['kem_public'])))
        with self.assertRaises(ValueError):
            self.service.publish_hybrid_prekey('alice', invalid)
        self.assertIsNone(self.repo.hybrid_prekey('alice'))
        self.service.publish_hybrid_prekey('alice', self.public)
        self.assertEqual(self.repo.hybrid_prekey('alice'), self.public)

    def test_missing_or_unsupported_backend_fails_closed_without_publication(self):
        target = 'securechat.infrastructure.hybrid_handshake'
        with patch(target + '._MLKEM', None):
            with self.assertRaises(HybridUnavailable):
                self.service.publish_hybrid_prekey('alice', self.public)
        self.assertIsNone(self.repo.hybrid_prekey('alice'))
        with patch(target + '._MLKEM.MLKEM768PublicKey.from_public_bytes',
                   side_effect=UnsupportedAlgorithm('unavailable')):
            with self.assertRaises(HybridUnavailable):
                self.service.publish_hybrid_prekey('alice', self.public)
        self.assertIsNone(self.repo.hybrid_prekey('alice'))
        self.service.publish_hybrid_prekey('alice', self.public)
        self.assertEqual(self.repo.hybrid_prekey('alice'), self.public)

    def test_immutable_conflicting_valid_prekey_fails(self):
        _, different = generate_prekey(crypto, self.alice)
        self.service.publish_hybrid_prekey('alice', self.public)
        with self.assertRaises(ValueError):
            self.service.publish_hybrid_prekey('alice', different)
        self.assertEqual(self.repo.hybrid_prekey('alice'), self.public)

    def test_concurrent_distinct_records_one_wins(self):
        _, second = generate_prekey(crypto, self.alice)
        def publish(record):
            try:
                self.service.publish_hybrid_prekey('alice', record)
                return 'stored'
            except ValueError:
                return 'conflict'
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(publish, [self.public, second])), ['conflict', 'stored'])
        self.assertIn(self.repo.hybrid_prekey('alice'), [self.public, second])

    def test_recipient_verifies_user_pin_and_prekey_independently(self):
        self.service.publish_hybrid_prekey('alice', self.public)
        class Gateway:
            def bundle(inner, name): return self.alice.bundle()
            def hybrid_prekey(inner, name): return self.repo.hybrid_prekey(name)
        bstate = {'identity': self.bob.serialize(), 'contacts': {}, 'sessions': {}, 'history': [], 'outbox': []}
        contact = Client(Gateway(), crypto, lambda _: None, bstate)
        directory = HybridDirectory(contact, Gateway(), HybridPrekeyVerifier())
        with self.assertRaises(ValueError): directory.verified_prekey('alice')
        contact.trust('alice', contact.safety('alice'))
        self.assertEqual(directory.verified_prekey('alice'), self.public)
        changed = copy.deepcopy(self.public); changed['kem_public'] = crypto.b64(bytes(1184))
        Gateway.hybrid_prekey = lambda inner, name: changed
        with self.assertRaises((InvalidSignature, ValueError)):
            directory.verified_prekey('alice')


class LegacyDatabaseMigrationTest(unittest.TestCase):
    def test_adds_table_without_modifying_existing_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'old.db')
            with closing(sqlite3.connect(path)) as db:
                db.execute('CREATE TABLE users (name TEXT PRIMARY KEY, password_hash TEXT NOT NULL, bundle TEXT NOT NULL)')
                db.execute('CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT NOT NULL, sender TEXT NOT NULL, envelope TEXT NOT NULL)')
                db.execute('INSERT INTO users VALUES (?, ?, ?)', ('alice', 'oldhash', '{"old":true}'))
                db.execute('INSERT INTO messages (recipient,sender,envelope) VALUES (?,?,?)', ('alice', 'bobby', '{"ciphertext":"old"}'))
                db.commit()
            SqliteRepository(path)
            with closing(sqlite3.connect(path)) as db:
                self.assertEqual(db.execute('SELECT * FROM users').fetchall(), [('alice','oldhash','{"old":true}')])
                self.assertEqual(db.execute('SELECT recipient,sender,envelope FROM messages').fetchall(), [('alice','bobby','{"ciphertext":"old"}')])
                self.assertIsNotNone(db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='hybrid_prekeys'").fetchone())


class HybridDirectoryHttpTest(unittest.TestCase):
    def test_server_restricts_publication_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'server.db')
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
            def start():
                process = subprocess.Popen([sys.executable, '-m', 'servidor.server', '--port', str(port),
                                            '--database', path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                self.assertIn(b'Local server running', process.stdout.readline())
                return process
            def stop(process):
                process.terminate(); process.wait(timeout=5); process.stdout.close(); process.stderr.close()
            server = start()
            try:
                alice, bob = crypto.Identity.generate('alice'), crypto.Identity.generate('bobby')
                ga, gb = HttpGateway(port), HttpGateway(port)
                ga.register('alice', 'test-password-123', alice.bundle())
                gb.register('bobby', 'test-password-123', bob.bundle())
                ga.login('alice', 'test-password-123'); gb.login('bobby', 'test-password-123')
                private, public = generate_prekey(crypto, alice)
                req = urllib.request.Request(f'http://127.0.0.1:{port}/hybrid-prekey',
                    data=json.dumps({'prekey': public}).encode(), headers={'Content-Type':'application/json'})
                with self.assertRaises(urllib.error.HTTPError) as no_login:
                    urllib.request.urlopen(req)
                self.assertEqual(no_login.exception.code, 401)
                no_login.exception.close()
                with self.assertRaises(urllib.error.HTTPError) as no_read:
                    urllib.request.urlopen(f'http://127.0.0.1:{port}/hybrid-prekey?username=alice')
                self.assertEqual(no_read.exception.code, 401)
                no_read.exception.close()
                with self.assertRaises(urllib.error.HTTPError) as wrong_user:
                    gb.publish_hybrid_prekey(public)
                wrong_user.exception.close()
                self.assertTrue(ga.publish_hybrid_prekey(public)['ok'])
                self.assertTrue(ga.publish_hybrid_prekey(public)['ok'])
                self.assertEqual(gb.hybrid_prekey('alice'), public)
                with open(path, 'rb') as db:
                    contents = db.read()
                self.assertNotIn(crypto.b64(private.private_bytes_raw()).encode(), contents)
                self.assertNotIn(alice.serialize()['signing'].encode(), contents)
                stop(server); server = None
                server = start()
                gb.login('bobby', 'test-password-123')
                self.assertEqual(gb.hybrid_prekey('alice'), public)
            finally:
                if server: stop(server)
