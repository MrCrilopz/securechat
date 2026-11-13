"""Ensure approved provider preserves existing digest and MAC encodings."""
from contextlib import closing
import hashlib
import hmac
import os
import sqlite3
import tempfile
import time
import unittest
from securechat.infrastructure.hashing import sha256, hmac_sha256
from securechat.infrastructure import crypto
from securechat.infrastructure.encoding import canonical
from securechat.infrastructure.ratchet import advance
from securechat.infrastructure.server_adapters import SqliteRepository

class AllowedHashingTest(unittest.TestCase):
    def test_sha256_and_hmac_match_existing_encodings(self):
        for data in (b'', b'abc', bytes(range(256))):
            self.assertEqual(sha256(data), hashlib.sha256(data).digest())
            for key in (b'', b'key', bytes(range(256))):
                self.assertEqual(hmac_sha256(key, data), hmac.digest(key, data, 'sha256'))
        self.assertEqual(advance(b'key'), (hmac.digest(b'key', b'message', 'sha256'), hmac.digest(b'key', b'next', 'sha256')))

    def test_identity_fingerprint_matches_original_algorithm(self):
        first, second = crypto.Identity.generate('alice').bundle(), crypto.Identity.generate('bobby').bundle()
        keys = sorted(canonical({k: bundle[k] for k in ('username', 'identity', 'agreement')}) for bundle in (first, second))
        expected = hashlib.sha256(b'securechat safety v1\0' + keys[0] + b'\0' + keys[1]).hexdigest()
        self.assertEqual(crypto.fingerprint(first, second), expected)

    def test_existing_token_hash_remains_usable(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'server.db')
            repo = SqliteRepository(path)
            token = 'existing-token-ñ'
            with closing(sqlite3.connect(path)) as db:
                with db:
                    db.execute('INSERT INTO tokens VALUES (?, ?, ?)', (hashlib.sha256(token.encode()).hexdigest(), 'alice', time.time() + 60))
            self.assertEqual(repo.token_user(token, time.time()), 'alice')
            repo.revoke_token(token)
            self.assertIsNone(repo.token_user(token, time.time()))
