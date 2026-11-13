"""Nonce handling, state rollback and legacy message compatibility."""
import copy
import unittest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from securechat.infrastructure import crypto
from securechat.infrastructure.encoding import b64, unb64, canonical
from securechat.infrastructure.ratchet import advance

class NonceSafetyTests(unittest.TestCase):
    def setUp(self):
        self.alice = crypto.Identity.generate('alice')
        self.bob = crypto.Identity.generate('bobby')
        self.sender, header = crypto.initiate(self.alice, self.bob.bundle())
        self.receiver = crypto.accept(self.bob, self.alice.bundle(), header)

    def test_nonce_is_the_counter_and_a_restored_copy_repeats_it(self):
        fresh = copy.deepcopy(self.sender)
        restored = copy.deepcopy(self.sender)
        first = crypto.encrypt(fresh, 'first')
        repeated = crypto.encrypt(restored, 'other plaintext')
        second = crypto.encrypt(fresh, 'second')
        self.assertEqual(unb64(first['nonce']), b'\x01' + (0).to_bytes(11, 'big'))
        self.assertEqual(first['nonce'], repeated['nonce'])
        self.assertEqual(unb64(second['nonce']), b'\x01' + (1).to_bytes(11, 'big'))
        self.assertEqual(crypto.decrypt(copy.deepcopy(self.receiver), first), 'first')
        advanced = copy.deepcopy(self.receiver)
        crypto.decrypt(advanced, first)
        self.assertEqual(crypto.decrypt(advanced, second), 'second')

    def test_legacy_message_with_zero_nonce_remains_readable(self):
        s = self.sender
        metadata = {'session': s['session'], 'sender': s['me'], 'recipient': s['peer'], 'counter': 0}
        key, _ = advance(unb64(s['send_key']))
        legacy = dict(metadata, ciphertext=b64(AESGCM(key).encrypt(bytes(12), b'legacy', canonical(metadata))))
        self.assertEqual(crypto.decrypt(self.receiver, legacy), 'legacy')

    def test_tampered_nonce_is_rejected_without_advancing_state(self):
        message = crypto.encrypt(self.sender, 'secret')
        original_state = copy.deepcopy(self.receiver)
        tampered = dict(message)
        raw = bytearray(unb64(message['nonce'])); raw[0] ^= 1
        tampered['nonce'] = b64(raw)
        with self.assertRaises(InvalidTag):
            crypto.decrypt(self.receiver, tampered)
        self.assertEqual(self.receiver, original_state)
        self.assertEqual(crypto.decrypt(self.receiver, message), 'secret')

    def test_invalid_nonce_size_is_rejected_without_state_change(self):
        message = crypto.encrypt(self.sender, 'secret')
        original_state = copy.deepcopy(self.receiver)
        message['nonce'] = b64(b'bad')
        with self.assertRaises(ValueError):
            crypto.decrypt(self.receiver, message)
        self.assertEqual(self.receiver, original_state)

class MalformedNonceIntegrationTest(unittest.TestCase):
    def test_heartbeat_alerts_for_malformed_nonce_and_preserves_message(self):
        import http.cookiejar, json, os, re, socket, sqlite3, subprocess, sys, tempfile, urllib.parse, urllib.request
        with tempfile.TemporaryDirectory() as directory:
            def port():
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]
            sp, up = port(), port(); dbpath = os.path.join(directory, 'server.db')
            server = subprocess.Popen([sys.executable, '-m', 'securechat.server', '--port', str(sp), '--database', dbpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ui = None
            try:
                server.stdout.readline()
                ui = subprocess.Popen([sys.executable, '-m', 'securechat.ui', '--port', str(up), '--server-port', str(sp), '--database', dbpath, '--home', os.path.join(directory, 'clients')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                ui.stdout.readline(); base = f'http://127.0.0.1:{up}'
                def browser():
                    client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                    page = client.open(base).read().decode()
                    token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
                    def post(**fields):
                        fields['csrf'] = token
                        req = urllib.request.Request(base + '/', data=urllib.parse.urlencode(fields).encode(), headers={'Origin':base})
                        return client.open(req).read().decode()
                    return post
                a, b = browser(), browser()
                a(action='register', user='alice', password='example-password-123')
                b(action='register', user='bobby', password='example-password-123')
                fingerprint_a = re.search(r'[a-f0-9]{64}', a(action='safety', peer='bobby')).group()
                fingerprint_b = re.search(r'[a-f0-9]{64}', b(action='safety', peer='alice')).group()
                a(action='trust', peer='bobby', safety=fingerprint_a); b(action='trust', peer='alice', safety=fingerprint_b)
                a(action='send', peer='bobby', message='confidencial')
                db = sqlite3.connect(dbpath)
                try:
                    rowid, raw = db.execute('SELECT id, envelope FROM messages').fetchone()
                    envelope = json.loads(raw); envelope['message']['nonce'] = b64(b'bad')
                    db.execute('UPDATE messages SET envelope=? WHERE id=?', (json.dumps(envelope), rowid)); db.commit()
                finally: db.close()
                b(action='select', peer='alice')
                response = json.loads(b(action='heartbeat'))
                self.assertIn('rechazado', response['alert'])
                self.assertNotIn('confidencial', response['alert'])
                self.assertNotIn('confidencial', str(response.get('history', [])))
                db = sqlite3.connect(dbpath)
                try: self.assertEqual(db.execute('SELECT count(*) FROM messages').fetchone()[0], 1)
                finally: db.close()
            finally:
                for proc in (ui, server):
                    if proc: proc.terminate(); proc.wait(timeout=5); proc.stdout.close(); proc.stderr.close()
