"""Conservative handling of old counters with stored received-envelope evidence."""
import copy
import unittest
from securechat.application.client import Client
from securechat.domain.errors import ReusedNonceCounter, UnexpectedOldMessage
from securechat.infrastructure import crypto

class MemoryGateway:
    def __init__(self, user, bundles, queues):
        self.user, self.bundles, self.queues = user, bundles, queues
        self.acknowledged = []
        self.fail_ack = False
        self.issued = {}
    def reserve_send_counter(self, recipient, session, counter):
        current = self.issued.get((recipient, session), 0)
        if counter != current: raise ReusedNonceCounter('Send counter already used')
        self.issued[(recipient, session)] = counter + 1
    def bundle(self, name): return self.bundles[name]
    def send(self, recipient, envelope):
        self.queues[recipient].append({'id': len(self.acknowledged) + len(self.queues[recipient]) + 1, 'envelope': copy.deepcopy(envelope)})
    def inbox(self): return copy.deepcopy(self.queues[self.user])
    def acknowledge(self, message_id):
        if self.fail_ack: raise OSError('ack lost')
        self.acknowledged.append(message_id)
        self.queues[self.user] = [item for item in self.queues[self.user] if item['id'] != message_id]

class ReplayEvidenceTest(unittest.TestCase):
    def setUp(self):
        a, b = crypto.Identity.generate('alice'), crypto.Identity.generate('bobby')
        bundles = {'alice': a.bundle(), 'bobby': b.bundle()}; queues = {'alice': [], 'bobby': []}
        self.a_gateway, self.b_gateway = MemoryGateway('alice', bundles, queues), MemoryGateway('bobby', bundles, queues)
        def mk(g, identity):
            state = {'identity': identity.serialize(), 'contacts': {}, 'sessions': {}, 'history': [], 'outbox': []}
            return Client(g, crypto, lambda _: None, state)
        self.a, self.b = mk(self.a_gateway, a), mk(self.b_gateway, b)
        number = self.a.safety('bobby'); self.a.trust('bobby', number); self.b.trust('alice', number)
        session, header = crypto.initiate(self.a.identity, bundles['bobby'])
        self.a.state['sessions']['bobby'] = {'state': session, 'header': header}

    def test_sender_rollback_does_not_encrypt_a_second_message(self):
        old_sender = copy.deepcopy(self.a.state)
        self.a.send('bobby', 'first'); self.assertEqual(self.b.receive(), [('alice', 'first')])
        self.a.state.clear(); self.a.state.update(copy.deepcopy(old_sender))
        with self.assertRaises(ReusedNonceCounter):
            self.a.send('bobby', 'different after restoring old state')
        self.assertEqual(self.a.state, old_sender)
        self.assertEqual(self.b_gateway.inbox(), [])

    def test_exact_duplicate_after_lost_ack_is_safely_acknowledged(self):
        self.a.send('bobby', 'once'); self.b_gateway.fail_ack = True
        with self.assertRaises(OSError): self.b.receive()
        prior = copy.deepcopy(self.b.state)
        self.b_gateway.fail_ack = False
        self.assertEqual(self.b.receive(), [])
        self.assertEqual(self.b.state, prior)
        self.assertEqual(self.b_gateway.inbox(), [])
        self.assertEqual(len(self.b.state['history']), 1)

    def test_legacy_state_without_evidence_fails_closed(self):
        self.a.send('bobby', 'legacy'); self.b_gateway.fail_ack = True
        with self.assertRaises(OSError): self.b.receive()
        self.b_gateway.fail_ack = False
        self.b.state['sessions']['alice'].pop('received_digests', None)
        prior = copy.deepcopy(self.b.state)
        with self.assertRaises(UnexpectedOldMessage): self.b.receive()
        self.assertEqual(self.b.state, prior)
        self.assertEqual(len(self.b_gateway.inbox()), 1)

class ReplayHeartbeatTest(unittest.TestCase):
    def test_heartbeat_surfaces_old_counter_alert_and_preserves_queue(self):
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
                    page = client.open(base).read().decode(); token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
                    def post(**fields):
                        fields['csrf'] = token
                        req = urllib.request.Request(base + '/', data=urllib.parse.urlencode(fields).encode(), headers={'Origin':base})
                        return client.open(req).read().decode()
                    return post
                a, b = browser(), browser()
                a(action='register', user='alice', password='example-password-123')
                b(action='register', user='bobby', password='example-password-123')
                fa = re.search(r'[a-f0-9]{64}', a(action='safety', peer='bobby')).group()
                fb = re.search(r'[a-f0-9]{64}', b(action='safety', peer='alice')).group()
                a(action='trust', peer='bobby', safety=fa); b(action='trust', peer='alice', safety=fb)
                a(action='send', peer='bobby', message='original')
                db = sqlite3.connect(dbpath)
                try: envelope = json.loads(db.execute('SELECT envelope FROM messages').fetchone()[0])
                finally: db.close()
                self.assertIn('original', b(action='select', peer='alice'))
                raw = bytearray(crypto.unb64(envelope['message']['ciphertext'])); raw[0] ^= 1
                envelope['message']['ciphertext'] = crypto.b64(raw)
                db = sqlite3.connect(dbpath)
                try:
                    db.execute('INSERT INTO messages (recipient, sender, envelope) VALUES (?, ?, ?)', ('bobby','alice',json.dumps(envelope))); db.commit()
                finally: db.close()
                response = json.loads(b(action='heartbeat'))
                self.assertIn('ALERTA', response['alert'])
                self.assertIn('contador', response['alert'].lower())
                self.assertEqual([item['text'] for item in response['history']], ['original'])
                db = sqlite3.connect(dbpath)
                try: self.assertEqual(db.execute('SELECT count(*) FROM messages').fetchone()[0], 1)
                finally: db.close()
            finally:
                for proc in (ui, server):
                    if proc: proc.terminate(); proc.wait(timeout=5); proc.stdout.close(); proc.stderr.close()
