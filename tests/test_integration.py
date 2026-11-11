"""Comprueba en un servidor real que el mensaje llega y el disco no guarda el texto."""
import os, socket, subprocess, sys, tempfile, time, unittest
from securechat.infrastructure.http_gateway import HttpGateway
from securechat.infrastructure import crypto
from securechat.application.client import Client

class IntegrationTest(unittest.TestCase):
    def test_real_server_delivery_and_stored_ciphertext(self):
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
            db = os.path.join(directory, 'server.db')
            server = subprocess.Popen([sys.executable, '-m', 'securechat.server', '--port', str(port), '--database', db], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertIn(b'Local server running', server.stdout.readline())
                a, b = crypto.Identity.generate('alice'), crypto.Identity.generate('bobby')
                ga, gb = HttpGateway(port), HttpGateway(port)
                ga.register('alice', 'secret password alice', a.bundle()); gb.register('bobby', 'secret password bobby', b.bundle())
                ga.login('alice', 'secret password alice'); gb.login('bobby', 'secret password bobby')
                def make(g, identity):
                    state = {'identity': identity.serialize(), 'contacts': {}, 'sessions': {}, 'history': [], 'outbox': []}
                    return Client(g, crypto, lambda _: None, state)
                alice, bob = make(ga, a), make(gb, b)
                number = alice.safety('bobby'); self.assertEqual(number, bob.safety('alice'))
                alice.trust('bobby', number); bob.trust('alice', number)
                alice.send('bobby', 'private test message')
                with open(db, 'rb') as dbfile: self.assertNotIn(b'private test message', dbfile.read())
                self.assertEqual(bob.receive(), [('alice', 'private test message')])
                bob.send('alice', 'answer'); self.assertEqual(alice.receive(), [('bobby', 'answer')])
            finally:
                server.terminate(); server.wait(timeout=5)
                server.stdout.close(); server.stderr.close()
