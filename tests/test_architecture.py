"""Comprueba reloj y token inyectados, y el rechazo de dos sesiones iniciales simultáneas."""
import unittest
from securechat.application.service import ChatService
from securechat.application.ports import CryptoProvider, Clock, TokenGenerator

class Repository:
    def __init__(self): self.tokens = {}
    def user(self, name): return {'password_hash': 'encoded'} if name == 'alice' else None
    def save_token(self, digest, name, expires): self.tokens[digest] = (name, expires)
    def token_user(self, digest, now):
        item = self.tokens.get(digest)
        return item[0] if item and item[1] > now else None
class Hasher:
    def verify(self, encoded, password): return password == 'password'

class ArchitectureTest(unittest.TestCase):
    def test_time_and_token_are_supplied_through_ports(self):
        repository = Repository()
        service = ChatService(repository, Hasher(), None, clock=lambda: 100, token_generator=lambda: 'fixed-test-token')
        token = service.login('alice', 'password')
        self.assertEqual(token, 'fixed-test-token')
        self.assertEqual(service.authorize(token), 'alice')
        self.assertEqual(next(iter(repository.tokens.values()))[1], 3700)

class SimultaneousSessionTest(unittest.TestCase):
    def test_simultaneous_first_messages_are_rejected_not_merged(self):
        from securechat.application.client import Client
        from securechat.infrastructure import crypto
        alice_id, bob_id = crypto.Identity.generate('alice'), crypto.Identity.generate('bobby')
        bundles = {'alice': alice_id.bundle(), 'bobby': bob_id.bundle()}
        messages = {'alice': [], 'bobby': []}
        class Gateway:
            def __init__(self, user): self.user = user
            def bundle(self, name): return bundles[name]
            def send(self, recipient, envelope): messages[recipient].append({'id': 1, 'envelope': envelope})
            def inbox(self): return messages[self.user]
            def acknowledge(self, message_id): pass
        def client(name, identity):
            state = {'identity': identity.serialize(), 'contacts': {}, 'sessions': {}, 'history': [], 'outbox': []}
            return Client(Gateway(name), crypto, lambda _: None, state)
        alice, bob = client('alice', alice_id), client('bobby', bob_id)
        safety = alice.safety('bobby'); alice.trust('bobby', safety); bob.trust('alice', safety)
        alice.send('bobby', 'first'); bob.send('alice', 'also first')
        with self.assertRaisesRegex(ValueError, 'Unexpected concurrent or replaced session'): alice.receive()
        with self.assertRaisesRegex(ValueError, 'Unexpected concurrent or replaced session'): bob.receive()
