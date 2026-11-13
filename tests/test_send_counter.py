"""El servidor entrega cada contador una sola vez y el cliente no cifra si ya se usó."""
import copy
import os
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from securechat.application.client import Client
from securechat.domain.errors import ReusedNonceCounter
from securechat.infrastructure import crypto
from securechat.infrastructure.http_gateway import HttpGateway
from securechat.infrastructure.server_adapters import SqliteRepository


class SendCounterRepositoryTest(unittest.TestCase):
    def test_reserve_is_exclusive_and_a_different_envelope_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = SqliteRepository(os.path.join(directory, 'db.sqlite'))
            repo.reserve_send_counter('alice', 'bobby', 'session-1', 0)
            with self.assertRaises(ReusedNonceCounter):
                repo.reserve_send_counter('alice', 'bobby', 'session-1', 0)
            first = {'message': {'sender': 'alice', 'recipient': 'bobby', 'session': 'session-1', 'counter': 0, 'ciphertext': 'one'}}
            second = dict(first, message=dict(first['message'], ciphertext='two'))
            self.assertGreater(repo.enqueue('bobby', 'alice', first), 0)
            self.assertEqual(repo.enqueue('bobby', 'alice', first), repo.enqueue('bobby', 'alice', first))
            with self.assertRaises(ReusedNonceCounter):
                repo.enqueue('bobby', 'alice', second)
            repo.reserve_send_counter('alice', 'bobby', 'session-1', 1)

    def test_dr_slot_is_unique_per_ratchet_key_and_repeat_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = SqliteRepository(os.path.join(directory, 'db.sqlite'))
            session = 'ab' * 16
            first_key = 'cd' * 32
            other_key = 'ef' * 32
            def packet(dh, number, ciphertext):
                return {'message': {'sender': 'alice', 'recipient': 'bobby', 'protocol': 'double-ratchet',
                                    'version': 1, 'session_id': session,
                                    'packet': {'header': {'dh': dh, 'pn': 0, 'n': number},
                                               'nonce': '00' * 12, 'ciphertext': ciphertext}}}
            repo.reserve_dr_send('alice', 'bobby', session, first_key, 0)
            with self.assertRaises(ReusedNonceCounter):
                repo.reserve_dr_send('alice', 'bobby', session, first_key, 0)
            first = packet(first_key, 0, 'aa' * 16)
            other = packet(first_key, 0, 'bb' * 16)
            self.assertGreater(repo.enqueue('bobby', 'alice', first), 0)
            self.assertEqual(repo.enqueue('bobby', 'alice', first), repo.enqueue('bobby', 'alice', first))
            with self.assertRaises(ReusedNonceCounter):
                repo.enqueue('bobby', 'alice', other)
            repo.reserve_dr_send('alice', 'bobby', session, other_key, 0)
            self.assertGreater(repo.enqueue('bobby', 'alice', packet(other_key, 0, 'cc' * 16)), 0)

    def test_concurrent_reserve_of_the_same_counter_allows_one(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = SqliteRepository(os.path.join(directory, 'db.sqlite'))
            gate = threading.Barrier(2)
            results = []
            def attempt():
                gate.wait()
                try:
                    repo.reserve_send_counter('alice', 'bobby', 'session-1', 0)
                    results.append('ok')
                except ReusedNonceCounter:
                    results.append('used')
            threads = [threading.Thread(target=attempt) for _ in range(2)]
            for thread in threads: thread.start()
            for thread in threads: thread.join()
            self.assertCountEqual(results, ['ok', 'used'])


class RestoredClientHttpTest(unittest.TestCase):
    def test_restored_client_does_not_encrypt_again(self):
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
            server = subprocess.Popen([sys.executable, '-m', 'securechat.server', '--port', str(port), '--database', os.path.join(directory, 'server.db')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertIn(b'Local server running', server.stdout.readline())
                alice_id, bob_id = crypto.Identity.generate('alice'), crypto.Identity.generate('bobby')
                alice_gateway, bob_gateway = HttpGateway(port), HttpGateway(port)
                alice_gateway.register('alice', 'secret password alice', alice_id.bundle())
                bob_gateway.register('bobby', 'secret password bobby', bob_id.bundle())
                alice_gateway.login('alice', 'secret password alice')
                bob_gateway.login('bobby', 'secret password bobby')
                def make(gateway, identity):
                    state = {'identity': identity.serialize(), 'contacts': {}, 'sessions': {}, 'history': [], 'outbox': []}
                    return Client(gateway, crypto, lambda _: None, state)
                alice, bob = make(alice_gateway, alice_id), make(bob_gateway, bob_id)
                number = alice.safety('bobby')
                alice.trust('bobby', number); bob.trust('alice', number)
                session, header = crypto.initiate(alice.identity, bob_id.bundle())
                alice.state['sessions']['bobby'] = {'state': session, 'header': header}
                previous = copy.deepcopy(alice.state)
                alice.send('bobby', 'primero')
                alice.state.clear(); alice.state.update(copy.deepcopy(previous))
                with self.assertRaises(ReusedNonceCounter):
                    alice.send('bobby', 'otro texto')
                self.assertEqual(alice.state, previous)
                self.assertEqual(bob.receive(), [('alice', 'primero')])
                with open(os.path.join(directory, 'server.db'), 'rb') as stored_file:
                    stored = stored_file.read()
                self.assertNotIn(b'otro texto', stored)
                self.assertNotIn(b'primero', stored)
            finally:
                server.terminate(); server.wait(timeout=5)
                server.stdout.close(); server.stderr.close()

    def test_restored_dr_client_does_not_encrypt_the_same_send_again(self):
        from cliente.infrastructure.dr_chat import DoubleRatchetChat
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0)); port = sock.getsockname()[1]
            server = subprocess.Popen([sys.executable, '-m', 'securechat.server', '--port', str(port), '--database', os.path.join(directory, 'server.db')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertIn(b'Local server running', server.stdout.readline())
                alice_id, bob_id = crypto.Identity.generate('alice'), crypto.Identity.generate('bobby')
                alice_gateway, bob_gateway = HttpGateway(port), HttpGateway(port)
                alice_gateway.register('alice', 'secret password alice', alice_id.bundle())
                bob_gateway.register('bobby', 'secret password bobby', bob_id.bundle())
                alice_gateway.login('alice', 'secret password alice')
                bob_gateway.login('bobby', 'secret password bobby')
                def make(gateway, identity):
                    state = {'identity': identity.serialize(), 'contacts': {}, 'sessions': {}, 'history': [], 'outbox': []}
                    return Client(gateway, crypto, lambda _: None, state, dr=DoubleRatchetChat())
                alice, bob = make(alice_gateway, alice_id), make(bob_gateway, bob_id)
                number = alice.safety('bobby')
                alice.trust('bobby', number); bob.trust('alice', number)
                alice.send_dr('bobby', 'inicio')
                self.assertEqual(bob.receive(), [('alice', 'inicio')])
                previous = copy.deepcopy(alice.state)
                alice.send_dr('bobby', 'siguiente')
                alice.state.clear(); alice.state.update(copy.deepcopy(previous))
                with self.assertRaises(ReusedNonceCounter):
                    alice.send_dr('bobby', 'repetido')
                self.assertEqual(alice.state, previous)
                self.assertEqual(bob.receive(), [('alice', 'siguiente')])
                with open(os.path.join(directory, 'server.db'), 'rb') as stored_file:
                    stored = stored_file.read()
                self.assertNotIn(b'repetido', stored)
                self.assertNotIn(b'siguiente', stored)
            finally:
                server.terminate(); server.wait(timeout=5)
                server.stdout.close(); server.stderr.close()
