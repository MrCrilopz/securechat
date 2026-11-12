import copy
import os
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

from cliente.application.hybrid_acceptance import HybridReplayError, HybridPersistenceError
from cliente.infrastructure.hybrid_state_store import HybridStateStore
from securechat.infrastructure.ratchet_durable_bootstrap import DurableBootstrap
from securechat.infrastructure.ratchet_bootstrap import initiate, BootstrapError
from securechat.infrastructure.ratchet_provider import CryptographyRatchet
from securechat.infrastructure.identity import Identity

class DurableBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, 'ratchet.db'); self.key = bytes(range(32))
        self.provider = CryptographyRatchet(); self.alice = Identity.generate('alice'); self.bob = Identity.generate('bob')
        self.a = self.alice.bundle(); self.b = self.bob.bundle()
        self.alice_state, self.packet = initiate(self.provider, self.alice, self.b, self.b, b'test')
    def make(self):
        return DurableBootstrap(self.provider, self.bob, self.a, HybridStateStore(self.path, self.key))
    def test_replay_restart_recovery_and_altered_packet(self):
        expected = self.make().accept(self.packet)
        with self.assertRaises(HybridReplayError): self.make().accept(self.packet)
        self.assertEqual(self.make().recover(self.packet), expected)
        altered = copy.deepcopy(self.packet); altered['ciphertext'] = altered['ciphertext'][:-2] + 'AA'
        with self.assertRaises((BootstrapError, HybridPersistenceError)): self.make().recover(altered)
    def test_competing_acceptances_one_wins(self):
        def run(_):
            try: self.make().accept(self.packet); return 'ok'
            except HybridReplayError: return 'replay'
        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(sorted(pool.map(run, range(2))), ['ok', 'replay'])
    def test_tamper_fails_before_persistence(self):
        altered = copy.deepcopy(self.packet); altered['session'] = altered['session'][:-2] + 'AA'
        with self.assertRaises(BootstrapError): self.make().accept(altered)
        self.assertEqual(self.make().accept(self.packet)[1], b'test')
