"""El estado local rechaza escrituras obsoletas entre procesos cooperantes."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest

from cliente.infrastructure import local_store
from cliente.application.client import Client
from securechat.infrastructure import crypto


class LocalStateConcurrencyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, 'alice.json')
        self.password = 'example-password-2026'
        self.original = {'identity': crypto.Identity.generate('alice').serialize(), 'contacts': {},
                         'sessions': {}, 'history': [], 'outbox': []}
        local_store.save(self.path, self.password, copy.deepcopy(self.original))

    def test_separate_process_stale_write_is_rejected_and_reload_can_continue(self):
        code = '''import os, time
from cliente.infrastructure import local_store
state = local_store.load(os.environ['TEST_PATH'], os.environ['TEST_PASSWORD'])
state['history'].append({'peer': 'bobby', 'direction': 'out', 'text': os.environ['TEST_MARKER']})
open(os.environ['TEST_READY'], 'w').close()
while not os.path.exists(os.environ['TEST_GO']): time.sleep(.005)
try:
    local_store.save(os.environ['TEST_PATH'], os.environ['TEST_PASSWORD'], state)
    print('saved', flush=True)
except local_store.StaleLocalStateError:
    print('stale', flush=True)
'''
        go = os.path.join(self.tmp.name, 'go')
        ready = [os.path.join(self.tmp.name, f'ready-{i}') for i in range(2)]
        processes = []
        try:
            for index in range(2):
                env = dict(os.environ, TEST_PATH=self.path, TEST_PASSWORD=self.password, TEST_GO=go,
                           TEST_READY=ready[index], TEST_MARKER=f'mensaje-{index}')
                processes.append(subprocess.Popen([sys.executable, '-c', code], env=env, stdout=subprocess.PIPE,
                                                  stderr=subprocess.PIPE, text=True))
            deadline = time.monotonic() + 15
            while not all(os.path.exists(p) for p in ready):
                if time.monotonic() > deadline or any(p.poll() is not None for p in processes):
                    self.fail('Los procesos no alcanzaron la barrera de lectura')
                time.sleep(.01)
            with open(go, 'w') as f: f.write('go')
            results = []
            for process in processes:
                out, err = process.communicate(timeout=30)
                self.assertEqual(process.returncode, 0, err)
                results.append(out.strip())
            self.assertEqual(sorted(results), ['saved', 'stale'])
            current = local_store.load(self.path, self.password)
            self.assertEqual(len(current['history']), 1)
            current['history'].append({'peer': 'bobby', 'direction': 'out', 'text': 'recargado'})
            local_store.save(self.path, self.password, current)
            self.assertEqual(len(local_store.load(self.path, self.password)['history']), 2)
        finally:
            for process in processes:
                if process.poll() is None: process.kill(); process.communicate()

    def test_raw_dict_cannot_overwrite_existing_state(self):
        changed = copy.deepcopy(self.original)
        changed['history'].append({'peer':'bobby', 'direction':'out', 'text':'stale'})
        with self.assertRaises(local_store.StaleLocalStateError):
            local_store.save(self.path, self.password, changed)
        self.assertEqual(local_store.load(self.path, self.password), self.original)

    def test_successive_client_commits_adopt_revision(self):
        identity = crypto.Identity.restore(self.original['identity'])
        bob = crypto.Identity.generate('bobby')
        class Gateway:
            def bundle(self, name): return bob.bundle()
        loaded = local_store.load(self.path, self.password)
        client = Client(Gateway(), crypto, lambda state: local_store.save(self.path, self.password, state), loaded)
        safety = client.safety('bobby')
        client.trust('bobby', safety)
        client.trust('bobby', safety)
        self.assertEqual(local_store.load(self.path, self.password)['contacts']['bobby']['identity'], bob.bundle()['identity'])

    def test_removed_file_does_not_allow_stale_snapshot_to_recreate(self):
        snapshot = local_store.load(self.path, self.password)
        os.unlink(self.path)
        with self.assertRaises(local_store.StaleLocalStateError):
            local_store.save(self.path, self.password, snapshot)
        self.assertFalse(os.path.exists(self.path))

    def test_existing_legacy_encrypted_file_loads_and_upgrades_on_save(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        salt, nonce = os.urandom(16), os.urandom(12)
        legacy = AESGCM(local_store.key(self.password, salt)).encrypt(
            nonce, json.dumps(self.original).encode(), b'securechat local v1')
        record = {'salt': crypto.b64(salt), 'nonce': crypto.b64(nonce), 'ciphertext': crypto.b64(legacy)}
        with open(self.path, 'w') as output: json.dump(record, output)
        first = local_store.load(self.path, self.password)
        stale = local_store.load(self.path, self.password)
        self.assertEqual(first, self.original)
        first['history'].append({'peer': 'bobby', 'direction': 'out', 'text': 'new'})
        local_store.save(self.path, self.password, first)
        with open(self.path) as source: upgraded = json.load(source)
        self.assertRegex(upgraded['revision'], r'^[0-9a-f]{32}$')
        with self.assertRaises(local_store.StaleLocalStateError): local_store.save(self.path, self.password, stale)
        self.assertEqual(len(local_store.load(self.path, self.password)['history']), 1)

    def test_revision_is_authenticated_and_cannot_be_removed(self):
        from cryptography.exceptions import InvalidTag
        with open(self.path) as source: record = json.load(source)
        for change in ('modified', 'removed'):
            bad = dict(record)
            if change == 'modified': bad['revision'] = '0' * 32
            else: bad.pop('revision')
            with open(self.path, 'w') as output: json.dump(bad, output)
            with self.subTest(change=change), self.assertRaises(InvalidTag):
                local_store.load(self.path, self.password)

    def test_stale_client_is_invalidated_then_fresh_client_can_reload(self):
        from securechat.domain.errors import ClientStateInvalidated, LocalStateWriteFailed
        bob = crypto.Identity.generate('bobby')
        class Gateway:
            def bundle(self, name): return bob.bundle()
        first_state = local_store.load(self.path, self.password)
        second_state = local_store.load(self.path, self.password)
        persist = lambda state: local_store.save(self.path, self.password, state)
        first = Client(Gateway(), crypto, persist, first_state)
        second = Client(Gateway(), crypto, persist, second_state)
        safety = first.safety('bobby')
        first.trust('bobby', safety)
        with self.assertRaises(LocalStateWriteFailed): second.trust('bobby', safety)
        with self.assertRaises(ClientStateInvalidated): second.trust('bobby', safety)
        fresh = Client(Gateway(), crypto, persist, local_store.load(self.path, self.password))
        fresh.trust('bobby', safety)
        self.assertTrue(local_store.load(self.path, self.password)['contacts']['bobby']['verified'])

    def test_stale_client_cannot_publish_new_message(self):
        from securechat.domain.errors import LocalStateWriteFailed
        bob = crypto.Identity.generate('bobby')
        sent = []
        class Gateway:
            def bundle(self, name): return bob.bundle()
            def send(self, recipient, envelope): sent.append((recipient, envelope))
        gateway = Gateway()
        persist = lambda state: local_store.save(self.path, self.password, state)
        setup = Client(gateway, crypto, persist, local_store.load(self.path, self.password))
        setup.trust('bobby', setup.safety('bobby'))
        first = Client(gateway, crypto, persist, local_store.load(self.path, self.password))
        stale = Client(gateway, crypto, persist, local_store.load(self.path, self.password))
        first.send('bobby', 'first')
        with self.assertRaises(LocalStateWriteFailed):
            stale.send('bobby', 'must not be sent')
        self.assertEqual(len(sent), 1)
        self.assertEqual([row['text'] for row in local_store.load(self.path, self.password)['history']], ['first'])

class AliasSafetyTests(unittest.TestCase):
    def test_rejects_symbolic_and_hard_links(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, 'state.json')
            local_store.save(path, 'password', {'value': 1})
            symbolic = os.path.join(folder, 'symbolic.json')
            os.symlink(path, symbolic)
            with self.assertRaises(OSError):
                local_store.load(symbolic, 'password')
            os.unlink(symbolic)
            hard = os.path.join(folder, 'hard.json')
            os.link(path, hard)
            with self.assertRaises(OSError):
                local_store.load(path, 'password')
            with self.assertRaises(OSError):
                local_store.load(hard, 'password')

    def test_parent_symlink_uses_same_revision_and_lock(self):
        with tempfile.TemporaryDirectory() as folder:
            real = os.path.join(folder, 'real')
            os.mkdir(real)
            alias = os.path.join(folder, 'alias')
            os.symlink(real, alias)
            path = os.path.join(real, 'state.json')
            local_store.save(path, 'password', {'value': 1})
            a = local_store.load(path, 'password')
            b = local_store.load(os.path.join(alias, 'state.json'), 'password')
            a['value'] = 2
            local_store.save(path, 'password', a)
            b['value'] = 3
            with self.assertRaises(local_store.StaleLocalStateError):
                local_store.save(os.path.join(alias, 'state.json'), 'password', b)

    def test_existing_loaded_state_rejects_new_hard_link_before_save(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, 'state.json')
            local_store.save(path, 'password', {'value': 1})
            state = local_store.load(path, 'password')
            os.link(path, os.path.join(folder, 'alias.json'))
            state['value'] = 2
            with self.assertRaises(OSError):
                local_store.save(path, 'password', state)
