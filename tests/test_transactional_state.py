"""No mensaje se descarta por un fallo al persistir el estado local."""
import copy
import unittest
from securechat.application.client import Client
from securechat.infrastructure import crypto
from tests.test_replay_evidence import MemoryGateway

class TransactionalStateTest(unittest.TestCase):
    def setUp(self):
        ids={name:crypto.Identity.generate(name) for name in ('alice','bobby')}
        bundles={name:identity.bundle() for name,identity in ids.items()}
        queues={'alice': [],'bobby': []}
        self.ga,self.gb=MemoryGateway('alice',bundles,queues),MemoryGateway('bobby',bundles,queues)
        self.durable={};self.blocked=set();self.calls={}
        def make(user,gateway):
            state={'identity':ids[user].serialize(),'contacts':{},'sessions':{},'history':[],'outbox':[]}
            def persist(data):
                self.calls[user]=self.calls.get(user,0)+1
                if user in self.blocked: raise OSError('storage failed')
                self.durable[user]=copy.deepcopy(data)
            return Client(gateway,crypto,persist,state)
        self.alice,self.bob=make('alice',self.ga),make('bobby',self.gb)
        fp=self.alice.safety('bobby');self.alice.trust('bobby',fp);self.bob.trust('alice',fp)
        self.persist_bob=self.bob.persist;self.persist_alice=self.alice.persist

    def test_receive_persist_failure_keeps_memory_queue_and_retry_after_restart(self):
        self.alice.send('bobby','first')
        original=copy.deepcopy(self.bob.state); durable=copy.deepcopy(self.durable['bobby'])
        self.blocked.add('bobby')
        with self.assertRaises(OSError):self.bob.receive()
        self.assertEqual(self.bob.state,original)
        self.assertEqual(self.durable['bobby'],durable)
        self.assertEqual(len(self.gb.inbox()),1);self.assertEqual(self.gb.acknowledged,[])
        self.blocked.remove('bobby')
        restarted=Client(self.gb,crypto,self.persist_bob,copy.deepcopy(self.durable['bobby']))
        self.assertEqual(restarted.receive(),[('alice','first')]);self.assertEqual(self.gb.inbox(),[])
        self.assertEqual([x['text'] for x in self.durable['bobby']['history']],['first'])

    def test_receive_retry_in_same_process_after_storage_recovers(self):
        self.alice.send('bobby', 'retry')
        self.blocked.add('bobby')
        with self.assertRaises(OSError): self.bob.receive()
        self.blocked.remove('bobby')
        from securechat.domain.errors import ClientStateInvalidated
        with self.assertRaises(ClientStateInvalidated): self.bob.receive()
        self.bob = Client(self.gb, crypto, self.persist_bob, copy.deepcopy(self.durable['bobby']))
        self.assertEqual(self.bob.receive(), [('alice', 'retry')])
        self.assertEqual([x['text'] for x in self.durable['bobby']['history']], ['retry'])
        restarted = Client(self.gb, crypto, self.persist_bob, copy.deepcopy(self.durable['bobby']))
        self.assertEqual(restarted.receive(), [])
        self.assertEqual([x['text'] for x in restarted.state['history']], ['retry'])

    def test_send_persist_failure_never_publishes_or_enqueues(self):
        before=copy.deepcopy(self.alice.state);self.blocked.add('alice')
        with self.assertRaises(OSError):self.alice.send('bobby','not yet')
        self.assertEqual(self.alice.state,before);self.assertEqual(self.gb.inbox(),[])
        self.blocked.remove('alice')
        self.alice = Client(self.ga, crypto, self.persist_alice, copy.deepcopy(self.durable['alice']))
        self.alice.send('bobby','not yet')
        self.assertEqual(self.bob.receive(),[('alice','not yet')])

    def test_network_failure_after_acceptance_retries_without_duplicate_display(self):
        original_send = self.ga.send
        def send_then_fail(recipient, envelope):
            original_send(recipient, envelope)
            raise OSError('response lost after server accepted')
        self.ga.send = send_then_fail
        with self.assertRaises(OSError): self.alice.send('bobby', 'exactly once')
        self.assertEqual(len(self.alice.state['outbox']), 1)
        self.assertEqual(len(self.durable['alice']['outbox']), 1)
        self.assertEqual(len(self.gb.inbox()), 1)
        self.ga.send = original_send
        restarted = Client(self.ga, crypto, self.persist_alice, copy.deepcopy(self.durable['alice']))
        restarted.flush()
        self.assertEqual(len(self.gb.inbox()), 2)
        self.assertEqual(self.bob.receive(), [('alice', 'exactly once')])
        self.assertEqual(self.gb.inbox(), [])
        self.assertEqual([row['text'] for row in self.bob.state['history']], ['exactly once'])

    def test_outbox_cleanup_failure_keeps_durable_entry_for_safe_retry(self):
        count={'n':0}
        def persist(data):
            count['n']+=1
            if count['n']==2:raise OSError('cleanup failed')
            self.durable['alice']=copy.deepcopy(data)
        self.alice.persist=persist
        with self.assertRaises(OSError):self.alice.send('bobby','once')
        self.assertEqual(len(self.alice.state['outbox']),1)
        self.assertEqual(len(self.durable['alice']['outbox']),1)
        self.assertEqual(len(self.gb.inbox()),1)
        self.alice = Client(self.ga, crypto, self.persist_alice, copy.deepcopy(self.durable['alice']))
        self.alice.flush()
        self.assertEqual(len(self.gb.inbox()),2)
        self.assertEqual(self.bob.receive(),[('alice','once')]);self.assertEqual(self.gb.inbox(),[])

class PersistenceAlertTest(unittest.TestCase):
    def test_local_persistence_failure_explains_retry(self):
        from securechat.domain.errors import LocalStateWriteFailed
        from securechat.ui import user_error
        message = user_error(LocalStateWriteFailed('private path must not leak'))
        self.assertIn('guardar', message.lower())
        self.assertNotIn('private path', message)

class IndeterminatePersistenceTest(unittest.TestCase):
    setUp = TransactionalStateTest.setUp
    def test_trust_failure_does_not_publish_and_invalidates_client(self):
        from securechat.domain.errors import LocalStateWriteFailed, ClientStateInvalidated
        other = crypto.Identity.generate('carol')
        self.ga.bundles['carol'] = other.bundle()
        safety = self.alice.safety('carol'); original = copy.deepcopy(self.alice.state)
        self.blocked.add('alice')
        with self.assertRaises(LocalStateWriteFailed): self.alice.trust('carol', safety)
        self.assertEqual(self.alice.state, original)
        self.blocked.remove('alice')
        with self.assertRaises(ClientStateInvalidated): self.alice.send('bobby', 'must not send')
        self.assertEqual(self.gb.inbox(), [])

    def test_uncertain_send_persistence_requires_reconstruct_from_persisted_state(self):
        from securechat.domain.errors import LocalStateWriteFailed, ClientStateInvalidated
        def write_then_fail(candidate):
            self.durable['alice'] = copy.deepcopy(candidate)
            raise OSError('uncertain result')
        self.alice.persist = write_then_fail
        with self.assertRaises(LocalStateWriteFailed): self.alice.send('bobby', 'recover')
        self.assertEqual(self.gb.inbox(), [])
        self.assertEqual(len(self.durable['alice']['outbox']), 1)
        with self.assertRaises(ClientStateInvalidated): self.alice.send('bobby', 'must not send')
        restarted = Client(self.ga, crypto, self.persist_alice, copy.deepcopy(self.durable['alice']))
        restarted.flush()
        self.assertEqual(self.bob.receive(), [('alice', 'recover')])

class UiInvalidationTest(unittest.TestCase):
    def test_browser_script_handles_forced_relogin(self):
        from securechat.ui import UI_SCRIPT
        self.assertIn('data.relogin', UI_SCRIPT)
        self.assertIn('clearInterval', UI_SCRIPT)

class CliPersistenceAlertTest(unittest.TestCase):
    def test_uncertain_write_prompts_reload_without_private_details(self):
        from securechat.client import explain_failure
        from securechat.domain.errors import LocalStateWriteFailed
        message = explain_failure(LocalStateWriteFailed('private path'))
        self.assertIn('nuevamente', message.lower())
        self.assertNotIn('private path', message)
