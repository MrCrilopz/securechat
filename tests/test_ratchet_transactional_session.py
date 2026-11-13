import copy
import unittest
from cryptography.exceptions import InvalidTag
from securechat.application.ratchet_transactional_session import TransactionalRatchet, RatchetSessionInvalidated
from securechat.application.double_ratchet import init_alice, init_bob
from securechat.infrastructure.ratchet_provider import CryptographyRatchet

class Gateway:
    def __init__(self): self.sent=[]; self.acked=[]
    def send(self, packet): self.sent.append(copy.deepcopy(packet))
    def acknowledge(self, message_id): self.acked.append(message_id)

class TransactionalSessionTests(unittest.TestCase):
    def setUp(self):
        self.provider=CryptographyRatchet(); key=self.provider.generate_dh(); root=b'x'*32
        self.a=init_alice(self.provider,root,self.provider.dh_public(key)); self.b=init_bob(self.provider,root,key)
        self.gateway=Gateway(); self.saved=[]
    def persist(self,candidate): self.saved.append(copy.deepcopy(candidate))
    def test_send_persists_outbox_before_transport_and_receive_before_ack(self):
        sender=TransactionalRatchet(self.provider,self.gateway,self.persist,self.a,b'context')
        sender.send(b'hello')
        self.assertEqual(len(self.saved[0]['outbox']),1); packet=self.gateway.sent[0]
        receiver=TransactionalRatchet(self.provider,self.gateway,self.persist,self.b,b'context')
        self.assertEqual(receiver.receive('1',packet),b'hello')
        self.assertEqual(self.gateway.acked,['1']); self.assertEqual(self.saved[-1]['history'][-1],b'hello')
        self.assertIsNone(receiver.receive('1',packet)); self.assertEqual(self.gateway.acked,['1','1'])
    def test_failed_persistence_never_transmits_and_invalidates(self):
        def fail(_): raise OSError('failure')
        sender=TransactionalRatchet(self.provider,self.gateway,fail,self.a,b'context')
        with self.assertRaises(RatchetSessionInvalidated): sender.send(b'hello')
        self.assertEqual(self.gateway.sent,[])
        with self.assertRaises(RatchetSessionInvalidated): sender.send(b'again')
    def test_tamper_does_not_ack_or_publish_state(self):
        sender=TransactionalRatchet(self.provider,self.gateway,self.persist,self.a,b'context'); sender.send(b'hello')
        packet=copy.deepcopy(self.gateway.sent[0]); packet['ciphertext']=packet['ciphertext'][:-1]+bytes([packet['ciphertext'][-1]^1])
        receiver=TransactionalRatchet(self.provider,self.gateway,self.persist,self.b,b'context')
        with self.assertRaises(InvalidTag): receiver.receive('1',packet)
        self.assertEqual(self.gateway.acked,[]); self.assertEqual(receiver.state['ratchet'],self.b)

    def test_receive_persist_failure_does_not_ack(self):
        sender=TransactionalRatchet(self.provider,self.gateway,self.persist,self.a,b'context'); sender.send(b'hello')
        packet=copy.deepcopy(self.gateway.sent[0])
        def fail(_): raise OSError('failure')
        receiver=TransactionalRatchet(self.provider,self.gateway,fail,self.b,b'context')
        with self.assertRaises(RatchetSessionInvalidated): receiver.receive('1',packet)
        self.assertEqual(self.gateway.acked,[])
        self.assertEqual(receiver.state['ratchet'],self.b)
        with self.assertRaises(RatchetSessionInvalidated): receiver.receive('1',packet)

    def test_replay_with_new_server_id_is_acknowledged_without_redelivery(self):
        sender=TransactionalRatchet(self.provider,self.gateway,self.persist,self.a,b'context'); sender.send(b'hello')
        packet=copy.deepcopy(self.gateway.sent[0])
        receiver=TransactionalRatchet(self.provider,self.gateway,self.persist,self.b,b'context')
        self.assertEqual(receiver.receive('1',packet),b'hello')
        self.assertIsNone(receiver.receive('2',packet))
        self.assertEqual(len(receiver.state['history']),1)

    def test_long_id_is_rejected_before_decrypt_and_commit(self):
        from securechat.application.double_ratchet import RatchetError
        sender=TransactionalRatchet(self.provider,self.gateway,self.persist,self.a,b'context');sender.send(b'hello')
        receiver=TransactionalRatchet(self.provider,self.gateway,self.persist,self.b,b'context')
        before=len(self.saved)
        with self.assertRaises(RatchetError): receiver.receive('x'*129,self.gateway.sent[0])
        self.assertEqual(len(self.saved),before);self.assertEqual(self.gateway.acked,[])
        self.assertFalse(receiver.invalid)
        self.assertEqual(receiver.receive('valid',self.gateway.sent[0]),b'hello')

    def test_full_history_rejected_before_sending_or_committing(self):
        from securechat.application.double_ratchet import RatchetError
        session=TransactionalRatchet(self.provider,self.gateway,self.persist,self.a,b'context')
        session.state['history']=[b'x']*1024
        before=copy.deepcopy(session.state)
        with self.assertRaises(RatchetError):session.send(b'overflow')
        self.assertEqual(self.gateway.sent,[]);self.assertEqual(self.saved,[])
        self.assertEqual(session.state,before);self.assertFalse(session.invalid)

    def test_full_history_rejected_before_ack_or_commit(self):
        from securechat.application.double_ratchet import RatchetError
        sender=TransactionalRatchet(self.provider,self.gateway,self.persist,self.a,b'context');sender.send(b'hello')
        receiver=TransactionalRatchet(self.provider,self.gateway,self.persist,self.b,b'context')
        receiver.state['history']=[b'x']*1024
        before=copy.deepcopy(receiver.state);saved=len(self.saved)
        with self.assertRaises(RatchetError):receiver.receive('1',self.gateway.sent[0])
        self.assertEqual(self.gateway.acked,[]);self.assertEqual(len(self.saved),saved)
        self.assertEqual(receiver.state,before);self.assertFalse(receiver.invalid)

    def test_full_history_still_acknowledges_known_exact_duplicate(self):
        sender=TransactionalRatchet(self.provider,self.gateway,self.persist,self.a,b'context');sender.send(b'hello')
        receiver=TransactionalRatchet(self.provider,self.gateway,self.persist,self.b,b'context')
        self.assertEqual(receiver.receive('i'*128,self.gateway.sent[0]),b'hello')
        receiver.state['history']=[b'x']*1024
        self.assertIsNone(receiver.receive('i'*128,self.gateway.sent[0]))
        self.assertEqual(len(self.gateway.acked),2)

    def test_oversized_plaintext_rejected_without_sending(self):
        from securechat.application.double_ratchet import RatchetError
        session=TransactionalRatchet(self.provider,self.gateway,self.persist,self.a,b'context')
        with self.assertRaises(RatchetError):session.send(b'x'*65537)
        self.assertEqual(self.gateway.sent,[]);self.assertFalse(session.invalid)
