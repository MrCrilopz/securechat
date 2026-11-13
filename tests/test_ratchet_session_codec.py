import copy
import tempfile
import unittest
from pathlib import Path
from cliente.infrastructure.local_store import save, load
from securechat.application.ratchet_transactional_session import TransactionalRatchet
from securechat.application.ratchet_session_codec import encode_session, decode_session, SessionCodecError
from securechat.application.double_ratchet import init_alice, init_bob
from securechat.infrastructure.ratchet_provider import CryptographyRatchet

class Gateway:
    def __init__(self): self.packets=[]; self.acks=[]
    def send(self,p): self.packets.append(copy.deepcopy(p))
    def acknowledge(self,id): self.acks.append(id)

class SessionCodecTests(unittest.TestCase):
    def setUp(self):
        self.p=CryptographyRatchet(); priv=self.p.generate_dh(); root=b'R'*32
        self.a=init_alice(self.p,root,self.p.dh_public(priv)); self.b=init_bob(self.p,root,priv)
    def test_roundtrip_with_encrypted_local_store_and_resume(self):
        g=Gateway(); session=TransactionalRatchet(self.p,g,lambda _:None,self.a,b'context')
        session.send(b'hello')
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'state'; save(f,'temporary-password',{'dr':encode_session(session.state)})
            loaded=decode_session(load(f,'temporary-password')['dr'])
            self.assertEqual(loaded, session.state)
            restored=TransactionalRatchet(self.p,g,lambda _:None,None,b'context',snapshot=loaded)
            restored.send(b'after restart')
            receiver=TransactionalRatchet(self.p,g,lambda _:None,self.b,b'context')
            self.assertEqual(receiver.receive('first',g.packets[0]),b'hello')
            self.assertEqual(receiver.receive('second',g.packets[1]),b'after restart')
    def test_roundtrip_incoming_and_reject_invalid_shapes(self):
        g=Gateway(); sender=TransactionalRatchet(self.p,g,lambda _:None,self.a,b'context');sender.send(b'one')
        receiver=TransactionalRatchet(self.p,g,lambda _:None,self.b,b'context');receiver.receive('1',g.packets[0])
        encoded=encode_session(receiver.state)
        self.assertEqual(decode_session(encoded),receiver.state)
        for mutate in (lambda v:v.update(version=2),lambda v:v['accepted'].append(v['accepted'][0]),lambda v:v['accepted'][0]['packet'].update(nonce='00')):
            v=copy.deepcopy(encoded);mutate(v)
            with self.assertRaises(SessionCodecError):decode_session(v)

    def test_failed_transport_persists_outbox_for_restart(self):
        class FailingGateway(Gateway):
            def send(self,p): raise ConnectionError('offline')
        with tempfile.TemporaryDirectory() as d:
            f=Path(d)/'state'; save(f,'temporary-password',{'dr':None})
            def persist(state):
                saved=load(f,'temporary-password'); saved['dr']=encode_session(state)
                save(f,'temporary-password',saved)
            sender=TransactionalRatchet(self.p,FailingGateway(),persist,self.a,b'context')
            with self.assertRaises(ConnectionError): sender.send(b'durable')
            snapshot=decode_session(load(f,'temporary-password')['dr'])
            self.assertEqual(len(snapshot['outbox']),1)
            g=Gateway(); restored=TransactionalRatchet(self.p,g,persist,None,b'context',snapshot=snapshot)
            restored.flush()
            self.assertEqual(len(g.packets),1)
            self.assertEqual(decode_session(load(f,'temporary-password')['dr'])['outbox'],[])
            receiver=TransactionalRatchet(self.p,g,lambda _:None,self.b,b'context')
            self.assertEqual(receiver.receive('one',g.packets[0]),b'durable')
