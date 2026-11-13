"""End-to-end tests for explicitly selected, persisted DR conversations."""
import copy
import tempfile
import unittest
from pathlib import Path
from tests.sqlite_test_connection import transaction

from cliente.application.client import Client
from cliente.infrastructure.local_store import save, load
from cliente.infrastructure.dr_chat import DoubleRatchetChat
from securechat.infrastructure import crypto


class ConversationTests(unittest.TestCase):
    def setUp(self):
        self.alice_id = crypto.Identity.generate('alice')
        self.bob_id = crypto.Identity.generate('bobby')
        self.bundles = {'alice':self.alice_id.bundle(), 'bobby':self.bob_id.bundle()}
        self.inboxes = {'alice':[], 'bobby':[]}; self.sent = []
        outer = self
        class Gateway:
            def __init__(self, username): self.username = username
            def bundle(self, username):
                from securechat.domain.errors import UnknownContact
                if username not in outer.bundles: raise UnknownContact('Unknown contact')
                return copy.deepcopy(outer.bundles[username])
            def send(self, recipient, envelope):
                outer.sent.append(copy.deepcopy(envelope))
                outer.inboxes[recipient].append({'id':len(outer.sent), 'envelope':copy.deepcopy(envelope)})
            def inbox(self): return copy.deepcopy(outer.inboxes[self.username])
            def acknowledge(self, mid): outer.inboxes[self.username] = [e for e in outer.inboxes[self.username] if e['id'] != mid]
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        def create(name, identity):
            path = Path(self.temp.name)/name
            initial = {'identity':identity.serialize(),'contacts':{},'sessions':{},'history':[],'outbox':[]}
            save(path,'temporary-password',initial)
            state = load(path,'temporary-password')
            def persist(candidate): save(path,'temporary-password',candidate)
            return Client(Gateway(name),crypto,persist,state,dr=DoubleRatchetChat())
        self.alice = create('alice',self.alice_id); self.bob = create('bobby',self.bob_id)
        safety = self.alice.safety('bobby'); self.alice.trust('bobby',safety); self.bob.trust('alice',safety)

    def test_explicit_opt_in_then_reply_and_replay(self):
        self.alice.send_dr('bobby','secret one')
        self.assertEqual(self.bob.receive(), [('alice','secret one')])
        self.bob.send('alice','secret reply')
        self.assertEqual(self.alice.receive(), [('bobby','secret reply')])
        self.assertNotIn('secret',repr(self.sent))
        # A transport duplicate after a lost ACK is consumed without re-delivery.
        self.inboxes['bobby'].append({'id':99,'envelope':copy.deepcopy(self.sent[0])})
        self.assertEqual(self.bob.receive(), [])
        self.assertEqual(self.inboxes['bobby'], [])

    def test_simultaneous_bootstraps_deliver_both_and_converge(self):
        self.alice.send_dr('bobby','from alice')
        self.bob.send_dr('alice','from bob')
        self.assertEqual(self.alice.receive(), [('bobby','from bob')])
        self.assertEqual(self.bob.receive(), [('alice','from alice')])
        self.alice.send_dr('bobby','alice later')
        self.bob.send_dr('alice','bob later')
        self.assertEqual(self.alice.receive(), [('bobby','bob later')])
        self.assertEqual(self.bob.receive(), [('alice','alice later')])
        self.assertFalse(self.inboxes['alice']); self.assertFalse(self.inboxes['bobby'])

    def test_second_bootstrap_after_accept_stays_readable_and_third_does_not_block(self):
        from securechat.domain.errors import ConcurrentRatchetSession
        saved = copy.deepcopy(self.alice.state)
        self.alice.send_dr('bobby', 'first session')
        self.assertEqual(self.bob.receive(), [('alice', 'first session')])
        self.alice.state.clear(); self.alice.state.update(copy.deepcopy(saved))
        self.alice.send_dr('bobby', 'second session')
        self.assertEqual(self.bob.receive(), [('alice', 'second session')])
        self.assertIsNotNone(self.bob.state['dr_sessions']['alice'].get('simultaneous'))
        self.alice.send_dr('bobby', 'still readable')
        restarted = Client(self.alice.gateway, crypto, lambda _: None, copy.deepcopy(saved), dr=DoubleRatchetChat())
        restarted.send_dr('bobby', 'third session')
        visible = self.inboxes['bobby'][0]
        third = self.inboxes['bobby'][1]
        self.inboxes['bobby'] = [third, visible]
        with self.assertRaises(ConcurrentRatchetSession):
            self.bob.receive()
        self.assertEqual(self.bob.state['history'][-1]['text'], 'still readable')
        self.assertEqual([item['envelope']['message']['payload']['ciphertext'] for item in self.inboxes['bobby']],
                         [third['envelope']['message']['payload']['ciphertext']])
        self.bob.send('alice', 'reply on the session alice kept')
        self.assertEqual(self.alice.receive(), [('bobby', 'reply on the session alice kept')])

    def test_simultaneous_bootstrap_delayed_messages_after_restart(self):
        self.alice.send_dr('bobby','alice first')
        self.bob.send_dr('alice','bob first')
        self.bob.send_dr('alice','bob second')
        self.assertEqual(self.alice.receive(), [('bobby','bob first'),('bobby','bob second')])
        # Alice may send on either known session while Bob has yet to receive her bootstrap.
        self.alice.send_dr('bobby','alice second')
        path = Path(self.temp.name)/'bobby'
        bob = Client(self.bob.gateway,crypto,lambda state:save(path,'temporary-password',state),
                     load(path,'temporary-password'),dr=DoubleRatchetChat())
        self.assertEqual(bob.receive(), [('alice','alice first'),('alice','alice second')])
        bob.send_dr('alice','bob after restart')
        path = Path(self.temp.name)/'alice'
        alice = Client(self.alice.gateway,crypto,lambda state:save(path,'temporary-password',state),
                       load(path,'temporary-password'),dr=DoubleRatchetChat())
        self.assertEqual(alice.receive(), [('bobby','bob after restart')])

    def test_reordered_message_before_bootstrap_is_deferred_without_loss(self):
        self.alice.send_dr('bobby','first')
        self.alice.send_dr('bobby','second')
        self.inboxes['bobby'].reverse()
        self.assertEqual(self.bob.receive(), [('alice','first'),('alice','second')])
        self.assertFalse(self.inboxes['bobby'])

    def test_deferred_message_without_bootstrap_remains_unacknowledged(self):
        self.alice.send_dr('bobby','first')
        self.alice.send_dr('bobby','second')
        bootstrap = self.inboxes['bobby'].pop(0)
        state_before = copy.deepcopy(self.bob.state)
        queued = copy.deepcopy(self.inboxes['bobby'])
        with self.assertRaises(ValueError): self.bob.receive()
        self.assertEqual(self.bob.state,state_before)
        self.assertEqual(self.inboxes['bobby'],queued)
        self.inboxes['bobby'].append(bootstrap)
        self.assertEqual(self.bob.receive(), [('alice','first'),('alice','second')])

    def test_unknown_session_cannot_block_legitimate_deferred_message(self):
        from securechat.domain.errors import UnknownRatchetSession
        from cliente.ui import user_error
        self.alice.send_dr('bobby','first')
        self.alice.send_dr('bobby','second')
        initial, second = self.inboxes['bobby']
        forged = copy.deepcopy(second)
        forged['id'] = 999
        forged['envelope']['message']['session_id'] = 'f' * 32
        self.inboxes['bobby'] = [forged, second, initial]
        with self.assertRaises(UnknownRatchetSession) as error:
            self.bob.receive()
        self.assertIn('conservó sin confirmar',user_error(error.exception))
        self.assertEqual([r['text'] for r in self.bob.state['history']], ['first','second'])
        self.assertEqual(self.inboxes['bobby'], [forged])

    def test_bad_ciphertext_does_not_block_valid_packet(self):
        from securechat.domain.errors import RatchetAuthenticationFailed, InvalidClassicHeader, InvalidClassicCounter, InvalidMessageNonce
        from cliente.ui import user_error
        self.alice.send_dr('bobby','first'); self.bob.receive()
        self.alice.send_dr('bobby','second')
        valid = self.inboxes['bobby'][0]
        forged = copy.deepcopy(valid); forged['id'] = 999
        ciphertext = forged['envelope']['message']['packet']['ciphertext']
        forged['envelope']['message']['packet']['ciphertext'] = ('0' if ciphertext[0] != '0' else '1') + ciphertext[1:]
        self.inboxes['bobby'].insert(0, forged)
        with self.assertRaises(RatchetAuthenticationFailed) as error:
            self.bob.receive()
        self.assertIn('alterado', user_error(error.exception))
        self.assertEqual([r['text'] for r in self.bob.state['history']], ['first', 'second'])
        self.assertEqual(self.inboxes['bobby'], [forged])

    def test_bad_bootstrap_signature_does_not_block_valid_bootstrap(self):
        from securechat.domain.errors import RatchetAuthenticationFailed
        self.alice.send_dr('bobby','first')
        forged = copy.deepcopy(self.inboxes['bobby'][0]); forged['id'] = 999
        signature = forged['envelope']['message']['payload']['signature']
        forged['envelope']['message']['payload']['signature'] = ('A' if signature[0] != 'A' else 'B') + signature[1:]
        self.inboxes['bobby'].insert(0, forged)
        with self.assertRaises(RatchetAuthenticationFailed): self.bob.receive()
        self.assertEqual([r['text'] for r in self.bob.state['history']], ['first'])
        self.assertEqual(self.inboxes['bobby'], [forged])

    def test_malformed_bootstrap_and_unknown_sender_do_not_block_valid(self):
        from securechat.domain.errors import RatchetAuthenticationFailed
        self.alice.send_dr('bobby','first')
        valid = self.inboxes['bobby'][0]
        malformed = copy.deepcopy(valid); malformed['id'] = 998
        malformed['envelope']['message'].pop('payload')
        unknown = copy.deepcopy(valid); unknown['id'] = 999
        unknown['envelope']['message']['sender'] = 'stranger'
        self.inboxes['bobby'] = [malformed, unknown, valid]
        with self.assertRaises(RatchetAuthenticationFailed): self.bob.receive()
        self.assertEqual([r['text'] for r in self.bob.state['history']], ['first'])
        self.assertEqual(self.inboxes['bobby'],[malformed,unknown])

    def test_missing_or_unknown_protocol_does_not_fall_through_to_classic(self):
        from securechat.domain.errors import RatchetAuthenticationFailed
        self.alice.send_dr('bobby','first'); valid = self.inboxes['bobby'][0]
        missing = copy.deepcopy(valid); missing['id'] = 998
        del missing['envelope']['message']['protocol']
        unknown = copy.deepcopy(valid); unknown['id'] = 999
        unknown['envelope']['message']['protocol'] = 'unsupported'
        self.inboxes['bobby'] = [missing, unknown, valid]
        with self.assertRaises(RatchetAuthenticationFailed): self.bob.receive()
        self.assertEqual([r['text'] for r in self.bob.state['history']],['first'])
        self.assertEqual(self.inboxes['bobby'],[missing,unknown])

    def test_unverified_contact_remains_visible_and_unacknowledged(self):
        from securechat.domain.errors import ContactNotVerified
        from cliente.ui import user_error
        self.alice.send_dr('bobby','first'); self.bob.state['contacts'].clear()
        with self.assertRaises(ContactNotVerified) as error: self.bob.receive()
        self.assertIn('verificar',user_error(error.exception).lower())
        self.assertEqual(len(self.inboxes['bobby']),1)

    def test_malformed_classic_before_valid_is_retained_and_alerted(self):
        from securechat.domain.errors import RatchetAuthenticationFailed
        self.alice.send('bobby','classic first'); valid = self.inboxes['bobby'][0]
        malformed = copy.deepcopy(valid); malformed['id'] = 998
        malformed['envelope']['header'].pop('ephemeral')
        self.inboxes['bobby'] = [malformed,valid]
        with self.assertRaises(RatchetAuthenticationFailed): self.bob.receive()
        self.assertEqual([r['text'] for r in self.bob.state['history']], ['classic first'])
        self.assertEqual(self.inboxes['bobby'],[malformed])

    def test_classic_tampering_does_not_block_first_valid_message(self):
        from securechat.domain.errors import RatchetAuthenticationFailed
        self.alice.send('bobby','classic first'); valid = self.inboxes['bobby'][0]
        bad_cipher = copy.deepcopy(valid); bad_cipher['id'] = 998
        ciphertext = bytearray(crypto.unb64(bad_cipher['envelope']['message']['ciphertext']))
        ciphertext[0] ^= 1; bad_cipher['envelope']['message']['ciphertext'] = crypto.b64(ciphertext)
        bad_key = copy.deepcopy(valid); bad_key['id'] = 999
        bad_key['envelope']['header']['ephemeral'] = crypto.b64(b'bad')
        self.inboxes['bobby'] = [bad_cipher,bad_key,valid]
        with self.assertRaises(RatchetAuthenticationFailed): self.bob.receive()
        self.assertEqual([r['text'] for r in self.bob.state['history']],['classic first'])
        self.assertEqual(self.inboxes['bobby'],[bad_cipher,bad_key])

    def test_classic_tampering_in_established_session_does_not_block_valid(self):
        from securechat.domain.errors import InvalidClassicHeader, InvalidClassicCounter, InvalidMessageNonce
        from cliente.ui import user_error
        self.alice.send('bobby','first'); self.bob.receive()
        for case, error_type in [('header',InvalidClassicHeader),('counter',InvalidClassicCounter),('nonce',InvalidMessageNonce)]:
            with self.subTest(case=case):
                self.alice.send('bobby',case); valid = self.inboxes['bobby'][0]
                forged = copy.deepcopy(valid); forged['id'] = 999
                if case == 'header': forged['envelope']['header']['ephemeral'] = crypto.b64(b'a'*32)
                if case == 'counter': forged['envelope']['message']['counter'] = 99999
                if case == 'nonce': forged['envelope']['message']['nonce'] = crypto.b64(b'bad')
                self.inboxes['bobby'].insert(0,forged)
                with self.assertRaises(error_type) as error: self.bob.receive()
                self.assertIn('ALERTA',user_error(error.exception))
                self.assertEqual(self.bob.state['history'][-1]['text'],case)
                self.assertEqual(self.inboxes['bobby'],[forged])
                self.inboxes['bobby'].clear()

    def test_classic_invalid_header_does_not_hide_persistence_failure(self):
        from securechat.domain.errors import LocalStateWriteFailed
        self.alice.send('bobby','first'); self.bob.receive()
        self.alice.send('bobby','second')
        forged = copy.deepcopy(self.inboxes['bobby'][0]); forged['id'] = 999
        forged['envelope']['header']['ephemeral'] = crypto.b64(b'a'*32)
        self.inboxes['bobby'].insert(0,forged)
        self.bob.persist = lambda _: (_ for _ in ()).throw(OSError('disk failure'))
        with self.assertRaises(LocalStateWriteFailed): self.bob.receive()
        self.assertEqual(len(self.inboxes['bobby']),2)

    def test_classic_invalid_metadata_and_ciphertext_do_not_block_valid(self):
        from securechat.domain.errors import RatchetAuthenticationFailed
        self.alice.send('bobby', 'first'); self.bob.receive()
        for field, value in [('ciphertext', '!'), ('session', 'forged')]:
            with self.subTest(field=field):
                self.alice.send('bobby', field); valid = self.inboxes['bobby'][0]
                forged = copy.deepcopy(valid); forged['id'] = 999
                forged['envelope']['message'][field] = value
                self.inboxes['bobby'].insert(0, forged)
                with self.assertRaises(RatchetAuthenticationFailed): self.bob.receive()
                self.assertEqual(self.bob.state['history'][-1]['text'], field)
                self.assertEqual(self.inboxes['bobby'], [forged]); self.inboxes['bobby'].clear()

    def test_directory_network_failure_is_not_hidden(self):
        self.alice.send_dr('bobby','first')
        before = copy.deepcopy(self.inboxes['bobby']); state = copy.deepcopy(self.bob.state)
        self.bob.gateway.bundle = lambda _: (_ for _ in ()).throw(ConnectionError('offline'))
        with self.assertRaises(ConnectionError): self.bob.receive()
        self.assertEqual(self.inboxes['bobby'],before); self.assertEqual(self.bob.state,state)

    def test_malformed_or_impossible_dr_packets_do_not_block_valid_packet(self):
        from securechat.domain.errors import RatchetAuthenticationFailed
        self.alice.send_dr('bobby','first'); self.bob.receive()
        for case in ('invalid_hex', 'excessive_counter', 'low_order_dh'):
            with self.subTest(case=case):
                self.alice.send_dr('bobby',case)
                valid = self.inboxes['bobby'][0]
                forged = copy.deepcopy(valid); forged['id'] = 999
                packet = forged['envelope']['message']['packet']
                if case == 'invalid_hex': packet['ciphertext'] = 'xx'
                if case == 'excessive_counter': packet['header']['n'] = 100000
                if case == 'low_order_dh': packet['header']['dh'] = '00' * 32
                self.inboxes['bobby'].insert(0,forged)
                with self.assertRaises(RatchetAuthenticationFailed): self.bob.receive()
                self.assertEqual(self.bob.state['history'][-1]['text'],case)
                self.assertEqual(self.inboxes['bobby'],[forged])
                self.inboxes['bobby'].clear()

    def test_packet_rejection_does_not_hide_persistence_failure(self):
        from securechat.domain.errors import LocalStateWriteFailed
        self.alice.send_dr('bobby','first'); self.bob.receive()
        self.alice.send_dr('bobby','second')
        forged = copy.deepcopy(self.inboxes['bobby'][0]); forged['id'] = 999
        forged['envelope']['message']['packet']['ciphertext'] = 'xx'
        self.inboxes['bobby'].insert(0, forged)
        self.bob.persist = lambda _: (_ for _ in ()).throw(OSError('disk failure'))
        with self.assertRaises(LocalStateWriteFailed): self.bob.receive()
        self.assertEqual(len(self.inboxes['bobby']),2)

    def test_altered_first_packet_is_not_acknowledged_or_persisted(self):
        self.alice.send_dr('bobby','secret one')
        message = self.inboxes['bobby'][0]['envelope']['message']
        message['payload']['ciphertext'] = message['payload']['ciphertext'][:-2] + 'AA'
        before = copy.deepcopy(self.bob.state)
        with self.assertRaises(ValueError): self.bob.receive()
        self.assertEqual(before,self.bob.state)
        self.assertEqual(len(self.inboxes['bobby']),1)

    def test_no_automatic_migration_of_existing_classical_session(self):
        self.alice.send('bobby','old')
        self.assertEqual(self.bob.receive(), [('alice','old')])
        self.alice.send('bobby','still classic')
        self.assertNotIn('dr_sessions', self.alice.state)
        self.assertEqual(self.bob.receive(), [('alice','still classic')])
        self.alice.send_dr('bobby','explicit')
        self.assertEqual(self.alice.state['history'][0]['text'],'old')
        self.assertIn('bobby', self.alice.state['sessions'])
        self.bob.send('alice','bob remains classic')
        self.assertNotIn('double-ratchet', repr(self.sent[-1]))
        self.assertEqual(self.alice.receive(), [('bobby','bob remains classic')])

    def test_failed_persistence_preserves_inbox_and_sends_no_ack(self):
        self.alice.send_dr('bobby','secret one')
        before = copy.deepcopy(self.bob.state)
        self.bob.persist = lambda _: (_ for _ in ()).throw(OSError('disk failure'))
        with self.assertRaises(OSError): self.bob.receive()
        self.assertEqual(before,self.bob.state)
        self.assertEqual(len(self.inboxes['bobby']),1)

    def test_failed_sender_persistence_does_not_send(self):
        self.alice.persist = lambda _: (_ for _ in ()).throw(OSError('disk failure'))
        with self.assertRaises(OSError): self.alice.send_dr('bobby','secret')
        self.assertEqual(self.sent,[])

    def test_direction_is_bound_in_aad(self):
        from cryptography.exceptions import InvalidTag
        from securechat.application.double_ratchet import decrypt_message
        from securechat.application.ratchet_state_codec import decode_state
        from securechat.application.ratchet_transport import unwrap
        self.alice.send_dr('bobby','first'); self.bob.receive()
        self.bob.send('alice','reply')
        envelope = self.sent[-1]
        session = self.alice.state['dr_sessions']['bobby']
        sid = session['id']; packet = unwrap(envelope,'bobby','alice',sid)
        receiving_state = decode_state(session['state'])
        # The same valid packet and receiving state fail when roles are reversed.
        with self.assertRaises(InvalidTag):
            decrypt_message(self.alice.dr.provider, receiving_state, packet,
                            self.alice.dr._aad('alice','bobby',sid))
        self.assertEqual(self.alice.receive(), [('bobby','reply')])

    def test_simultaneous_sessions_are_authenticated_and_preserved(self):
        self.alice.send_dr('bobby','message from alice')
        self.bob.send_dr('alice','message from bobby')
        queued = copy.deepcopy(self.inboxes)
        self.assertEqual(self.alice.receive(), [('bobby','message from bobby')])
        self.assertEqual(self.bob.receive(), [('alice','message from alice')])
        for client, name in ((self.alice,'alice'),(self.bob,'bobby')):
            self.inboxes[name].extend(queued[name])
            before = copy.deepcopy(client.state)
            self.assertEqual(client.receive(), [])
            self.assertEqual(before,client.state); self.assertFalse(self.inboxes[name])

    def test_unauthenticated_competing_bootstrap_is_not_classified_as_conflict(self):
        from securechat.domain.errors import ConcurrentRatchetSession
        self.alice.send_dr('bobby','alice start'); self.bob.send_dr('alice','bobby start')
        envelope=self.inboxes['alice'][0]['envelope']
        envelope['message']['payload']['signature']='A' * 88
        before=copy.deepcopy(self.alice.state); queue=copy.deepcopy(self.inboxes['alice'])
        with self.assertRaises(ValueError) as result: self.alice.receive()
        self.assertNotIsInstance(result.exception,ConcurrentRatchetSession)
        self.assertEqual(before,self.alice.state); self.assertEqual(queue,self.inboxes['alice'])

    def test_bootstrap_after_acceptance_joins_the_second_session(self):
        early = copy.deepcopy(self.alice.state)
        self.alice.send_dr('bobby','first session')
        self.assertEqual(self.bob.receive(), [('alice','first session')])
        restored = Client(self.alice.gateway, crypto, lambda candidate: None, copy.deepcopy(early), dr=DoubleRatchetChat())
        restored.send_dr('bobby','second session')
        self.assertEqual(self.bob.receive(), [('alice','second session')])
        self.assertFalse(self.inboxes['bobby'])
        self.assertIn('simultaneous', self.bob.state['dr_sessions']['alice'])
        self.alice.send_dr('bobby','continues')
        self.assertEqual(self.bob.receive(), [('alice','continues')])

    def test_third_bootstrap_does_not_block_a_known_session(self):
        from securechat.domain.errors import ConcurrentRatchetSession
        early = copy.deepcopy(self.alice.state)
        self.alice.send_dr('bobby','first')
        self.bob.receive()
        Client(self.alice.gateway, crypto, lambda candidate: None, copy.deepcopy(early), dr=DoubleRatchetChat()).send_dr('bobby','second')
        self.bob.receive()
        third = Client(self.alice.gateway, crypto, lambda candidate: None, copy.deepcopy(early), dr=DoubleRatchetChat())
        third.send_dr('bobby','third')
        extra = self.inboxes['bobby'].pop()
        self.alice.send_dr('bobby','still delivered')
        self.inboxes['bobby'].insert(0, extra)
        with self.assertRaises(ConcurrentRatchetSession):
            self.bob.receive()
        self.assertEqual(self.bob.state['history'][-1]['text'], 'still delivered')
        self.assertEqual([item['id'] for item in self.inboxes['bobby']], [extra['id']])

    def test_conflict_error_message_does_not_claim_automatic_resolution(self):
        from securechat.domain.errors import ConcurrentRatchetSession
        from cliente.ui import user_error
        text=user_error(ConcurrentRatchetSession('conflict'))
        self.assertIn('conservaron',text); self.assertIn('no hay resolución automática',text)

    def test_full_replay_evidence_keeps_the_new_message_and_acks_a_known_duplicate(self):
        from securechat.domain.errors import DrReplayEvidenceFull
        from cliente.ui import user_error
        self.alice.send_dr('bobby', 'kept')
        self.assertEqual(self.bob.receive(), [('alice', 'kept')])
        accepted = self.bob.state['dr_sessions']['alice']['accepted']
        while len(accepted) < 256:
            accepted['pad-%d' % len(accepted)] = 'digest-%d' % len(accepted)
        self.alice.send_dr('bobby', 'overflow')
        overflow = self.inboxes['bobby'][-1]
        known = {'id': 99, 'envelope': copy.deepcopy(self.sent[0])}
        self.inboxes['bobby'] = [overflow, known]
        with self.assertRaises(DrReplayEvidenceFull):
            self.bob.receive()
        self.assertEqual(self.bob.state['history'][-1]['text'], 'kept')
        self.assertNotIn('overflow', [row['text'] for row in self.bob.state['history']])
        self.assertEqual([item['id'] for item in self.inboxes['bobby']], [overflow['id']])
        self.assertEqual(len(self.bob.state['dr_sessions']['alice']['accepted']), 256)
        text = user_error(DrReplayEvidenceFull('full'))
        self.assertIn('256', text)
        self.assertIn('sin confirmar', text)
        self.assertIn('No se borra', text)

    def test_explicit_opt_in_requires_contact_verification(self):
        self.alice.state['contacts'].clear()
        with self.assertRaises(ValueError): self.alice.send_dr('bobby','secret')
        self.assertEqual(self.sent,[])


    def test_explicit_migration_keeps_classic_messages_until_each_side_opts_in(self):
        self.alice.send('bobby', 'classic hello')
        self.assertEqual(self.bob.receive(), [('alice', 'classic hello')])
        self.alice.send_dr('bobby', 'now ratchet')
        self.assertIn('bobby', self.alice.state['sessions'])
        self.assertTrue(self.alice.state['dr_sessions']['bobby'].get('local_opt_in'))
        self.assertEqual(self.bob.receive(), [('alice', 'now ratchet')])
        self.assertIn('alice', self.bob.state['sessions'])
        self.assertFalse(self.bob.state['dr_sessions']['alice'].get('local_opt_in'))
        self.bob.send('alice', 'still classic')
        self.assertEqual(self.alice.receive(), [('bobby', 'still classic')])
        self.bob.send_dr('alice', 'bob opted in')
        self.assertTrue(self.bob.state['dr_sessions']['alice'].get('local_opt_in'))
        self.assertEqual(self.alice.receive(), [('bobby', 'bob opted in')])
        self.alice.send('bobby', 'alice stays on ratchet')
        self.assertEqual(self.bob.receive(), [('alice', 'alice stays on ratchet')])
        self.assertEqual([row['text'] for row in self.alice.state['history']], ['classic hello', 'now ratchet', 'still classic', 'bob opted in', 'alice stays on ratchet'])

    def test_dr_attachment_round_trip_hides_the_file_from_the_relay(self):
        from cliente.infrastructure.attachment_codec import AttachmentCodec
        from cliente.ui import conversation_dr_mode
        from cliente.workspace import workspace_screen
        codec = AttachmentCodec()
        self.alice.attachments = codec
        self.bob.attachments = codec
        self.alice.send_dr('bobby', 'hello')
        self.assertEqual(self.bob.receive(), [('alice', 'hello')])
        self.alice.send_attachment('bobby', 'nota.txt', b'secreto de archivo')
        relay = repr(self.sent[-1])
        self.assertNotIn('nota.txt', relay)
        self.assertNotIn('secreto de archivo', relay)
        self.assertNotIn('content_format', relay)
        received = self.bob.receive()
        self.assertEqual(received[0][0], 'alice')
        row = self.bob.state['history'][-1]
        self.assertEqual(row['kind'], 'attachment-v1')
        self.assertEqual(codec.open(row['text']), ('nota.txt', b'secreto de archivo'))
        self.assertEqual(self.alice.state['history'][-1]['kind'], 'attachment-v1')
        self.assertEqual(conversation_dr_mode(self.alice.state, 'bobby'), 'active')
        fresh = {'sessions': {'bobby': {}}, 'dr_sessions': {}}
        self.assertEqual(conversation_dr_mode(fresh, 'bobby'), 'migrate')
        page = workspace_screen('csrf', 'alice', [{'name': 'bobby', 'online': True}], [], 'bobby', '', 'chat', [], '', dr_mode='migrate')
        self.assertIn('Pasar a Double Ratchet', page)
        self.assertIn('id="attachment-form"', page)
        active = workspace_screen('csrf', 'alice', [{'name': 'bobby', 'online': True}], [], 'bobby', '', 'chat', [], '', dr_mode='active')
        self.assertIn('id="attachment-form"', active)
        self.assertNotIn('Pasar a Double Ratchet', active)


class HttpConversationTests(unittest.TestCase):
    def test_relay_retains_bad_classic_and_delivers_authentic(self):
        import socket, subprocess, sys, sqlite3, json
        from cliente.infrastructure.http_gateway import HttpGateway
        from securechat.domain.errors import RatchetAuthenticationFailed, InvalidClassicHeader, InvalidClassicCounter, InvalidMessageNonce
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); db = directory/'relay.sqlite3'
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
            process = subprocess.Popen([sys.executable,'-m','servidor.server','--port',str(port),'--database',str(db)],cwd=root,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            try:
                self.assertIn(b'Local server running',process.stdout.readline())
                clients=[]; gateways=[]
                for name in ('alice','bobby'):
                    identity=crypto.Identity.generate(name); gateway=HttpGateway(port)
                    gateway.register(name,'test password 1234',identity.bundle()); gateway.login(name,'test password 1234')
                    path=directory/name
                    save(path,'temporary-password',{'identity':identity.serialize(),'contacts':{},'sessions':{},'history':[],'outbox':[]})
                    clients.append(Client(gateway,crypto,lambda state,p=path:save(p,'temporary-password',state),load(path,'temporary-password')))
                    gateways.append(gateway)
                alice,bob=clients; safety=alice.safety('bobby'); alice.trust('bobby',safety); bob.trust('alice',safety)
                alice.send('bobby','classic authentic first')
                with transaction(db) as conn:
                    mid,recipient,sender,encoded=conn.execute('SELECT id,recipient,sender,envelope FROM messages').fetchone()
                    bad_cipher=json.loads(encoded); data=bytearray(crypto.unb64(bad_cipher['message']['ciphertext'])); data[0] ^= 1; bad_cipher['message']['ciphertext']=crypto.b64(data)
                    bad_header=json.loads(encoded); bad_header['header']['ephemeral']=crypto.b64(b'bad')
                    conn.execute('UPDATE messages SET id=500 WHERE id=?',(mid,))
                    conn.execute('INSERT INTO messages (id,recipient,sender,envelope) VALUES (?,?,?,?)',(498,recipient,sender,json.dumps(bad_cipher)))
                    conn.execute('INSERT INTO messages (id,recipient,sender,envelope) VALUES (?,?,?,?)',(499,recipient,sender,json.dumps(bad_header)))
                with self.assertRaises(RatchetAuthenticationFailed): bob.receive()
                self.assertEqual(bob.state['history'][-1]['text'],'classic authentic first')
                self.assertEqual([entry['id'] for entry in gateways[1].inbox()],[498,499])
                for index, (attack, error_type) in enumerate((('header',InvalidClassicHeader),('counter',InvalidClassicCounter),('nonce',InvalidMessageNonce),('ciphertext',RatchetAuthenticationFailed),('session',RatchetAuthenticationFailed))):
                    with transaction(db) as conn: conn.execute('DELETE FROM messages WHERE recipient=?',('bobby',))
                    alice.send('bobby',attack)
                    with transaction(db) as conn:
                        mid,recipient,sender,encoded=conn.execute('SELECT id,recipient,sender,envelope FROM messages WHERE recipient=?',('bobby',)).fetchone()
                        forged=json.loads(encoded)
                        if attack == 'header': forged['header']['ephemeral']=crypto.b64(b'a'*32)
                        if attack == 'counter': forged['message']['counter']=99999
                        if attack == 'nonce': forged['message']['nonce']=crypto.b64(b'bad')
                        if attack == 'ciphertext': forged['message']['ciphertext']='!'
                        if attack == 'session': forged['message']['session']='forged'
                        legit_id=1000+2*index
                        conn.execute('UPDATE messages SET id=? WHERE id=?',(legit_id,mid))
                        conn.execute('INSERT INTO messages (id,recipient,sender,envelope) VALUES (?,?,?,?)',(legit_id-1,recipient,sender,json.dumps(forged)))
                    with self.assertRaises(error_type): bob.receive()
                    self.assertEqual(bob.state['history'][-1]['text'],attack)
                    self.assertEqual([entry['id'] for entry in gateways[1].inbox()],[legit_id-1])
            finally:
                process.terminate(); process.wait(timeout=5); process.stdout.close(); process.stderr.close()

    def test_relay_keeps_bad_bootstrap_but_delivers_authentic_one(self):
        import socket, subprocess, sys, sqlite3, json
        from cliente.infrastructure.http_gateway import HttpGateway
        from securechat.domain.errors import RatchetAuthenticationFailed
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp); db = directory/'relay.sqlite3'
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
            process = subprocess.Popen([sys.executable,'-m','servidor.server','--port',str(port),'--database',str(db)],
                                       cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertIn(b'Local server running',process.stdout.readline())
                clients=[]; gateways=[]
                for name in ('alice','bobby'):
                    identity=crypto.Identity.generate(name); gateway=HttpGateway(port)
                    gateway.register(name,'test password 1234',identity.bundle()); gateway.login(name,'test password 1234')
                    path=directory/name
                    save(path,'temporary-password',{'identity':identity.serialize(),'contacts':{},'sessions':{},'history':[],'outbox':[]})
                    clients.append(Client(gateway,crypto,lambda state,p=path:save(p,'temporary-password',state),load(path,'temporary-password'),dr=DoubleRatchetChat()))
                    gateways.append(gateway)
                alice,bob=clients; safety=alice.safety('bobby'); alice.trust('bobby',safety); bob.trust('alice',safety)
                alice.send_dr('bobby','authentic first')
                with transaction(db) as conn:
                    mid,recipient,sender,encoded=conn.execute('SELECT id,recipient,sender,envelope FROM messages').fetchone()
                    forged=json.loads(encoded); payload=forged['message']['payload']; signature=payload['signature']
                    payload['signature']=('A' if signature[0] != 'A' else 'B')+signature[1:]
                    conn.execute('UPDATE messages SET id=500 WHERE id=?',(mid,))
                    conn.execute('INSERT INTO messages (id,recipient,sender,envelope) VALUES (?,?,?,?)',(499,recipient,sender,json.dumps(forged)))
                    malformed=json.loads(encoded); malformed['message'].pop('payload')
                    unknown=json.loads(encoded); unknown['message']['sender']='stranger'
                    missing_protocol=json.loads(encoded); del missing_protocol['message']['protocol']
                    changed_protocol=json.loads(encoded); changed_protocol['message']['protocol']='unsupported'
                    conn.execute('INSERT INTO messages (id,recipient,sender,envelope) VALUES (?,?,?,?)',(495,recipient,sender,json.dumps(missing_protocol)))
                    conn.execute('INSERT INTO messages (id,recipient,sender,envelope) VALUES (?,?,?,?)',(496,recipient,sender,json.dumps(changed_protocol)))
                    conn.execute('INSERT INTO messages (id,recipient,sender,envelope) VALUES (?,?,?,?)',(497,recipient,sender,json.dumps(malformed)))
                    conn.execute('INSERT INTO messages (id,recipient,sender,envelope) VALUES (?,?,?,?)',(498,recipient,'stranger',json.dumps(unknown)))
                with self.assertRaises(RatchetAuthenticationFailed): bob.receive()
                self.assertEqual(bob.state['history'][-1]['text'],'authentic first')
                self.assertEqual([entry['id'] for entry in gateways[1].inbox()],[495,496,497,498,499])
            finally:
                process.terminate(); process.wait(timeout=5); process.stdout.close(); process.stderr.close()

    def test_real_relay_store_reopen_and_receive(self):
        import socket
        import subprocess
        import sys
        from cliente.infrastructure.http_gateway import HttpGateway
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
            db = directory/'server.sqlite3'
            process = subprocess.Popen([sys.executable,'-m','servidor.server','--port',str(port),
                                        '--database',str(db)], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertIn(b'Local server running', process.stdout.readline())
                clients=[]; identities=[]; gateways=[]; paths=[]
                for name in ('alice','bobby'):
                    identity=crypto.Identity.generate(name); gateway=HttpGateway(port)
                    gateway.register(name,'test password 1234',identity.bundle()); gateway.login(name,'test password 1234')
                    path=directory/name
                    save(path,'temporary-password',{'identity':identity.serialize(),'contacts':{},'sessions':{},'history':[],'outbox':[]})
                    def persist(candidate, p=path): save(p,'temporary-password',candidate)
                    client=Client(gateway,crypto,persist,load(path,'temporary-password'),dr=DoubleRatchetChat())
                    identities.append(identity); gateways.append(gateway); paths.append(path); clients.append(client)
                alice,bob=clients
                safety=alice.safety('bobby'); alice.trust('bobby',safety); bob.trust('alice',safety)
                alice.send_dr('bobby','DR bootstrap private text')
                alice.send_dr('bobby','DR subsequent private text')
                self.assertNotIn(b'DR bootstrap private text',db.read_bytes())
                # Reopen recipient from encrypted disk state before delivering the initial packet.
                bob=Client(gateways[1],crypto,lambda state:save(paths[1],'temporary-password',state),
                           load(paths[1],'temporary-password'),dr=DoubleRatchetChat())
                original_inbox = gateways[1].inbox
                gateways[1].inbox = lambda: list(reversed(original_inbox()))
                self.assertEqual(bob.receive(),[('alice','DR bootstrap private text'),('alice','DR subsequent private text')])
                # Put a tampered copy before the authentic packet in the actual temporary relay DB.
                import sqlite3, json
                from securechat.domain.errors import RatchetAuthenticationFailed
                alice.send_dr('bobby','DR authentic message')
                with transaction(db) as conn:
                    mid, recipient, sender, encoded = conn.execute('SELECT id, recipient, sender, envelope FROM messages WHERE recipient=?', ('bobby',)).fetchone()
                    forged = json.loads(encoded)
                    ciphertext = forged['message']['packet']['ciphertext']
                    forged['message']['packet']['ciphertext'] = ('0' if ciphertext[0] != '0' else '1') + ciphertext[1:]
                    conn.execute('UPDATE messages SET id=? WHERE id=?', (500, mid))
                    conn.execute('INSERT INTO messages (id,recipient,sender,envelope) VALUES (?,?,?,?)', (499,recipient,sender,json.dumps(forged)))
                gateways[1].inbox = original_inbox
                with self.assertRaises(RatchetAuthenticationFailed): bob.receive()
                self.assertEqual(bob.state['history'][-1]['text'],'DR authentic message')
                self.assertEqual([entry['id'] for entry in original_inbox()], [499])
                for index, attack in enumerate(('invalid_hex','excessive_counter','low_order_dh')):
                    # Only synthetic rows in the temporary test database are removed.
                    with transaction(db) as conn: conn.execute('DELETE FROM messages WHERE recipient=?', ('bobby',))
                    alice.send_dr('bobby',attack)
                    with transaction(db) as conn:
                        mid, recipient, sender, encoded = conn.execute('SELECT id,recipient,sender,envelope FROM messages WHERE recipient=?',('bobby',)).fetchone()
                        forged = json.loads(encoded); packet = forged['message']['packet']
                        if attack == 'invalid_hex': packet['ciphertext'] = 'xx'
                        if attack == 'excessive_counter': packet['header']['n'] = 100000
                        if attack == 'low_order_dh': packet['header']['dh'] = '00' * 32
                        legit_id = 1000 + 2 * index
                        conn.execute('UPDATE messages SET id=? WHERE id=?',(legit_id,mid))
                        conn.execute('INSERT INTO messages (id,recipient,sender,envelope) VALUES (?,?,?,?)',(legit_id-1,recipient,sender,json.dumps(forged)))
                    with self.assertRaises(RatchetAuthenticationFailed): bob.receive()
                    self.assertEqual(bob.state['history'][-1]['text'],attack)
                    self.assertEqual([entry['id'] for entry in original_inbox()], [legit_id-1])
                with transaction(db) as conn: conn.execute('DELETE FROM messages WHERE recipient=?', ('bobby',))
                bob.send('alice','DR reply private text')
                # Reopen sender after its initial outbox was delivered.
                alice=Client(gateways[0],crypto,lambda state:save(paths[0],'temporary-password',state),
                             load(paths[0],'temporary-password'),dr=DoubleRatchetChat())
                self.assertEqual(alice.receive(),[('bobby','DR reply private text')])
                self.assertEqual(gateways[0].inbox(),[]); self.assertEqual(gateways[1].inbox(),[])
                self.assertNotIn(b'DR reply private text',db.read_bytes())
            finally:
                process.terminate(); process.wait(timeout=5)
                process.stdout.close(); process.stderr.close()

    def test_simultaneous_offline_starts_remain_queued_over_http(self):
        import socket, subprocess, sys
        from cliente.infrastructure.http_gateway import HttpGateway
        from securechat.domain.errors import ConcurrentRatchetSession
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
            process = subprocess.Popen([sys.executable,'-m','servidor.server','--port',str(port),
                                        '--database',str(directory/'relay.sqlite3')], cwd=root,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertIn(b'Local server running',process.stdout.readline())
                clients=[]; gateways=[]; paths=[]
                for name in ('alice','bobby'):
                    identity=crypto.Identity.generate(name); gateway=HttpGateway(port)
                    gateway.register(name,'test password 1234',identity.bundle()); gateway.login(name,'test password 1234')
                    path=directory/name
                    save(path,'temporary-password',{'identity':identity.serialize(),'contacts':{},'sessions':{},'history':[],'outbox':[]})
                    persist=lambda state,p=path: save(p,'temporary-password',state)
                    clients.append(Client(gateway,crypto,persist,load(path,'temporary-password'),dr=DoubleRatchetChat()))
                    gateways.append(gateway); paths.append(path)
                a,b=clients; safety=a.safety('bobby'); a.trust('bobby',safety); b.trust('alice',safety)
                a.send_dr('bobby','message from alice'); b.send_dr('alice','message from bobby')
                for gateway,path,expected in zip(gateways,paths,[('bobby','message from bobby'),('alice','message from alice')]):
                    reopened=Client(gateway,crypto,lambda state,p=path:save(p,'temporary-password',state),
                                    load(path,'temporary-password'),dr=DoubleRatchetChat())
                    self.assertEqual(reopened.receive(),[expected])
                    self.assertEqual(gateway.inbox(),[])
                    self.assertEqual(len(reopened.state['history']),2)
            finally:
                process.terminate(); process.wait(timeout=5)
                process.stdout.close(); process.stderr.close()

if __name__ == "__main__": unittest.main()
