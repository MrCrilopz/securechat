"""Acuerdo híbrido y grupos dentro del chat, no como laboratorios sueltos."""
import copy
import tempfile
import unittest
from pathlib import Path

from cliente.application.client import Client
from cliente.application.group_mailbox import MissingGroupKey
from cliente.infrastructure.local_store import load, save
from securechat.infrastructure import crypto


class ChatExtensionsTests(unittest.TestCase):
    def setUp(self):
        names = ('alice', 'bobby', 'carol')
        self.identities = {name: crypto.Identity.generate(name) for name in names}
        self.bundles = {name: identity.bundle() for name, identity in self.identities.items()}
        self.inboxes = {name: [] for name in names}
        self.hybrid = {}
        self.sent = []
        self.group_mail = []
        outer = self

        class Gateway:
            def __init__(self, username):
                self.username = username

            def bundle(self, username):
                from securechat.domain.errors import UnknownContact
                if username not in outer.bundles:
                    raise UnknownContact('Unknown contact')
                return copy.deepcopy(outer.bundles[username])

            def send(self, recipient, envelope):
                outer.sent.append(copy.deepcopy(envelope))
                outer.inboxes[recipient].append({'id': len(outer.sent), 'envelope': copy.deepcopy(envelope)})

            def inbox(self):
                return copy.deepcopy(outer.inboxes[self.username])

            def acknowledge(self, mid):
                outer.inboxes[self.username] = [item for item in outer.inboxes[self.username] if item['id'] != mid]

            def send_group_mail(self, group_id, members, envelope):
                outer.sent.append(copy.deepcopy(envelope))
                outer.group_mail.append({'id': len(outer.sent), 'envelope': copy.deepcopy(envelope), 'pending': set(members)})

            def group_inbox(self, group_id=None):
                rows = []
                for item in outer.group_mail:
                    message = item['envelope']['message']
                    if self.username not in item['pending']:
                        continue
                    if group_id and message.get('group') != group_id:
                        continue
                    rows.append({'id': item['id'], 'envelope': copy.deepcopy(item['envelope'])})
                return rows

            def group_pending(self):
                counts = {}
                for item in outer.group_mail:
                    if self.username in item['pending']:
                        gid = item['envelope']['message'].get('group')
                        counts[gid] = counts.get(gid, 0) + 1
                return counts

            def acknowledge_group(self, mail_id):
                for item in outer.group_mail:
                    if item['id'] == mail_id:
                        item['pending'].discard(self.username)

            def publish_hybrid_prekey(self, record):
                outer.hybrid[self.username] = copy.deepcopy(record)

            def hybrid_prekey(self, username):
                if username not in outer.hybrid:
                    raise LookupError('Hybrid prekey not available')
                return copy.deepcopy(outer.hybrid[username])

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

        def create(name):
            path = Path(self.temp.name) / name
            identity = self.identities[name]
            initial = {'identity': identity.serialize(), 'contacts': {}, 'sessions': {}, 'history': [], 'outbox': []}
            save(path, 'temporary-password', initial)
            state = load(path, 'temporary-password')

            def persist(candidate):
                save(path, 'temporary-password', candidate)

            return Client(Gateway(name), crypto, persist, state)

        self.clients = {name: create(name) for name in names}
        self.alice, self.bob, self.carol = self.clients['alice'], self.clients['bobby'], self.clients['carol']
        for left, right in (('alice', 'bobby'), ('alice', 'carol'), ('bobby', 'carol')):
            safety = self.clients[left].safety(right)
            self.clients[left].trust(right, safety)
            self.clients[right].trust(left, safety)

    def test_hybrid_round_trip_replay_and_missing_prekey(self):
        with self.assertRaises(LookupError):
            self.alice.send_hybrid('bobby', 'antes')
        self.assertEqual(self.sent, [])
        self.bob.ensure_hybrid_prekey()
        self.alice.send_hybrid('bobby', 'inicio hibrido')
        self.assertNotIn('inicio hibrido', repr(self.sent))
        self.assertNotIn(self.alice.state['hybrid_secret']['seed'], repr(self.sent))
        self.assertEqual(self.bob.receive(), [('alice', 'inicio hibrido')])
        remembered = copy.deepcopy(self.sent[-1])
        self.inboxes['bobby'].append({'id': 99, 'envelope': remembered})
        self.assertEqual(self.bob.receive(), [])
        self.assertEqual(self.inboxes['bobby'], [])
        self.assertEqual([row['text'] for row in self.bob.state['history']], ['inicio hibrido'])
        self.bob.send('alice', 'respuesta')
        self.assertEqual(self.alice.receive(), [('bobby', 'respuesta')])

    def test_group_hides_sender_key_and_rotates_when_a_member_leaves(self):
        group_id = self.alice.create_group('Equipo', ['bobby', 'carol'])
        chain_key = self.alice.state['groups'][group_id]['send']['chain_key']
        self.alice.send_group(group_id, 'hola')
        mailed = [item for item in self.sent if item.get('message', {}).get('protocol') == 'group-v1']
        self.assertEqual(len(mailed), 1)
        self.assertNotIn('recipient', mailed[0]['message'])
        self.assertEqual(self.group_mail[-1]['pending'], {'bobby', 'carol'})
        self.assertNotIn(chain_key, repr(self.sent))
        self.assertEqual(self.bob.receive(), [('alice', 'hola')])
        self.assertEqual(self.carol.receive(), [('alice', 'hola')])
        self.assertTrue(all(chain_key not in row['text'] for row in self.bob.state['history']))
        self.assertIn('Clave de grupo actualizada', [row['text'] for row in self.bob.state['history']])
        self.alice.remove_group_member(group_id, 'carol')
        self.alice.send_group(group_id, 'secreto')
        self.assertEqual(self.bob.receive(), [('alice', 'secreto')])
        self.assertEqual(self.carol.receive(), [])
        self.assertNotIn('secreto', repr(self.inboxes['carol']))
        self.assertNotIn('carol', self.group_mail[-1]['pending'])
        self.assertEqual([row for row in self.bob.state['history'] if row['kind'] == 'group-v1'][0]['peer'], 'g:' + group_id)
        self.assertEqual([row for row in self.bob.state['history'] if row['kind'] == 'group-v1'][0]['author'], 'alice')
        self.assertNotIn('hola', [row['text'] for row in self.bob.state['history'] if row['peer'] == 'alice'])

    def test_group_receive_leaves_a_private_message_queued(self):
        group_id = self.alice.create_group('Equipo', ['bobby'])
        self.alice.send('bobby', 'privado')
        self.alice.send_group(group_id, 'hola')
        self.bob.gateway.pending_kinds = lambda: {'alice': ['group-key-v1', 'group-v1', 'classic']}
        self.bob.pull_group_traffic()
        self.assertEqual([row['text'] for row in self.bob.state['history'] if row['peer'] == 'g:' + group_id and row['kind'] == 'group-v1'], ['hola'])
        self.assertEqual(self.bob.receive(only_peer='alice'), [('alice', 'privado')])
        self.alice.send_group(group_id, 'despues')
        self.assertEqual(self.bob.receive(only_group=group_id), [('alice', 'despues')])

    def test_group_message_without_sender_key_stays_unacknowledged(self):
        group_id = self.alice.create_group('Equipo', ['bobby'])
        self.alice.send_group(group_id, 'temprano')
        self.inboxes['bobby'] = [
            item for item in self.inboxes['bobby']
            if item['envelope']['message'].get('protocol') != 'group-key-v1'
        ]
        with self.assertRaises(MissingGroupKey):
            self.bob.receive()
        self.assertIn('bobby', self.group_mail[-1]['pending'])
        self.assertNotIn('temprano', repr(self.bob.state['history']))

    def test_available_screen_offers_hybrid_and_groups(self):
        from cliente.workspace import workspace_screen
        page = workspace_screen('csrf', 'alice', [{'name': 'bobby', 'online': True}], [], 'bobby', '', 'chat', [], '', dr_mode='available')
        self.assertIn('Enviar con acuerdo híbrido', page)
        groups = workspace_screen('csrf', 'alice', [{'name': 'bobby', 'online': True, 'verified': True}, {'name': 'carol', 'online': False}], [], '', '', 'groups', [], '')
        self.assertIn('Crear grupo y enviar', groups)
        self.assertIn('id="member-search"', groups)
        self.assertIn('data-names="bobby"', groups)
        self.assertNotIn('carol', groups)
        self.assertNotIn('chain_key', groups)
        conversation = workspace_screen('csrf', 'alice', [], [{'peer': 'g:' + 'ab' * 16, 'direction': 'in', 'text': 'hola', 'kind': 'group-v1', 'author': 'bobby'}], 'g:' + 'ab' * 16, '', 'chat', [], '', groups=[{'id': 'ab' * 16, 'name': 'Equipo', 'members': ['alice', 'bobby']}])
        self.assertIn('Equipo', conversation)
        self.assertIn('class="who">bobby', conversation)
        self.assertIn('value="send_group"', conversation)
        self.assertNotIn('Enviar con Double Ratchet', conversation)
        self.assertIn('data-contact="Equipo"', conversation)
