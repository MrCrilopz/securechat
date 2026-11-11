"""Un mensaje de grupo ocupa un solo sobre y cada miembro lo confirma aparte."""
import tempfile
import unittest
from pathlib import Path

from securechat.domain.errors import ReusedNonceCounter
from servidor.application.service import ChatService
from servidor.infrastructure.server_adapters import SqliteRepository


def envelope(group, counter=0, ciphertext=None):
    packet = {
        'group': group, 'epoch': 0, 'sender': 'alice', 'key_id': 'cd' * 16, 'counter': counter,
        'nonce': 'aa' * 12, 'ciphertext': ciphertext or ('bb' * 20), 'signature': 'cc' * 64,
    }
    return {'message': {'sender': 'alice', 'protocol': 'group-v1', 'group': group, 'packet': packet}}


class GroupMailboxTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = SqliteRepository(Path(self.temp.name) / 'db.sqlite')
        for name in ('alice', 'bobby', 'carol'):
            self.repo.create_user(name, 'hash', {'username': name})
        self.service = ChatService(self.repo, None, None, lambda: 0, lambda: 'token')
        self.group = 'ab' * 16

    def test_one_envelope_stays_until_every_member_acknowledges(self):
        mail_id = self.service.send_group_mail('alice', self.group, ['bobby', 'carol'], envelope(self.group))
        self.assertEqual(self.repo.group_inbox('bobby'), self.repo.group_inbox('carol'))
        self.assertEqual(self.repo.group_inbox('bobby')[0]['id'], mail_id)
        self.assertNotIn('recipient', self.repo.group_inbox('bobby')[0]['envelope']['message'])
        self.assertEqual(self.repo.inbox('bobby'), [])
        self.service.acknowledge_group('bobby', mail_id)
        self.assertEqual(self.repo.group_inbox('bobby'), [])
        self.assertEqual(self.repo.group_inbox('carol')[0]['id'], mail_id)
        self.service.acknowledge_group('carol', mail_id)
        self.assertEqual(self.repo.group_pending('carol'), {})
        with self.assertRaises(ReusedNonceCounter):
            self.service.send_group_mail('alice', self.group, ['bobby'], envelope(self.group, ciphertext='dd' * 20))

    def test_same_envelope_can_be_stored_again_without_a_second_copy(self):
        first = self.service.send_group_mail('alice', self.group, ['bobby', 'carol'], envelope(self.group))
        self.service.acknowledge_group('bobby', first)
        again = self.service.send_group_mail('alice', self.group, ['bobby', 'carol'], envelope(self.group))
        self.assertEqual(again, first)
        self.assertEqual(self.repo.group_inbox('bobby'), [])
        self.assertEqual(len(self.repo.group_inbox('carol')), 1)

    def test_unknown_member_is_rejected_before_storing(self):
        with self.assertRaises(LookupError):
            self.service.send_group_mail('alice', self.group, ['bobby', 'nadie'], envelope(self.group))
        self.assertEqual(self.repo.group_pending('bobby'), {})
