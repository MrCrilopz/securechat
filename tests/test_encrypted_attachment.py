"""Pruebas del laboratorio aislado de adjuntos cifrados."""
import base64
import copy
import unittest
from cryptography.exceptions import InvalidTag
from cliente.application.attachment import create_attachment, open_attachment, AttachmentError, MAX_ATTACHMENT_BYTES
from cliente.infrastructure.attachment_cipher import AttachmentCipher


class EncryptedAttachmentTests(unittest.TestCase):
    def setUp(self):
        self.cipher = AttachmentCipher()
        self.name = 'informe-secreto.pdf'
        self.content = b'contenido privado\x00\xff'

    def create(self):
        return create_attachment(self.cipher, self.name, self.content)

    def test_metadata_and_content_are_not_visible_in_envelope(self):
        key, envelope = self.create()
        self.assertNotIn(self.name, repr(envelope))
        self.assertNotIn(self.content.hex(), repr(envelope))
        self.assertNotIn(base64.b64encode(self.content).decode(), repr(envelope))
        self.assertNotIn(base64.b64encode(key).decode(), repr(envelope))
        self.assertEqual(open_attachment(self.cipher, key, envelope), (self.name, self.content))

    def test_each_file_uses_a_fresh_key_and_the_fixed_one_time_nonce(self):
        first_key, first = self.create()
        second_key, second = self.create()
        self.assertNotEqual(first_key, second_key)
        self.assertEqual(first['nonce'], second['nonce'])
        self.assertEqual(len(base64.b64decode(first['nonce'], validate=True)), 12)
        self.assertNotEqual(first['ciphertext'], second['ciphertext'])

    def test_changes_or_wrong_key_are_rejected(self):
        key, envelope = self.create()
        for field in ('nonce', 'ciphertext'):
            with self.subTest(field=field):
                altered = copy.deepcopy(envelope)
                value = bytearray(base64.b64decode(altered[field], validate=True))
                value[0] ^= 1
                altered[field] = base64.b64encode(value).decode()
                with self.assertRaises((AttachmentError, InvalidTag, ValueError)):
                    open_attachment(self.cipher, key, altered)
        with self.assertRaises((AttachmentError, InvalidTag, ValueError)):
            open_attachment(self.cipher, bytes(len(key)), envelope)
        altered = dict(envelope, version=2)
        with self.assertRaises(AttachmentError):
            open_attachment(self.cipher, key, altered)

    def test_dangerous_filenames_and_oversize_are_rejected(self):
        for name in ('../evil', 'x/evil', 'x\\evil', '', '.', '..', 'bad\x00name', 'bad\u202ename'):
            with self.subTest(name=name), self.assertRaises(AttachmentError):
                create_attachment(self.cipher, name, b'data')
        with self.assertRaises(AttachmentError):
            create_attachment(self.cipher, 'file', bytes(MAX_ATTACHMENT_BYTES + 1))
        key, envelope = create_attachment(self.cipher, 'archivo.bin', bytes(MAX_ATTACHMENT_BYTES))
        self.assertEqual(len(open_attachment(self.cipher, key, envelope)[1]), MAX_ATTACHMENT_BYTES)

    def test_malformed_envelopes_fail_closed(self):
        key, envelope = self.create()
        for changed in (dict(envelope, nonce='!'), dict(envelope, ciphertext='!'),
                        dict(envelope, extra='value'), dict(envelope, version=True)):
            with self.subTest(changed=changed), self.assertRaises((AttachmentError, ValueError)):
                open_attachment(self.cipher, key, changed)

    def test_prototype_package_inside_encrypted_chat_message(self):
        import contextlib
        import json
        import os
        import socket
        import sqlite3
        import subprocess
        import sys
        import tempfile
        from cliente.application.client import Client
        from cliente.infrastructure.http_gateway import HttpGateway
        from securechat.infrastructure import crypto

        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            database = os.path.join(directory, 'server.sqlite3')
            server = subprocess.Popen([sys.executable, '-m', 'servidor.server', '--port', str(port),
                                       '--database', database], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertIn(b'Local server running', server.stdout.readline())
                gateways = [HttpGateway(port), HttpGateway(port)]
                identities = [crypto.Identity.generate(name) for name in ('alice', 'bobby')]
                clients = []
                for name, gateway, identity in zip(('alice', 'bobby'), gateways, identities):
                    gateway.register(name, 'password for testing', identity.bundle())
                    gateway.login(name, 'password for testing')
                    state = {'identity': identity.serialize(), 'contacts': {}, 'sessions': {},
                             'history': [], 'outbox': []}
                    clients.append(Client(gateway, crypto, lambda _: None, state))
                alice, bob = clients
                fingerprint = alice.safety('bobby')
                alice.trust('bobby', fingerprint)
                bob.trust('alice', fingerprint)
                key, envelope = self.create()
                package = json.dumps({'key': base64.b64encode(key).decode(), 'attachment': envelope})
                alice.send('bobby', package)
                with contextlib.closing(sqlite3.connect(database)) as db:
                    stored = db.execute('SELECT envelope FROM messages').fetchone()[0]
                for secret in (self.name, base64.b64encode(self.content).decode(),
                               base64.b64encode(key).decode()):
                    self.assertNotIn(secret, stored)
                [(peer, received)] = bob.receive()
                self.assertEqual(peer, 'alice')
                obj = json.loads(received)
                opened = open_attachment(self.cipher, base64.b64decode(obj['key']), obj['attachment'])
                self.assertEqual(opened, (self.name, self.content))
            finally:
                server.terminate()
                server.wait(timeout=5)
                server.stdout.close()
                server.stderr.close()
