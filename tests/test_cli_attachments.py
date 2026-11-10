"""La consola no debe mostrar claves ni el sobre interno de los adjuntos."""
import base64
import contextlib
import io
import sys
import unittest
from unittest.mock import patch
from cliente.infrastructure.attachment_codec import AttachmentCodec
import cliente.client as cli


class CliAttachmentTests(unittest.TestCase):
    def run_action(self, action):
        codec = AttachmentCodec()
        package = codec.create('informe.txt', b'contenido reservado')
        import json
        key = json.loads(package)['key']
        rows = [{'peer': 'bobby', 'direction': 'in', 'kind': 'attachment-v1', 'text': package}]
        state = {'history': rows[:] if action == 'history' else []}
        observed = {}
        class Gateway:
            def __init__(self, port): pass
            def login(self, user, password): pass
        class FakeClient:
            def __init__(self, gateway, crypto, persist, loaded, attachments=None, dr=None):
                observed['codec'] = attachments
                self.state = loaded
            def receive(self):
                self.state['history'].append(rows[0])
                return [('bobby', package)]
        output = io.StringIO()
        with patch.object(sys, 'argv', ['client', '--password', 'password-for-test', 'alice', action]), \
             patch.object(cli, 'HttpGateway', Gateway), patch.object(cli.local_store, 'load', return_value=state), \
             patch.object(cli, 'Client', FakeClient), contextlib.redirect_stdout(output):
            cli.main()
        rendered = output.getvalue()
        self.assertIsNotNone(observed['codec'])
        self.assertIn('informe.txt', rendered)
        self.assertNotIn(key, rendered)
        self.assertNotIn(package, rendered)
        self.assertNotIn(base64.b64encode(b'contenido reservado').decode(), rendered)

    def test_history_hides_attachment_keys(self):
        self.run_action('history')

    def test_receive_hides_attachment_keys(self):
        self.run_action('receive')

    def test_cli_receives_real_attachment_without_exposing_key(self):
        import json
        import os
        import socket
        import subprocess
        import tempfile
        from cliente.application.client import Client
        from cliente.infrastructure.http_gateway import HttpGateway
        from cliente.infrastructure import local_store
        from securechat.infrastructure import crypto

        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
            database = os.path.join(directory, 'server.db')
            server = subprocess.Popen([sys.executable, '-m', 'servidor.server', '--port', str(port),
                                       '--database', database], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                server.stdout.readline()
                clients = []
                for name in ('alice', 'bobby'):
                    identity = crypto.Identity.generate(name)
                    gateway = HttpGateway(port)
                    gateway.register(name, 'example-password-123', identity.bundle())
                    gateway.login(name, 'example-password-123')
                    state = {'identity': identity.serialize(), 'contacts': {}, 'sessions': {}, 'history': [], 'outbox': []}
                    path = os.path.join(directory, name + '.json')
                    persist = lambda data, path=path: local_store.save(path, 'example-password-123', data)
                    persist(state)
                    state = local_store.load(path, 'example-password-123')
                    clients.append(Client(gateway, crypto, persist, state, attachments=AttachmentCodec()))
                alice, bobby = clients
                number = alice.safety('bobby')
                alice.trust('bobby', number); bobby.trust('alice', number)
                alice.send_attachment('bobby', 'secreto.txt', b'contenido privado')
                key = json.loads(alice.state['history'][-1]['text'])['key']
                command = [sys.executable, '-m', 'cliente.client', '--port', str(port), '--home', directory,
                           '--password', 'example-password-123', 'bobby']
                received = subprocess.run(command + ['receive'], capture_output=True, text=True, timeout=20)
                self.assertEqual(received.returncode, 0, received.stderr)
                self.assertIn('secreto.txt', received.stdout)
                self.assertNotIn(key, received.stdout)
                history = subprocess.run(command + ['history'], capture_output=True, text=True, timeout=20)
                self.assertEqual(history.returncode, 0, history.stderr)
                self.assertIn('secreto.txt', history.stdout)
                self.assertNotIn(key, history.stdout)
            finally:
                server.terminate(); server.wait(timeout=5)
                server.stdout.close(); server.stderr.close()
