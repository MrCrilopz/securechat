"""Verifica la ubicación real y compatibilidad de las partes desplegables."""
import importlib
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


class SeparationTests(unittest.TestCase):
    def test_implementation_is_located_in_its_component(self):
        for name, folder in (
            ('cliente.ui', 'cliente'), ('cliente.client', 'cliente'),
            ('cliente.application.client', 'cliente'),
            ('cliente.infrastructure.local_store', 'cliente'),
            ('servidor.server', 'servidor'), ('servidor.admin', 'servidor'),
            ('servidor.application.service', 'servidor'),
            ('servidor.infrastructure.server_adapters', 'servidor'),
        ):
            with self.subTest(name=name):
                module = importlib.import_module(name)
                self.assertTrue(pathlib.Path(module.__file__).resolve().is_relative_to(ROOT / folder))

    def test_new_and_original_commands_offer_help(self):
        for name in ('cliente.ui', 'cliente.client', 'servidor.server', 'servidor.admin',
                     'securechat.ui', 'securechat.client', 'securechat.server', 'securechat.admin'):
            with self.subTest(name=name):
                process = subprocess.run([sys.executable, '-m', name, '--help'], cwd=ROOT,
                                         capture_output=True, text=True, timeout=10)
                self.assertEqual(process.returncode, 0, process.stderr)
                self.assertIn('usage:', process.stdout)

    def test_original_imports_refer_to_same_classes(self):
        from cliente.application.client import Client
        from securechat.application.client import Client as OldClient
        from servidor.application.service import ChatService
        from securechat.application.service import ChatService as OldService
        self.assertIs(Client, OldClient)
        self.assertIs(ChatService, OldService)

    def test_new_server_with_new_client_delivers_encrypted_message(self):
        import socket
        import tempfile
        from cliente.application.client import Client
        from cliente.infrastructure.http_gateway import HttpGateway
        from securechat.infrastructure import crypto

        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0))
                port = probe.getsockname()[1]
            db = str(pathlib.Path(directory) / 'test.sqlite3')
            process = subprocess.Popen([sys.executable, '-m', 'servidor.server', '--port', str(port),
                                        '--database', db], cwd=ROOT, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE)
            try:
                self.assertIn(b'Local server running', process.stdout.readline())
                identities = [crypto.Identity.generate(name) for name in ('alice', 'bobby')]
                gateways = [HttpGateway(port), HttpGateway(port)]
                clients = []
                for gateway, identity, name in zip(gateways, identities, ('alice', 'bobby')):
                    gateway.register(name, 'test password 1234', identity.bundle())
                    gateway.login(name, 'test password 1234')
                    state = {'identity': identity.serialize(), 'contacts': {}, 'sessions': {},
                             'history': [], 'outbox': []}
                    clients.append(Client(gateway, crypto, lambda _: None, state))
                alice, bob = clients
                safety = alice.safety('bobby')
                self.assertEqual(safety, bob.safety('alice'))
                alice.trust('bobby', safety)
                bob.trust('alice', safety)
                alice.send('bobby', 'separacion mensaje privado')
                self.assertNotIn(b'separacion mensaje privado', pathlib.Path(db).read_bytes())
                self.assertEqual(bob.receive(), [('alice', 'separacion mensaje privado')])
            finally:
                process.terminate()
                process.wait(timeout=5)
                process.stdout.close()
                process.stderr.close()

    def test_server_announces_ready_only_after_binding(self):
        import contextlib
        import io
        from unittest.mock import patch
        import servidor.server as server

        output = io.StringIO()
        class BoundServer:
            def __init__(self, address, handler):
                self.address = address
                self.server_port = address[1]
                self.output_at_binding = output.getvalue()
            def serve_forever(self):
                self.assertion = 'Local server running' in output.getvalue()
                if not self.assertion:
                    raise AssertionError('No se anunció el servidor después de enlazarlo')

        with tempfile_for_database() as db, patch.object(server, 'ThreadingHTTPServer', BoundServer), \
             patch.object(sys, 'argv', ['servidor.server', '--database', db]), \
             contextlib.redirect_stdout(output):
            created = []
            class ObservedServer(BoundServer):
                def __init__(self, address, handler):
                    super().__init__(address, handler)
                    created.append(self)
            with patch.object(server, 'ThreadingHTTPServer', ObservedServer):
                server.main()
            self.assertEqual(created[0].output_at_binding, '')
            self.assertTrue(created[0].assertion)


def tempfile_for_database():
    import tempfile
    class Database:
        def __enter__(self):
            self.directory = tempfile.TemporaryDirectory()
            return str(pathlib.Path(self.directory.name) / 'test.sqlite3')
        def __exit__(self, *args):
            self.directory.cleanup()
    return Database()
