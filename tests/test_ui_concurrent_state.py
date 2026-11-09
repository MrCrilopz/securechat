"""Una sesión web obsoleta se cierra sin pisar el estado escrito por otro proceso."""
import http.cookiejar
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
import urllib.request
from cliente.infrastructure import local_store
from cliente.infrastructure.http_gateway import HttpGateway
from securechat.infrastructure import crypto


class UiConcurrentStateTests(unittest.TestCase):
    def test_stale_ui_forces_login_and_preserves_other_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            def port():
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]
            sp, up = port(), port()
            db = os.path.join(directory, 'server.db'); home = os.path.join(directory, 'clients')
            server = subprocess.Popen([sys.executable, '-m', 'servidor.server', '--port', str(sp), '--database', db],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ui = None
            try:
                server.stdout.readline()
                bob = crypto.Identity.generate('bobby')
                HttpGateway(sp).register('bobby', 'test-password-123', bob.bundle())
                ui = subprocess.Popen([sys.executable, '-m', 'cliente.ui', '--port', str(up),
                                       '--server-port', str(sp), '--database', db, '--home', home],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                ui.stdout.readline(); base = f'http://127.0.0.1:{up}'
                opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                page = opener.open(base).read().decode()
                csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
                def action(**data):
                    data['csrf'] = csrf
                    request = urllib.request.Request(base + '/', data=urllib.parse.urlencode(data).encode(),
                                                     headers={'Origin': base})
                    return opener.open(request).read().decode()
                self.assertIn('Cerrar sesión', action(action='register', user='alice', password='test-password-123'))
                fingerprint = re.search(r'[a-f0-9]{64}', action(action='safety', peer='bobby')).group()
                path = os.path.join(home, 'alice.json')
                externally_loaded = local_store.load(path, 'test-password-123')
                externally_loaded['history'].append({'peer':'bobby', 'direction':'out', 'text':'conservado'})
                local_store.save(path, 'test-password-123', externally_loaded)
                stale = action(action='trust', peer='bobby', safety=fingerprint)
                self.assertIn('sesión se cerró', stale)
                self.assertIn('conservado', json.dumps(local_store.load(path, 'test-password-123')))
                self.assertIn('Cerrar sesión', action(action='login', user='alice', password='test-password-123'))
                self.assertIn('conservado', action(action='select', peer='bobby'))
            finally:
                for process in (ui, server):
                    if process:
                        process.terminate(); process.wait(timeout=5)
                        process.stdout.close(); process.stderr.close()
