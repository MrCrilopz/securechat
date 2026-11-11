"""Comprueba sesiones, presencia, recepción automática y las pantallas de la conversación."""
import os, tempfile, time, unittest
from securechat.infrastructure.server_adapters import SqliteRepository

class SessionFeaturesTest(unittest.TestCase):
    def test_logout_revokes_token_and_online_status(self):
        with tempfile.TemporaryDirectory() as directory:
            db = SqliteRepository(os.path.join(directory, 'chat.db'))
            db.create_user('alice', 'hash', {})
            db.save_token('tokenhash', 'alice', time.time() + 3600)
            db.touch_presence('alice', time.time())
            self.assertTrue(db.is_online('alice', time.time()))
            db.revoke_token('tokenhash')
            db.clear_presence('alice')
            self.assertIsNone(db.token_user('tokenhash', time.time()))
            self.assertFalse(db.is_online('alice', time.time()))

    def test_server_inspection_returns_only_queued_ciphertexts(self):
        with tempfile.TemporaryDirectory() as directory:
            db = SqliteRepository(os.path.join(directory, 'chat.db'))
            db.enqueue('bob', 'alice', {'message': {'ciphertext': 'encrypted123'}})
            rows = db.inspect_messages()
            self.assertEqual(rows[0]['envelope']['message']['ciphertext'], 'encrypted123')
            self.assertNotIn('plaintext', str(rows))

class WorkspaceViewTest(unittest.TestCase):
    def test_login_is_first_screen_and_chat_has_logout(self):
        from securechat.workspace import login_screen, workspace_screen
        self.assertIn('Iniciar sesión', login_screen('csrf'))
        self.assertNotIn('Cerrar sesión', login_screen('csrf'))
        page = workspace_screen('csrf', 'alice', [], [], '', '', 'chat', [], '')
        self.assertIn('Cerrar sesión', page)
        self.assertIn('Conversaciones', page)
        self.assertNotIn('value="view_server"', page)

class FullLoginTest(unittest.TestCase):
    def test_registration_login_duplicate_and_logout(self):
        import http.cookiejar, re, socket, subprocess, sys, urllib.error, urllib.parse, urllib.request
        with tempfile.TemporaryDirectory() as directory:
            def free_port():
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]
            server_port, ui_port = free_port(), free_port()
            database = os.path.join(directory, 'server.db')
            server = subprocess.Popen([sys.executable, '-m', 'securechat.server', '--port', str(server_port), '--database', database], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ui = None
            try:
                server.stdout.readline()
                ui = subprocess.Popen([sys.executable, '-m', 'securechat.ui', '--port', str(ui_port), '--server-port', str(server_port), '--database', database, '--home', os.path.join(directory, 'clients')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                ui.stdout.readline()
                base = f'http://127.0.0.1:{ui_port}'
                opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                first = opener.open(base).read().decode()
                csrf = re.search(r'name="csrf" value="([^"]+)"', first).group(1)
                def action(**data):
                    data['csrf'] = csrf
                    request = urllib.request.Request(base + '/', data=urllib.parse.urlencode(data).encode(), headers={'Origin': base})
                    return opener.open(request).read().decode()
                self.assertIn('Cerrar sesión', action(action='register', user='alice', password='password-demo-123'))
                self.assertIn('Sesión cerrada', action(action='logout'))
                self.assertIn('ya existe', action(action='register', user='alice', password='password-demo-123'))
                self.assertIn('Cerrar sesión', action(action='login', user='alice', password='password-demo-123'))
                self.assertIn('Sesión cerrada', action(action='logout'))
                self.assertIn('Iniciar sesión', opener.open(base).read().decode())
            finally:
                for process in (ui, server):
                    if process:
                        process.terminate(); process.wait(timeout=5); process.stdout.close(); process.stderr.close()

class IdentityWarningTest(unittest.TestCase):
    def test_changed_identity_warning_is_shown_in_chat_and_contacts(self):
        from securechat.workspace import workspace_screen
        contacts = [{'name': 'bob', 'online': False, 'verified': False, 'changed': True}]
        for view in ('chat', 'contacts'):
            page = workspace_screen('csrf', 'alice', contacts, [], 'bob', '', view, [], '')
            self.assertIn('La clave de identidad cambió', page)

class WorkspaceEndToEndTest(unittest.TestCase):
    def test_chat_server_ciphertext_and_session_isolation(self):
        import http.cookiejar, re, socket, subprocess, sys, urllib.parse, urllib.request
        with tempfile.TemporaryDirectory() as directory:
            def free_port():
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]
            sp, up = free_port(), free_port(); db = os.path.join(directory, 'db.sqlite')
            server = subprocess.Popen([sys.executable, '-m', 'securechat.server', '--port', str(sp), '--database', db], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ui = None
            try:
                server.stdout.readline()
                ui = subprocess.Popen([sys.executable, '-m', 'securechat.ui', '--port', str(up), '--server-port', str(sp), '--database', db, '--home', os.path.join(directory, 'users')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                ui.stdout.readline(); base = f'http://127.0.0.1:{up}'
                def browser():
                    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                    page = op.open(base).read().decode(); token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
                    def post(**data):
                        data['csrf'] = token
                        return op.open(urllib.request.Request(base + '/', data=urllib.parse.urlencode(data).encode(), headers={'Origin':base})).read().decode()
                    return post
                alice, bob = browser(), browser()
                for post, name in ((alice, 'alice'), (bob, 'bobby')):
                    self.assertIn('Cerrar sesión', post(action='register', user=name, password='demo-password-123'))
                self.assertIn('En línea', alice(action='view_chat'))
                ah = alice(action='safety', peer='bobby'); bh = bob(action='safety', peer='alice')
                a = re.search(r'[a-f0-9]{64}', ah).group(); b = re.search(r'[a-f0-9]{64}', bh).group(); self.assertEqual(a, b)
                self.assertIn('Contacto verificado', alice(action='trust', peer='bobby', safety=a))
                self.assertIn('Contacto verificado', bob(action='trust', peer='alice', safety=b))
                chat = alice(action='send', peer='bobby', message='mensaje privado 123')
                self.assertIn('mensaje privado 123', chat)
                queued = SqliteRepository(db).inspect_messages(); self.assertNotIn('mensaje privado 123', str(queued)); self.assertEqual(len(queued), 1)
                waiting = bob(action='heartbeat'); self.assertNotIn('mensaje privado 123', waiting)
                self.assertEqual(len(SqliteRepository(db).inspect_messages()), 1)
                received = bob(action='select', peer='alice'); self.assertIn('mensaje privado 123', received)
                self.assertEqual(len(SqliteRepository(db).inspect_messages()), 0)
                self.assertIn('mensaje privado 123', bob(action='heartbeat'))
                left = bob(action='leave')
                self.assertIn('Selecciona un contacto para comenzar', left)
                self.assertNotIn('data-peer="alice"', left)
                self.assertNotIn('Escribe un mensaje', left)
                alice(action='send', peer='bobby', message='sigue en la cola')
                self.assertNotIn('sigue en la cola', bob(action='heartbeat'))
                self.assertEqual(len(SqliteRepository(db).inspect_messages()), 1)
                self.assertIn('Sesión cerrada', alice(action='logout'))
                self.assertIn('Cerrar sesión', bob(action='view_chat'))
                self.assertIn('Sin conexión', bob(action='view_chat'))
            finally:
                for process in (ui, server):
                    if process: process.terminate(); process.wait(timeout=5); process.stdout.close(); process.stderr.close()

class PrivateServerPanelTest(unittest.TestCase):
    def test_user_workspace_hides_server_and_security_views(self):
        from securechat.workspace import workspace_screen
        page = workspace_screen('csrf', 'alice', [], [], '', '', 'chat', [], '')
        self.assertNotIn('value="view_server"', page)
        self.assertNotIn('value="view_security"', page)

    def test_admin_login_and_access_control(self):
        from securechat.admin import make_admin_handler
        self.assertTrue(callable(make_admin_handler))

class OperatorHttpTest(unittest.TestCase):
    def test_panel_requires_password_and_never_exposes_plaintext(self):
        import http.cookiejar, json, re, threading, urllib.error, urllib.parse, urllib.request
        from http.server import HTTPServer
        from securechat.admin import make_admin_handler
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, 'db.sqlite'); db = SqliteRepository(path)
            db.enqueue('bob', 'alice', {'message': {'ciphertext': 'CIFRADO-123', 'plaintext': 'texto secreto'}})
            webserver = HTTPServer(('127.0.0.1', 0), make_admin_handler(path, 'clave-admin-segura'))
            thread = threading.Thread(target=webserver.serve_forever, daemon=True); thread.start()
            try:
                url = f'http://127.0.0.1:{webserver.server_port}/'
                client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                page = client.open(url).read().decode()
                self.assertNotIn('CIFRADO-123', page)
                token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
                def post(password):
                    data = urllib.parse.urlencode({'csrf':token, 'action':'login', 'password':password}).encode()
                    return client.open(urllib.request.Request(url, data=data, headers={'Origin':url.rstrip('/')})).read().decode()
                self.assertNotIn('CIFRADO-123', post('incorrecta'))
                panel = post('clave-admin-segura')
                self.assertIn('CIFRADO-123', panel)
                self.assertIn('card-select', panel)
                self.assertNotIn('Ver sobre', panel)
                self.assertIn('texto secreto', panel)
                self.assertIn('id="lab-steps"', panel)
                self.assertIn('id="queue"', panel); self.assertIn('/admin.js', panel)
                self.assertIn('id="envelope-json"', panel)
                self.assertIn('class="cipher envelope-pane"', panel)
                queue = json.loads(client.open(urllib.request.Request(url + 'queue', headers={'Accept': 'application/json'})).read().decode())
                self.assertEqual(queue[0]['envelope']['message']['ciphertext'], 'CIFRADO-123')
                self.assertEqual(queue[0]['protocol'], 'clásico')
                self.assertNotIn('Actualiza la página', panel)
            finally:
                webserver.shutdown(); thread.join(); webserver.server_close()

class AutoReceiveViewTest(unittest.TestCase):
    def test_workspace_has_automatic_message_target(self):
        from securechat.workspace import workspace_screen
        page = workspace_screen('csrf', 'alice', [{'name':'bobby','online': True}], [], 'bobby', '', 'chat', [], '')
        self.assertIn('id="messages"', page)
        self.assertIn('data-peer="bobby"', page)
        self.assertNotIn('Esc para salir', page)
        self.assertNotIn('>Recibir</button>', page)
        from cliente.ui import UI_SCRIPT
        self.assertIn("event.key !== 'Escape'", UI_SCRIPT)
        self.assertIn("'leave'", UI_SCRIPT)
