"""Comprueba el HTML local, el escape de resultados y la protección de cada petición."""
import unittest
from securechat.ui import render_page

class UiTest(unittest.TestCase):
    def test_action_form_is_present_and_escapes_output(self):
        page = render_page('token123', 'alice', '<script>alert(1)</script>')
        self.assertIn('name="password"', page)
        self.assertIn('name="csrf"', page)
        self.assertIn('value="register"', page)
        self.assertIn('&lt;script&gt;', page)
        self.assertNotIn('<script>alert(1)</script>', page)

class UiHttpTest(unittest.TestCase):
    def test_http_protects_mutations_from_untrusted_requests(self):
        import socket, subprocess, sys, urllib.request, urllib.error
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        server = subprocess.Popen([sys.executable, '-m', 'securechat.ui', '--port', str(port)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertIn(b'Local interface running', server.stdout.readline())
            base = f'http://127.0.0.1:{port}'
            page = urllib.request.urlopen(base + '/').read().decode()
            self.assertIn('Mensajería segura', page)
            request = urllib.request.Request(base + '/', data=b'csrf=invalid', headers={'Origin': base})
            with self.assertRaises(urllib.error.HTTPError) as error:
                urllib.request.urlopen(request)
            self.assertEqual(error.exception.code, 403)
            error.exception.close()
        finally:
            server.terminate()
            server.wait(timeout=5)
            server.stdout.close()
            server.stderr.close()

class SpanishExperienceTest(unittest.TestCase):
    def test_spanish_tabs_and_attack_button(self):
        page = render_page('token')
        self.assertIn('lang="es"', page)
        self.assertIn('Conversación', page)
        self.assertIn('Pruebas de seguridad', page)
        self.assertIn('value="attacks"', page)

    def test_attacks_run_without_user_credentials(self):
        from securechat.ui import perform
        result = perform({'action': 'attacks'}, 8765, '/tmp/unused')
        self.assertIn('3 pruebas', result)
        self.assertIn('correctamente', result)

class UiErrorTest(unittest.TestCase):
    def test_changed_identity_has_visible_specific_warning(self):
        from securechat.ui import user_error
        self.assertIn('cambió', user_error(ValueError('ALERT: contact identity key changed; verify the new safety number')))
        self.assertNotIn('ALERT:', user_error(ValueError('ALERT: contact identity key changed; verify the new safety number')))

class UiVisualControlsTest(unittest.TestCase):
    def test_password_toggle_is_accessible(self):
        page = render_page('token')
        self.assertIn('aria-label="Mostrar contraseña"', page)
        self.assertIn('aria-pressed="false"', page)
        self.assertIn('src="/ui.js"', page)

    def test_differences_are_marked_and_escaped(self):
        from securechat.ui import render_result
        rendered = render_result('RECHAZADO\nAntes: a<b\nDespués: a>c\nQué ocurrió: seguro')
        self.assertIn('<mark', rendered)
        self.assertIn('&lt;', rendered)
        self.assertIn('&gt;', rendered)
        self.assertNotIn('a<b', rendered)
        self.assertNotIn('<mark', render_result('Antes: test\nDespués: test'))

class CopySafetyNumberTest(unittest.TestCase):
    def test_copy_control_only_appears_for_valid_fingerprint(self):
        from securechat.workspace import workspace_screen
        value = 'a' * 64
        page = workspace_screen('csrf', 'alice', [], [], '', 'Huella', 'contacts', [], value)
        self.assertIn('Copiar huella', page)
        self.assertIn('data-fingerprint="' + value + '"', page)
        page = workspace_screen('csrf', 'alice', [], [], '', 'Otro resultado', 'contacts', [], '')
        self.assertNotIn('Copiar huella', page)
        page = workspace_screen('csrf', 'alice', [], [], '', 'Otro resultado', 'contacts', [], '<script>')
        self.assertNotIn('Copiar huella', page)
