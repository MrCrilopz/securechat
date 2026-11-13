"""Comprueba que los tres ataques usen el proveedor real y expliquen el rechazo."""
import unittest
from securechat.application.attacks import run_scenario
from securechat.infrastructure import crypto

class AttackLabTest(unittest.TestCase):
    def test_attacks_use_actual_crypto_and_explain_result(self):
        for name in ('prekey', 'tamper', 'replay'):
            with self.subTest(name=name):
                result = run_scenario(crypto, name, 'Mensaje de prueba')
                self.assertTrue(result['rejected'])
                self.assertTrue(result['before'])
                self.assertTrue(result['after'])
                self.assertTrue(result['explanation'])

    def test_unknown_scenario_is_rejected(self):
        with self.assertRaises(ValueError): run_scenario(crypto, 'other', 'Hola')

class AttackUiTest(unittest.TestCase):
    def test_lab_controls_are_rendered(self):
        from securechat.ui import render_page, perform
        page = render_page('test', tab='tests')
        for scenario in ('prekey', 'tamper', 'replay'):
            self.assertIn('value="lab_' + scenario + '"', page)
            result = perform({'action': 'lab_' + scenario, 'demo_text': 'Ejemplo'}, 8765, '/tmp/unused')
            self.assertIn('RECHAZADO', result)
            self.assertIn('Antes:', result)
            self.assertIn('Después:', result)
