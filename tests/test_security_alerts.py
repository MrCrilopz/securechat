"""Avisos independientes y confirmación individual."""
import unittest

from cliente.ui import SecurityAlerts


class SecurityAlertTests(unittest.TestCase):
    def test_individual_confirmation_preserves_later_alerts_and_other_session(self):
        alice, bob = SecurityAlerts(), SecurityAlerts()
        alice.add('Mensaje alterado')
        first, revision = alice.current()
        alice.add('Clave cambiada')
        bob.add('Otro usuario')
        alice.add('Mensaje alterado')  # La misma alerta pendiente no se duplica en cada sondeo.
        self.assertEqual(alice.current()[0], first)
        self.assertFalse(alice.dismiss('identificador-antiguo'))
        self.assertTrue(alice.dismiss(first['id']))
        second, revision2 = alice.current()
        self.assertEqual(second['text'], 'Clave cambiada')
        self.assertGreater(revision2, revision)
        self.assertEqual(bob.current()[0]['text'], 'Otro usuario')
        self.assertFalse(alice.dismiss(first['id']))
        self.assertTrue(alice.dismiss(second['id']))
        self.assertIsNone(alice.current()[0])
