import copy
import unittest

from securechat.application.double_ratchet import init_alice, init_bob, encrypt_message, decrypt_message
from securechat.infrastructure.ratchet_provider import CryptographyRatchet
from cryptography.exceptions import InvalidTag
from securechat.application.ratchet_transport import (
    RatchetTransportError, context, wrap, unwrap,
)


class RatchetTransportTests(unittest.TestCase):
    def setUp(self):
        self.crypto = CryptographyRatchet()
        private = self.crypto.generate_dh()
        self.alice = init_alice(self.crypto, b'R' * 32, self.crypto.dh_public(private))
        self.bob = init_bob(self.crypto, b'R' * 32, private)
        self.sid = 'ab' * 16
        self.aad = context('alice', 'bobby', self.sid)
        _, self.packet = encrypt_message(self.crypto, self.alice, b'hello', self.aad)

    def test_json_roundtrip_and_authentication(self):
        import json
        encoded = json.loads(json.dumps(wrap('alice', 'bobby', self.sid, self.packet)))
        decoded = unwrap(encoded, 'alice', 'bobby', self.sid)
        self.assertEqual(decoded, self.packet)
        _, text = decrypt_message(self.crypto, self.bob, decoded, context('bobby', 'alice', self.sid))
        self.assertEqual(text, b'hello')
        self.assertNotIn('hello', json.dumps(encoded))

    def test_reject_tampering_with_metadata_and_format(self):
        valid = wrap('alice', 'bobby', self.sid, self.packet)
        for change in (
            lambda e: e['message'].update(sender='mallory'),
            lambda e: e['message'].update(recipient='mallory'),
            lambda e: e['message'].update(session_id='cd' * 16),
            lambda e: e['message'].update(version=2),
            lambda e: e['message']['packet'].update(nonce='00'),
            lambda e: e.update(unexpected=True),
        ):
            altered = copy.deepcopy(valid); change(altered)
            with self.assertRaises(RatchetTransportError):
                unwrap(altered, 'alice', 'bobby', self.sid)

    def test_different_context_cannot_decrypt(self):
        with self.assertRaises(InvalidTag):
            decrypt_message(self.crypto, self.bob, self.packet, context('alice', 'bobby', 'cd' * 16))

    def test_post_bootstrap_transport_uses_authenticated_session(self):
        from securechat.infrastructure.identity import Identity
        from securechat.infrastructure.encoding import unb64
        from securechat.infrastructure.ratchet_bootstrap import initiate, accept
        alice, bob = Identity.generate('alice'), Identity.generate('bobby')
        state_a, initial = initiate(self.crypto, alice, bob.bundle(), bob.bundle(), b'initial')
        state_b, _ = accept(self.crypto, bob, alice.bundle(), initial)
        sid = unb64(initial['session']).hex()
        aad = context('alice', 'bobby', sid)
        _, reply = encrypt_message(self.crypto, state_b, b'reply', aad)
        transport = wrap('bobby', 'alice', sid, reply)
        packet = unwrap(transport, 'bobby', 'alice', sid)
        _, plaintext = decrypt_message(self.crypto, state_a, packet, aad)
        self.assertEqual(plaintext, b'reply')

    def test_temporary_http_relay_carries_ciphertext_without_cleartext(self):
        import json
        import pathlib
        import socket
        import subprocess
        import sys
        import tempfile
        from cliente.infrastructure.http_gateway import HttpGateway
        from securechat.infrastructure import crypto

        root = pathlib.Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            with socket.socket() as probe:
                probe.bind(('127.0.0.1', 0)); port = probe.getsockname()[1]
            db = pathlib.Path(directory) / 'server.sqlite3'
            process = subprocess.Popen([sys.executable, '-m', 'servidor.server', '--port', str(port),
                '--database', str(db)], cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                self.assertIn(b'Local server running', process.stdout.readline())
                alice, bob = HttpGateway(port), HttpGateway(port)
                for gateway, name in ((alice, 'alice'), (bob, 'bobby')):
                    gateway.register(name, 'test password 1234', crypto.Identity.generate(name).bundle())
                    gateway.login(name, 'test password 1234')
                envelope = wrap('alice', 'bobby', self.sid, self.packet)
                alice.send('bobby', envelope)
                self.assertNotIn(b'hello', db.read_bytes())
                entry = bob.inbox()[0]
                payload = unwrap(entry['envelope'], 'alice', 'bobby', self.sid)
                _, text = decrypt_message(self.crypto, self.bob, payload, self.aad)
                self.assertEqual(text, b'hello')
                bob.acknowledge(entry['id'])
                self.assertEqual(bob.inbox(), [])
            finally:
                process.terminate(); process.wait(timeout=5)
                process.stdout.close(); process.stderr.close()

    def test_relay_alters_ciphertext_decryption_rejects(self):
        envelope = wrap('alice', 'bobby', self.sid, self.packet)
        text = envelope['message']['packet']['ciphertext']
        envelope['message']['packet']['ciphertext'] = ('00' if text[:2] != '00' else '01') + text[2:]
        altered = unwrap(envelope, 'alice', 'bobby', self.sid)
        with self.assertRaises(InvalidTag):
            decrypt_message(self.crypto, self.bob, altered, self.aad)

    def test_invalid_peer_and_session_rejected(self):
        for args in (('alice', 'alice', self.sid), ('alice', 'bobby', '00'), ('alice', 'bobby', 'AA' * 16)):
            with self.assertRaises(RatchetTransportError): context(*args)


if __name__ == '__main__': unittest.main()
