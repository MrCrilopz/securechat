"""Formato y persistencia del adjunto antes de cualquier interfaz."""
import copy
import unittest
from cryptography.exceptions import InvalidTag
from cliente.application.client import Client
from cliente.application.attachment import AttachmentError
from cliente.infrastructure.attachment_codec import AttachmentCodec
from securechat.infrastructure import crypto


class AttachmentConversationTests(unittest.TestCase):
    def setUp(self):
        self.aid = crypto.Identity.generate('alice')
        self.bid = crypto.Identity.generate('bobby')
        self.bundles = {'alice': self.aid.bundle(), 'bobby': self.bid.bundle()}
        self.messages = {'alice': [], 'bobby': []}
        self.acknowledged = []
        outer = self
        class Gateway:
            def __init__(self, name): self.name = name
            def bundle(self, name): return outer.bundles[name]
            def send(self, recipient, envelope):
                outer.messages[recipient].append({'id': len(outer.messages[recipient])+1, 'envelope': envelope})
            def inbox(self): return copy.deepcopy(outer.messages[self.name])
            def acknowledge(self, message_id):
                outer.acknowledged.append(message_id)
                outer.messages[self.name] = [x for x in outer.messages[self.name] if x['id'] != message_id]
        def make(name, identity, codec=AttachmentCodec()):
            state = {'identity': identity.serialize(), 'contacts': {}, 'sessions': {}, 'history': [], 'outbox': []}
            return Client(Gateway(name), crypto, lambda _: None, state, attachments=codec)
        self.alice, self.bob = make('alice', self.aid), make('bobby', self.bid)
        number = self.alice.safety('bobby')
        self.alice.trust('bobby', number); self.bob.trust('alice', number)

    def test_legacy_text_that_looks_like_json_remains_text(self):
        text = '{"type":"attachment-v1","name":"not-a-file"}'
        self.alice.send('bobby', text)
        self.assertEqual(self.bob.receive(), [('alice', text)])
        self.assertNotIn('kind', self.bob.state['history'][0])

    def test_attachment_round_trip_keeps_sensitive_fields_from_relay(self):
        self.alice.send_attachment('bobby', 'archivo-privado.txt', b'contenido privado')
        entry = self.messages['bobby'][0]
        self.assertEqual(entry['envelope']['message']['content_format'], 'attachment-v1')
        serialized = repr(entry)
        self.assertNotIn('archivo-privado.txt', serialized)
        self.assertNotIn('contenido privado', serialized)
        self.bob.receive()
        row = self.bob.state['history'][0]
        self.assertEqual(row['kind'], 'attachment-v1')
        self.assertEqual(AttachmentCodec().open(row['text']), ('archivo-privado.txt', b'contenido privado'))
        self.assertEqual(self.acknowledged, [1])

    def test_format_tampering_rejected_without_ack_or_advance(self):
        self.alice.send_attachment('bobby', 'name.txt', b'content')
        self.messages['bobby'][0]['envelope']['message'].pop('content_format')
        before = copy.deepcopy(self.bob.state)
        with self.assertRaises((InvalidTag, ValueError)):
            self.bob.receive()
        self.assertEqual(self.bob.state, before)
        self.assertEqual(self.acknowledged, [])

    def test_malformed_authenticated_attachment_not_acknowledged(self):
        self.alice._send_message('bobby', '{"invalid":true}', 'attachment-v1')
        before = copy.deepcopy(self.bob.state)
        with self.assertRaises((AttachmentError, ValueError)):
            self.bob.receive()
        self.assertEqual(self.bob.state, before)
        self.assertEqual(self.acknowledged, [])

    def test_missing_attachment_decoder_does_not_ack(self):
        self.alice.send_attachment('bobby', 'name.txt', b'content')
        self.bob.attachments = None
        before = copy.deepcopy(self.bob.state)
        with self.assertRaises(ValueError): self.bob.receive()
        self.assertEqual(self.bob.state, before)
        self.assertEqual(self.acknowledged, [])

    def test_older_decoder_rejects_new_attachment_without_advancing(self):
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from securechat.infrastructure.encoding import canonical, unb64
        from securechat.infrastructure.ratchet import advance
        self.alice.send_attachment('bobby', 'name.txt', b'content')
        envelope = self.messages['bobby'][0]['envelope']
        old_state = crypto.accept(self.bid, self.aid.bundle(), envelope['header'])
        message = envelope['message']
        key, _ = advance(unb64(old_state['receive_key']))
        legacy_metadata = {name: message[name] for name in ('session', 'sender', 'recipient', 'counter')}
        with self.assertRaises(InvalidTag):
            AESGCM(key).decrypt(unb64(message['nonce']), unb64(message['ciphertext']), canonical(legacy_metadata))
        self.assertEqual(old_state['receive_counter'], 0)
