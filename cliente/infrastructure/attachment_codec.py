"""Codifica el adjunto y su clave dentro del mensaje cifrado del cliente."""
import base64
import binascii
import json
from cliente.application.attachment import AttachmentError, create_attachment, open_attachment
from cliente.infrastructure.attachment_cipher import AttachmentCipher


class AttachmentCodec:
    def __init__(self):
        self.cipher = AttachmentCipher()

    def create(self, name, content):
        key, envelope = create_attachment(self.cipher, name, content)
        return json.dumps({'key': base64.b64encode(key).decode('ascii'), 'envelope': envelope},
                          sort_keys=True, separators=(',', ':'))

    def open(self, text):
        if not isinstance(text, str) or len(text) > 50 * 1024:
            raise AttachmentError('Adjunto inválido')
        try:
            record = json.loads(text)
            if not isinstance(record, dict) or set(record) != {'key', 'envelope'}:
                raise AttachmentError('Adjunto inválido')
            raw = record['key']
            if not isinstance(raw, str) or len(raw) != 44:
                raise AttachmentError('Clave de adjunto inválida')
            key = base64.b64decode(raw, validate=True)
            return open_attachment(self.cipher, key, record['envelope'])
        except (json.JSONDecodeError, binascii.Error, UnicodeError, TypeError) as exc:
            raise AttachmentError('Adjunto inválido') from exc
