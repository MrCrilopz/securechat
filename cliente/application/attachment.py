"""Laboratorio aislado de adjuntos: no está conectado al chat ni a la interfaz."""
import base64
import binascii
import json
import unicodedata
from typing import Protocol

MAX_ATTACHMENT_BYTES = 24 * 1024
MAX_ENCODED_CIPHERTEXT = 48 * 1024
_AAD = b'ProyectoCriptologia/experimental/adjunto/v1'


class AttachmentError(ValueError):
    """Adjunto inválido o no admitido."""


class AttachmentCipherPort(Protocol):
    def key(self) -> bytes: ...
    def nonce(self) -> bytes: ...
    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes: ...
    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes: ...


def _name(value):
    if not isinstance(value, str) or not value or value != value.strip() or value in ('.', '..'):
        raise AttachmentError('Nombre de archivo inválido')
    if '/' in value or '\\' in value or ':' in value or value.endswith('.'):
        raise AttachmentError('Nombre de archivo inválido')
    if any(unicodedata.category(char).startswith('C') for char in value):
        raise AttachmentError('Nombre de archivo inválido')
    try:
        if len(value.encode('utf-8')) > 120:
            raise AttachmentError('Nombre de archivo demasiado largo')
    except UnicodeError as exc:
        raise AttachmentError('Nombre de archivo inválido') from exc
    return value


def _encode(value):
    return base64.b64encode(value).decode('ascii')


def _decode(value, max_chars):
    if not isinstance(value, str) or len(value) > max_chars:
        raise AttachmentError('Adjunto codificado inválido')
    try:
        return base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise AttachmentError('Adjunto codificado inválido') from exc


def create_attachment(cipher: AttachmentCipherPort, filename: str, content: bytes):
    _name(filename)
    if not isinstance(content, bytes) or len(content) > MAX_ATTACHMENT_BYTES:
        raise AttachmentError('El archivo supera el tamaño admitido')
    body = json.dumps({'name': filename, 'content': _encode(content)},
                      ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    key, nonce = cipher.key(), cipher.nonce()
    encrypted = cipher.encrypt(key, nonce, body, _AAD)
    return key, {'version': 1, 'nonce': _encode(nonce), 'ciphertext': _encode(encrypted)}


def open_attachment(cipher: AttachmentCipherPort, key: bytes, envelope: dict):
    if not isinstance(key, bytes) or len(key) != 32:
        raise AttachmentError('Clave de adjunto inválida')
    if not isinstance(envelope, dict) or set(envelope) != {'version', 'nonce', 'ciphertext'}:
        raise AttachmentError('Sobre de adjunto inválido')
    if type(envelope['version']) is not int or envelope['version'] != 1:
        raise AttachmentError('Versión de adjunto no admitida')
    nonce = _decode(envelope['nonce'], 16)
    encrypted = _decode(envelope['ciphertext'], MAX_ENCODED_CIPHERTEXT)
    if len(nonce) != 12 or len(encrypted) < 16:
        raise AttachmentError('Sobre de adjunto inválido')
    plaintext = cipher.decrypt(key, nonce, encrypted, _AAD)
    try:
        payload = json.loads(plaintext)
        if not isinstance(payload, dict) or set(payload) != {'name', 'content'}:
            raise AttachmentError('Contenido de adjunto inválido')
        filename = _name(payload['name'])
        content = _decode(payload['content'], 4 * ((MAX_ATTACHMENT_BYTES + 2) // 3))
        if len(content) > MAX_ATTACHMENT_BYTES:
            raise AttachmentError('El archivo supera el tamaño admitido')
        return filename, content
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise AttachmentError('Contenido de adjunto inválido') from exc
