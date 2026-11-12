"""Formato experimental DR sobre el relay existente; no activa el protocolo.

El identificador de sesión y ambas identidades deben ser fijados por un acuerdo
inicial autenticado. El contexto que se entrega al ratchet debe ser exactamente
el resultado de `context`; cambiar solo las cabeceras no puede autorizar nada.
"""
import json
import re

from securechat.application.ratchet_session_codec import encode_packet, decode_packet, SessionCodecError
from securechat.domain.models import username


class RatchetTransportError(ValueError):
    """Sobre de transporte DR inválido o incompatible."""


def _validate(sender, recipient, session_id):
    try:
        username(sender)
        username(recipient)
    except (ValueError, TypeError) as exc:
        raise RatchetTransportError('Invalid peer') from exc
    if sender == recipient:
        raise RatchetTransportError('Invalid peer')
    if type(session_id) is not str or not re.fullmatch(r'[0-9a-f]{32}', session_id):
        raise RatchetTransportError('Invalid session id')


def context(sender, recipient, session_id):
    _validate(sender, recipient, session_id)
    data = {'protocol': 'double-ratchet', 'version': 1, 'peers': sorted((sender, recipient)),
            'session_id': session_id}
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def wrap(sender, recipient, session_id, packet):
    _validate(sender, recipient, session_id)
    try:
        encoded = encode_packet(packet)
    except SessionCodecError as exc:
        raise RatchetTransportError('Invalid packet') from exc
    return {'message': {'sender': sender, 'recipient': recipient, 'protocol': 'double-ratchet',
                        'version': 1, 'session_id': session_id, 'packet': encoded}}


def unwrap(envelope, sender, recipient, session_id):
    _validate(sender, recipient, session_id)
    if type(envelope) is not dict or set(envelope) != {'message'}:
        raise RatchetTransportError('Invalid envelope')
    message = envelope['message']
    fields = {'sender', 'recipient', 'protocol', 'version', 'session_id', 'packet'}
    if type(message) is not dict or set(message) != fields:
        raise RatchetTransportError('Invalid message')
    if (message['sender'] != sender or message['recipient'] != recipient
            or message['protocol'] != 'double-ratchet' or type(message['version']) is not int
            or message['version'] != 1 or message['session_id'] != session_id):
        raise RatchetTransportError('Session or protocol mismatch')
    try:
        return decode_packet(message['packet'])
    except SessionCodecError as exc:
        raise RatchetTransportError('Invalid packet') from exc
