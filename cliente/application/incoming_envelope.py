"""Validación estructural previa de sobres no confiables, sin verificarlos criptográficamente."""
from securechat.domain.errors import InvalidIncomingEnvelope
from securechat.domain.models import username


def classify(entry, recipient):
    try:
        if type(entry) is not dict: raise InvalidIncomingEnvelope('Invalid entry')
        envelope = entry['envelope']
        if type(envelope) is not dict: raise InvalidIncomingEnvelope('Invalid envelope')
        message = envelope['message']
        if type(message) is not dict: raise InvalidIncomingEnvelope('Invalid message')
        peer = username(message['sender'])
        protocol = message.get('protocol')
        if protocol == 'group-v1':
            if 'recipient' in message and username(message['recipient']) != recipient:
                raise InvalidIncomingEnvelope('Invalid recipient')
            packet = message.get('packet')
            if not isinstance(packet, dict) or not isinstance(packet.get('group'), str):
                raise InvalidIncomingEnvelope('Invalid group message')
            if 'group' in message and message.get('group') != packet.get('group'):
                raise InvalidIncomingEnvelope('Invalid group message')
            return envelope, message, peer, protocol
        if username(message['recipient']) != recipient: raise InvalidIncomingEnvelope('Invalid recipient')
        if protocol in ('dr-bootstrap-v1', 'double-ratchet', 'hybrid-v1'):
            return envelope, message, peer, protocol
        if protocol not in (None, 'group-key-v1'): raise InvalidIncomingEnvelope('Unsupported protocol')
        header = envelope['header']
        if type(header) is not dict or not all(type(header.get(k)) is str for k in ('ephemeral','session')):
            raise InvalidIncomingEnvelope('Invalid classic header')
        if (not all(type(message.get(k)) is str for k in ('session','ciphertext'))
                or type(message.get('counter')) is not int or message['counter'] < 0):
            raise InvalidIncomingEnvelope('Invalid classic message')
        return envelope, message, peer, None
    except (KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, InvalidIncomingEnvelope): raise
        raise InvalidIncomingEnvelope('Invalid inbound envelope') from exc
