"""Nonce de 96 bits fijado al contador: un mismo contador produce siempre el mismo nonce."""
from securechat.domain.errors import InvalidMessageNonce

_DOMAIN = b'\x01'
_MAX_COUNTER = 2**64 - 1


def message_nonce(counter):
    if type(counter) is not int or not 0 <= counter <= _MAX_COUNTER:
        raise InvalidMessageNonce('Invalid message counter for nonce')
    return _DOMAIN + counter.to_bytes(11, 'big')
