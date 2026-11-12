"""Cifra y descifra cada mensaje con AES-GCM y una clave distinta por contador."""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .encoding import b64, unb64, canonical
from .nonce import message_nonce
from .ratchet import advance
from securechat.domain.errors import InvalidMessageNonce, UnsupportedMessageFormat, InvalidClassicMessage

def encrypt(state, text, content_format=None):
    counter = state['send_counter']; key, next_key = advance(unb64(state['send_key']))
    metadata = {'session': state['session'], 'sender': state['me'], 'recipient': state['peer'], 'counter': counter}
    if content_format is not None:
        if content_format != 'attachment-v1': raise UnsupportedMessageFormat('Unsupported content format')
        metadata['content_format'] = content_format
    nonce = message_nonce(counter)
    ciphertext = AESGCM(key).encrypt(nonce, text.encode(), canonical(metadata))
    state['send_key'] = b64(next_key); state['send_counter'] += 1
    return dict(metadata, nonce=b64(nonce), ciphertext=b64(ciphertext))

def decrypt(state, message):
    metadata = {k: message[k] for k in ('session', 'sender', 'recipient', 'counter')}
    if metadata != {'session': state['session'], 'sender': state['peer'], 'recipient': state['me'], 'counter': state['receive_counter']}:
        raise InvalidClassicMessage('Unexpected session, sender, recipient or counter')
    if 'content_format' in message:
        if message['content_format'] != 'attachment-v1': raise UnsupportedMessageFormat('Unsupported content format')
        metadata['content_format'] = message['content_format']
    key, next_key = advance(unb64(state['receive_key']))
    # Messages produced before nonce support used a 96-bit all-zero nonce.
    try:
        nonce = unb64(message['nonce']) if 'nonce' in message else bytes(12)
    except (AttributeError, TypeError, ValueError, UnicodeError) as exc:
        raise InvalidMessageNonce('Invalid nonce encoding') from exc
    if len(nonce) != 12:
        raise InvalidMessageNonce('Invalid nonce length')
    try:
        ciphertext = unb64(message['ciphertext'])
    except (AttributeError, TypeError, ValueError, UnicodeError) as exc:
        raise InvalidClassicMessage('Invalid ciphertext encoding') from exc
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, canonical(metadata)).decode()
    state['receive_key'] = b64(next_key); state['receive_counter'] += 1
    return plaintext
