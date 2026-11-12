"""Codec experimental de agregado DR. El resultado contiene secretos en claro.

El llamador debe usar cifrado autenticado y una transacción junto con los demás
componentes del cliente. No valida de forma exhaustiva toda invariante del protocolo.
"""
import re
from securechat.application.double_ratchet import MAX_COUNTER
from securechat.application.ratchet_state_codec import encode_state, decode_state, RatchetStateCodecError
from securechat.application.ratchet_session_limits import (
    MAX_ACCEPTED, MAX_HISTORY, MAX_MESSAGE_ID_LENGTH, MAX_OUTBOX, MAX_PLAINTEXT_BYTES,
)

class SessionCodecError(ValueError):
    """Agregado de sesión inválido."""

_MAX_BYTES = MAX_PLAINTEXT_BYTES


def _binary(value, *, size=None, max_size=_MAX_BYTES + 16, encode):
    if encode:
        if type(value) is not bytes: raise SessionCodecError('Invalid bytes')
        data = value
    else:
        if type(value) is not str or len(value) > max_size * 2 or len(value) % 2 or not re.fullmatch(r'[0-9a-f]*', value):
            raise SessionCodecError('Invalid encoded bytes')
        data = bytes.fromhex(value)
    if len(data) > max_size or (size is not None and len(data) != size):
        raise SessionCodecError('Invalid byte length')
    return data.hex() if encode else data


def _packet(packet, encode):
    if type(packet) is not dict or set(packet) != {'header', 'nonce', 'ciphertext'}: raise SessionCodecError('Invalid packet')
    h = packet['header']
    if type(h) is not dict or set(h) != {'dh', 'pn', 'n'}: raise SessionCodecError('Invalid header')
    if any(type(h[k]) is not int or not 0 <= h[k] <= MAX_COUNTER for k in ('pn','n')): raise SessionCodecError('Invalid counter')
    result = {'header': {'dh': _binary(h['dh'],size=32,encode=encode), 'pn':h['pn'],'n':h['n']},
              'nonce':_binary(packet['nonce'],size=12,encode=encode),
              'ciphertext':_binary(packet['ciphertext'],encode=encode)}
    ciphertext_len = len(packet['ciphertext']) if encode else len(result['ciphertext'])
    if ciphertext_len < 16: raise SessionCodecError('Invalid ciphertext')
    return result


def _convert(value, encode):
    required = {'ratchet', 'outbox', 'accepted', 'history'}
    if type(value) is not dict or set(value) != (required if encode else required | {'version'}): raise SessionCodecError('Invalid session')
    if not encode and (type(value['version']) is not int or value['version'] != 1): raise SessionCodecError('Unsupported version')
    outbox, history = value['outbox'], value['history']
    if type(outbox) is not list or len(outbox) > MAX_OUTBOX or type(history) is not list or len(history) > MAX_HISTORY: raise SessionCodecError('Session limit reached')
    accepted = value['accepted']
    if encode:
        if type(accepted) is not dict: raise SessionCodecError('Invalid accepted messages')
        entries = [{'id':k,'packet':v} for k,v in accepted.items()]
    else: entries = accepted
    if type(entries) is not list or len(entries) > MAX_ACCEPTED: raise SessionCodecError('Invalid accepted messages')
    decoded = {}
    for entry in entries:
        if type(entry) is not dict or set(entry) != {'id','packet'} or type(entry['id']) is not str or not 0 < len(entry['id']) <= MAX_MESSAGE_ID_LENGTH or entry['id'] in decoded: raise SessionCodecError('Invalid accepted id')
        decoded[entry['id']] = _packet(entry['packet'], encode)
    try: ratchet = encode_state(value['ratchet']) if encode else decode_state(value['ratchet'])
    except RatchetStateCodecError as exc: raise SessionCodecError('Invalid ratchet state') from exc
    result = {'ratchet':ratchet, 'outbox':[_packet(p, encode) for p in outbox],
              'accepted':([{'id':k,'packet':v} for k,v in sorted(decoded.items())] if encode else decoded),
              'history':[_binary(item, max_size=_MAX_BYTES, encode=encode) for item in history]}
    if encode: result['version'] = 1
    return result


def encode_session(state): return _convert(state, True)
def decode_session(state): return _convert(state, False)


def encode_packet(packet):
    """Codifica un sobre ratchet para un transporte JSON."""
    return _packet(packet, True)


def decode_packet(packet):
    """Valida y decodifica un sobre ratchet recibido por JSON."""
    return _packet(packet, False)
