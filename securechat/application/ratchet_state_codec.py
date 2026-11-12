"""Representación versionada para el estado experimental, sin integración al chat.

Contiene secretos: el llamador debe cifrar y autenticar toda representación
persistida y guardar cada transición junto con sus efectos de forma atómica.
"""
import re

from securechat.application.double_ratchet import MAX_COUNTER, MAX_SKIPPED_KEYS


class RatchetStateCodecError(ValueError):
    """El estado no cumple el formato esperado."""


_REQUIRED = {'dh_private', 'dh_remote', 'root', 'send_chain', 'receive_chain',
             'send_n', 'receive_n', 'previous_n', 'skipped'}
_REQUIRED_WIRE = _REQUIRED | {'version'}
_MANDATORY_KEYS = ('dh_private', 'root')
_OPTIONAL_KEYS = ('dh_remote', 'send_chain', 'receive_chain')
_COUNTERS = ('send_n', 'receive_n', 'previous_n')


def _counter(value):
    # A message with index MAX_COUNTER advances the in-memory count by one.
    if type(value) is not int or not 0 <= value <= MAX_COUNTER + 1:
        raise RatchetStateCodecError('Invalid ratchet state counter')
    return value


def _wire_key(value, optional=False):
    if value is None and optional:
        return None
    if not isinstance(value, bytes) or len(value) != 32:
        raise RatchetStateCodecError('Invalid ratchet state key')
    return value.hex()


def _memory_key(value, optional=False):
    if value is None and optional:
        return None
    if type(value) is not str or not re.fullmatch(r'[0-9a-f]{64}', value):
        raise RatchetStateCodecError('Invalid encoded ratchet key')
    return bytes.fromhex(value)


def _validate_chain_invariants(state):
    if state['send_chain'] is None and state['send_n'] != 0:
        raise RatchetStateCodecError('Sending chain is not initialized')
    if state['receive_chain'] is None and state['receive_n'] != 0:
        raise RatchetStateCodecError('Receiving chain is not initialized')
    if state['dh_remote'] is None and state['receive_chain'] is not None:
        raise RatchetStateCodecError('Receiving chain has no remote key')
    for (dh, count) in state['skipped']:
        if dh == state['dh_remote'] and count >= state['receive_n']:
            raise RatchetStateCodecError('Skipped key is not behind receiving counter')


def encode_state(state):
    if type(state) is not dict or set(state) != _REQUIRED:
        raise RatchetStateCodecError('Invalid ratchet state')
    result = {'version': 1}
    for name in _MANDATORY_KEYS:
        result[name] = _wire_key(state[name])
    for name in _OPTIONAL_KEYS:
        result[name] = _wire_key(state[name], optional=True)
    for name in _COUNTERS:
        result[name] = _counter(state[name])
    skipped = state['skipped']
    if type(skipped) is not dict or len(skipped) > MAX_SKIPPED_KEYS:
        raise RatchetStateCodecError('Invalid skipped key collection')
    entries = []
    for identifier, key in skipped.items():
        if type(identifier) is not tuple or len(identifier) != 2:
            raise RatchetStateCodecError('Invalid skipped key identifier')
        dh, count = identifier
        if _counter(count) > MAX_COUNTER:
            raise RatchetStateCodecError('Invalid skipped key counter')
        entries.append({'dh': _wire_key(dh), 'n': count, 'key': _wire_key(key)})
    result['skipped'] = sorted(entries, key=lambda item: (item['dh'], item['n']))
    _validate_chain_invariants(state)
    return result


def decode_state(encoded):
    if type(encoded) is not dict or set(encoded) != _REQUIRED_WIRE or type(encoded['version']) is not int or encoded['version'] != 1:
        raise RatchetStateCodecError('Invalid ratchet state version')
    result = {}
    for name in _MANDATORY_KEYS:
        result[name] = _memory_key(encoded[name])
    for name in _OPTIONAL_KEYS:
        result[name] = _memory_key(encoded[name], optional=True)
    for name in _COUNTERS:
        result[name] = _counter(encoded[name])
    entries = encoded['skipped']
    if type(entries) is not list or len(entries) > MAX_SKIPPED_KEYS:
        raise RatchetStateCodecError('Invalid skipped key collection')
    skipped = {}
    for entry in entries:
        if type(entry) is not dict or set(entry) != {'dh', 'n', 'key'}:
            raise RatchetStateCodecError('Invalid skipped key entry')
        count = _counter(entry['n'])
        if count > MAX_COUNTER:
            raise RatchetStateCodecError('Invalid skipped key counter')
        identifier = (_memory_key(entry['dh']), count)
        if identifier in skipped:
            raise RatchetStateCodecError('Duplicate skipped key')
        skipped[identifier] = _memory_key(entry['key'])
    result['skipped'] = skipped
    _validate_chain_invariants(result)
    return result
