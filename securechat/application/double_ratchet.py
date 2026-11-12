"""Laboratorio aislado de Double Ratchet; no es el protocolo del chat activo.

El llamador debe autenticar el secreto inicial y las identidades, proteger el
estado persistido, impedir rollback y guardar cada transición de forma atómica.
"""
import copy

from securechat.application.ratchet_ports import RatchetProvider

MAX_SKIP = 32
MAX_SKIPPED_KEYS = 128
MAX_COUNTER = 2**64 - 1


class RatchetError(ValueError):
    """Entrada o transición no válida en el laboratorio."""


class InvalidRatchetPublicKey(RatchetError):
    """La clave pública no produce un secreto X25519 válido."""


def _bytes(value, size, field):
    if not isinstance(value, bytes) or len(value) != size:
        raise RatchetError(f'Invalid {field}')
    return value


def _root(root):
    return _bytes(root, 32, 'initial root')


def _state(private, remote, root, send_chain):
    return {'dh_private': private, 'dh_remote': remote, 'root': root,
            'send_chain': send_chain, 'receive_chain': None, 'send_n': 0,
            'receive_n': 0, 'previous_n': 0, 'skipped': {}}


def init_alice(provider: RatchetProvider, root: bytes, bob_public: bytes):
    _root(root)
    _bytes(bob_public, 32, 'ratchet public key')
    private = provider.generate_dh()
    next_root, chain = provider.root_step(root, provider.dh(private, bob_public))
    return _state(private, bob_public, next_root, chain)


def init_bob(provider: RatchetProvider, root: bytes, bob_private: bytes):
    _root(root)
    _bytes(bob_private, 32, 'ratchet private key')
    return _state(bob_private, None, root, None)


def _header(header):
    if not isinstance(header, dict) or set(header) != {'dh', 'pn', 'n'}:
        raise RatchetError('Invalid ratchet header')
    dh = _bytes(header['dh'], 32, 'ratchet public key')
    for name in ('pn', 'n'):
        value = header[name]
        if type(value) is not int or not 0 <= value <= MAX_COUNTER:
            raise RatchetError('Invalid ratchet counter')
    return dh + header['pn'].to_bytes(8, 'big') + header['n'].to_bytes(8, 'big')


def _aad(associated_data, header):
    if not isinstance(associated_data, bytes) or len(associated_data) > 2**32 - 1:
        raise RatchetError('Invalid associated data')
    return b'ExperimentalDR\x01' + len(associated_data).to_bytes(4, 'big') + associated_data + _header(header)


def next_send_slot(provider: RatchetProvider, state):
    """Identifica la clave de envío actual sin avanzar la cadena."""
    if (not isinstance(state, dict) or state.get('send_chain') is None
            or type(state.get('send_n')) is not int or not 0 <= state['send_n'] <= MAX_COUNTER):
        raise RatchetError('Sending chain unavailable or exhausted')
    return provider.dh_public(state['dh_private']), state['send_n']


def encrypt_message(provider: RatchetProvider, state, plaintext, associated_data):
    if not isinstance(plaintext, bytes):
        raise RatchetError('Plaintext must be bytes')
    next_state = copy.deepcopy(state)
    if next_state['send_chain'] is None or next_state['send_n'] > MAX_COUNTER:
        raise RatchetError('Sending chain unavailable or exhausted')
    next_state['send_chain'], message_key = provider.chain_step(next_state['send_chain'])
    header = {'dh': provider.dh_public(next_state['dh_private']),
              'pn': next_state['previous_n'], 'n': next_state['send_n']}
    next_state['send_n'] += 1
    nonce = header['n'].to_bytes(12, 'big')
    ciphertext = provider.seal(message_key, nonce, plaintext, _aad(associated_data, header))
    return next_state, {'header': header, 'nonce': nonce, 'ciphertext': ciphertext}


def _skip(provider, state, until):
    if until < state['receive_n'] or until - state['receive_n'] > MAX_SKIP:
        raise RatchetError('Skipped message limit or old counter')
    amount = until - state['receive_n']
    if len(state['skipped']) + amount > MAX_SKIPPED_KEYS:
        raise RatchetError('Skipped message key storage full')
    if amount and state['receive_chain'] is None:
        raise RatchetError('Receiving chain not initialized')
    while state['receive_n'] < until:
        state['receive_chain'], key = provider.chain_step(state['receive_chain'])
        state['skipped'][(state['dh_remote'], state['receive_n'])] = key
        state['receive_n'] += 1


def _dh_ratchet(provider, state, remote):
    state['previous_n'] = state['send_n']
    state['send_n'] = state['receive_n'] = 0
    state['dh_remote'] = remote
    state['root'], state['receive_chain'] = provider.root_step(
        state['root'], provider.dh(state['dh_private'], remote))
    state['dh_private'] = provider.generate_dh()
    state['root'], state['send_chain'] = provider.root_step(
        state['root'], provider.dh(state['dh_private'], remote))


def decrypt_message(provider: RatchetProvider, state, packet, associated_data):
    if not isinstance(packet, dict) or set(packet) != {'header', 'nonce', 'ciphertext'}:
        raise RatchetError('Invalid packet')
    header = packet['header']
    aad = _aad(associated_data, header)
    nonce = _bytes(packet['nonce'], 12, 'nonce')
    ciphertext = packet['ciphertext']
    if not isinstance(ciphertext, bytes) or len(ciphertext) < 16:
        raise RatchetError('Invalid ciphertext')
    candidate = copy.deepcopy(state)
    skipped_id = (header['dh'], header['n'])
    if skipped_id in candidate['skipped']:
        key = candidate['skipped'].pop(skipped_id)
    else:
        if header['dh'] != candidate['dh_remote']:
            _skip(provider, candidate, header['pn'])
            _dh_ratchet(provider, candidate, header['dh'])
        _skip(provider, candidate, header['n'])
        if candidate['receive_chain'] is None:
            raise RatchetError('Receiving chain unavailable')
        candidate['receive_chain'], key = provider.chain_step(candidate['receive_chain'])
        candidate['receive_n'] += 1
    plaintext = provider.open(key, nonce, ciphertext, aad)
    return candidate, plaintext
