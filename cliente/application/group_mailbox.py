"""Codifica claves de emisor para guardarlas en el estado cifrado del cliente."""
import json

from cliente.application.group_sender_keys import GroupError


class MissingGroupKey(GroupError):
    """El mensaje de grupo llegó antes que la clave de ese emisor."""


_PREFIX = 'GRP1\n'
_DIST_FIELDS = ('group', 'epoch', 'sender', 'key_id', 'chain_key', 'signing_public')
_PACKET_BYTES = ('nonce', 'ciphertext', 'signature')


def _hex(value, size):
    if not isinstance(value, str) or len(value) != size * 2 or any(char not in '0123456789abcdef' for char in value):
        raise GroupError('Valor de grupo inválido')
    return bytes.fromhex(value)


def export_distribution(info, name, members):
    payload = {
        'name': name,
        'members': list(members),
        'distribution': {
            'group': info['group'], 'epoch': info['epoch'], 'sender': info['sender'], 'key_id': info['key_id'],
            'chain_key': info['chain_key'].hex(), 'signing_public': info['signing_public'].hex(),
        },
    }
    return _PREFIX + json.dumps(payload, sort_keys=True, separators=(',', ':'))


def parse_distribution(text, sender):
    if not isinstance(text, str) or not text.startswith(_PREFIX):
        raise GroupError('Distribución inválida')
    try:
        payload = json.loads(text[len(_PREFIX):])
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise GroupError('Distribución inválida') from exc
    if not isinstance(payload, dict) or set(payload) != {'name', 'members', 'distribution'}:
        raise GroupError('Distribución inválida')
    raw = payload['distribution']
    if not isinstance(raw, dict) or set(raw) != set(_DIST_FIELDS) or raw['sender'] != sender:
        raise GroupError('Distribución inválida')
    if not isinstance(payload['members'], list) or sender not in payload['members']:
        raise GroupError('Distribución inválida')
    distribution = {
        'group': raw['group'], 'epoch': raw['epoch'], 'sender': raw['sender'], 'key_id': raw['key_id'],
        'chain_key': _hex(raw['chain_key'], 32), 'signing_public': _hex(raw['signing_public'], 32),
    }
    return payload['name'], list(payload['members']), distribution


def pack_sender(state):
    return {
        'group': state['group'], 'epoch': state['epoch'], 'sender': state['sender'], 'key_id': state['key_id'],
        'chain_key': state['chain_key'].hex(), 'signing_public': state['signing_public'].hex(),
        'signing_private': state['signing_private'].hex(), 'counter': state['counter'],
    }


def unpack_sender(packed):
    return {
        'group': packed['group'], 'epoch': packed['epoch'], 'sender': packed['sender'], 'key_id': packed['key_id'],
        'chain_key': _hex(packed['chain_key'], 32), 'signing_public': _hex(packed['signing_public'], 32),
        'signing_private': _hex(packed['signing_private'], 32), 'counter': packed['counter'],
    }


def pack_receiver(state):
    skipped = [{'n': number, 'key': key.hex()} for number, key in sorted(state['skipped'].items())]
    return {
        'group': state['group'], 'epoch': state['epoch'], 'sender': state['sender'], 'key_id': state['key_id'],
        'chain_key': state['chain_key'].hex(), 'signing_public': state['signing_public'].hex(),
        'counter': state['counter'], 'skipped': skipped,
    }


def unpack_receiver(packed):
    return {
        'group': packed['group'], 'epoch': packed['epoch'], 'sender': packed['sender'], 'key_id': packed['key_id'],
        'chain_key': _hex(packed['chain_key'], 32), 'signing_public': _hex(packed['signing_public'], 32),
        'counter': packed['counter'],
        'skipped': {item['n']: _hex(item['key'], 32) for item in packed['skipped']},
    }


def export_packet(packet):
    exported = {key: packet[key] for key in ('group', 'epoch', 'sender', 'key_id', 'counter')}
    exported.update({key: packet[key].hex() for key in _PACKET_BYTES})
    return exported


def import_packet(packet):
    if not isinstance(packet, dict) or set(packet) != set(('group', 'epoch', 'sender', 'key_id', 'counter', *_PACKET_BYTES)):
        raise GroupError('Mensaje grupal inválido')
    imported = {key: packet[key] for key in ('group', 'epoch', 'sender', 'key_id', 'counter')}
    imported['nonce'] = _hex(packet['nonce'], 12)
    imported['signature'] = _hex(packet['signature'], 64)
    imported['ciphertext'] = _hex(packet['ciphertext'], len(packet['ciphertext']) // 2)
    return imported
