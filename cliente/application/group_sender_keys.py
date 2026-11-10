"""Laboratorio aislado de claves por emisor; no integrado al chat.

La distribución debe viajar cifrada y autenticada por un canal independiente.
La pertenencia, la rotación y el almacenamiento durable son responsabilidad del
llamador; este módulo no los implementa ni sustituye una revisión de seguridad.
"""
import copy
import json
import re
import unicodedata
from typing import Protocol

MAX_SKIP = 32
MAX_STORED_KEYS = 128
MAX_PLAINTEXT = 32 * 1024
MAX_COUNTER = 2**64 - 1
_DOMAIN = b'ProyectoCriptologia/experimental/grupo/v1\x00'


class GroupError(ValueError):
    """Formato o transición inválida en el laboratorio grupal."""


class GroupCryptoPort(Protocol):
    def random_key(self) -> bytes: ...
    def key_id(self) -> str: ...
    def nonce(self) -> bytes: ...
    def generate_signing_key(self) -> bytes: ...
    def signing_public(self, private: bytes) -> bytes: ...
    def chain_step(self, key: bytes) -> tuple[bytes, bytes]: ...
    def sign(self, private: bytes, payload: bytes) -> bytes: ...
    def verify(self, public: bytes, signature: bytes, payload: bytes) -> None: ...
    def encrypt(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes: ...
    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes: ...


def _text(value):
    if not isinstance(value, str) or not value or len(value.encode('utf-8', errors='ignore')) > 128:
        raise GroupError('Identificador inválido')
    if any(unicodedata.category(c).startswith('C') for c in value):
        raise GroupError('Identificador inválido')
    return value


def _counter(value):
    if type(value) is not int or not 0 <= value <= MAX_COUNTER:
        raise GroupError('Contador inválido')
    return value


def _bytes(value, length):
    if not isinstance(value, bytes) or len(value) != length:
        raise GroupError('Valor binario inválido')
    return value


def _validate_identity(value):
    _text(value['group'])
    _text(value['sender'])
    _counter(value['epoch'])
    if not isinstance(value['key_id'], str) or re.fullmatch(r'[0-9a-f]{32}', value['key_id']) is None:
        raise GroupError('Identificador de clave inválido')


def _header(packet):
    fields = ('group', 'epoch', 'sender', 'key_id', 'counter')
    header = {key: packet[key] for key in fields}
    _validate_identity(header)
    _counter(header['counter'])
    return _DOMAIN + json.dumps(header, sort_keys=True, separators=(',', ':'),
                                ensure_ascii=False).encode('utf-8')


def _signed(header, nonce, ciphertext):
    return header + len(nonce).to_bytes(2, 'big') + nonce + len(ciphertext).to_bytes(4, 'big') + ciphertext


def create_sender(provider: GroupCryptoPort, group: str, epoch: int, sender: str):
    signing_key = provider.generate_signing_key()
    info = {'group': group, 'epoch': epoch, 'sender': sender, 'key_id': provider.key_id(),
            'chain_key': provider.random_key(), 'signing_public': provider.signing_public(signing_key)}
    _validate_identity(info)
    _bytes(info['chain_key'], 32)
    _bytes(info['signing_public'], 32)
    state = dict(info, signing_private=signing_key, counter=0)
    return state, copy.deepcopy(info)


def create_receiver(provider: GroupCryptoPort, distribution: dict):
    expected = {'group', 'epoch', 'sender', 'key_id', 'chain_key', 'signing_public'}
    if not isinstance(distribution, dict) or set(distribution) != expected:
        raise GroupError('Distribución inválida')
    _validate_identity(distribution)
    _bytes(distribution['chain_key'], 32)
    _bytes(distribution['signing_public'], 32)
    return dict(copy.deepcopy(distribution), counter=0, skipped={})


def send_group_message(provider: GroupCryptoPort, state: dict, plaintext: bytes):
    if not isinstance(plaintext, bytes) or len(plaintext) > MAX_PLAINTEXT:
        raise GroupError('Mensaje inválido o demasiado grande')
    candidate = copy.deepcopy(state)
    _counter(candidate['counter'])
    packet = {key: candidate[key] for key in ('group', 'epoch', 'sender', 'key_id', 'counter')}
    aad = _header(packet)
    candidate['chain_key'], message_key = provider.chain_step(candidate['chain_key'])
    nonce = candidate['counter'].to_bytes(12, 'big')
    ciphertext = provider.encrypt(message_key, nonce, plaintext, aad)
    signature = provider.sign(candidate['signing_private'], _signed(aad, nonce, ciphertext))
    candidate['counter'] += 1
    return candidate, dict(packet, nonce=nonce, ciphertext=ciphertext, signature=signature)


def receive_group_message(provider: GroupCryptoPort, state: dict, packet: dict):
    expected = {'group', 'epoch', 'sender', 'key_id', 'counter', 'nonce', 'ciphertext', 'signature'}
    if not isinstance(packet, dict) or set(packet) != expected:
        raise GroupError('Mensaje grupal inválido')
    aad = _header(packet)
    nonce = _bytes(packet['nonce'], 12)
    signature = _bytes(packet['signature'], 64)
    ciphertext = packet['ciphertext']
    if not isinstance(ciphertext, bytes) or not 16 <= len(ciphertext) <= MAX_PLAINTEXT + 16:
        raise GroupError('Contenido cifrado inválido')
    if any(packet[key] != state[key] for key in ('group', 'epoch', 'sender', 'key_id')):
        raise GroupError('Grupo, época o emisor no coinciden')
    provider.verify(state['signing_public'], signature, _signed(aad, nonce, ciphertext))
    candidate = copy.deepcopy(state)
    number = packet['counter']
    if number in candidate['skipped']:
        message_key = candidate['skipped'].pop(number)
    else:
        gap = number - candidate['counter']
        if gap < 0 or gap > MAX_SKIP or len(candidate['skipped']) + gap > MAX_STORED_KEYS:
            raise GroupError('Repetición o límite de mensajes omitidos')
        for index in range(candidate['counter'], number):
            candidate['chain_key'], candidate['skipped'][index] = provider.chain_step(candidate['chain_key'])
        candidate['chain_key'], message_key = provider.chain_step(candidate['chain_key'])
        candidate['counter'] = number + 1
    plaintext = provider.decrypt(message_key, nonce, ciphertext, aad)
    return candidate, plaintext
