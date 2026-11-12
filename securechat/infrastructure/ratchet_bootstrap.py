"""Experimental authenticated Double Ratchet bootstrap, not used by the chat.

Trust anchors must be established independently. This custom construction is not
Signal X3DH, is unaudited, and provides no durable replay/rollback protection.
"""
import secrets

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from securechat.application.double_ratchet import (
    InvalidRatchetPublicKey, init_alice, init_bob, encrypt_message, decrypt_message,
)
from securechat.infrastructure.encoding import b64, canonical, private, public, unb64, xpub
from securechat.infrastructure.hashing import sha256
from securechat.infrastructure.identity import verify_bundle

SUITE = 'experimental-x3dh-double-ratchet-v1'
_SIGN_DOMAIN = b'securechat dr bootstrap signature v1\x00'
_KDF_DOMAIN = b'securechat dr bootstrap root v1\x00'
_AAD_DOMAIN = b'securechat dr bootstrap initial v1\x00'
_TRANSCRIPT_FIELDS = ('suite', 'sender', 'recipient', 'session', 'ephemeral')
_PACKET_FIELDS = set(_TRANSCRIPT_FIELDS) | {'signature', 'header', 'nonce', 'ciphertext'}
_MAX_INITIAL = 65536


class BootstrapError(ValueError):
    """Bootstrap has an invalid format, trust anchor, or authentication."""


def _key(value, size):
    if type(value) is not str or len(value) > ((_MAX_INITIAL + 16) * 2):
        raise BootstrapError('Invalid encoded value')
    try:
        raw = unb64(value)
    except (ValueError, UnicodeError) as exc:
        raise BootstrapError('Invalid encoded value') from exc
    if b64(raw) != value or (size is not None and len(raw) != size):
        raise BootstrapError('Invalid encoded value')
    return raw


def _bundle(bundle, trusted):
    if type(bundle) is not dict or type(trusted) is not dict or bundle != trusted:
        raise BootstrapError('Identity bundle differs from independently verified anchor')
    try:
        verify_bundle(bundle)
    except (ValueError, KeyError, TypeError, InvalidSignature) as exc:
        raise BootstrapError('Invalid identity bundle') from exc


def _exchange(private_key, public_key):
    try:
        return private_key.exchange(public_key)
    except ValueError as exc:
        raise BootstrapError('Invalid X25519 public key for exchange') from exc


def _root(parts, transcript):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=_KDF_DOMAIN + sha256(canonical(transcript))).derive(b''.join(parts))


def initiate(provider, sender, recipient_bundle, trusted_recipient, plaintext):
    """Return provisional state and a signed first packet; caller must persist safely."""
    _bundle(recipient_bundle, trusted_recipient)
    sender_bundle = sender.bundle()
    _bundle(sender_bundle, sender_bundle)
    if sender_bundle['username'] == recipient_bundle['username']:
        raise BootstrapError('Sender and recipient must differ')
    if not isinstance(plaintext, bytes) or len(plaintext) > _MAX_INITIAL:
        raise BootstrapError('Invalid first message')
    ephemeral = x25519.X25519PrivateKey.generate()
    transcript = {'suite': SUITE, 'sender': sender_bundle, 'recipient': recipient_bundle,
                  'session': b64(secrets.token_bytes(16)), 'ephemeral': b64(public(ephemeral))}
    root = _root([_exchange(sender.agreement, xpub(recipient_bundle['prekey'])),
                  _exchange(ephemeral, xpub(recipient_bundle['agreement'])),
                  _exchange(ephemeral, xpub(recipient_bundle['prekey']))], transcript)
    state = init_alice(provider, root, _key(recipient_bundle['prekey'], 32))
    state, encrypted = encrypt_message(provider, state, plaintext, _AAD_DOMAIN + canonical(transcript))
    header = encrypted['header']
    packet = dict(transcript, signature=b64(sender.signing.sign(_SIGN_DOMAIN + canonical(transcript))),
                  header={'dh': b64(header['dh']), 'pn': header['pn'], 'n': header['n']},
                  nonce=b64(encrypted['nonce']), ciphertext=b64(encrypted['ciphertext']))
    return state, packet


def accept(provider, recipient, trusted_sender, packet):
    """Authenticate the complete first message before returning provisional state."""
    if type(packet) is not dict or set(packet) != _PACKET_FIELDS or packet['suite'] != SUITE:
        raise BootstrapError('Invalid or unsupported bootstrap packet')
    transcript = {name: packet[name] for name in _TRANSCRIPT_FIELDS}
    _bundle(packet['sender'], trusted_sender)
    _bundle(packet['recipient'], recipient.bundle())
    if packet['sender']['username'] == packet['recipient']['username']:
        raise BootstrapError('Sender and recipient must differ')
    _key(packet['session'], 16)
    ephemeral = x25519.X25519PublicKey.from_public_bytes(_key(packet['ephemeral'], 32))
    try:
        ed25519.Ed25519PublicKey.from_public_bytes(_key(packet['sender']['identity'], 32)).verify(
            _key(packet['signature'], 64), _SIGN_DOMAIN + canonical(transcript))
    except InvalidSignature as exc:
        raise BootstrapError('Invalid bootstrap signature') from exc
    header = packet['header']
    if type(header) is not dict or set(header) != {'dh', 'pn', 'n'} or type(header['pn']) is not int or type(header['n']) is not int or header['pn'] != 0 or header['n'] != 0:
        raise BootstrapError('Invalid initial header')
    ciphertext = _key(packet['ciphertext'], None)
    if not 16 <= len(ciphertext) <= _MAX_INITIAL + 16:
        raise BootstrapError('Invalid first ciphertext')
    root = _root([_exchange(recipient.prekey, xpub(packet['sender']['agreement'])),
                  _exchange(recipient.agreement, ephemeral), _exchange(recipient.prekey, ephemeral)], transcript)
    state = init_bob(provider, root, private(recipient.prekey))
    wire = {'header': {'dh': _key(header['dh'], 32), 'pn': 0, 'n': 0},
            'nonce': _key(packet['nonce'], 12), 'ciphertext': ciphertext}
    try:
        return decrypt_message(provider, state, wire, _AAD_DOMAIN + canonical(transcript))
    except InvalidTag as exc:
        raise BootstrapError('Invalid first message authentication') from exc
    except InvalidRatchetPublicKey as exc:
        raise BootstrapError('Invalid initial ratchet public key') from exc
