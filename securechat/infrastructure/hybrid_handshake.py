"""Experimental isolated X25519 + ML-KEM-768 handshake; not PQXDH.

Both callers MUST authenticate the supplied pinned identity through an independent
trusted channel. The returned state and prekeys are not wired into the chat. This
module provides neither replay prevention nor post-compromise recovery; it has not
been independently audited and must not be used to protect production data.
"""
import secrets
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .encoding import b64, canonical, unb64
from .hashing import sha256
from securechat.domain.crypto_suites import HYBRID_SUITE_V1

try:
    from cryptography.hazmat.primitives.asymmetric import mlkem as _MLKEM
except ImportError:
    _MLKEM = None

SUITE = HYBRID_SUITE_V1
_PREKEY_DOMAIN = b'securechat hybrid prekey experimental v1\x00'
_KDF_DOMAIN = b'securechat hybrid kdf experimental v1\x00'
_PIN_FIELDS = ('username', 'identity', 'agreement')
_TRANSCRIPT_FIELDS = ('suite', 'sender', 'recipient_prekey', 'classical_header', 'kem_ciphertext', 'nonce')


class HybridUnavailable(RuntimeError):
    """ML-KEM is unavailable; callers must not fall back to classical-only."""


def _require_kem():
    if _MLKEM is None:
        raise HybridUnavailable('ML-KEM-768 requires cryptography >= 47 and a supported backend')
    return _MLKEM


def _check_pinned(bundle, pinned):
    if not isinstance(bundle, dict) or not isinstance(pinned, dict):
        raise ValueError('Pinned identity is required')
    if any(not isinstance(pinned.get(key), str) or not pinned[key] or bundle.get(key) != pinned[key]
           for key in _PIN_FIELDS):
        raise ValueError('Public identity does not match the independently verified pin')


def _prekey_payload(suite, bundle, kem_public):
    return _PREKEY_DOMAIN + canonical({'suite': suite, 'identity_bundle': bundle, 'kem_public': kem_public})


def _validate_prekey(provider, prekey, pinned):
    if not isinstance(prekey, dict) or set(prekey) != {'suite', 'identity_bundle', 'kem_public', 'kem_signature'}:
        raise ValueError('Invalid hybrid prekey')
    if prekey['suite'] != SUITE:
        raise ValueError('Unexpected hybrid suite')
    bundle = prekey['identity_bundle']
    _check_pinned(bundle, pinned)
    provider.verify_bundle(bundle)
    ed25519.Ed25519PublicKey.from_public_bytes(unb64(bundle['identity'])).verify(
        unb64(prekey['kem_signature']), _prekey_payload(SUITE, bundle, prekey['kem_public']))
    key_bytes = unb64(prekey['kem_public'])
    if len(key_bytes) != 1184:
        raise ValueError('Invalid ML-KEM-768 public key length')
    kem = _require_kem()
    try:
        public = kem.MLKEM768PublicKey.from_public_bytes(key_bytes)
        if public.public_bytes_raw() != key_bytes:
            raise ValueError('Noncanonical ML-KEM-768 public key')
    except UnsupportedAlgorithm as exc:
        raise HybridUnavailable('Backend does not support ML-KEM-768') from exc
    return bundle, key_bytes


def verify_hybrid_prekey(provider, prekey, pinned_bundle):
    """Verify a signed hybrid record against an already authenticated full bundle."""
    bundle, _ = _validate_prekey(provider, prekey, pinned_bundle)
    if bundle != pinned_bundle:
        raise ValueError('Hybrid prekey bundle differs from the trusted bundle')


def _derive(classical_first, classical_second, kem_secret, transcript):
    material = unb64(classical_first) + unb64(classical_second) + kem_secret
    if len(material) != 96:
        raise ValueError('Invalid shared-secret length')
    return HKDF(algorithm=hashes.SHA256(), length=96, salt=None,
                info=_KDF_DOMAIN + sha256(canonical(transcript))).derive(material)


def transcript_digest(packet):
    """Fingerprint session inputs, excluding ciphertext that does not derive keys."""
    if not isinstance(packet, dict) or set(packet) != set(_TRANSCRIPT_FIELDS) | {'initial_ciphertext'}:
        raise ValueError('Invalid hybrid packet')
    transcript = {key: packet[key] for key in _TRANSCRIPT_FIELDS}
    return sha256(canonical(transcript))


def generate_prekey(provider, recipient):
    """Create one signed ML-KEM prekey and return (private_key, public_record)."""
    kem = _require_kem()
    bundle = recipient.bundle()
    provider.verify_bundle(bundle)
    try:
        private_key = kem.MLKEM768PrivateKey.generate()
        kem_public = b64(private_key.public_key().public_bytes_raw())
    except UnsupportedAlgorithm as exc:
        raise HybridUnavailable('Backend does not support ML-KEM-768') from exc
    signature = b64(recipient.signing.sign(_prekey_payload(SUITE, bundle, kem_public)))
    return private_key, {'suite': SUITE, 'identity_bundle': bundle,
                         'kem_public': kem_public, 'kem_signature': signature}


def initiate_hybrid(provider, sender, recipient_prekey, trusted_recipient, plaintext):
    """Produce provisional initiator state and one authenticated initial packet.

    `trusted_recipient` MUST come from independent identity verification, not from
    the same untrusted directory that delivered `recipient_prekey`.
    """
    kem = _require_kem()
    if not isinstance(plaintext, bytes):
        raise TypeError('Initial plaintext must be bytes')
    recipient_bundle, kem_public = _validate_prekey(provider, recipient_prekey, trusted_recipient)
    try:
        public_key = kem.MLKEM768PublicKey.from_public_bytes(kem_public)
        kem_secret, kem_ciphertext = public_key.encapsulate()
    except UnsupportedAlgorithm as exc:
        raise HybridUnavailable('Backend does not support ML-KEM-768') from exc
    state, header = provider.initiate(sender, recipient_bundle)
    nonce = secrets.token_bytes(12)
    transcript = {'suite': SUITE, 'sender': sender.bundle(), 'recipient_prekey': recipient_prekey,
                  'classical_header': header, 'kem_ciphertext': b64(kem_ciphertext), 'nonce': b64(nonce)}
    derived = _derive(state['send_key'], state['receive_key'], kem_secret, transcript)
    ciphertext = AESGCM(derived[:32]).encrypt(nonce, plaintext, canonical(transcript))
    state['send_key'], state['receive_key'] = b64(derived[32:64]), b64(derived[64:96])
    return state, dict(transcript, initial_ciphertext=b64(ciphertext))


def accept_hybrid(provider, recipient, kem_private, trusted_sender, packet):
    """Authenticate initial packet before returning any state or plaintext.

    `trusted_sender` MUST be pinned using an independent channel. No caller-owned
    state or packet is modified, including on KEM/AEAD authentication failure.
    """
    _require_kem()
    if not isinstance(packet, dict) or set(packet) != set(_TRANSCRIPT_FIELDS) | {'initial_ciphertext'}:
        raise ValueError('Invalid hybrid packet')
    if packet['suite'] != SUITE:
        raise ValueError('Unexpected hybrid suite')
    sender_bundle = packet['sender']
    _check_pinned(sender_bundle, trusted_sender)
    provider.verify_bundle(sender_bundle)
    own_bundle = recipient.bundle()
    recipient_bundle, _ = _validate_prekey(provider, packet['recipient_prekey'], own_bundle)
    if recipient_bundle != own_bundle:
        raise ValueError('Hybrid prekey does not belong to this recipient')
    kem_ciphertext = unb64(packet['kem_ciphertext'])
    nonce = unb64(packet['nonce'])
    if len(kem_ciphertext) != 1088 or len(nonce) != 12:
        raise ValueError('Invalid hybrid packet lengths')
    try:
        kem_secret = kem_private.decapsulate(kem_ciphertext)
    except UnsupportedAlgorithm as exc:
        raise HybridUnavailable('Backend does not support ML-KEM-768') from exc
    state = provider.accept(recipient, sender_bundle, packet['classical_header'])
    transcript = {key: packet[key] for key in _TRANSCRIPT_FIELDS}
    derived = _derive(state['receive_key'], state['send_key'], kem_secret, transcript)
    plaintext = AESGCM(derived[:32]).decrypt(nonce, unb64(packet['initial_ciphertext']), canonical(transcript))
    state['receive_key'], state['send_key'] = b64(derived[32:64]), b64(derived[64:96])
    return state, plaintext
