"""SHA-256 and HMAC-SHA256 using the approved cryptography provider."""
from cryptography.hazmat.primitives import hashes, hmac


def sha256(data):
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()


def hmac_sha256(key, data):
    mac = hmac.HMAC(key, hashes.SHA256())
    mac.update(data)
    return mac.finalize()


def envelope_digest(envelope):
    """Hash the complete canonical envelope to recognize an exact retransmission."""
    from .encoding import canonical
    return sha256(b'securechat received envelope v1\0' + canonical(envelope)).hex()
