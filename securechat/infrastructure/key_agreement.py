"""Inicia y acepta la sesión con tres acuerdos X25519 y deriva ambas claves."""
import secrets
from cryptography.hazmat.primitives.asymmetric import x25519
from .encoding import b64, public, xpub
from .identity import verify_bundle
from .key_derivation import derive
from securechat.domain.errors import InvalidClassicHeader

def initiate(identity, other):
    verify_bundle(other)
    ephemeral = x25519.X25519PrivateKey.generate()
    header = {'ephemeral': b64(public(ephemeral)), 'session': b64(secrets.token_bytes(16))}
    own = identity.bundle()
    a, b = derive([identity.agreement.exchange(xpub(other['prekey'])), ephemeral.exchange(xpub(other['agreement'])), ephemeral.exchange(xpub(other['prekey']))], header, own, other)
    return state(identity.username, other['username'], header, a, b), header

def accept(identity, other, header):
    verify_bundle(other)
    try:
        ephemeral = xpub(header['ephemeral'])
        second = identity.agreement.exchange(ephemeral)
        third = identity.prekey.exchange(ephemeral)
    except (KeyError, TypeError, ValueError, UnicodeError) as exc:
        raise InvalidClassicHeader('Invalid classic session public key') from exc
    a, b = derive([identity.prekey.exchange(xpub(other['agreement'])), second, third], header, other, identity.bundle())
    return state(identity.username, other['username'], header, b, a)

def state(me, peer, header, send, receive):
    return {'me': me, 'peer': peer, 'session': header['session'], 'send_key': b64(send), 'receive_key': b64(receive), 'send_counter': 0, 'receive_counter': 0}

