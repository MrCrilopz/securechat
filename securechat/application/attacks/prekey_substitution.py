"""Sustituye la preclave firmada y comprueba que Ed25519 rechace el cambio."""
from securechat.application.attacks.participants import ephemeral_pair

def run(crypto, _text):
    sender, recipient = ephemeral_pair(crypto)
    bundle = recipient.bundle()
    before = bundle['prekey']
    bundle['prekey'] = sender.bundle()['prekey']
    try:
        crypto.initiate(sender, bundle)
        rejected = False
    except crypto.InvalidSignature:
        rejected = True
    return {'before': before, 'after': bundle['prekey'], 'rejected': rejected,
            'explanation': 'La firma Ed25519 ya no corresponde a la preclave sustituida.'}
