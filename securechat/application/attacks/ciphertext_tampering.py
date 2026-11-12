"""Cambia un byte del texto cifrado y comprueba que AES-GCM rechace el mensaje."""
from securechat.application.attacks.participants import ephemeral_pair

def run(crypto, text):
    sender, recipient = ephemeral_pair(crypto)
    send_state, header = crypto.initiate(sender, recipient.bundle())
    receive_state = crypto.accept(recipient, sender.bundle(), header)
    message = crypto.encrypt(send_state, text)
    before = message['ciphertext']
    altered = bytearray(crypto.unb64(before))
    altered[0] ^= 1
    changed = dict(message, ciphertext=crypto.b64(altered))
    try:
        crypto.decrypt(receive_state, changed)
        rejected = False
    except crypto.InvalidTag:
        rejected = True
    return {'before': before, 'after': changed['ciphertext'], 'rejected': rejected,
            'explanation': 'AES-GCM detectó el cambio al comprobar la etiqueta de autenticación.'}
