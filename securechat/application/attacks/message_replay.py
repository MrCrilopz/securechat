"""Reenvía un mensaje ya aceptado y comprueba que el contador esperado lo rechace."""
from securechat.application.attacks.participants import ephemeral_pair

def run(crypto, text):
    sender, recipient = ephemeral_pair(crypto)
    send_state, header = crypto.initiate(sender, recipient.bundle())
    receive_state = crypto.accept(recipient, sender.bundle(), header)
    message = crypto.encrypt(send_state, text)
    crypto.decrypt(receive_state, message)
    try:
        crypto.decrypt(receive_state, message)
        rejected = False
    except ValueError:
        rejected = True
    return {'before': 'Primer envío: contador ' + str(message['counter']),
            'after': 'Reenvío: contador ' + str(message['counter']) + '; esperado: ' + str(receive_state['receive_counter']),
            'rejected': rejected, 'explanation': 'El contador esperado avanzó tras aceptar el primer mensaje.'}
