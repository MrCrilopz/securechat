"""Consola local que compone el cliente, el almacén cifrado y la puerta HTTP."""
import argparse, getpass, os, sys
from cliente.application.client import Client
from cliente.application.group_mailbox import MissingGroupKey
from securechat.domain.errors import ClientStateInvalidated, LocalStateWriteFailed, ReusedNonceCounter, UnsupportedMessageFormat, ConcurrentRatchetSession, DrReplayEvidenceFull
from securechat.infrastructure import crypto
from cliente.infrastructure import local_store
from cliente.infrastructure.dr_chat import DoubleRatchetChat
from cliente.infrastructure.http_gateway import HttpGateway
from cliente.infrastructure.attachment_codec import AttachmentCodec
from cliente.history_view import visible_history, describe_visible_row

def main():
    parser = argparse.ArgumentParser(description='Local educational secure messenger')
    parser.add_argument('--port', type=int, default=8765); parser.add_argument('--home', default='clients')
    parser.add_argument('--password')
    parser.add_argument('user'); parser.add_argument('action', choices=['register', 'safety', 'trust', 'send', 'receive', 'history']); parser.add_argument('peer', nargs='?'); parser.add_argument('value', nargs='?')
    args = parser.parse_args()
    password = args.password if args.password is not None else getpass.getpass('Password: ')
    from securechat.domain.models import username
    username(args.user)
    path = os.path.join(args.home, args.user + '.json'); gateway = HttpGateway(args.port)
    if args.action == 'register':
        if os.path.exists(path): raise ValueError('Local identity already exists')
        identity = crypto.Identity.generate(args.user)
        state = {'identity': identity.serialize(), 'contacts': {}, 'sessions': {}, 'history': [], 'outbox': []}
        gateway.register(args.user, password, identity.bundle()); local_store.save(path, password, state)
        print('Registered. Back up the encrypted local identity securely.'); return
    state = local_store.load(path, password); gateway.login(args.user, password)
    attachments = AttachmentCodec()
    app = Client(gateway, crypto, lambda data: local_store.save(path, password, data), state, attachments=attachments, dr=DoubleRatchetChat())
    if args.action == 'safety': print(app.safety(args.peer))
    elif args.action == 'trust': app.trust(args.peer, args.value); print('Contact verified.')
    elif args.action == 'send': app.send(args.peer, args.value if args.value is not None else input('Message: ')); print('Message sent.')
    elif args.action == 'receive':
        before = len(state['history'])
        app.receive()
        for row in visible_history(state['history'][before:], attachments):
            print(f"{row['peer']}: {describe_visible_row(row)}")
    elif args.action == 'history':
        for row in visible_history(state['history'], attachments):
            print(f"{row['direction']} {row['peer']}: {describe_visible_row(row)}")
def explain_failure(exc):
    if isinstance(exc, ReusedNonceCounter):
        return 'Este contador ya fue usado. No se cifró otro mensaje, para no repetir la clave y el nonce. No restaures ni clones el estado local.'
    if isinstance(exc, ConcurrentRatchetSession):
        return 'Ya hay dos sesiones de Double Ratchet y llegó otra distinta. Los mensajes nuevos se entregan y los anteriores se conservaron. El inicio extra quedó sin confirmar; no hay resolución automática para una tercera sesión.'
    if isinstance(exc, DrReplayEvidenceFull):
        return 'Esta conversación ya guardó 256 mensajes de Double Ratchet. El mensaje nuevo se conservó sin confirmar. No se borra la evidencia anterior para hacer espacio.'
    if isinstance(exc, LookupError) and str(exc) == 'Hybrid prekey not available':
        return 'El contacto no tiene una preclave híbrida publicada. No se envió un mensaje clásico en su lugar.'
    if isinstance(exc, MissingGroupKey):
        return 'Falta la clave de grupo de ese emisor. El mensaje se conservó sin confirmar.'
    if isinstance(exc, UnsupportedMessageFormat):
        return 'El mensaje tiene un formato desconocido o alterado. Se conservó sin confirmar.'
    if isinstance(exc, (LocalStateWriteFailed, ClientStateInvalidated)):
        return 'No se pudo confirmar el guardado del estado local. Cierra el cliente y ejecútalo nuevamente para recuperar el estado guardado.'
    return f'Error: {exc}'

if __name__ == '__main__':
    try: main()
    except Exception as exc: print(explain_failure(exc), file=sys.stderr); sys.exit(1)
