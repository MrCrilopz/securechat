"""Casos de uso del servidor para cuentas, sesión, bandeja de entrada y presencia."""
import re
from securechat.application.ports import Repository, PasswordHasher, BundleVerifier, Clock, TokenGenerator
from securechat.domain.models import username, password
from securechat.domain.errors import UnknownContact

class ChatService:
    def __init__(self, repository: Repository, hasher: PasswordHasher, verifier: BundleVerifier, clock: Clock, token_generator: TokenGenerator):
        self.repository, self.hasher, self.verifier = repository, hasher, verifier
        self.clock, self.token_generator = clock, token_generator
    def register(self, name, secret, bundle):
        username(name); password(secret)
        if bundle.get('username') != name: raise ValueError('Bundle identity mismatch')
        self.verifier.verify(bundle)
        self.repository.create_user(name, self.hasher.hash(secret), bundle)
    def login(self, name, secret):
        user = self.repository.user(name)
        if not user or not self.hasher.verify(user['password_hash'], secret): raise PermissionError('Invalid credentials')
        token = self.token_generator()
        self.repository.save_token(token, name, self.clock() + 3600)
        return token
    def authorize(self, token):
        name = self.repository.token_user(token, self.clock())
        if not name: raise PermissionError('Invalid or expired session')
        return name
    def bundle(self, name):
        user = self.repository.user(username(name))
        if not user: raise UnknownContact('Unknown user')
        return user['bundle']
    def publish_hybrid_prekey(self, name, record):
        user = self.repository.user(username(name))
        if not user: raise LookupError('Unknown user')
        self.verifier.verify_hybrid(record, user['bundle'])
        self.repository.save_hybrid_prekey(name, record)
    def hybrid_prekey(self, name):
        record = self.repository.hybrid_prekey(username(name))
        if record is None: raise LookupError('Hybrid prekey not available')
        return record
    def send(self, sender, recipient, envelope):
        if not self.repository.user(username(recipient)): raise LookupError('Unknown recipient')
        if envelope.get('message', {}).get('sender') != sender or envelope['message'].get('recipient') != recipient: raise ValueError('Envelope identity mismatch')
        return self.repository.enqueue(recipient, sender, envelope)
    def reserve_send_counter(self, sender, recipient, session, counter):
        if not isinstance(session, str) or not 0 < len(session) <= 128 or type(counter) is not int or not 0 <= counter < 2**64:
            raise ValueError('Invalid send counter')
        if not self.repository.user(username(recipient)): raise LookupError('Unknown recipient')
        self.repository.reserve_send_counter(sender, username(recipient), session, counter)
    def reserve_dr_send(self, sender, recipient, session, dh, counter):
        if (not isinstance(session, str) or len(session) != 32 or not isinstance(dh, str) or len(dh) != 64
                or type(counter) is not int or not 0 <= counter < 2**64):
            raise ValueError('Invalid DR send slot')
        if not self.repository.user(username(recipient)): raise LookupError('Unknown recipient')
        self.repository.reserve_dr_send(sender, username(recipient), session, dh, counter)
    def inbox(self, name, only_sender=None): return self.repository.inbox(name, only_sender)
    def pending_counts(self, name): return self.repository.pending_counts(name)
    def pending_kinds(self, name): return self.repository.pending_kinds(name)
    def acknowledge(self, name, message_id): self.repository.acknowledge(name, int(message_id))
    def send_group_mail(self, sender, group_id, members, envelope):
        username(sender)
        if not isinstance(group_id, str) or re.fullmatch(r'[0-9a-f]{32}', group_id) is None:
            raise ValueError('Invalid group')
        if not isinstance(members, list) or not 1 <= len(members) <= 32:
            raise ValueError('Invalid group members')
        recipients = []
        for member in members:
            member = username(member)
            if member == sender or member in recipients:
                continue
            if not self.repository.user(member):
                raise LookupError('Unknown recipient')
            recipients.append(member)
        if not recipients:
            raise ValueError('Invalid group members')
        key_id, counter = self._group_envelope(sender, group_id, envelope)
        return self.repository.store_group_mail(sender, group_id, key_id, counter, recipients, envelope)
    def group_inbox(self, name, group_id=None):
        if group_id is not None and (not isinstance(group_id, str) or re.fullmatch(r'[0-9a-f]{32}', group_id) is None):
            raise ValueError('Invalid group')
        return self.repository.group_inbox(username(name), group_id)
    def group_pending(self, name): return self.repository.group_pending(username(name))
    def acknowledge_group(self, name, mail_id): self.repository.acknowledge_group(username(name), int(mail_id))
    def _group_envelope(self, sender, group_id, envelope):
        if not isinstance(envelope, dict): raise ValueError('Invalid group envelope')
        message = envelope.get('message')
        packet = message.get('packet') if isinstance(message, dict) else None
        if not isinstance(message, dict) or not isinstance(packet, dict): raise ValueError('Invalid group envelope')
        if set(message) != {'sender', 'protocol', 'group', 'packet'}: raise ValueError('Invalid group envelope')
        if message.get('sender') != sender or message.get('protocol') != 'group-v1' or message.get('group') != group_id:
            raise ValueError('Invalid group envelope')
        if packet.get('group') != group_id or packet.get('sender') != sender: raise ValueError('Invalid group envelope')
        key_id, counter, epoch = packet.get('key_id'), packet.get('counter'), packet.get('epoch')
        if re.fullmatch(r'[0-9a-f]{32}', key_id or '') is None or type(counter) is not int or not 0 <= counter < 2**64:
            raise ValueError('Invalid group envelope')
        if type(epoch) is not int or epoch < 0: raise ValueError('Invalid group envelope')
        for field, size in (('nonce', 24), ('signature', 128)):
            value = packet.get(field)
            if not isinstance(value, str) or len(value) != size or any(char not in '0123456789abcdef' for char in value):
                raise ValueError('Invalid group envelope')
        ciphertext = packet.get('ciphertext')
        if not isinstance(ciphertext, str) or len(ciphertext) < 32 or len(ciphertext) % 2 or any(char not in '0123456789abcdef' for char in ciphertext):
            raise ValueError('Invalid group envelope')
        if len(ciphertext) > 70000: raise ValueError('Invalid group envelope')
        return key_id, counter

    def heartbeat(self, name):
        self.repository.touch_presence(name, self.clock())
    def contacts(self, name):
        return self.repository.contacts(name, self.clock())
    def logout(self, token):
        name = self.authorize(token)
        self.repository.revoke_token(token)
        self.repository.clear_presence(name)
