"""Casos de uso del cliente para verificar contactos y enviar o recibir mensajes."""
import copy
import secrets
from cryptography.exceptions import InvalidSignature, InvalidTag
from securechat.application.ports import AttachmentPort, ChatGateway, CryptoProvider, StateWriter
from securechat.domain.errors import ClientStateInvalidated, LocalStateWriteFailed, UnexpectedOldMessage, ConcurrentRatchetSession, UnknownRatchetSession, RatchetAuthenticationFailed, RatchetPacketRejected, DrReplayEvidenceFull, UnknownContact, ContactNotVerified, ContactIdentityChanged, InvalidIncomingEnvelope, InvalidClassicHeader, InvalidClassicCounter, InvalidMessageNonce
from cliente.application.group_mailbox import (
    MissingGroupKey, export_distribution, export_packet, import_packet, pack_receiver, pack_sender,
    parse_distribution, unpack_receiver, unpack_sender,
)
from cliente.application.group_sender_keys import GroupError, create_receiver, create_sender, receive_group_message, send_group_message
from cliente.application.incoming_envelope import classify
from cliente.infrastructure.group_crypto import GroupCrypto
from cliente.infrastructure.hybrid_prekeys import HybridPrekeyCodec
from securechat.infrastructure.hybrid_handshake import accept_hybrid, initiate_hybrid, transcript_digest
from securechat.domain.errors import InvalidClassicMessage
from securechat.domain.errors import InvalidPrekeySignature

class Client:
    def __init__(self, gateway: ChatGateway, crypto: CryptoProvider, persist: StateWriter, state: dict, attachments: AttachmentPort | None = None, dr=None):
        self.gateway, self.crypto, self.persist, self.state = gateway, crypto, persist, state
        self.attachments = attachments
        self.dr = dr
        self.identity = crypto.Identity.restore(state['identity'])
        self._invalid = False
    def _ensure_valid(self):
        if self._invalid:
            raise ClientStateInvalidated('Reload encrypted state before using this client')
    def bundle(self, peer):
        self._ensure_valid()
        bundle = self.gateway.bundle(peer)
        try:
            self.crypto.verify_bundle(bundle)
        except InvalidSignature as exc:
            raise InvalidPrekeySignature('Contact public-key bundle signature is invalid') from exc
        if bundle['username'] != peer: raise ValueError('Unexpected contact')
        return bundle
    def safety(self, peer): return self.crypto.fingerprint(self.identity.bundle(), self.bundle(peer))
    def trust(self, peer, supplied):
        bundle = self.bundle(peer); current = self.crypto.fingerprint(self.identity.bundle(), bundle)
        if supplied.lower().replace(' ', '') != current: raise ValueError('Safety number does not match')
        candidate = copy.deepcopy(self.state)
        candidate['contacts'][peer] = {'identity': bundle['identity'], 'agreement': bundle['agreement'], 'verified': True}
        self._commit(candidate)
    def verified_bundle(self, peer):
        bundle = self.bundle(peer); saved = self.state['contacts'].get(peer)
        if not saved or not saved['verified']: raise ContactNotVerified('Contact not verified: compare safety number through another channel first')
        if saved['identity'] != bundle['identity'] or saved['agreement'] != bundle['agreement']:
            raise ContactIdentityChanged('ALERT: contact identity key changed; verify the new safety number')
        return bundle
    def _commit(self, candidate):
        # Persist the complete candidate before exposing it to later operations.
        self._ensure_valid()
        try:
            self.persist(candidate)
            adopt_revision = getattr(self.state, 'adopt_saved_revision', None)
            if adopt_revision is not None:
                adopt_revision(candidate)
        except Exception as exc:
            self._invalid = True
            raise LocalStateWriteFailed('Local state write outcome is uncertain; reload required') from exc
        self.state.clear()
        self.state.update(candidate)
    def flush(self):
        self._ensure_valid()
        while self.state['outbox']:
            entry = copy.deepcopy(self.state['outbox'][0])
            mail = entry.get('group_mail')
            if mail:
                self.gateway.send_group_mail(mail['group'], mail['members'], mail['envelope'])
            else:
                self.gateway.send(entry['peer'], entry['envelope'])
            candidate = copy.deepcopy(self.state)
            candidate['outbox'].pop(0)
            self._commit(candidate)
    def _sends_with_dr(self, peer):
        record = self.state.get('dr_sessions', {}).get(peer)
        if not record:
            return False
        if peer not in self.state.get('sessions', {}):
            return True
        return bool(record.get('local_opt_in'))
    def send(self, peer, text):
        if self._sends_with_dr(peer):
            return self.send_dr(peer, text)
        self._send_message(peer, text)
    def send_attachment(self, peer, name, content):
        if self.attachments is None: raise ValueError('Attachment support unavailable')
        package = self.attachments.create(name, content)
        if self._sends_with_dr(peer):
            return self.send_dr(peer, package, 'attachment-v1')
        self._send_message(peer, package, 'attachment-v1')
    def send_dr(self, peer, text, kind=None):
        """Opt-in explícito. Una sesión clásica previa se conserva y no cambia sola."""
        if self.dr is None: raise ValueError('Double Ratchet unavailable')
        wire = text
        if kind is not None:
            if kind != 'attachment-v1': raise ValueError('Unsupported DR content')
            if self.attachments is None: raise ValueError('Attachment support unavailable')
            self.attachments.open(text)
            wire = 'DR1\nattachment-v1\n' + text
        if type(wire) is not str or len(wire.encode('utf8')) > 65536: raise ValueError('Invalid message')
        self.flush(); other = self.verified_bundle(peer)
        candidate = copy.deepcopy(self.state)
        sessions = candidate.setdefault('dr_sessions', {})
        session = sessions.get(peer)
        if session is None:
            sid, encoded, envelope = self.dr.initiate(self.identity, other, wire)
            session = {'id':sid, 'state':encoded, 'initial_digest':None, 'accepted':{}, 'local_opt_in':True}
            sessions[peer] = session
        else:
            session['local_opt_in'] = True
            active = self._active_dr_session(session)
            reserve = getattr(self.gateway, 'reserve_dr_send', None)
            if reserve is not None:
                dh, number = self.dr.next_send(active['state'])
                reserve(peer, active['id'], dh, number)
            encoded, envelope = self.dr.encrypt(active['state'], self.identity.username, peer, active['id'], wire)
            active['state'] = encoded
        candidate['outbox'].append({'peer':peer,'envelope':envelope})
        row = {'peer':peer,'direction':'out','text':text}
        if kind: row['kind'] = kind
        candidate['history'].append(row)
        self._commit(candidate); self.flush()

    def _receive_dr(self, peer, other, entry):
        if self.dr is None: raise ValueError('Double Ratchet unavailable')
        envelope = entry['envelope']; msg = envelope['message']
        sid = str(entry['id'])
        if not 0 < len(sid) <= 128: raise ValueError('Invalid message identifier')
        digest = self.dr.digest(envelope)
        candidate = copy.deepcopy(self.state); sessions = candidate.setdefault('dr_sessions', {})
        session = sessions.get(peer)
        if msg.get('protocol') == 'dr-bootstrap-v1':
            if session is not None:
                alt = session.get('simultaneous')
                if session['initial_digest'] == digest or (alt and alt['initial_digest'] == digest):
                    self.gateway.acknowledge(entry['id']); return None
                session_id, encoded, text = self.dr.accept(self.identity, other, envelope)
                same = session_id == session['id'] or (alt is not None and session_id == alt['id'])
                if alt is not None or same:
                    raise ConcurrentRatchetSession('Authenticated competing DR session; messages preserved')
                session['simultaneous'] = {'id':session_id, 'state':encoded, 'initial_digest':digest, 'accepted':{}}
            else:
                session_id, encoded, text = self.dr.accept(self.identity, other, envelope)
                session = {'id':session_id, 'state':encoded, 'initial_digest':digest, 'accepted':{}}
                sessions[peer] = session
        elif msg.get('protocol') == 'double-ratchet':
            if session is None: raise ValueError('DR session not established')
            if msg.get('session_id') != session['id']:
                alt = session.get('simultaneous')
                if not alt or msg.get('session_id') != alt['id']: raise ValueError('Unexpected DR session')
                session = alt
            accepted = session['accepted']
            if sid in accepted:
                if accepted[sid] != digest: raise ValueError('Reused message identifier')
                self.gateway.acknowledge(entry['id']); return None
            if digest in accepted.values():
                self.gateway.acknowledge(entry['id']); return None
            encoded, text = self.dr.decrypt(session['state'], peer, self.identity.username, session['id'], envelope)
            if len(accepted) >= 256:
                raise DrReplayEvidenceFull('DR replay evidence is full')
            session['state'] = encoded; accepted[sid] = digest
        else: raise ValueError('Unsupported DR protocol')
        text, kind = self._dr_history_content(text)
        row = {'peer':peer,'direction':'in','text':text}
        if kind: row['kind'] = kind
        candidate['history'].append(row)
        self._commit(candidate); self.gateway.acknowledge(entry['id'])
        return (peer,text)

    @staticmethod
    def _active_dr_session(session):
        """Elige la sesión de envío cuando hay dos inicios autenticados."""
        other = session.get('simultaneous')
        if not other:
            return session
        # Cada parte creó una sesión: el identificador menor coincide en los dos clientes.
        if session.get('initial_digest') is None or other.get('initial_digest') is None:
            return min((session, other), key=lambda item: item['id'])
        # Los dos inicios llegaron del mismo contacto. El más reciente es el que aún puede leer.
        return other

    def _dr_history_content(self, text):
        prefix = 'DR1\nattachment-v1\n'
        if not isinstance(text, str) or not text.startswith(prefix):
            return text, None
        body = text[len(prefix):]
        if self.attachments is None: raise ValueError('Attachment support unavailable')
        self.attachments.open(body)
        return body, 'attachment-v1'

    def _send_message(self, peer, text, content_format=None, history_text=None, history_kind=None, record_history=True, protocol=None):
        self.flush(); other = self.verified_bundle(peer)
        candidate = copy.deepcopy(self.state)
        if peer not in candidate['sessions']:
            session, header = self.crypto.initiate(self.identity, other)
            candidate['sessions'][peer] = {'state': session, 'header': header}
        session = candidate['sessions'][peer]
        reserve = getattr(self.gateway, 'reserve_send_counter', None)
        if reserve is not None:
            reserve(peer, session['state']['session'], session['state']['send_counter'])
        message = (self.crypto.encrypt(session['state'], text, content_format=content_format)
                   if content_format else self.crypto.encrypt(session['state'], text))
        if protocol:
            message = dict(message)
            message['protocol'] = protocol
        envelope = {'header': session['header'], 'message': message}
        candidate['outbox'].append({'peer': peer, 'envelope': envelope})
        if record_history:
            row = {'peer': peer, 'direction': 'out', 'text': history_text if history_text is not None else text}
            if history_kind: row['kind'] = history_kind
            elif content_format: row['kind'] = content_format
            candidate['history'].append(row)
        self._commit(candidate)
        self.flush()

    def ensure_hybrid_prekey(self):
        """Guarda la semilla ML-KEM solo en el estado local y publica la preclave firmada."""
        candidate = copy.deepcopy(self.state)
        changed = False
        if 'hybrid_secret' not in candidate:
            stored = HybridPrekeyCodec(self.crypto).create(self.identity)
            candidate['hybrid_secret'] = stored
            candidate['hybrid_record'] = stored['record']
            changed = True
        publish = getattr(self.gateway, 'publish_hybrid_prekey', None)
        if publish is not None and not candidate.get('hybrid_published'):
            if changed:
                self._commit(candidate)
                changed = False
            publish(self.state['hybrid_record'])
            candidate = copy.deepcopy(self.state)
            candidate['hybrid_published'] = True
            changed = True
        if changed:
            self._commit(candidate)
        return self.state['hybrid_record']

    def send_hybrid(self, peer, text):
        """Acuerdo explícito X25519 + ML-KEM-768. No sustituye una sesión ya abierta."""
        if type(text) is not str or len(text.encode('utf8')) > 65536: raise ValueError('Invalid message')
        if peer in self.state.get('sessions', {}) or peer in self.state.get('dr_sessions', {}):
            raise ValueError('Hybrid session requires a new conversation')
        self.ensure_hybrid_prekey()
        try:
            record = self.gateway.hybrid_prekey(peer)
        except Exception as exc:
            raise LookupError('Hybrid prekey not available') from exc
        trusted = self.verified_bundle(peer)
        state, packet = initiate_hybrid(self.crypto, self.identity, record, trusted, text.encode('utf8'))
        digest = transcript_digest(packet).hex()
        envelope = {'message': {'sender': self.identity.username, 'recipient': peer, 'protocol': 'hybrid-v1', 'payload': packet}}
        candidate = copy.deepcopy(self.state)
        candidate.setdefault('sessions', {})[peer] = {'state': state, 'header': packet['classical_header'], 'hybrid_digest': digest}
        candidate['outbox'].append({'peer': peer, 'envelope': envelope})
        candidate['history'].append({'peer': peer, 'direction': 'out', 'text': text})
        self._commit(candidate)
        self.flush()

    def _receive_hybrid(self, peer, other, entry):
        payload = entry['envelope']['message'].get('payload')
        if not isinstance(payload, dict): raise ValueError('Invalid hybrid packet')
        digest = transcript_digest(payload).hex()
        current = self.state.get('sessions', {}).get(peer)
        if current and current.get('hybrid_digest') == digest:
            self.gateway.acknowledge(entry['id'])
            return None
        if current: raise ValueError('Hybrid session already established')
        if 'hybrid_secret' not in self.state: raise ValueError('Hybrid prekey not available')
        private = HybridPrekeyCodec(self.crypto).restore(self.identity, self.state['hybrid_secret'])
        state, plaintext = accept_hybrid(self.crypto, self.identity, private, other, payload)
        text = plaintext.decode('utf8')
        candidate = copy.deepcopy(self.state)
        candidate.setdefault('sessions', {})[peer] = {'state': state, 'header': payload['classical_header'], 'hybrid_digest': digest}
        candidate['history'].append({'peer': peer, 'direction': 'in', 'text': text})
        self._commit(candidate)
        self.gateway.acknowledge(entry['id'])
        return (peer, text)

    def _group_record(self, candidate, group_id):
        record = candidate.setdefault('groups', {}).get(group_id)
        if record is None: raise GroupError('Grupo desconocido')
        return record

    def _targets(self, record):
        return [member for member in record['members'] if member != self.identity.username]

    def create_group(self, name, members):
        if not isinstance(name, str) or not name.strip() or len(name.encode('utf8')) > 40: raise ValueError('Invalid group name')
        if not isinstance(members, list) or not members or any(type(member) is not str for member in members):
            raise ValueError('Invalid group members')
        others = sorted(set(members))
        if self.identity.username in others: raise ValueError('Invalid group members')
        for member in others: self.verified_bundle(member)
        group_id = secrets.token_hex(16)
        everyone = sorted(others + [self.identity.username])
        sender, info = create_sender(GroupCrypto(), group_id, 0, self.identity.username)
        candidate = copy.deepcopy(self.state)
        candidate.setdefault('groups', {})[group_id] = {
            'name': name.strip(), 'epoch': 0, 'members': everyone,
            'send': pack_sender(sender), 'recv': {},
        }
        self._commit(candidate)
        secret = export_distribution(info, name.strip(), everyone)
        for member in others:
            self._send_message(member, secret, record_history=False, protocol='group-key-v1')
        self._remember_group(group_id, 'Clave de grupo actualizada', 'group-key-v1')
        return group_id

    def _distribute_current_sender(self, group_id):
        record = self.state['groups'][group_id]
        if record.get('send') and record['send']['epoch'] == record['epoch']:
            return unpack_sender(record['send'])
        sender, info = create_sender(GroupCrypto(), group_id, record['epoch'], self.identity.username)
        candidate = copy.deepcopy(self.state)
        candidate['groups'][group_id]['send'] = pack_sender(sender)
        self._commit(candidate)
        secret = export_distribution(info, record['name'], record['members'])
        for member in self._targets(record):
            self._send_message(member, secret, record_history=False, protocol='group-key-v1')
        self._remember_group(group_id, 'Clave de grupo actualizada', 'group-key-v1')
        return sender

    def remove_group_member(self, group_id, member):
        record = self.state.get('groups', {}).get(group_id)
        if record is None or member not in record['members'] or member == self.identity.username:
            raise ValueError('Invalid group member')
        candidate = copy.deepcopy(self.state)
        current = candidate['groups'][group_id]
        current['members'] = [item for item in current['members'] if item != member]
        current['epoch'] += 1
        current['send'] = None
        current['recv'] = {key: value for key, value in current['recv'].items() if value['epoch'] == current['epoch']}
        self._commit(candidate)
        self._distribute_current_sender(group_id)

    def send_group(self, group_id, text):
        if type(text) is not str or len(text.encode('utf8')) > 32768: raise ValueError('Invalid message')
        record = self.state.get('groups', {}).get(group_id)
        if record is None: raise ValueError('Unknown group')
        sender = self._distribute_current_sender(group_id)
        record = self.state['groups'][group_id]
        targets = self._targets(record)
        sender, packet = send_group_message(GroupCrypto(), sender, text.encode('utf8'))
        exported = export_packet(packet)
        candidate = copy.deepcopy(self.state)
        candidate['groups'][group_id]['send'] = pack_sender(sender)
        posted = getattr(self.gateway, 'send_group_mail', None)
        if callable(posted):
            envelope = {'message': {'sender': self.identity.username, 'protocol': 'group-v1', 'group': group_id, 'packet': exported}}
            candidate['outbox'].append({'peer': 'g:' + group_id, 'group_mail': {'group': group_id, 'members': targets, 'envelope': envelope}})
        else:
            reserve = getattr(self.gateway, 'reserve_dr_send', None)
            if reserve is not None:
                for member in targets:
                    reserve(member, packet['group'], sender['signing_public'].hex(), packet['counter'])
            for member in targets:
                envelope = {'message': {'sender': self.identity.username, 'recipient': member, 'protocol': 'group-v1', 'packet': exported}}
                candidate['outbox'].append({'peer': member, 'envelope': envelope})
        candidate['history'].append({'peer': 'g:' + group_id, 'direction': 'out', 'text': text, 'kind': 'group-v1', 'author': self.identity.username})
        self._commit(candidate)
        self.flush()

    def _install_group_key(self, sender, text, candidate):
        name, members, distribution = parse_distribution(text, sender)
        if self.identity.username not in members: raise GroupError('Distribución inválida')
        group_id = distribution['group']
        record = candidate.setdefault('groups', {}).get(group_id)
        if record is not None and distribution['epoch'] < record['epoch']:
            return group_id
        receiver = create_receiver(GroupCrypto(), distribution)
        if record is None:
            record = {'name': name, 'epoch': distribution['epoch'], 'members': members, 'send': None, 'recv': {}}
            candidate['groups'][group_id] = record
        if distribution['epoch'] > record['epoch']:
            record['epoch'] = distribution['epoch']
            record['send'] = None
            record['recv'] = {}
        record['name'] = name
        record['members'] = members
        record['recv'][distribution['sender'] + ':' + distribution['key_id']] = pack_receiver(receiver)
        return group_id

    def _receive_group(self, entry):
        packet = import_packet(entry['envelope']['message'].get('packet'))
        record = self.state.get('groups', {}).get(packet['group'])
        stored = None if record is None else record['recv'].get(packet['sender'] + ':' + packet['key_id'])
        if stored is None or stored['epoch'] != packet['epoch']:
            raise MissingGroupKey('Group sender key has not arrived')
        receiver, plaintext = receive_group_message(GroupCrypto(), unpack_receiver(stored), packet)
        candidate = copy.deepcopy(self.state)
        candidate['groups'][packet['group']]['recv'][packet['sender'] + ':' + packet['key_id']] = pack_receiver(receiver)
        text = plaintext.decode('utf8')
        candidate['history'].append({'peer': 'g:' + packet['group'], 'direction': 'in', 'text': text, 'kind': 'group-v1', 'author': packet['sender']})
        self._commit(candidate)
        if entry.get('mailbox') == 'group':
            self.gateway.acknowledge_group(entry['id'])
        else:
            self.gateway.acknowledge(entry['id'])
        return (packet['sender'], text)

    def _remember_group(self, group_id, text, kind):
        candidate = copy.deepcopy(self.state)
        candidate['history'].append({'peer': 'g:' + group_id, 'direction': 'out', 'text': text, 'kind': kind, 'author': self.identity.username})
        self._commit(candidate)

    def _entries_from(self, sender):
        try:
            found = self.gateway.inbox(sender)
        except TypeError:
            found = [entry for entry in self.gateway.inbox() if entry.get('envelope', {}).get('message', {}).get('sender') == sender]
        return found

    def _accept_group_distribution(self, entry, envelope, message, peer):
        try:
            other = self.verified_bundle(peer)
        except UnknownContact:
            return False
        except ContactNotVerified:
            return False
        candidate = copy.deepcopy(self.state)
        session = candidate['sessions'].get(peer)
        if session is None:
            try:
                session = {'state': self.crypto.accept(self.identity, other, envelope['header']), 'header': envelope['header']}
            except InvalidClassicHeader:
                return False
        elif envelope['header'] != session['header']:
            return False
        counter = message['counter']
        if counter != session['state']['receive_counter']:
            return False
        try:
            text = self.crypto.decrypt(session['state'], message)
        except (InvalidMessageNonce, InvalidTag, InvalidClassicMessage):
            return False
        if not isinstance(text, str) or not text.startswith('GRP1\n'):
            return False
        try:
            group_id = self._install_group_key(peer, text, candidate)
        except GroupError:
            return False
        session.setdefault('received_digests', {})[str(counter)] = self.crypto.envelope_digest(envelope)
        candidate['sessions'][peer] = session
        candidate['history'].append({'peer': 'g:' + group_id, 'direction': 'in', 'kind': 'group-key-v1', 'text': 'Clave de grupo actualizada', 'author': peer})
        self._commit(candidate)
        self.gateway.acknowledge(entry['id'])
        return True

    def _group_mail_entries(self, group_id):
        fetch = getattr(self.gateway, 'group_inbox', None)
        if not callable(fetch):
            return []
        try:
            found = fetch(group_id) if group_id else fetch()
        except TypeError:
            found = fetch()
            if group_id:
                found = [item for item in found if item.get('envelope', {}).get('message', {}).get('group') == group_id]
        rows = []
        for item in found if isinstance(found, list) else []:
            if isinstance(item, dict):
                row = dict(item)
                row['mailbox'] = 'group'
                rows.append(row)
        return rows

    def pull_group_traffic(self):
        kinds_fn = getattr(self.gateway, 'pending_kinds', None)
        pending = None
        if callable(kinds_fn):
            try:
                pending = kinds_fn()
            except (LocalStateWriteFailed, ClientStateInvalidated):
                raise
            except Exception:
                pending = None
        if isinstance(pending, dict):
            for sender, labels in pending.items():
                if isinstance(labels, list) and any(label in ('group-v1', 'group-key-v1') for label in labels):
                    self.receive(only_peer=sender, groups_only=True)
        groups_fn = getattr(self.gateway, 'group_pending', None)
        if not callable(groups_fn):
            return
        try:
            found = groups_fn()
        except (LocalStateWriteFailed, ClientStateInvalidated):
            raise
        except Exception:
            return
        if not isinstance(found, dict):
            return
        for group_id, count in found.items():
            if isinstance(group_id, str) and count:
                self.receive(only_group=group_id)

    def receive(self, only_peer=None, only_group=None, groups_only=False):
        self.flush(); received = []; deferred = []; deferred_group = []; invalid_authentication = False; conflicting = False; evidence_full = False
        invalid_classic_header = invalid_classic_counter = invalid_nonce = old_message = False
        if only_group:
            groups_only = True
            record = self.state.get('groups', {}).get(only_group)
            entries = []
            if isinstance(record, dict):
                seen = set()
                for member in self._targets(record):
                    for entry in self._entries_from(member):
                        marker = entry.get('id')
                        if marker in seen:
                            continue
                        seen.add(marker)
                        entries.append(entry)
        else:
            try:
                entries = self.gateway.inbox(only_peer) if only_peer else self.gateway.inbox()
            except TypeError:
                entries = self.gateway.inbox()
                if only_peer:
                    entries = [entry for entry in entries if entry.get('envelope', {}).get('message', {}).get('sender') == only_peer]
        if only_group:
            entries.extend(self._group_mail_entries(only_group))
        elif not groups_only and not only_peer:
            entries.extend(self._group_mail_entries(None))
        for entry in entries:
            try:
                envelope, message, peer, protocol = classify(entry, self.identity.username)
            except InvalidIncomingEnvelope:
                invalid_authentication = True
                continue
            if groups_only:
                if protocol in ('dr-bootstrap-v1', 'double-ratchet', 'hybrid-v1'):
                    continue
                if protocol == 'group-v1':
                    packet = message.get('packet')
                    if only_group and (type(packet) is not dict or packet.get('group') != only_group):
                        continue
                    deferred_group.append(entry)
                    continue
                if protocol not in (None, 'group-key-v1'):
                    continue
                self._accept_group_distribution(entry, envelope, message, peer)
                continue
            try:
                other = self.verified_bundle(peer)
            except UnknownContact:
                invalid_authentication = True
                continue
            if protocol in ('dr-bootstrap-v1', 'double-ratchet'):
                if protocol == 'double-ratchet':
                    current = self.state.get('dr_sessions', {}).get(peer)
                    ids = {s['id'] for s in (current, current.get('simultaneous') if current else None) if s}
                    if message.get('session_id') not in ids:
                        # Check the declared envelope shape before deferring; no ACK or state change.
                        if self.dr is None: raise ValueError('Double Ratchet unavailable')
                        from securechat.application.ratchet_transport import unwrap, RatchetTransportError
                        try:
                            unwrap(envelope, peer, self.identity.username, message.get('session_id'))
                        except RatchetTransportError:
                            invalid_authentication = True
                            continue
                        deferred.append(entry)
                        continue
                try:
                    item = self._receive_dr(peer, other, entry)
                except ConcurrentRatchetSession:
                    conflicting = True
                    continue
                except DrReplayEvidenceFull:
                    evidence_full = True
                    continue
                except (InvalidTag, RatchetPacketRejected):
                    invalid_authentication = True
                    continue
                if item is not None: received.append(item)
                continue
            if protocol == 'hybrid-v1':
                try:
                    item = self._receive_hybrid(peer, other, entry)
                except InvalidTag:
                    invalid_authentication = True
                    continue
                if item is not None: received.append(item)
                continue
            if protocol == 'group-v1':
                deferred_group.append(entry)
                continue
            if peer in self.state.get('dr_sessions', {}) and peer not in self.state.get('sessions', {}):
                raise ValueError('Unexpected classic message in DR session')
            candidate = copy.deepcopy(self.state)
            session = candidate['sessions'].get(peer)
            if session is None:
                try:
                    session = {'state': self.crypto.accept(self.identity, other, envelope['header']), 'header': envelope['header']}
                except InvalidClassicHeader:
                    invalid_authentication = True
                    continue
            elif envelope['header'] != session['header']:
                invalid_classic_header = True
                continue
            counter = message['counter']; expected = session['state']['receive_counter']
            if counter < expected:
                evidence = session.get('received_digests', {}).get(str(counter))
                if evidence != self.crypto.envelope_digest(envelope):
                    old_message = True
                    continue
                self.gateway.acknowledge(entry['id']); continue
            if counter > expected:
                invalid_classic_counter = True
                continue
            try:
                text = self.crypto.decrypt(session['state'], message)
            except InvalidMessageNonce:
                invalid_nonce = True
                continue
            except (InvalidTag, InvalidClassicMessage):
                invalid_authentication = True
                continue
            content_format = message.get('content_format')
            if content_format:
                if self.attachments is None: raise ValueError('Attachment support unavailable')
                self.attachments.open(text)
            session.setdefault('received_digests', {})[str(counter)] = self.crypto.envelope_digest(envelope)
            candidate['sessions'][peer] = session
            if protocol == 'group-key-v1' and not text.startswith('GRP1\n'):
                invalid_authentication = True
                continue
            if text.startswith('GRP1\n'):
                try:
                    group_id = self._install_group_key(peer, text, candidate)
                except GroupError:
                    invalid_authentication = True
                    continue
                candidate['history'].append({'peer': 'g:' + group_id, 'direction': 'in', 'kind': 'group-key-v1', 'text': 'Clave de grupo actualizada', 'author': peer})
                self._commit(candidate)
                self.gateway.acknowledge(entry['id'])
                continue
            row = {'peer': peer, 'direction': 'in', 'text': text}
            if content_format: row['kind'] = content_format
            candidate['history'].append(row)
            self._commit(candidate)
            self.gateway.acknowledge(entry['id']); received.append((peer, text))
        unresolved = False
        for entry in deferred:
            peer = entry['envelope']['message']['sender']
            message = entry['envelope']['message']
            current = self.state.get('dr_sessions', {}).get(peer)
            ids = {s['id'] for s in (current, current.get('simultaneous') if current else None) if s}
            if message.get('session_id') not in ids:
                unresolved = True
                continue
            try:
                item = self._receive_dr(peer, self.verified_bundle(peer), entry)
            except ConcurrentRatchetSession:
                conflicting = True
                continue
            except DrReplayEvidenceFull:
                evidence_full = True
                continue
            except (InvalidTag, RatchetPacketRejected):
                invalid_authentication = True
                continue
            if item is not None: received.append(item)
        missing_group = False
        for entry in deferred_group:
            try:
                item = self._receive_group(entry)
            except MissingGroupKey:
                missing_group = True
                continue
            except GroupError:
                invalid_authentication = True
                continue
            if item is not None: received.append(item)
        if old_message:
            raise UnexpectedOldMessage('Old counter without exact accepted-envelope evidence')
        if invalid_classic_header:
            raise InvalidClassicHeader('Unexpected concurrent or replaced session')
        if invalid_nonce:
            raise InvalidMessageNonce('At least one message nonce is invalid and was retained')
        if invalid_classic_counter:
            raise InvalidClassicCounter('At least one message counter is ahead of the expected state')
        if invalid_authentication:
            raise RatchetAuthenticationFailed('At least one DR message failed authentication and was retained')
        if conflicting:
            raise ConcurrentRatchetSession('Authenticated competing DR session; messages preserved')
        if evidence_full:
            raise DrReplayEvidenceFull('DR replay evidence is full')
        if unresolved:
            raise UnknownRatchetSession('Unauthenticated message awaiting a known DR session')
        if missing_group:
            raise MissingGroupKey('Group sender key has not arrived')
        return received
