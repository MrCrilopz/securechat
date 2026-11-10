"""Cliente HTTP local que lleva las operaciones de la cuenta hasta el servidor."""
import json, urllib.request, urllib.parse, urllib.error
from securechat.domain.errors import ReusedNonceCounter, UnknownContact
class HttpGateway:
    def __init__(self, port): self.base = f'http://127.0.0.1:{port}'; self.token = None
    def request(self, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else None
        headers = {'Content-Type': 'application/json'}
        if self.token: headers['Authorization'] = 'Bearer ' + self.token
        with urllib.request.urlopen(urllib.request.Request(self.base + path, data=data, headers=headers), timeout=10) as response: return json.load(response)
    def register(self, name, password, bundle): return self.request('/register', {'username': name, 'password': password, 'bundle': bundle})
    def login(self, name, password): self.token = self.request('/login', {'username': name, 'password': password})['token']
    def bundle(self, name):
        try:
            return self.request('/bundle?' + urllib.parse.urlencode({'username': name}))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                exc.close()
                raise UnknownContact('Unknown contact') from exc
            raise
    def publish_hybrid_prekey(self, prekey): return self.request('/hybrid-prekey', {'prekey': prekey})
    def hybrid_prekey(self, name): return self.request('/hybrid-prekey?' + urllib.parse.urlencode({'username': name}))
    def reserve_send_counter(self, recipient, session, counter):
        try:
            return self.request('/reserve-send-counter', {'recipient': recipient, 'session': session, 'counter': counter})
        except urllib.error.HTTPError as exc:
            try:
                if exc.code == 409: raise ReusedNonceCounter('Send counter already used') from exc
                raise
            finally:
                exc.close()
    def reserve_dr_send(self, recipient, session, dh, counter):
        try:
            return self.request('/reserve-dr-send', {'recipient': recipient, 'session': session, 'dh': dh, 'counter': counter})
        except urllib.error.HTTPError as exc:
            try:
                if exc.code == 409: raise ReusedNonceCounter('DR send slot already used') from exc
                raise
            finally:
                exc.close()
    def send(self, recipient, envelope): return self.request('/send', {'recipient': recipient, 'envelope': envelope})
    def inbox(self, only_sender=None):
        path = '/inbox'
        if only_sender: path += '?' + urllib.parse.urlencode({'sender': only_sender})
        return self.request(path)
    def pending_counts(self): return self.request('/pending-counts')
    def pending_kinds(self): return self.request('/pending-kinds')
    def acknowledge(self, message_id): return self.request('/ack', {'id': message_id})
    def send_group_mail(self, group_id, members, envelope):
        try:
            return self.request('/group-send', {'group': group_id, 'members': members, 'envelope': envelope})
        except urllib.error.HTTPError as exc:
            try:
                if exc.code == 409: raise ReusedNonceCounter('Group send counter already used') from exc
                raise
            finally:
                exc.close()
    def group_inbox(self, group_id=None):
        path = '/group-inbox'
        if group_id: path += '?' + urllib.parse.urlencode({'group': group_id})
        return self.request(path)
    def group_pending(self): return self.request('/group-pending')
    def acknowledge_group(self, mail_id): return self.request('/group-ack', {'id': mail_id})

    def contacts(self): return self.request('/contacts')
    def heartbeat(self): return self.request('/heartbeat', {})
    def logout(self):
        try: return self.request('/logout', {})
        finally: self.token = None
