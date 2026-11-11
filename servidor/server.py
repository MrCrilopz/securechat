"""Servidor HTTP local que convierte cada petición en un caso de uso."""
import argparse, json, sqlite3, secrets, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs
from servidor.application.service import ChatService
from servidor.infrastructure.server_adapters import SqliteRepository, ArgonHasher, BundleVerifier
from securechat.infrastructure.hybrid_handshake import HybridUnavailable
from securechat.domain.errors import ReusedNonceCounter, UnknownContact

class Handler(BaseHTTPRequestHandler):
    service = None
    def log_message(self, format, *args): pass
    def respond(self, code, value):
        data = json.dumps(value).encode(); self.send_response(code); self.send_header('Content-Type', 'application/json'); self.send_header('Content-Length', str(len(data))); self.end_headers(); self.wfile.write(data)
    def body(self):
        size = int(self.headers.get('Content-Length', '0'))
        if size <= 0 or size > 1048576: raise ValueError('Invalid request size')
        obj = json.loads(self.rfile.read(size))
        if not isinstance(obj, dict): raise ValueError('Invalid request')
        return obj
    def name(self):
        auth = self.headers.get('Authorization', '')
        if not auth.startswith('Bearer '): raise PermissionError('Authentication required')
        return self.service.authorize(auth[7:])
    def do_POST(self): self.dispatch()
    def do_GET(self): self.dispatch()
    def dispatch(self):
        try:
            url = urlparse(self.path); path = url.path
            if self.command == 'POST' and path == '/register':
                data = self.body(); self.service.register(data['username'], data['password'], data['bundle']); result = {'ok': True}
            elif self.command == 'POST' and path == '/login':
                data = self.body(); result = {'token': self.service.login(data['username'], data['password'])}
            elif self.command == 'POST' and path == '/heartbeat':
                self.service.heartbeat(self.name()); result = {'ok': True}
            elif self.command == 'POST' and path == '/logout':
                self.service.logout(self.headers.get('Authorization', '')[7:]); result = {'ok': True}
            elif self.command == 'GET' and path == '/contacts':
                result = self.service.contacts(self.name())
            elif self.command == 'GET' and path == '/bundle':
                self.name(); result = self.service.bundle(parse_qs(url.query)['username'][0])
            elif self.command == 'POST' and path == '/hybrid-prekey':
                name = self.name(); data = self.body(); self.service.publish_hybrid_prekey(name, data['prekey']); result = {'ok': True}
            elif self.command == 'GET' and path == '/hybrid-prekey':
                self.name(); result = self.service.hybrid_prekey(parse_qs(url.query)['username'][0])
            elif self.command == 'POST' and path == '/reserve-send-counter':
                name = self.name(); data = self.body(); self.service.reserve_send_counter(name, data['recipient'], data['session'], data['counter']); result = {'ok': True}
            elif self.command == 'POST' and path == '/reserve-dr-send':
                name = self.name(); data = self.body(); self.service.reserve_dr_send(name, data['recipient'], data['session'], data['dh'], data['counter']); result = {'ok': True}
            elif self.command == 'POST' and path == '/send':
                name = self.name(); data = self.body(); result = {'id': self.service.send(name, data['recipient'], data['envelope'])}
            elif self.command == 'GET' and path == '/inbox':
                sender = parse_qs(url.query).get('sender', [None])[0]
                result = self.service.inbox(self.name(), sender)
            elif self.command == 'GET' and path == '/pending-counts': result = self.service.pending_counts(self.name())
            elif self.command == 'GET' and path == '/pending-kinds': result = self.service.pending_kinds(self.name())
            elif self.command == 'POST' and path == '/ack':
                name = self.name(); self.service.acknowledge(name, self.body()['id']); result = {'ok': True}
            elif self.command == 'POST' and path == '/group-send':
                name = self.name(); data = self.body(); result = {'id': self.service.send_group_mail(name, data['group'], data['members'], data['envelope'])}
            elif self.command == 'GET' and path == '/group-inbox':
                group = parse_qs(url.query).get('group', [None])[0]
                result = self.service.group_inbox(self.name(), group)
            elif self.command == 'GET' and path == '/group-pending':
                result = self.service.group_pending(self.name())
            elif self.command == 'POST' and path == '/group-ack':
                name = self.name(); self.service.acknowledge_group(name, self.body()['id']); result = {'ok': True}
            else: return self.respond(404, {'error': 'Not found'})
            self.respond(200, result)
        except ReusedNonceCounter: self.respond(409, {'error': 'Nonce counter already used'})
        except UnknownContact: self.respond(404, {'error': 'Unknown user'})
        except HybridUnavailable: self.respond(503, {'error': 'Hybrid prekey support unavailable'})
        except PermissionError: self.respond(401, {'error': 'Invalid credentials or session'})
        except (ValueError, KeyError, LookupError, sqlite3.IntegrityError): self.respond(400, {'error': 'Invalid request or duplicate user'})
        except Exception: self.respond(400, {'error': 'Request rejected'})

def main():
    parser = argparse.ArgumentParser(); parser.add_argument('--database', default='server.sqlite3'); parser.add_argument('--port', type=int, default=8765); args = parser.parse_args()
    Handler.service = ChatService(SqliteRepository(args.database), ArgonHasher(), BundleVerifier(), time.time, lambda: secrets.token_urlsafe(32))
    server = ThreadingHTTPServer(('127.0.0.1', args.port), Handler)
    print(f'Local server running at http://127.0.0.1:{server.server_port}', flush=True)
    server.serve_forever()
if __name__ == '__main__': main()
