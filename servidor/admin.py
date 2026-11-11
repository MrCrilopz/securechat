"""Panel local del operador para ver textos cifrados pendientes y lanzar ataques."""
import argparse
import getpass
import hmac
import json
import os
import secrets
import time
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from securechat.application.attacks import run_scenario
from securechat.infrastructure import crypto
from servidor.infrastructure.server_adapters import SqliteRepository
from securechat.presentation import describe_attack, render_result
from securechat.theme import STYLE, e

LAB_STEPS = {
    'prekey': ('Sustituir preclave', '1. Se toma la preclave firmada del destinatario.\n2. Se cambia la preclave y se conserva la firma anterior.\n3. El inicio de sesión comprueba esa firma.'),
    'tamper': ('Modificar mensaje', '1. Se cifra el mensaje de ejemplo con AES-GCM.\n2. Se cambia un byte del texto cifrado.\n3. Quien recibe comprueba la etiqueta de autenticación.'),
    'replay': ('Repetir mensaje', '1. Se cifra el mensaje de ejemplo y quien recibe lo acepta.\n2. El contador esperado avanza.\n3. Se reenvía exactamente el mismo mensaje.'),
}

ADMIN_SCRIPT = """'use strict';
const queue = document.getElementById('queue');
if (queue) setInterval(async () => {
  try {
    const response = await fetch('/queue', {headers: {'Accept': 'application/json'}});
    if (!response.ok) return;
    const data = await response.json();
    const signature = JSON.stringify(data);
    if (queue.dataset.signature === signature) return;
    queue.replaceChildren();
    queue.dataset.signature = signature;
    if (!data.length) {
      const empty = document.createElement('p');
      empty.className = 'muted';
      empty.textContent = 'No hay mensajes pendientes.';
      queue.append(empty);
      showEnvelope(null, '');
      return;
    }
    for (const row of data) {
      const item = document.createElement('div');
      item.className = 'item';
      item.dataset.id = String(row.id);
      if (queue.dataset.armed === item.dataset.id) item.classList.add('armed');
      const form = document.createElement('form');
      form.method = 'post'; form.className = 'card-form';
      const csrf = document.createElement('input');
      csrf.type = 'hidden'; csrf.name = 'csrf'; csrf.value = queue.dataset.csrf || '';
      const message = document.createElement('input');
      message.type = 'hidden'; message.name = 'message_id'; message.value = String(row.id);
      const button = document.createElement('button');
      button.className = 'card-select'; button.name = 'action'; button.value = 'arm_pending';
      const check = document.createElement('span');
      check.className = 'check'; check.setAttribute('aria-hidden', 'true');
      const body = document.createElement('span');
      body.className = 'card-body';
      const title = document.createElement('strong');
      title.textContent = row.sender + ' → ' + row.recipient;
      const meta = document.createElement('span');
      meta.className = 'muted';
      meta.textContent = 'Mensaje pendiente #' + row.id + (row.protocol ? ' · ' + row.protocol : '');
      body.append(title, meta);
      button.append(check, body);
      form.append(csrf, message, button);
      const source = document.createElement('script');
      source.type = 'application/json'; source.className = 'envelope-source';
      source.textContent = JSON.stringify(row.envelope);
      item.append(form, source);
      queue.append(item);
    }
    const pane = document.getElementById('envelope-json');
    const selected = pane && pane.dataset.id;
    const current = selected && data.some(row => String(row.id) === selected)
      ? queue.querySelector('.item[data-id="' + selected + '"]')
      : queue.querySelector('.item');
    if (current) showEnvelope(current.querySelector('.envelope-source').textContent, current.dataset.id);
  } catch (_) {}
}, 2000);
function showEnvelope(raw, id) {
  const pre = document.getElementById('envelope-json');
  if (!pre) return;
  pre.dataset.id = id || '';
  if (!raw) {
    pre.textContent = 'No hay mensajes pendientes.';
  } else {
    try { pre.textContent = JSON.stringify(JSON.parse(raw), null, 2); }
    catch (_) { pre.textContent = raw; }
  }
  for (const item of document.querySelectorAll('#queue .item')) item.classList.toggle('shown', item.dataset.id === pre.dataset.id);
}
const interception = document.getElementById('interception-status');
if (interception) setInterval(async () => {
  try {
    const response = await fetch('/interception', {headers: {'Accept': 'application/json'}});
    if (!response.ok) return;
    const data = await response.json();
    const waiting = data.target_id ? 'Esperando entregar el mensaje #' + data.target_id + ' de ' + (data.sender || '') + ' para ' + (data.recipient || '') + '.' : 'Esperando un mensaje nuevo de ' + (data.sender || '') + ' para ' + (data.recipient || '') + '.';
    const text = {inactive: 'Modo desactivado.', armed: waiting, expired: 'La activación caducó.', intercepted: 'Se alteró una copia durante la entrega; el original permanece intacto.'}[data.status] || 'Estado no disponible.';
    const armed = (data.status === 'armed' || data.status === 'intercepted') && data.target_id ? String(data.target_id) : '';
    if (queue) queue.dataset.armed = armed;
    for (const item of document.querySelectorAll('#queue .item')) item.classList.toggle('armed', item.dataset.id === armed);
    interception.replaceChildren();
    const title = document.createElement('strong'); title.textContent = text; interception.append(title);
    if (data.status === 'intercepted') {
      for (const [label, value, other] of [['Original: ', data.original, data.altered], ['Alterado: ', data.altered, data.original]]) {
        const row = document.createElement('div'); row.className = 'cipher';
        row.append(document.createTextNode(label));
        for (let i = 0; i < value.length; i++) {
          const node = document.createElement(value[i] !== other[i] ? 'mark' : 'span');
          node.textContent = value[i]; row.append(node);
        }
        interception.append(row);
      }
    }
  } catch (_) {}
}, 2000);
"""


def make_admin_handler(database, password):
    csrf = secrets.token_urlsafe(32)
    password_bytes = password.encode('utf-8')
    sessions = {}

    class AdminHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args): pass
        def output(self, body, status=200, cookie=None, content_type='text/html; charset=utf-8'):
            data = body.encode('utf-8'); self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            if cookie: self.send_header('Set-Cookie', cookie)
            self.end_headers(); self.wfile.write(data)
        def safe_host(self): return self.headers.get('Host') == f'127.0.0.1:{self.server.server_port}'
        def session_id(self):
            try:
                cookies = SimpleCookie(self.headers.get('Cookie', ''))
                return cookies['admin_session'].value if 'admin_session' in cookies else ''
            except Exception: return ''
        def authorized(self):
            sid = self.session_id()
            expiry = sessions.get(sid, 0)
            if expiry > time.time(): return True
            sessions.pop(sid, None)
            return False
        def wrap(self, body):
            return f'<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Panel del servidor</title><style>{STYLE}</style></head><body><header class="top"><div class="brand">◈ &nbsp; Panel del servidor</div></header><main class="shell">{body}</main></body></html>'
        def login(self, error=''):
            return self.wrap(f'''<section class="login"><h1>Acceso al servidor</h1><p class="muted">Contraseña definida al iniciar el panel</p><p class="notice">{e(error)}</p><form method="post"><input type="hidden" name="csrf" value="{e(csrf)}"><label class="field" for="password">Contraseña del operador</label><input id="password" name="password" type="password" required><button class="primary" name="action" value="login">Ingresar</button></form></section>''')
        def pending(self):
            if not os.path.isfile(database): return []
            rows = SqliteRepository(database).inspect_messages()
            listed = []
            for row in rows:
                envelope = row['envelope'] if isinstance(row['envelope'], dict) else {}
                message = envelope.get('message') if isinstance(envelope.get('message'), dict) else {}
                protocol = message.get('protocol') if isinstance(message.get('protocol'), str) else ''
                if not protocol:
                    protocol = 'clásico' if 'ciphertext' in message else 'sobre'
                ciphertext = message.get('ciphertext', '')
                listed.append({'id': row['id'], 'sender': row['sender'], 'recipient': row['recipient'],
                               'protocol': protocol, 'ciphertext': ciphertext if isinstance(ciphertext, str) else '',
                               'envelope': envelope})
            return listed
        def panel(self, result='', lab_name='', lab_text=''):
            armed_id = None
            try:
                queued = self.pending()
                try:
                    state = SqliteRepository(database).interception_status(time.time())
                except Exception:
                    state = {}
                armed_id = state.get('target_id') if state.get('status') == 'armed' else None
                selected = next((row for row in queued if row['id'] == armed_id), None) or (queued[0] if queued else None)
                parts = []
                for row in queued:
                    blob = json.dumps(row['envelope'], ensure_ascii=True, indent=2).replace('<', '\\u003c')
                    mark = ' shown' if selected and row['id'] == selected['id'] else ''
                    armed = ' armed' if armed_id == row['id'] else ''
                    parts.append(f'<div class="item{mark}{armed}" data-id="{e(row["id"])}"><form method="post" class="card-form"><input type="hidden" name="csrf" value="{e(csrf)}"><input type="hidden" name="message_id" value="{e(row["id"])}"><button class="card-select" name="action" value="arm_pending"><span class="check" aria-hidden="true"></span><span class="card-body"><strong>{e(row["sender"])} → {e(row["recipient"])}</strong><span class="muted">Mensaje pendiente #{e(row["id"])} · {e(row["protocol"])}</span></span></button></form><script type="application/json" class="envelope-source">{blob}</script></div>')
                listing = ''.join(parts)
                first = selected
            except Exception:
                listing = '<p>No fue posible consultar la base de datos.</p>'
                first = None
            if not listing:
                listing = '<p class="muted">No hay mensajes pendientes.</p>'
                first = None
            shown = json.dumps(first['envelope'], ensure_ascii=True, indent=2).replace('<', '\\u003c') if first else 'No hay mensajes pendientes.'
            shown_id = e(first['id']) if first else ''
            feedback = f'<div class="notice" role="status">{render_result(result)}</div>' if result else ''
            forms = ''.join(f'''<form method="post"><input type="hidden" name="csrf" value="{e(csrf)}"><label class="field">Mensaje de ejemplo</label><input name="demo_text" value="Mensaje de prueba" maxlength="500"><button class="secondary" name="action" value="lab_{name}">{label}</button></form>''' for name, label in [('prekey','Sustituir preclave'),('tamper','Modificar mensaje'),('replay','Repetir mensaje')])
            if lab_name in LAB_STEPS and lab_text:
                title, steps = LAB_STEPS[lab_name]
                lab_html = f'<strong>{e(title)}</strong>\n{e(steps)}\n\n{render_result(lab_text)}'
            else:
                lab_html = 'Elige una prueba para ver aquí los pasos y el resultado.'
            demo = f'''<section class="panel"><h2>Intercepción de un mensaje real</h2><p class="muted">El mensaje marcado es el que se ve al lado. Al hacer clic, su entrega se altera en una copia; el original se conserva y llega después. La activación caduca en dos minutos.</p><div id="interception-status" class="notice">Consultando estado…</div><form method="post"><input type="hidden" name="csrf" value="{e(csrf)}"><button class="secondary" name="action" value="cancel_interception">Cancelar</button></form></section><br>'''
            return self.wrap(f'''<div class="row"><h1>Servidor local</h1><form method="post"><input type="hidden" name="csrf" value="{e(csrf)}"><button class="secondary" name="action" value="logout">Cerrar sesión</button></form></div><section class="panel"><h2>Mensajes cifrados pendientes</h2><p class="muted">La cola se actualiza sola. El círculo marca el JSON del recuadro. Un clic deja ese mensaje listo para interceptar. El texto y el archivo van dentro del cifrado.</p><div class="pending-board"><div id="queue" data-csrf="{e(csrf)}" data-armed="{e(armed_id or '')}">{listing}</div><pre id="envelope-json" class="cipher envelope-pane" data-id="{shown_id}">{shown}</pre></div></section><br>{demo}<section class="panel"><h2>Pruebas de seguridad</h2><p class="muted">Cada botón usa un mensaje de ejemplo, no el pendiente de arriba.</p>{feedback}<div class="pending-board"><div>{forms}</div><div id="lab-steps" class="cipher envelope-pane">{lab_html}</div></div></section><script src="/admin.js" defer></script>''')
        def do_GET(self):
            if not self.safe_host(): return self.output('Solicitud inválida', 400)
            if self.path == '/admin.js':
                return self.output(ADMIN_SCRIPT, content_type='application/javascript; charset=utf-8')
            if self.path == '/interception':
                if not self.authorized(): return self.output('{}', 403, content_type='application/json; charset=utf-8')
                try:
                    return self.output(json.dumps(SqliteRepository(database).interception_status(time.time())), content_type='application/json; charset=utf-8')
                except Exception:
                    return self.output('{}', 400, content_type='application/json; charset=utf-8')
            if self.path == '/queue':
                if not self.authorized(): return self.output('[]', 403, content_type='application/json; charset=utf-8')
                try:
                    return self.output(json.dumps(self.pending()), content_type='application/json; charset=utf-8')
                except Exception:
                    return self.output('[]', 400, content_type='application/json; charset=utf-8')
            if self.path != '/': return self.output('Solicitud inválida', 400)
            return self.output(self.panel() if self.authorized() else self.login())
        def do_POST(self):
            if not self.safe_host() or self.path != '/' or self.headers.get('Origin') != f'http://127.0.0.1:{self.server.server_port}':
                return self.output('Solicitud inválida', 403)
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 8192: raise ValueError('size')
                data = parse_qs(self.rfile.read(size).decode('utf-8'), keep_blank_values=True, max_num_fields=10)
                fields = {key: values[0] for key, values in data.items()}
                if not secrets.compare_digest(fields.get('csrf', ''), csrf): return self.output('Solicitud inválida', 403)
                action = fields.get('action', '')
                if action == 'login':
                    if not hmac.compare_digest(fields.get('password', '').encode('utf-8'), password_bytes):
                        return self.output(self.login('Contraseña incorrecta.'))
                    sid = secrets.token_urlsafe(32); sessions[sid] = time.time() + 3600
                    return self.output(self.panel(), cookie=f'admin_session={sid}; HttpOnly; SameSite=Strict; Path=/')
                if not self.authorized(): return self.output(self.login('Inicia sesión para continuar.'), 403)
                if action == 'logout':
                    sessions.pop(self.session_id(), None)
                    return self.output(self.login('Sesión cerrada.'), cookie='admin_session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/')
                if action == 'arm_interception':
                    repo = SqliteRepository(database)
                    sender, recipient = fields.get('sender', '').strip(), fields.get('recipient', '').strip()
                    if not repo.user(sender) or not repo.user(recipient):
                        return self.output(self.panel('No se encontraron ambos usuarios.'))
                    repo.arm_interception(sender, recipient, time.time())
                    return self.output(self.panel('Intercepción activada para el siguiente mensaje nuevo.'))
                if action == 'arm_pending':
                    repo = SqliteRepository(database)
                    try:
                        message_id = int(fields.get('message_id', ''))
                        repo.arm_pending_message(message_id, time.time())
                    except LookupError:
                        return self.output(self.panel('Ese mensaje ya no está pendiente.'))
                    except (TypeError, ValueError):
                        return self.output(self.panel('El mensaje pendiente no es válido.'))
                    return self.output(self.panel('Intercepción activada para ese mensaje pendiente.'))
                if action == 'cancel_interception':
                    SqliteRepository(database).cancel_interception()
                    return self.output(self.panel('Intercepción cancelada.'))
                if action.startswith('lab_'):
                    scenario = action[4:]
                    outcome = run_scenario(crypto, scenario, fields.get('demo_text', 'Mensaje de prueba'))
                    return self.output(self.panel(lab_name=scenario, lab_text=describe_attack(scenario, outcome)))
                return self.output('Solicitud inválida', 400)
            except Exception:
                return self.output('No se pudo completar la solicitud.', 400)
    return AdminHandler


def main():
    parser = argparse.ArgumentParser(description='Panel local del operador')
    parser.add_argument('--database', default='server.sqlite3')
    parser.add_argument('--port', type=int, default=8767)
    parser.add_argument('--password')
    args = parser.parse_args()
    password = args.password if args.password is not None else getpass.getpass('Define la contraseña del panel del servidor (mínimo 12 caracteres): ')
    if len(password) < 12:
        raise SystemExit('La contraseña debe tener al menos 12 caracteres.')
    server = HTTPServer(('127.0.0.1', args.port), make_admin_handler(args.database, password))
    print(f'Panel del servidor: http://127.0.0.1:{args.port}', flush=True)
    server.serve_forever()

if __name__ == '__main__': main()
