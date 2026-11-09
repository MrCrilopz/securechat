"""Interfaz web local que compone la sesión del usuario con el cliente inyectado."""
import argparse
import base64
import binascii
import html
import json
import os
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

from cliente.workspace import login_screen, workspace_screen
from securechat.presentation import describe_attack, render_result
from cliente.application.client import Client
from cliente.application.group_mailbox import MissingGroupKey
from cliente.infrastructure.dr_chat import DoubleRatchetChat
from securechat.application.attacks import run_scenario
from securechat.domain.models import username
from securechat.domain.errors import InvalidMessageNonce, LocalStateWriteFailed, UnexpectedOldMessage, UnsupportedMessageFormat, ConcurrentRatchetSession, UnknownRatchetSession, RatchetAuthenticationFailed, DrReplayEvidenceFull, ContactNotVerified, ContactIdentityChanged, InvalidClassicHeader, InvalidClassicCounter
from securechat.domain.errors import InvalidPrekeySignature, ReusedNonceCounter
from securechat.infrastructure import crypto
from securechat.infrastructure.hybrid_handshake import HybridUnavailable
from cliente.infrastructure import local_store
from cliente.infrastructure.http_gateway import HttpGateway
from cliente.infrastructure.attachment_codec import AttachmentCodec
from cliente.infrastructure.safe_download import save_download
from cliente.application.attachment import AttachmentError, MAX_ATTACHMENT_BYTES
from cliente.history_view import visible_history, describe_visible_row


class SecurityAlerts:
    """Cola de avisos de una sesión; no duplica avisos idénticos pendientes."""
    def __init__(self):
        self._lock = threading.Lock()
        self._items = []
        self._revision = 0

    def add(self, message):
        with self._lock:
            if not any(item['text'] == message for item in self._items):
                self._items.append({'id': secrets.token_urlsafe(16), 'text': message})
                self._revision += 1

    def current(self):
        with self._lock:
            return (dict(self._items[0]) if self._items else None, self._revision)

    def dismiss(self, alert_id):
        with self._lock:
            if (isinstance(alert_id, str) and alert_id.isascii() and self._items
                    and secrets.compare_digest(self._items[0]['id'], alert_id)):
                self._items.pop(0)
                self._revision += 1
                return True
            return False



UI_SCRIPT = """'use strict';
const attachmentForm = document.getElementById('attachment-form');
if (attachmentForm) attachmentForm.addEventListener('submit', event => {
  if (attachmentForm.dataset.ready === 'true') return;
  event.preventDefault();
  const file = document.getElementById('attachment-file').files[0];
  const status = document.getElementById('attachment-status');
  if (!file || file.size > 24576) { status.textContent = 'Selecciona un archivo de hasta 24 KiB.'; return; }
  const reader = new FileReader();
  reader.onerror = () => { status.textContent = 'No se pudo leer el archivo.'; };
  reader.onload = () => {
    attachmentForm.elements.attachment_name.value = file.name;
    attachmentForm.elements.attachment_data.value = String(reader.result).split(',')[1].split('+').join('-').split('/').join('_');
    attachmentForm.dataset.ready = 'true';
    attachmentForm.requestSubmit();
  };
  reader.readAsDataURL(file);
});
const password = document.getElementById('password');
const toggle = document.getElementById('password-toggle');
if (password && toggle) toggle.addEventListener('click', () => {
  const show = password.type === 'password';
  password.type = show ? 'text' : 'password';
  toggle.setAttribute('aria-label', show ? 'Ocultar contraseña' : 'Mostrar contraseña');
  toggle.setAttribute('aria-pressed', String(show));
  toggle.title = show ? 'Ocultar contraseña' : 'Mostrar contraseña';
});
const copyFingerprint = document.getElementById('copy-fingerprint');
if (copyFingerprint) copyFingerprint.addEventListener('click', async () => {
  const status = document.getElementById('copy-status');
  try {
    if (!navigator.clipboard || !navigator.clipboard.writeText) throw new Error('clipboard unavailable');
    await navigator.clipboard.writeText(copyFingerprint.dataset.fingerprint);
    status.textContent = 'Huella copiada';
  } catch (_) {
    status.textContent = 'No se pudo copiar. Selecciona la huella y cópiala manualmente.';
  }
});
if (document.querySelector('meta[name="heartbeat"]')) {
  const timer = setInterval(() => {
    const csrf = document.querySelector('input[name="csrf"]')?.value;
    if (csrf) fetch('/', {method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:new URLSearchParams({csrf, action:'heartbeat'})}).then(r => r.json()).then(data => {
      if (data.relogin) {
        clearInterval(timer);
        const box = document.getElementById('automatic-alert');
        if (box) {
          box.textContent = data.alert;
          box.hidden = false;
          const link = document.createElement('a');
          link.href = '/'; link.textContent = ' Iniciar sesión';
          box.append(link);
        }
        for (const el of document.querySelectorAll('form button, form input, form textarea')) el.disabled = true;
        return;
      }
      const target = document.getElementById('messages');
      if (target && target.dataset.peer && Array.isArray(data.history)) {
        const rows = data.history.filter(row => row.peer === target.dataset.peer);
        const signature = JSON.stringify(rows);
        if (target.dataset.signature !== signature) {
          target.replaceChildren();
          if (!rows.length) {
            const empty = document.createElement('div'); empty.className = 'empty';
            empty.textContent = 'Los mensajes aparecerán aquí.'; target.append(empty);
          }
          for (const row of rows) {
            const bubble = document.createElement('div');
            bubble.className = row.direction === 'out' ? 'bubble mine' : 'bubble';
            if (row.kind === 'attachment-v1') {
              const label = document.createElement('span'); label.textContent = 'Archivo: ' + row.name; bubble.append(label);
              const form = document.createElement('form'); form.method = 'post';
              for (const [name, value] of [['csrf', csrf], ['action', 'save_attachment'], ['attachment_index', String(row.index)]]) {
                const input = document.createElement('input'); input.type = 'hidden'; input.name = name; input.value = value; form.append(input);
              }
              const button = document.createElement('button'); button.className = 'secondary'; button.type = 'submit'; button.textContent = 'Guardar archivo'; form.append(button); bubble.append(form);
            } else {
              if (row.author) {
                const who = document.createElement('span'); who.className = 'who'; who.textContent = row.author; bubble.append(who);
              }
              bubble.append(document.createTextNode(row.text || ''));
            }
            target.append(bubble);
          }
          target.dataset.signature = signature;
          target.scrollTop = target.scrollHeight;
        }
      }
      const alert = document.getElementById('automatic-alert');
      const alertMessage = document.getElementById('automatic-alert-message');
      const alertId = document.getElementById('automatic-alert-id');
      if (alert && alertMessage && alertId && Number.isInteger(data.alert_revision) && data.alert_revision >= Number(alert.dataset.revision || 0)) {
        alert.dataset.revision = String(data.alert_revision);
        alertMessage.textContent = data.alert || '';
        alertId.value = data.alert_id || '';
        alert.hidden = !data.alert;
      }
      for (const contact of data.contacts || []) {
        for (const el of document.querySelectorAll('[data-online-user]')) {
          if (el.dataset.onlineUser === contact.name) {
            el.textContent = contact.online ? 'En línea' : 'Sin conexión';
            el.className = contact.online ? 'online' : 'offline';
          }
        }
      }
      const unread = data.unread || {};
      for (const el of document.querySelectorAll('[data-unread-user]')) {
        const count = Number(unread[el.dataset.unreadUser] || 0);
        el.textContent = count ? String(count) : '';
        el.hidden = !count;
      }
      filterContacts();
    }).catch(() => {});
  }, 3000);
}
function filterContacts() {
  const search = document.getElementById('contact-search');
  const query = (search && search.value || '').trim().toLowerCase();
  let visible = 0;
  for (const row of document.querySelectorAll('[data-contact]')) {
    const name = (row.dataset.contact || '').toLowerCase();
    const badge = row.querySelector('[data-unread-user]');
    const count = badge && !badge.hidden ? Number(badge.textContent || 0) : 0;
    const known = row.dataset.known === '1' || count > 0;
    const show = query ? name.includes(query) : known;
    row.hidden = !show;
    if (show && !query) visible += 1;
  }
  const empty = document.getElementById('no-chats');
  if (empty) empty.hidden = Boolean(query) || visible > 0;
}
const contactSearch = document.getElementById('contact-search');
if (contactSearch) contactSearch.addEventListener('input', filterContacts);
const memberSearch = document.getElementById('member-search');
const memberChoices = document.getElementById('member-choices');
const memberPicked = document.getElementById('member-picked');
const memberField = document.getElementById('group-members');
if (memberSearch && memberChoices && memberPicked && memberField) {
  const memberNames = (memberChoices.dataset.names || '').split(',').map(name => name.trim()).filter(Boolean);
  const memberSet = new Set();
  const memberHint = document.getElementById('member-empty');
  if (memberHint) memberHint.hidden = memberNames.length > 0;
  const paintMembers = () => {
    const query = memberSearch.value.trim().toLowerCase();
    memberChoices.replaceChildren();
    for (const name of memberNames) {
      if (memberSet.has(name) || (query && !name.toLowerCase().includes(query))) continue;
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'secondary'; button.textContent = name;
      button.addEventListener('click', () => { memberSet.add(name); paintMembers(); });
      memberChoices.append(button);
    }
    memberPicked.replaceChildren();
    for (const name of memberSet) {
      const chip = document.createElement('button');
      chip.type = 'button'; chip.className = 'secondary'; chip.textContent = name + ' ×';
      chip.addEventListener('click', () => { memberSet.delete(name); paintMembers(); });
      memberPicked.append(chip);
    }
    memberField.value = Array.from(memberSet).join(',');
  };
  memberSearch.addEventListener('input', paintMembers);
  paintMembers();
}
document.addEventListener('keydown', event => {
  if (event.key !== 'Escape') return;
  const messages = document.getElementById('messages');
  if (!messages || !messages.dataset.peer) return;
  const search = document.getElementById('contact-search');
  if (search && document.activeElement === search && search.value) {
    search.value = '';
    search.dispatchEvent(new Event('input'));
    return;
  }
  const csrf = document.querySelector('input[name="csrf"]')?.value;
  if (!csrf) return;
  event.preventDefault();
  const form = document.createElement('form');
  form.method = 'post';
  for (const [name, value] of [['csrf', csrf], ['action', 'leave']]) {
    const input = document.createElement('input');
    input.type = 'hidden';
    input.name = name;
    input.value = value;
    form.append(input);
  }
  document.body.append(form);
  form.submit();
});
"""

def render_page(csrf, user='', result='', tab='conversation'):
    esc = lambda value: html.escape(str(value), quote=True)
    checked = lambda name: 'checked' if tab == name else ''
    return f'''<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Mensajería segura</title><style>
:root{{--ink:#142436;--muted:#627384;--line:#dce5e8;--green:#147868;--dark:#102d32;--paper:#fff}}*{{box-sizing:border-box}}body{{margin:0;background:#f3f7f6;color:var(--ink);font:15px/1.5 system-ui,sans-serif}}.appbar{{background:var(--dark);color:#fff;padding:17px 5%;display:flex;justify-content:space-between;align-items:center;gap:16px}}.brand{{display:flex;align-items:center;gap:12px}}.logo{{display:grid;place-items:center;width:40px;height:40px;border-radius:12px;background:#1c635a;font-size:20px}}.brand strong{{display:block;font-size:17px}}.brand span{{display:block;font-size:12px;color:#b8d4ce}}.badge{{font-size:12px;border:1px solid #66958c;color:#d9f4e9;border-radius:30px;padding:6px 12px}}main{{max-width:1120px;margin:auto;padding:36px 24px 50px}}.eyebrow{{color:var(--green);font-size:11px;font-weight:750;letter-spacing:.12em;text-transform:uppercase}}h1{{font-size:30px;letter-spacing:-.03em;line-height:1.2;margin:7px 0}}.intro{{color:var(--muted);margin:0 0 26px}}.layout{{display:grid;grid-template-columns:300px 1fr;gap:22px;align-items:start}}.card{{background:var(--paper);border:1px solid var(--line);border-radius:16px;padding:22px;box-shadow:0 8px 25px #183d3809}}h2{{font-size:19px;margin:0 0 7px}}h3{{font-size:15px;margin:0 0 5px}}p{{margin:0 0 14px}}.muted,small{{color:var(--muted);font-size:13px}}label.field{{font-weight:650;display:block;margin:15px 0 6px;font-size:13px}}input:not([type=radio]):not([type=hidden]),textarea{{font:inherit;border:1px solid #cbd9d7;border-radius:9px;width:100%;padding:11px;background:#fff;color:var(--ink)}}input:focus,textarea:focus{{outline:2px solid #88c9b8;outline-offset:1px}}textarea{{min-height:100px;resize:vertical}}button{{font:inherit;font-weight:650;background:var(--green);color:white;border:0;border-radius:9px;padding:10px 15px;margin:12px 5px 0 0;cursor:pointer}}button:hover{{background:#0e5e52}}button.secondary{{background:#edf4f2;color:#21584f}}.tabs{{display:flex;gap:3px;padding:5px;background:#e7efed;border-radius:11px;margin-bottom:20px;flex-wrap:wrap}}.tabs label{{padding:9px 14px;border-radius:8px;color:#526a68;font-weight:650;cursor:pointer;font-size:13px}}.tab-radio{{position:absolute;opacity:0}}.panel{{display:none}}#t-chat:checked ~ .content #panel-chat,#t-contact:checked ~ .content #panel-contact,#t-tests:checked ~ .content #panel-tests{{display:block}}#t-chat:checked ~ .content label[for=t-chat],#t-contact:checked ~ .content label[for=t-contact],#t-tests:checked ~ .content label[for=t-tests]{{background:white;color:#135b50;box-shadow:0 2px 8px #254b3914}}.result{{margin-top:18px;border-left:3px solid #45a38f;background:#f1f8f5;padding:15px;border-radius:5px 10px 10px 5px}}.password-field{{position:relative}}.password-field input{{padding-right:52px !important}}.password-toggle{{position:absolute;right:5px;top:4px;margin:0;padding:8px;color:#536d68;background:transparent;border-radius:8px}}.password-toggle:hover{{background:#edf4f2}}.password-toggle svg{{display:block;width:20px;height:20px}}.diff{{background:#ffe197;color:#7a3508;border-radius:3px;font-weight:700;padding:1px 0}}pre{{font:13px/1.6 ui-monospace,monospace;white-space:pre-wrap;word-break:break-word;margin:8px 0 0}}.test{{padding:13px 0;border-bottom:1px solid #edf2f1}}.test:last-of-type{{border:0}}.foot{{color:#6c7e7c;font-size:12px;margin-top:24px}}@media(max-width:740px){{.layout{{grid-template-columns:1fr}}main{{padding:24px 16px}}.badge{{display:none}}}}
</style></head><body><header class="appbar"><div class="brand"><div class="logo">◈</div><div><strong>Mensajería segura</strong><span>Proyecto de criptología</span></div></div><span class="badge">● Entorno local · Prototipo académico</span></header><main><div class="eyebrow">Comunicación protegida</div><h1>Tu espacio de mensajería</h1><p class="intro">Gestiona tu identidad, verifica tus contactos y explora las pruebas del protocolo.</p><div class="layout"><aside class="card"><h2>Tu identidad</h2><p class="muted">Ingresa las credenciales para cada acción. La interfaz no conserva tu contraseña.</p><label class="field" for="user">Nombre de usuario</label><input id="user" form="chat-form" name="user" value="{esc(user)}" autocomplete="username"><label class="field" for="password">Contraseña</label><div class="password-field"><input type="password" id="password" form="chat-form" name="password" autocomplete="current-password"><button type="button" id="password-toggle" class="password-toggle" aria-label="Mostrar contraseña" aria-pressed="false" title="Mostrar contraseña"><svg aria-hidden="true" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg></button></div><button form="chat-form" name="action" value="register">Crear usuario</button><p class="foot">Utiliza al menos 12 caracteres. Protege el archivo local de tu identidad.</p></aside><div><input class="tab-radio" type="radio" name="view" id="t-chat" {checked('conversation')}><input class="tab-radio" type="radio" name="view" id="t-contact" {checked('contact')}><input class="tab-radio" type="radio" name="view" id="t-tests" {checked('tests')}><div class="content"><nav class="tabs" aria-label="Secciones"><label for="t-chat">Conversación</label><label for="t-contact">Contactos</label><label for="t-tests">Pruebas de seguridad</label></nav><form id="chat-form" method="post"><input type="hidden" name="csrf" value="{esc(csrf)}"></form><section class="panel card" id="panel-chat"><h2>Conversación</h2><p class="muted">Envía y recibe mensajes después de verificar a tu contacto.</p><label class="field" for="peer">Nombre del contacto</label><input form="chat-form" id="peer" name="peer"><label class="field" for="message">Mensaje</label><textarea form="chat-form" id="message" name="message" placeholder="Escribe un mensaje de prueba"></textarea><button form="chat-form" name="action" value="send">Enviar mensaje cifrado</button><button class="secondary" form="chat-form" name="action" value="receive">Recibir mensajes</button><button class="secondary" form="chat-form" name="action" value="history">Ver historial</button></section><section class="panel card" id="panel-contact"><h2>Verificación de identidad</h2><p class="muted">Ambas personas deben comparar la huella completa por un canal independiente antes de confiar en el contacto.</p><label class="field" for="peer-contact">Nombre del contacto</label><input form="chat-form" id="peer-contact" name="peer"><label class="field" for="safety">Huella confirmada</label><input form="chat-form" id="safety" name="safety" autocomplete="off"><button form="chat-form" name="action" value="safety">Mostrar huella</button><button class="secondary" form="chat-form" name="action" value="trust">Verificar contacto</button><p class="foot">Las credenciales de la columna izquierda se aplican también aquí.</p></section><section class="panel card" id="panel-tests"><h2>Pruebas de seguridad</h2><p class="muted">Elige una prueba y compara los resultados.</p><form method="post"><input type="hidden" name="csrf" value="{esc(csrf)}"><label class="field" for="demo_text">Mensaje de ejemplo para las simulaciones</label><input id="demo_text" name="demo_text" value="Mensaje de prueba" maxlength="500"><div class="test"><h3>01 · Sustituir una preclave firmada</h3><span class="muted">Se cambia la preclave pública sin cambiar su firma. Compara ambos valores en el resultado.</span><br><button class="secondary" name="action" value="lab_prekey">Sustituir preclave</button></div><div class="test"><h3>02 · Alterar un mensaje cifrado</h3><span class="muted">Se cifra el texto de ejemplo y se cambia un byte del resultado antes de descifrarlo.</span><br><button class="secondary" name="action" value="lab_tamper">Modificar mensaje</button></div><div class="test"><h3>03 · Repetir un mensaje</h3><span class="muted">Se acepta un mensaje y después se intenta recibir exactamente el mismo nuevamente.</span><br><button class="secondary" name="action" value="lab_replay">Repetir mensaje</button></div><button name="action" value="attacks">Ejecutar las tres pruebas automáticas</button></form></section><section class="result" aria-live="polite"><h3>Resultado</h3><pre>{render_result(result) if result else 'Los resultados aparecerán aquí.'}</pre></section></div></div></div><p class="foot">Demostración local · No utilizar información sensible ni exponer el servicio a redes públicas.</p></main><script src="/ui.js" defer></script></body></html>'''


def perform(fields, port, home):
    action = fields.get('action', '')
    if action.startswith('lab_'):
        result = run_scenario(crypto, action[4:], fields.get('demo_text', 'Mensaje de prueba'))
        return describe_attack(action[4:], result)
    if fields.get('action') == 'attacks':
        tests = [
            ('Sustitución de preclave', 'test_prekey_substitution_rejected'),
            ('Alteración del mensaje', 'test_modified_ciphertext_rejected_and_state_unchanged'),
            ('Repetición de mensaje', 'test_replay_rejected'),
        ]
        results = []
        for label, name in tests:
            command = [sys.executable, '-m', 'unittest', 'tests.test_protocol.ProtocolTests.' + name]
            try:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=30)
                results.append((label, completed.returncode == 0))
            except (OSError, subprocess.TimeoutExpired):
                results.append((label, False))
        status = '3 pruebas ejecutadas correctamente.' if all(ok for _, ok in results) else 'Una o más pruebas fallaron o no pudieron ejecutarse.'
        return status + '\n' + '\n'.join(label + (': ataque rechazado' if ok else ': no superada') for label, ok in results)
    user = fields.get('user', '').strip()
    password = fields.get('password', '')
    action = fields.get('action', '')
    peer = fields.get('peer', '').strip()
    username(user)
    if not password:
        raise ValueError('Se requiere la contraseña')
    path = os.path.join(home, user + '.json')
    gateway = HttpGateway(port)
    if action == 'register':
        if os.path.exists(path):
            raise ValueError('La identidad local ya existe')
        identity = crypto.Identity.generate(user)
        state = {'identity': identity.serialize(), 'contacts': {}, 'sessions': {}, 'history': [], 'outbox': []}
        gateway.register(user, password, identity.bundle())
        local_store.save(path, password, state)
        return 'Usuario registrado. Conserva segura la identidad local cifrada.'
    state = local_store.load(path, password)
    gateway.login(user, password)
    attachments = AttachmentCodec()
    app = Client(gateway, crypto, lambda data: local_store.save(path, password, data), state, attachments=attachments, dr=DoubleRatchetChat())
    if action in ('safety', 'trust', 'send'):
        username(peer)
    if action == 'safety':
        return 'Huella de seguridad de ' + peer + ':\n' + app.safety(peer)
    if action == 'trust':
        app.trust(peer, fields.get('safety', ''))
        return 'Contacto verificado: ' + peer
    if action == 'send':
        message = fields.get('message', '')
        if not message.strip():
            raise ValueError('Escribe un mensaje')
        app.send(peer, message)
        return 'Mensaje cifrado enviado a ' + peer
    if action == 'receive':
        before = len(state['history'])
        app.receive()
        rows = visible_history(state['history'][before:], attachments)
        return '\n'.join(f"{row['peer']}: {describe_visible_row(row)}" for row in rows) if rows else 'No hay mensajes nuevos.'
    if action == 'history':
        rows = visible_history(state['history'], attachments)
        return '\n'.join(f"{row['direction']} {row['peer']}: {describe_visible_row(row)}" for row in rows) or 'No hay mensajes en el historial local.'
    raise ValueError('Acción desconocida')


def group_id_from_peer(peer):
    if isinstance(peer, str) and peer.startswith('g:') and len(peer) == 34 and all(char in '0123456789abcdef' for char in peer[2:]):
        return peer[2:]
    return ''

def visible_groups(state):
    raw = state.get('groups') if isinstance(state, dict) else None
    groups = []
    if isinstance(raw, dict):
        for gid, record in raw.items():
            if isinstance(gid, str) and isinstance(record, dict) and isinstance(record.get('name'), str):
                members = record.get('members') if isinstance(record.get('members'), list) else []
                groups.append({'id': gid, 'name': record['name'], 'members': [member for member in members if isinstance(member, str)]})
    groups.sort(key=lambda item: item['name'].casefold())
    return groups

def conversation_dr_mode(state, peer):
    if not peer:
        return 'off'
    record = state.get('dr_sessions', {}).get(peer)
    classic = peer in state.get('sessions', {})
    if record and (not classic or record.get('local_opt_in')):
        return 'active'
    if classic:
        return 'migrate'
    return 'available'


def user_error(exc):
    if isinstance(exc, LookupError) and str(exc) == 'Hybrid prekey not available':
        return 'El contacto no tiene una preclave híbrida publicada. No se envió un mensaje clásico en su lugar.'
    if isinstance(exc, MissingGroupKey):
        return 'ALERTA: falta la clave de grupo de ese emisor. El mensaje se conservó sin confirmar.'
    if isinstance(exc, ReusedNonceCounter):
        return 'ALERTA: este contador ya fue usado. No se cifró otro mensaje, para no repetir la clave y el nonce. No restaures ni clones el estado local.'
    if isinstance(exc, InvalidPrekeySignature):
        return 'ALERTA: la firma de la preclave del contacto no es válida. El mensaje se conservó sin confirmar; verifica la identidad del contacto.'
    if isinstance(exc, InvalidClassicHeader):
        return 'ALERTA: la cabecera no corresponde a la sesión conocida. El mensaje se conservó sin confirmar.'
    if isinstance(exc, InvalidClassicCounter):
        return 'ALERTA: llegó un mensaje con contador adelantado. Se conservó sin confirmar hasta revisar la conversación.'
    if isinstance(exc, ContactNotVerified):
        return 'ALERTA: el contacto no está verificado. Compara la huella por un canal confiable antes de verificarlo. El mensaje se conservó sin confirmar.'
    if isinstance(exc, ContactIdentityChanged):
        return 'ALERTA: la clave de identidad del contacto cambió. Compara nuevamente la huella por un canal confiable antes de continuar.'
    if isinstance(exc, RatchetAuthenticationFailed):
        return 'ALERTA: un posible mensaje alterado, un límite de seguridad o un remitente desconocido requieren revisión. Se conservó sin confirmar.'
    if isinstance(exc, UnknownRatchetSession):
        return 'ALERTA: se recibió un mensaje de una sesión no reconocida. Se conservó sin confirmar; revisa la conversación.'
    if isinstance(exc, ConcurrentRatchetSession):
        return 'ALERTA: ya hay dos sesiones de Double Ratchet y llegó otra distinta. Los mensajes nuevos se entregan y los anteriores se conservaron. El inicio extra quedó sin confirmar; no hay resolución automática para una tercera sesión.'
    if isinstance(exc, DrReplayEvidenceFull):
        return 'ALERTA: esta conversación ya guardó 256 mensajes de Double Ratchet. El mensaje nuevo se conservó sin confirmar. No se borra la evidencia anterior para hacer espacio.'
    if isinstance(exc, ValueError) and str(exc) == 'Classic session requires explicit migration':
        return 'Esta conversación ya usa la sesión anterior. No se cambia a Double Ratchet sin una migración aparte.'
    if isinstance(exc, LocalStateWriteFailed):
        return 'No se pudo guardar el estado local. La sesión se cerró por seguridad; revisa el almacenamiento e inicia sesión nuevamente.'
    if isinstance(exc, UnexpectedOldMessage):
        return 'ALERTA: se recibió un mensaje con contador antiguo que no coincide con uno ya aceptado. Se conservó sin confirmar; revisa el estado de la conversación.'
    if isinstance(exc, AttachmentError):
        return 'ALERTA: el archivo adjunto es inválido o supera el tamaño permitido.'
    if isinstance(exc, UnsupportedMessageFormat):
        return 'ALERTA: el mensaje tiene un formato desconocido o alterado. Se conservó sin confirmar.'
    if isinstance(exc, InvalidMessageNonce):
        return 'ALERTA: el mensaje recibido no es válido y fue rechazado. No se mostró su contenido.'
    if isinstance(exc, crypto.InvalidTag):
        return 'ALERTA: se detectó un mensaje alterado y fue rechazado. No se mostró su contenido.'
    if isinstance(exc, ValueError) and str(exc).startswith('ALERT: contact identity key changed;'):
        return 'ALERTA: la clave de identidad del contacto cambió. Compara nuevamente la huella por un canal confiable antes de continuar.'
    return 'No se pudo completar la acción. Comprueba los datos, la contraseña y la conexión local.'


def main():
    parser = argparse.ArgumentParser(description='Local educational browser interface')
    parser.add_argument('--port', type=int, default=8766)
    parser.add_argument('--server-port', type=int, default=8765)
    parser.add_argument('--home', default='clients')
    parser.add_argument('--database', default='server.sqlite3')
    args = parser.parse_args()
    token = secrets.token_urlsafe(32)
    expected_host = f'127.0.0.1:{args.port}'
    sessions = {}
    attachments = AttachmentCodec()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass
        def output(self, status, page, content_type='text/html; charset=utf-8', cookie=None):
            data = page.encode('utf-8')
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(data)))
            self.send_header('Cache-Control', 'no-store')
            self.send_header('X-Content-Type-Options', 'nosniff')
            self.send_header('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; script-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
            if cookie is not None:
                self.send_header('Set-Cookie', cookie)
            self.end_headers()
            self.wfile.write(data)
        def valid_host(self):
            return self.headers.get('Host') == expected_host
        def session_id(self):
            try:
                jar = SimpleCookie(self.headers.get('Cookie', ''))
                return jar['session'].value if 'session' in jar else ''
            except Exception:
                return ''
        def active(self):
            sid = self.session_id()
            item = sessions.get(sid)
            if item and item['expires'] > time.time():
                return item
            sessions.pop(sid, None)
            return None
        def invalidate_session(self, item):
            sessions.pop(self.session_id(), None)
            try:
                item['gateway'].logout()
            except Exception:
                pass
        def show(self, item, message='', cookie=None, safety=''):
            gateway, user, state = item['gateway'], item['user'], item['state']
            try:
                contacts = gateway.contacts()
                contact_client = Client(gateway, crypto, lambda _: None, state)
                for contact in contacts:
                    contact['verified'] = bool(state['contacts'].get(contact['name'], {}).get('verified'))
                    contact['changed'] = False
                    if contact['verified']:
                        try:
                            contact_client.verified_bundle(contact['name'])
                        except ValueError as exc:
                            if str(exc).startswith('ALERT: contact identity key changed;'):
                                contact['verified'] = False
                                contact['changed'] = True
                        except Exception:
                            contact['verified'] = False
            except Exception:
                contacts = []
            try:
                def persist(data):
                    local_store.save(os.path.join(args.home, user + '.json'), item['secret'], data)
                Client(gateway, crypto, persist, state, dr=DoubleRatchetChat()).ensure_hybrid_prekey()
            except HybridUnavailable:
                pass
            except urllib.error.URLError:
                pass
            alert, revision = item['security_alerts'].current()
            peer = item['peer']
            dr_mode = conversation_dr_mode(state, peer)
            try:
                unread = gateway.pending_counts()
            except urllib.error.URLError:
                unread = {}
            page = workspace_screen(token, user, contacts, visible_history(state['history'], attachments), peer, message, item['tab'], [], safety, alert, revision, dr_mode, unread, visible_groups(state))
            return self.output(200, page, cookie=cookie)
        def do_GET(self):
            if not self.valid_host():
                return self.output(400, 'Solicitud inválida')
            if self.path == '/ui.js':
                return self.output(200, UI_SCRIPT, 'application/javascript; charset=utf-8')
            if self.path != '/':
                return self.output(404, 'No encontrado')
            item = self.active()
            return self.show(item) if item else self.output(200, login_screen(token))
        def do_POST(self):
            if not self.valid_host() or self.path != '/' or self.headers.get('Origin') != 'http://' + expected_host:
                return self.output(403, 'Solicitud inválida')
            try:
                size = int(self.headers.get('Content-Length', '0'))
                if not 0 < size <= 65536:
                    raise ValueError('Tamaño inválido')
                data = parse_qs(self.rfile.read(size).decode('utf-8'), keep_blank_values=True, max_num_fields=20)
                fields = {key: next((value for value in values if value), '') for key, values in data.items()}
                if not secrets.compare_digest(fields.get('csrf', ''), token):
                    return self.output(403, 'Solicitud inválida')
                action = fields.get('action', '')
                item = self.active()
                def begin(user, secret):
                    username(user)
                    if any(entry['user'] == user and entry['expires'] > time.time() for entry in sessions.values()):
                        return self.output(200, login_screen(token, 'Esta cuenta ya tiene una sesión activa. Ciérrala antes de volver a ingresar.'))
                    state = local_store.load(os.path.join(args.home, user + '.json'), secret)
                    gateway = HttpGateway(args.server_port); gateway.login(user, secret); gateway.heartbeat()
                    sid = secrets.token_urlsafe(32)
                    opened = {'user': user, 'secret': secret, 'state': state, 'gateway': gateway, 'peer': '', 'tab': 'chat', 'expires': time.time() + 3600, 'security_alerts': SecurityAlerts()}
                    sessions[sid] = opened
                    return self.show(opened, cookie=f'session={sid}; HttpOnly; SameSite=Strict; Path=/')
                if not item:
                    if action == 'register':
                        try:
                            perform(fields, args.server_port, args.home)
                        except Exception:
                            return self.output(200, login_screen(token, 'No fue posible crear la cuenta. Comprueba los datos o si el usuario ya existe.'))
                        try:
                            return begin(fields.get('user', '').strip(), fields.get('password', ''))
                        except Exception:
                            return self.output(200, login_screen(token, 'Cuenta creada. Inicia sesión para continuar.'))
                    if action != 'login':
                        return self.output(200, login_screen(token, 'Inicia sesión para continuar.'))
                    try:
                        return begin(fields.get('user', '').strip(), fields.get('password', ''))
                    except Exception:
                        return self.output(200, login_screen(token, 'Usuario o contraseña incorrectos, o servidor no disponible.'))
                if action == 'heartbeat':
                    try:
                        item['gateway'].heartbeat()
                        state, user = item['state'], item['user']
                        def persist(data):
                            local_store.save(os.path.join(args.home, user + '.json'), item['secret'], data)
                        client = Client(item['gateway'], crypto, persist, state, attachments=attachments, dr=DoubleRatchetChat())
                        alert = ''
                        try:
                            client.flush()
                            open_peer = item.get('peer') or ''
                            group_id = group_id_from_peer(open_peer) if item.get('tab') == 'chat' else ''
                            if group_id:
                                client.receive(only_group=group_id)
                            elif item.get('tab') == 'chat' and open_peer:
                                client.receive(only_peer=open_peer)
                            client.pull_group_traffic()
                        except LocalStateWriteFailed as exc:
                            self.invalidate_session(item)
                            response = json.dumps({'contacts': [], 'history': [], 'alert': user_error(exc), 'relogin': True})
                            return self.output(200, response, 'application/json; charset=utf-8', cookie='session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/')
                        except (crypto.InvalidTag, InvalidMessageNonce, UnexpectedOldMessage, AttachmentError, UnsupportedMessageFormat, ConcurrentRatchetSession, UnknownRatchetSession, RatchetAuthenticationFailed, DrReplayEvidenceFull, ContactNotVerified, ContactIdentityChanged, InvalidClassicHeader, InvalidClassicCounter, InvalidPrekeySignature, MissingGroupKey) as exc:
                            alert = user_error(exc)
                        except ValueError as exc:
                            if str(exc).startswith('ALERT: contact identity key changed;'):
                                alert = user_error(exc)
                        if alert:
                            item['security_alerts'].add(alert)
                        current_alert, alert_revision = item['security_alerts'].current()
                        try:
                            unread = item['gateway'].pending_counts()
                        except urllib.error.URLError:
                            unread = {}
                        response = json.dumps({'contacts': item['gateway'].contacts(), 'history': visible_history(state['history'], attachments), 'unread': unread, 'alert': current_alert['text'] if current_alert else '', 'alert_id': current_alert['id'] if current_alert else '', 'alert_revision': alert_revision})
                    except Exception:
                        response = json.dumps({'contacts': []})
                    return self.output(200, response, 'application/json; charset=utf-8')
                if action == 'logout':
                    try: item['gateway'].logout()
                    except Exception: pass
                    sessions.pop(self.session_id(), None)
                    return self.output(200, login_screen(token, 'Sesión cerrada.'), cookie='session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/')
                if action == 'dismiss_security_alert':
                    item['security_alerts'].dismiss(fields.get('alert_id', ''))
                    return self.show(item)
                item['gateway'].heartbeat()
                result = ''
                safety = ''
                if action.startswith('view_') and action[5:] in ('chat','contacts','groups'):
                    item['tab'] = action[5:]
                elif action == 'leave':
                    item['peer'] = ''; item['tab'] = 'chat'
                elif action == 'select':
                    item['peer'] = fields.get('peer', ''); item['tab'] = 'chat'
                    user, state = item['user'], item['state']
                    def save_selection(data):
                        local_store.save(os.path.join(args.home, user + '.json'), item['secret'], data)
                    client = Client(item['gateway'], crypto, save_selection, state, attachments=attachments, dr=DoubleRatchetChat())
                    group_id = group_id_from_peer(item['peer'])
                    if group_id:
                        client.receive(only_group=group_id)
                    else:
                        username(item['peer']); client.receive(only_peer=item['peer'])
                elif action == 'save_attachment':
                    index_text = fields.get('attachment_index', '')
                    if not index_text.isascii() or not index_text.isdecimal(): raise AttachmentError('Adjunto inválido')
                    index = int(index_text)
                    history = item['state']['history']
                    if index >= len(history) or history[index].get('kind') != 'attachment-v1': raise AttachmentError('Adjunto inválido')
                    name, content = attachments.open(history[index]['text'])
                    path = save_download(args.home, item['user'], name, content)
                    result = 'Archivo guardado en: ' + path
                elif action in ('send', 'send_dr', 'send_hybrid', 'send_attachment', 'receive', 'safety', 'trust', 'create_group', 'send_group'):
                    user, state = item['user'], item['state']
                    def save(data):
                        local_store.save(os.path.join(args.home, user + '.json'), item['secret'], data)
                    client = Client(item['gateway'], crypto, save, state, attachments=attachments, dr=DoubleRatchetChat())
                    peer = fields.get('peer', '')
                    if action == 'send':
                        client.send(peer, fields.get('message', '')); item['peer'] = peer; item['tab'] = 'chat'
                    elif action == 'send_dr':
                        client.send_dr(peer, fields.get('message', '')); item['peer'] = peer; item['tab'] = 'chat'
                    elif action == 'send_hybrid':
                        client.send_hybrid(peer, fields.get('message', '')); item['peer'] = peer; item['tab'] = 'chat'
                    elif action == 'create_group':
                        members = [part.strip() for part in fields.get('group_members', '').split(',') if part.strip()]
                        group_id = client.create_group(fields.get('group_name', ''), members)
                        client.send_group(group_id, fields.get('message', ''))
                        item['peer'] = 'g:' + group_id
                        item['tab'] = 'chat'
                    elif action == 'send_group':
                        group_id = group_id_from_peer('g:' + fields.get('group_id', ''))
                        if not group_id: raise ValueError('Unknown group')
                        client.send_group(group_id, fields.get('message', ''))
                        item['peer'] = 'g:' + group_id
                        item['tab'] = 'chat'
                    elif action == 'send_attachment':
                        encoded = fields.get('attachment_data', '')
                        if len(encoded) > 4 * ((MAX_ATTACHMENT_BYTES + 2) // 3): raise AttachmentError('Archivo demasiado grande')
                        try:
                            content = base64.b64decode(encoded.encode('ascii'), altchars=b'-_', validate=True)
                        except (UnicodeError, binascii.Error, ValueError) as exc:
                            raise AttachmentError('Archivo inválido') from exc
                        if len(content) > MAX_ATTACHMENT_BYTES: raise AttachmentError('Archivo demasiado grande')
                        client.send_attachment(peer, fields.get('attachment_name', ''), content)
                        item['peer'] = peer; item['tab'] = 'chat'
                    elif action == 'receive':
                        received = client.receive(); item['peer'] = peer; item['tab'] = 'chat'
                        if not received: result = 'No hay mensajes nuevos.'
                    elif action == 'safety':
                        safety = client.safety(peer); result = 'Huella de ' + peer + ':\n' + safety; item['tab'] = 'contacts'
                    else:
                        client.trust(peer, fields.get('safety', '')); result = 'Contacto verificado: ' + peer; item['tab'] = 'contacts'
                return self.show(item, result, safety=safety)
            except Exception as exc:
                item = self.active()
                if item and isinstance(exc, LocalStateWriteFailed):
                    self.invalidate_session(item)
                    return self.output(200, login_screen(token, user_error(exc)), cookie='session=; Max-Age=0; HttpOnly; SameSite=Strict; Path=/')
                if item: return self.show(item, user_error(exc))
                return self.output(400, login_screen(token, 'No se pudo completar la solicitud.'))
    server = HTTPServer(('127.0.0.1', args.port), Handler)
    print(f'Local interface running at http://{expected_host}', flush=True)
    server.serve_forever()

if __name__ == '__main__':
    main()
