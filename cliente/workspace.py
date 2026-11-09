"""Plantillas HTML del acceso, la conversación, los contactos y el laboratorio."""
import json
import re
from securechat.presentation import render_result
from securechat.theme import STYLE, e






def page(body, title='Mensajería segura', heartbeat=False):
    return f'''<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{e(title)}</title><style>{STYLE}</style></head><body>{body}<script src="/ui.js" defer></script>{'<meta name="heartbeat" content="on">' if heartbeat else ''}</body></html>'''


def password_control():
    return '''<div class="password"><input id="password" name="password" type="password" required minlength="12" autocomplete="current-password"><button id="password-toggle" type="button" class="eye" aria-label="Mostrar contraseña" aria-pressed="false"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/></svg></button></div>'''


def login_screen(csrf, message=''):
    notice = f'<div class="notice" role="status">{e(message)}</div>' if message else ''
    return page(f'''<header class="top"><div class="brand">◈ &nbsp; Mensajería segura <div class="sub">Proyecto de criptología</div></div></header><main class="login"><p class="muted">BIENVENIDO</p><h1>Tu espacio seguro</h1><p class="muted">Ingresa o crea tu cuenta para comenzar.</p>{notice}<form method="post"><input type="hidden" name="csrf" value="{e(csrf)}"><label class="field" for="user">Usuario</label><input id="user" name="user" required autocomplete="username"><label class="field" for="password">Contraseña</label>{password_control()}<div class="login-actions"><button class="primary" name="action" value="login">Iniciar sesión</button><button class="secondary" name="action" value="register">Crear cuenta</button></div></form></main>''')


def form(csrf, action, label, extra='', css='secondary'):
    return f'<form method="post"><input type="hidden" name="csrf" value="{e(csrf)}">{extra}<button class="{css}" name="action" value="{e(action)}">{e(label)}</button></form>'


def workspace_screen(csrf, user, contacts, history, peer, message, tab, encrypted, safety, security_alert=None, alert_revision=0, dr_mode='off', unread=None, groups=None):
    def nav(name, label):
        return form(csrf, 'view_' + name, label, css='active' if tab == name else '')
    top = f'''<header class="top"><div class="brand">◈ &nbsp; Mensajería segura<div class="sub">Proyecto de criptología</div></div><div class="top-actions"><span>{e(user)}</span>{form(csrf, 'logout', 'Cerrar sesión')}</div></header><main class="shell"><nav class="nav">{nav('chat','Conversaciones')}{nav('contacts','Contactos')}{nav('groups','Grupos')}</nav>'''
    copy_button = ''
    if tab == 'contacts' and re.fullmatch(r'[0-9a-f]{64}', safety or ''):
        copy_button = f'<div><button type="button" class="secondary" id="copy-fingerprint" data-fingerprint="{e(safety)}">Copiar huella</button> <span id="copy-status" aria-live="polite"></span></div>'
    notice = f'<div class="notice" role="status">{render_result(message)}{copy_button}</div>' if message else ''
    unread = unread or {}
    groups = groups or []
    def unread_mark(name):
        count = int(unread.get(name) or 0)
        hidden = '' if count else ' hidden'
        return f'<span class="unread" data-unread-user="{e(name)}" style="margin-left:8px;background:#176c5b;color:white;border-radius:99px;padding:0 7px;font-size:12px"{hidden}>{count if count else ""}</span>'
    contact_lookup = {c['name']: c for c in contacts}
    if tab == 'chat':
        talked = {row['peer'] for row in history}
        items = []
        known_count = 0
        for group in groups:
            token = 'g:' + group['id']
            known_count += 1
            selected = 'selected' if token == peer else ''
            items.append(f'<form class="contact-row" method="post" data-contact="{e(group["name"])}" data-known="1"><input type="hidden" name="csrf" value="{e(csrf)}"><input type="hidden" name="peer" value="{e(token)}"><button class="contact {selected}" name="action" value="select"><span class="avatar">G</span><span class="contact-info"><strong>{e(group["name"])}</strong><span class="muted">Grupo</span></span></button></form>')
        for contact in contacts:
            name = contact['name']; status = 'En línea' if contact['online'] else 'Sin conexión'; klass = 'online' if contact['online'] else 'offline'
            known = name in talked or int(unread.get(name) or 0) > 0 or name == peer
            if known: known_count += 1
            extra = f'<input type="hidden" name="peer" value="{e(name)}">'
            hidden = '' if known else ' hidden'
            items.append(f'<form class="contact-row" method="post" data-contact="{e(name)}" data-known="{1 if known else 0}"{hidden}><input type="hidden" name="csrf" value="{e(csrf)}">{extra}<button class="contact {"selected" if name == peer else ""}" name="action" value="select"><span class="avatar">{e(name[:1].upper())}</span><span class="contact-info"><strong>{e(name)}</strong>{unread_mark(name)}<span class="{klass}" data-online-user="{e(name)}">{status}</span></span></button></form>')
        def bubble(row):
            css = 'mine' if row['direction'] == 'out' else ''
            if row.get('kind') == 'attachment-v1':
                extra = f'<input type="hidden" name="attachment_index" value="{e(row["index"])}">'
                content = f'<span>Archivo: {e(row["name"])}</span>' + form(csrf, 'save_attachment', 'Guardar archivo', extra)
            else:
                who = f'<span class="who">{e(row["author"])}</span>' if row.get('author') else ''
                content = who + e(row['text'])
            return f'<div class="bubble {css}">{content}</div>'
        bubbles = ''.join(bubble(row) for row in history if row['peer'] == peer)
        open_group = next((group for group in groups if 'g:' + group['id'] == peer), None)
        if isinstance(peer, str) and peer.startswith('g:'):
            if open_group:
                head = f'<h2>{e(open_group["name"])}</h2><span class="muted">Grupo · {e(", ".join(open_group["members"]))}</span>'
                composer = f'<form class="composer" method="post"><input type="hidden" name="csrf" value="{e(csrf)}"><input type="hidden" name="group_id" value="{e(open_group["id"])}"><input name="message" placeholder="Escribe un mensaje" required maxlength="2000"><button class="primary" name="action" value="send_group">Enviar</button></form>'
            else:
                head = '<h2>Grupo</h2><span class="muted">Este grupo no está en este equipo.</span>'
                composer = ''
        elif peer:
            chosen = contact_lookup.get(peer, {}); status = 'En línea' if chosen.get('online') else 'Sin conexión'
            head = f'<h2>{e(peer)}</h2><span class="muted" data-online-user="{e(peer)}">{status}</span>' + ('<div class="alert">La clave de identidad cambió. Compara nuevamente la huella.</div>' if chosen.get('changed') else '')
            tip = ''
            actions = ''
            if dr_mode == 'available':
                tip = 'Enviar sigue en la sesión clásica. Double Ratchet cambia la clave en cada turno. El acuerdo híbrido solo se puede usar antes de abrir una sesión.'
                actions = '<button class="secondary" name="action" value="send_dr">Enviar con Double Ratchet</button><button class="secondary" name="action" value="send_hybrid">Enviar con acuerdo híbrido</button>'
            elif dr_mode == 'migrate':
                tip = 'Pasar a Double Ratchet conserva los mensajes ya enviados. Cada persona cambia cuando ella pulsa el botón.'
                actions = '<button class="secondary" name="action" value="send_dr">Pasar a Double Ratchet</button>'
            elif dr_mode == 'active':
                tip = 'Esta conversación usa Double Ratchet. Los mensajes anteriores se conservan. Si ambos lo inician a la vez, se conservan los dos inicios y los siguientes usan la sesión común.'
            info = f'<span class="tip"><button type="button" class="secondary tip-button" aria-label="Ayuda de la conversación">?</button><span class="tip-box" role="tooltip">{e(tip)}</span></span>' if tip else ''
            extra_actions = f'<div class="composer-actions">{actions}</div>' if actions else ''
            composer = f'<form class="composer" method="post"><input type="hidden" name="csrf" value="{e(csrf)}"><input type="hidden" name="peer" value="{e(peer)}"><input name="message" placeholder="Escribe un mensaje" required maxlength="2000"><button class="primary" name="action" value="send">Enviar</button>{info}{extra_actions}</form>'
            composer += f'''<form class="composer" id="attachment-form" method="post"><input type="hidden" name="csrf" value="{e(csrf)}"><input type="hidden" name="peer" value="{e(peer)}"><input type="hidden" name="action" value="send_attachment"><input type="hidden" name="attachment_name"><input type="hidden" name="attachment_data"><label for="attachment-file">Adjuntar archivo (máximo 24 KiB)</label><input id="attachment-file" type="file" required><button class="secondary" type="submit">Enviar archivo</button><span id="attachment-status" role="status"></span></form>'''
        else:
            head = '<h2>Tu conversación</h2><span class="muted">Selecciona un contacto para comenzar</span>'; composer = ''
        empty_list = '' if known_count else '<p class="muted" id="no-chats">Aún no tienes conversaciones. Busca a una persona para empezar.</p>'
        content = f'<div class="chat"><aside class="sidebar"><h2>Conversaciones</h2><input id="contact-search" type="search" placeholder="Buscar persona o grupo" autocomplete="off">{empty_list}{"".join(items)}</aside><section class="conversation"><header class="conversation-head">{head}</header><div class="messages" id="messages" data-peer="{e(peer)}">{bubbles or "<div class=empty>Los mensajes aparecerán aquí.</div>"}</div>{composer}</section></div>'
    elif tab == 'contacts':
        rows=[]
        for c in contacts:
            name = c['name']; verified = 'Verificado' if c.get('verified') else 'Sin verificar'
            extra=f'<input type="hidden" name="peer" value="{e(name)}">'
            rows.append(('<div class="alert">La clave de identidad cambió. Compara nuevamente la huella.</div>' if c.get('changed') else '') + f'<div class="item"><div class="row"><span class="avatar">{e(name[:1].upper())}</span><strong>{e(name)}</strong>{unread_mark(name)}<span class="status">{verified}</span><span class="muted">{"En línea" if c["online"] else "Sin conexión"}</span></div><div class="row">{form(csrf,"safety","Mostrar huella",extra)}<form method="post"><input type="hidden" name="csrf" value="{e(csrf)}">{extra}<div class="row"><input name="safety" placeholder="Huella confirmada" required><button class="secondary" name="action" value="trust">Verificar</button></div></form></div></div>')
        content=f'<section class="panel"><h2>Contactos</h2><p class="muted">Compara la huella por un canal independiente antes de verificar.</p>{"".join(rows) or "Aún no hay otros usuarios."}</section>'
    elif tab == 'groups':
        verified = [c['name'] for c in contacts if c.get('verified') and not c.get('changed')]
        existing = ''.join(f'<div class="item"><strong>{e(group["name"])}</strong><span class="muted">{e(", ".join(group["members"]))}</span>{form(csrf, "select", "Abrir", f"""<input type="hidden" name="peer" value="g:{e(group["id"])}">""")}</div>' for group in groups)
        content = f'''<section class="panel"><h2>Grupos</h2><p class="muted">Solo aparecen contactos con la huella verificada. El grupo se ve en Conversaciones, y cada mensaje indica quién lo envió. La clave de cada emisor sigue yendo cifrada de a dos: el servidor no tiene un buzón de grupo.</p><form method="post"><input type="hidden" name="csrf" value="{e(csrf)}"><div class="stack"><input name="group_name" placeholder="Nombre del grupo" required maxlength="40"><input id="member-search" placeholder="Buscar miembro verificado" autocomplete="off"><div id="member-choices" class="member-choices" data-names="{e(",".join(verified))}"></div><div id="member-picked" class="member-picked"></div><p class="muted" id="member-empty" hidden>Verifica la huella de un contacto antes de añadirlo.</p><input type="hidden" name="group_members" id="group-members" required><input name="message" placeholder="Primer mensaje" required maxlength="2000"><button class="primary" name="action" value="create_group">Crear grupo y enviar</button></div></form>{existing}</section>'''
    elif tab == 'server':
        rows=''.join(f'<div class="item"><strong>{e(row["sender"])} → {e(row["recipient"])}</strong><p class="muted">Mensaje pendiente #{e(row["id"])}</p><div class="cipher">{e(str(row["envelope"].get("message", {}).get("ciphertext", "")))}</div></div>' for row in encrypted)
        content=f'<section class="panel"><h2>Servidor local</h2><p class="muted">Mensajes cifrados pendientes de entrega</p>{rows or "No hay mensajes pendientes."}</section>'
    else:
        buttons=''.join(form(csrf, 'lab_'+scenario, label, '<input name="demo_text" value="Mensaje de prueba" maxlength="500">') for scenario,label in [('prekey','Sustituir preclave'),('tamper','Modificar mensaje'),('replay','Repetir mensaje')])
        content=f'<section class="panel"><h2>Pruebas de seguridad</h2><p class="muted">Elige un escenario para ver el resultado.</p><div class="stack">{buttons}</div></section>'
    hidden = '' if security_alert else ' hidden'
    extra = f'<input type="hidden" id="automatic-alert-id" name="alert_id" value="{e(security_alert["id"] if security_alert else "")}">'
    alert = f'<div id="automatic-alert" class="alert" role="alert" data-revision="{e(alert_revision)}"{hidden}><span id="automatic-alert-message">{e(security_alert["text"] if security_alert else "")}</span>{form(csrf, "dismiss_security_alert", "Entendido", extra)}</div>'
    return page(top+notice+alert+content+'</main>', heartbeat=True)
