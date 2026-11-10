"""Flujo HTTP real de un adjunto entre dos sesiones locales temporales."""
import base64
import contextlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
import urllib.request
from servidor.infrastructure.server_adapters import SqliteRepository


class AttachmentUiIntegrationTest(unittest.TestCase):
    def test_users_send_receive_and_save_attachment(self):
        with tempfile.TemporaryDirectory() as directory:
            def free_port():
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0)); return sock.getsockname()[1]
            sp, up = free_port(), free_port()
            database = os.path.join(directory, 'server.db')
            home = os.path.join(directory, 'clients')
            server = subprocess.Popen([sys.executable, '-m', 'servidor.server', '--port', str(sp),
                                       '--database', database], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ui = None
            try:
                server.stdout.readline()
                ui = subprocess.Popen([sys.executable, '-m', 'cliente.ui', '--port', str(up),
                                       '--server-port', str(sp), '--database', database, '--home', home],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                ui.stdout.readline()
                base = f'http://127.0.0.1:{up}'
                def browser():
                    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                    page = op.open(base).read().decode()
                    token = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
                    def post(**data):
                        data['csrf'] = token
                        request = urllib.request.Request(base + '/', data=urllib.parse.urlencode(data).encode(),
                                                         headers={'Origin': base})
                        return op.open(request).read().decode()
                    return post
                alice, bob = browser(), browser()
                for post, name in ((alice, 'alice'), (bob, 'bobby')):
                    self.assertIn('Cerrar sesión', post(action='register', user=name, password='demo-password-123'))
                fingerprint = re.search(r'[a-f0-9]{64}', alice(action='safety', peer='bobby')).group()
                self.assertIn('Contacto verificado', alice(action='trust', peer='bobby', safety=fingerprint))
                self.assertIn('Contacto verificado', bob(action='trust', peer='alice', safety=fingerprint))
                chat = alice(action='select', peer='bobby')
                self.assertIn('attachment-form', chat)
                content = b'contenido adjunto privado\x00'
                upload = base64.urlsafe_b64encode(content).decode()
                sent = alice(action='send_attachment', peer='bobby', attachment_name='secreto.txt', attachment_data=upload)
                self.assertIn('secreto.txt', sent)
                queued = repr(SqliteRepository(database).inspect_messages())
                self.assertNotIn('secreto.txt', queued)
                self.assertNotIn('contenido adjunto privado', queued)
                with contextlib.closing(sqlite3.connect(database)) as db:
                    message_id, original = db.execute('SELECT id, envelope FROM messages').fetchone()
                    altered = json.loads(original)
                    ciphertext = altered['message']['ciphertext']
                    altered['message']['ciphertext'] = ('A' if ciphertext[0] != 'A' else 'B') + ciphertext[1:]
                    db.execute('UPDATE messages SET envelope=? WHERE id=?', (json.dumps(altered), message_id))
                    db.commit()
                with contextlib.closing(sqlite3.connect(database)) as db:
                    changed = json.loads(original)
                    changed['message']['content_format'] = 'formato-desconocido'
                    db.execute('UPDATE messages SET envelope=? WHERE id=?', (json.dumps(changed), message_id))
                    db.commit()
                bob(action='select', peer='alice')
                unsupported = json.loads(bob(action='heartbeat'))
                self.assertIn('formato', unsupported['alert'].lower())
                self.assertEqual(unsupported['history'], [])
                self.assertEqual(len(SqliteRepository(database).inspect_messages()), 1)
                with contextlib.closing(sqlite3.connect(database)) as db:
                    db.execute('UPDATE messages SET envelope=? WHERE id=?', (json.dumps(altered), message_id))
                    db.commit()
                rejected = json.loads(bob(action='heartbeat'))
                self.assertIn('alterado', rejected['alert'])
                self.assertEqual(rejected['history'], [])
                self.assertEqual(len(SqliteRepository(database).inspect_messages()), 1)
                with contextlib.closing(sqlite3.connect(database)) as db:
                    db.execute('UPDATE messages SET envelope=? WHERE id=?', (original, message_id))
                    db.commit()
                heartbeat = json.loads(bob(action='heartbeat'))
                self.assertEqual(heartbeat['history'][0]['kind'], 'attachment-v1')
                self.assertEqual(heartbeat['history'][0]['name'], 'secreto.txt')
                self.assertNotIn('key', heartbeat['history'][0])
                chat = bob(action='select', peer='alice')
                self.assertIn('secreto.txt', chat)
                self.assertIn('Guardar archivo', chat)
                saved = bob(action='save_attachment', attachment_index='0')
                self.assertIn('Archivo guardado', saved)
                path = Path(home) / 'descargas' / 'bobby' / 'secreto.txt'
                self.assertEqual(path.read_bytes(), content)
                bob(action='save_attachment', attachment_index='0')
                self.assertEqual((path.parent / 'secreto (1).txt').read_bytes(), content)
                max_content = bytes(range(256)) * 96
                encoded = base64.urlsafe_b64encode(max_content).decode()
                self.assertIn('maximo.bin', alice(action='send_attachment', peer='bobby', attachment_name='maximo.bin', attachment_data=encoded))
                self.assertEqual(json.loads(bob(action='heartbeat'))['history'][1]['name'], 'maximo.bin')
                bob(action='save_attachment', attachment_index='1')
                self.assertEqual((path.parent / 'maximo.bin').read_bytes(), max_content)
                oversized = base64.urlsafe_b64encode(max_content + b'x').decode()
                failed = alice(action='send_attachment', peer='bobby', attachment_name='exceso.bin', attachment_data=oversized)
                self.assertIn('supera el tamaño', failed)
                self.assertEqual(SqliteRepository(database).inspect_messages(), [])
            finally:
                for process in (ui, server):
                    if process:
                        process.terminate(); process.wait(timeout=5)
                        process.stdout.close(); process.stderr.close()
