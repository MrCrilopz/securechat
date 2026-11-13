"""Ataques reproducibles contra servicios HTTP y SQLite temporales."""
import http.cookiejar
import json
import os
import re
import socket
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import urllib.parse
import urllib.request
from contextlib import closing

from securechat.infrastructure import crypto


class RealDeliveryAttackTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        def port():
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                return sock.getsockname()[1]
        sp, up = port(), port()
        self.database = os.path.join(self.temp.name, 'server.sqlite')
        self.server = subprocess.Popen([sys.executable, '-m', 'servidor.server', '--port', str(sp), '--database', self.database], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.stop, self.server)
        self.server.stdout.readline()
        self.ui = subprocess.Popen([sys.executable, '-m', 'cliente.ui', '--port', str(up), '--server-port', str(sp), '--database', self.database, '--home', os.path.join(self.temp.name, 'clients')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(self.stop, self.ui)
        self.ui.stdout.readline()
        self.base = f'http://127.0.0.1:{up}'
        self.alice, self.bob = self.browser(), self.browser()
        self.alice(action='register', user='alice', password='demo-password-alice')
        self.bob(action='register', user='bobby', password='demo-password-bobby')
        a = re.search(r'[a-f0-9]{64}', self.alice(action='safety', peer='bobby')).group()
        b = re.search(r'[a-f0-9]{64}', self.bob(action='safety', peer='alice')).group()
        self.assertEqual(a, b)
        self.alice(action='trust', peer='bobby', safety=a)
        self.bob(action='trust', peer='alice', safety=b)

    @staticmethod
    def stop(process):
        process.terminate()
        process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()

    def browser(self):
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        csrf = re.search(r'name="csrf" value="([^"]+)"', opener.open(self.base).read().decode()).group(1)
        def post(**fields):
            fields['csrf'] = csrf
            request = urllib.request.Request(self.base + '/', data=urllib.parse.urlencode(fields).encode(), headers={'Origin': self.base})
            return opener.open(request).read().decode()
        return post

    def test_signed_identity_substitution_is_alerted_and_never_acknowledged(self):
        self.alice(action='send', peer='bobby', message='texto de prueba')
        impostor = crypto.Identity.generate('alice').bundle()
        with closing(sqlite3.connect(self.database)) as db, db:
            old_bundle = db.execute('SELECT bundle FROM users WHERE name=?', ('alice',)).fetchone()[0]
            db.execute('UPDATE users SET bundle=? WHERE name=?', (json.dumps(impostor), 'alice'))
        self.bob(action='select', peer='alice')
        response = json.loads(self.bob(action='heartbeat'))
        self.assertIn('identidad', response['alert'].lower())
        self.assertNotIn('texto de prueba', str(response.get('history', [])))
        with closing(sqlite3.connect(self.database)) as db, db:
            self.assertEqual(db.execute('SELECT count(*) FROM messages').fetchone()[0], 1)
            db.execute('UPDATE users SET bundle=? WHERE name=?', (old_bundle, 'alice'))
        response = json.loads(self.bob(action='heartbeat'))
        self.assertEqual([row['text'] for row in response['history']], ['texto de prueba'])

    def test_exact_replay_is_not_delivered_twice_after_ack(self):
        self.alice(action='send', peer='bobby', message='entregar una vez')
        with closing(sqlite3.connect(self.database)) as db:
            saved_envelope = db.execute('SELECT envelope FROM messages').fetchone()[0]
        self.bob(action='select', peer='alice')
        self.assertEqual([row['text'] for row in json.loads(self.bob(action='heartbeat'))['history']], ['entregar una vez'])
        with closing(sqlite3.connect(self.database)) as db, db:
            db.execute('INSERT INTO messages (recipient, sender, envelope) VALUES (?, ?, ?)', ('bobby', 'alice', saved_envelope))
        response = json.loads(self.bob(action='heartbeat'))
        self.assertEqual([row['text'] for row in response['history']], ['entregar una vez'])
        with closing(sqlite3.connect(self.database)) as db:
            self.assertEqual(db.execute('SELECT count(*) FROM messages').fetchone()[0], 0)


if __name__ == '__main__':
    unittest.main()
