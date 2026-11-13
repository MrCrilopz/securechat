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
from contextlib import closing
import urllib.parse
import urllib.request


class PrekeyAlertTest(unittest.TestCase):
    def test_substituted_prekey_is_visible_and_message_remains_queued(self):
        with tempfile.TemporaryDirectory() as directory:
            def port():
                with socket.socket() as s:
                    s.bind(('127.0.0.1', 0)); return s.getsockname()[1]
            sp, up = port(), port(); dbpath = os.path.join(directory, 'server.sqlite')
            server = subprocess.Popen([sys.executable, '-m', 'servidor.server', '--port', str(sp), '--database', dbpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            ui = None
            try:
                server.stdout.readline()
                ui = subprocess.Popen([sys.executable, '-m', 'cliente.ui', '--port', str(up), '--server-port', str(sp), '--database', dbpath, '--home', os.path.join(directory, 'clients')], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                ui.stdout.readline(); base = f'http://127.0.0.1:{up}'
                def browser():
                    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                    csrf = re.search(r'name="csrf" value="([^"]+)"', op.open(base).read().decode()).group(1)
                    def post(**fields):
                        fields['csrf'] = csrf
                        req = urllib.request.Request(base + '/', data=urllib.parse.urlencode(fields).encode(), headers={'Origin': base})
                        return op.open(req).read().decode()
                    return post
                a, b = browser(), browser()
                a(action='register', user='alice', password='test-password-alice')
                b(action='register', user='bobby', password='test-password-bobby')
                af = re.search(r'[a-f0-9]{64}', a(action='safety', peer='bobby')).group()
                bf = re.search(r'[a-f0-9]{64}', b(action='safety', peer='alice')).group()
                a(action='trust', peer='bobby', safety=af); b(action='trust', peer='alice', safety=bf)
                a(action='send', peer='bobby', message='mensaje legítimo')
                with closing(sqlite3.connect(dbpath)) as db, db:
                    original = db.execute('SELECT bundle FROM users WHERE name=?', ('alice',)).fetchone()[0]
                    bundle = json.loads(original)
                    bundle['prekey'] = bundle['agreement']
                    db.execute('UPDATE users SET bundle=? WHERE name=?', (json.dumps(bundle), 'alice'))
                b(action='select', peer='alice')
                reply = json.loads(b(action='heartbeat'))
                self.assertIn('firma', reply['alert'].lower())
                self.assertNotIn('mensaje legítimo', str(reply.get('history', [])))
                with closing(sqlite3.connect(dbpath)) as db, db:
                    self.assertEqual(db.execute('SELECT count(*) FROM messages').fetchone()[0], 1)
                    db.execute('UPDATE users SET bundle=? WHERE name=?', (original, 'alice'))
                self.assertEqual(json.loads(b(action='heartbeat'))['history'][0]['text'], 'mensaje legítimo')
            finally:
                for proc in (ui, server):
                    if proc: proc.terminate(); proc.wait(timeout=5); proc.stdout.close(); proc.stderr.close()


if __name__ == '__main__': unittest.main()
