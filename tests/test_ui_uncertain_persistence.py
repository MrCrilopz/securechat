"""Session invalidation after a post-replacement write failure."""
from contextlib import closing
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

class UiUncertainPersistenceTest(unittest.TestCase):
    def test_heartbeat_closes_session_after_uncertain_commit_and_reloads(self):
        with tempfile.TemporaryDirectory() as root:
            def port():
                with socket.socket() as s:
                    s.bind(('127.0.0.1', 0)); return s.getsockname()[1]
            sp, up = port(), port(); dbpath = os.path.join(root, 'server.sqlite'); marker = os.path.join(root, 'fail')
            server = subprocess.Popen([sys.executable, '-m', 'securechat.server', '--port', str(sp), '--database', dbpath], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            bootstrap = os.path.join(root, 'bootstrap.py')
            with open(bootstrap, 'w') as f:
                f.write('''import os, sys\nfrom securechat.infrastructure import local_store\nimport securechat.ui as ui\noriginal = local_store.save\ndef uncertain(path, password, state):\n    original(path, password, state)\n    if path.endswith("bobby.json") and os.path.exists(os.environ["FAIL_MARKER"]):\n        raise OSError("simulated after replace")\nlocal_store.save = uncertain\nsys.argv = ["securechat.ui", "--port", os.environ["UI_PORT"], "--server-port", os.environ["SERVER_PORT"], "--database", os.environ["DB_PATH"], "--home", os.environ["HOME_PATH"]]\nui.main()\n''')
            ui = None
            try:
                server.stdout.readline()
                env = dict(os.environ, PYTHONPATH=os.getcwd(), FAIL_MARKER=marker, UI_PORT=str(up), SERVER_PORT=str(sp), DB_PATH=dbpath, HOME_PATH=os.path.join(root, 'clients'))
                ui = subprocess.Popen([sys.executable, bootstrap], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
                self.assertIn(b'Local interface running', ui.stdout.readline()); base=f'http://127.0.0.1:{up}'
                def browser():
                    op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                    page=op.open(base).read().decode(); csrf=re.search(r'name="csrf" value="([^"]+)"',page).group(1)
                    def post(**data):
                        data['csrf']=csrf
                        return op.open(urllib.request.Request(base+'/',data=urllib.parse.urlencode(data).encode(),headers={'Origin':base})).read().decode()
                    return post
                a,b=browser(),browser()
                a(action='register',user='alice',password='example-password-123'); b(action='register',user='bobby',password='example-password-123')
                fa=re.search(r'[a-f0-9]{64}',a(action='safety',peer='bobby')).group(); fb=re.search(r'[a-f0-9]{64}',b(action='safety',peer='alice')).group()
                a(action='trust',peer='bobby',safety=fa); b(action='trust',peer='alice',safety=fb)
                a(action='send',peer='bobby',message='pending-message')
                with open(marker,'w') as f: f.write('fail after save')
                failed=b(action='select',peer='alice')
                self.assertIn('sesión', failed.lower())
                self.assertNotIn('pending-message', failed)
                with closing(sqlite3.connect(dbpath)) as db: self.assertEqual(db.execute('select count(*) from messages').fetchone()[0],1)
                os.unlink(marker)
                self.assertIn('Cerrar sesión',b(action='login',user='bobby',password='example-password-123'))
                opened=b(action='select',peer='alice')
                self.assertIn('pending-message', opened)
                with closing(sqlite3.connect(dbpath)) as db: self.assertEqual(db.execute('select count(*) from messages').fetchone()[0],0)
                with open(marker,'w') as f: f.write('fail after save')
                failed_send = b(action='send', peer='alice', message='response-after-uncertain-write')
                self.assertIn('inicia sesión nuevamente', failed_send.lower())
                self.assertNotIn('response-after-uncertain-write', failed_send)
                with closing(sqlite3.connect(dbpath)) as db: self.assertEqual(db.execute('select count(*) from messages').fetchone()[0],0)
                os.unlink(marker)
                self.assertIn('Cerrar sesión', b(action='login', user='bobby', password='example-password-123'))
                b(action='heartbeat')
                self.assertIn('response-after-uncertain-write', a(action='heartbeat'))
            finally:
                for proc in (ui,server):
                    if proc: proc.terminate();proc.wait(timeout=5);proc.stdout.close();proc.stderr.close()
