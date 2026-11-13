"""Pruebas del modo de intercepción local y de la integridad del mensaje."""
import os
import tempfile
import time
import unittest
from securechat.infrastructure.server_adapters import SqliteRepository
from securechat.infrastructure import crypto

class ControlledInterceptionTest(unittest.TestCase):
    def test_targeted_single_delivery_is_modified_without_changing_stored_original(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = SqliteRepository(os.path.join(directory, 'db.sqlite'))
            alice, bob = crypto.Identity.generate('alice'), crypto.Identity.generate('bobby')
            sender, header = crypto.initiate(alice, bob.bundle())
            receiver = crypto.accept(bob, alice.bundle(), header)
            message = crypto.encrypt(sender, 'contenido de prueba')
            repo.arm_interception('alice', 'bobby', time.time())
            repo.enqueue('bobby', 'alice', {'header': header, 'message': message})
            altered = repo.inbox('bobby')[0]['envelope']['message']
            self.assertNotEqual(altered['ciphertext'], message['ciphertext'])
            self.assertEqual(repo.inspect_messages()[0]['envelope']['message'], message)
            with self.assertRaises(crypto.InvalidTag): crypto.decrypt(receiver, altered)
            self.assertEqual(crypto.decrypt(receiver, repo.inbox('bobby')[0]['envelope']['message']), 'contenido de prueba')
            self.assertEqual(repo.interception_status(time.time())['status'], 'intercepted')

    def test_queued_before_arming_and_unrelated_users_are_not_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = SqliteRepository(os.path.join(directory, 'db.sqlite'))
            raw = crypto.b64(b'a' * 20)
            envelope = {'message': {'ciphertext': raw}}
            repo.enqueue('bobby', 'alice', envelope)
            repo.arm_interception('alice', 'bobby', time.time())
            repo.enqueue('bobby', 'carol', envelope)
            self.assertEqual([x['envelope']['message']['ciphertext'] for x in repo.inbox('bobby')], [raw, raw])
            self.assertEqual(repo.interception_status(time.time())['status'], 'armed')

    def test_a_pending_message_can_be_chosen_without_naming_the_users(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = SqliteRepository(os.path.join(directory, 'db.sqlite'))
            raw = crypto.b64(b'a' * 20)
            other = crypto.b64(b'b' * 20)
            chosen = repo.enqueue('bobby', 'alice', {'message': {'ciphertext': raw}})
            repo.enqueue('bobby', 'carol', {'message': {'ciphertext': other}})
            repo.arm_pending_message(chosen, time.time())
            delivered = repo.inbox('bobby')
            self.assertNotEqual(delivered[0]['envelope']['message']['ciphertext'], raw)
            self.assertEqual(delivered[1]['envelope']['message']['ciphertext'], other)
            stored = next(row for row in repo.inspect_messages() if row['id'] == chosen)
            self.assertEqual(stored['envelope']['message']['ciphertext'], raw)
            status = repo.interception_status(time.time())
            self.assertEqual(status['status'], 'intercepted')
            self.assertEqual(status['sender'], 'alice')
            self.assertEqual(status['recipient'], 'bobby')

    def test_does_not_affect_other_sender_or_recipient_and_expires(self):
        with tempfile.TemporaryDirectory() as directory:
            repo = SqliteRepository(os.path.join(directory, 'db.sqlite'))
            repo.arm_interception('alice', 'bobby', time.time() - 300)
            self.assertEqual(repo.interception_status(time.time())['status'], 'expired')
            repo.cancel_interception()
            self.assertEqual(repo.interception_status(time.time())['status'], 'inactive')

class UserAlertTest(unittest.TestCase):
    def test_invalid_tag_has_clear_error(self):
        from securechat.ui import user_error
        self.assertIn('alterado', user_error(crypto.InvalidTag()))
        self.assertIn('rechazado', user_error(crypto.InvalidTag()))

class AdminInterceptionViewTest(unittest.TestCase):
    def test_operator_panel_has_arming_controls(self):
        import http.cookiejar, re, threading, urllib.parse, urllib.request
        from http.server import HTTPServer
        from securechat.admin import make_admin_handler
        with tempfile.TemporaryDirectory() as directory:
            dbpath=os.path.join(directory,'db.sqlite'); repo=SqliteRepository(dbpath)
            repo.create_user('alice','hash',{}); repo.create_user('bobby','hash',{})
            server=HTTPServer(('127.0.0.1',0), make_admin_handler(dbpath,'password-administrator'))
            thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
            try:
                url=f'http://127.0.0.1:{server.server_port}/'
                client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                page=client.open(url).read().decode(); token=re.search(r'name="csrf" value="([^"]+)"',page).group(1)
                def post(**data):
                    data['csrf']=token
                    return client.open(urllib.request.Request(url,data=urllib.parse.urlencode(data).encode(),headers={'Origin':url.rstrip('/')})).read().decode()
                page=post(action='login',password='password-administrator')
                message_id = repo.enqueue('bobby', 'alice', {'message': {'ciphertext': crypto.b64(b'a' * 20)}})
                page=post(action='login',password='password-administrator')
                self.assertIn('alice → bobby', page)
                self.assertIn('value="arm_pending"',page)
                page=post(action='arm_pending',message_id=str(message_id))
                self.assertIn('Intercepción activada para ese mensaje pendiente.',page)
                self.assertEqual(repo.interception_status(time.time())['target_id'], message_id)
                post(action='cancel_interception')
                self.assertEqual(repo.interception_status(time.time())['status'],'inactive')
            finally:
                server.shutdown();thread.join();server.server_close()

class LiveDeliveryIntegrationTest(unittest.TestCase):
    def test_connected_users_reject_modified_copy_then_receive_original(self):
        import http.cookiejar, re, socket, subprocess, sys, urllib.parse, urllib.request
        with tempfile.TemporaryDirectory() as directory:
            def free_port():
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1',0)); return sock.getsockname()[1]
            sp,up=free_port(),free_port(); db=os.path.join(directory,'server.sqlite')
            server=subprocess.Popen([sys.executable,'-m','securechat.server','--port',str(sp),'--database',db],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            ui=None
            try:
                server.stdout.readline()
                ui=subprocess.Popen([sys.executable,'-m','securechat.ui','--port',str(up),'--server-port',str(sp),'--database',db,'--home',os.path.join(directory,'users')],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
                ui.stdout.readline(); base=f'http://127.0.0.1:{up}'
                def browser():
                    op=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                    page=op.open(base).read().decode(); csrf=re.search(r'name="csrf" value="([^"]+)"',page).group(1)
                    def post(**values):
                        values['csrf']=csrf
                        return op.open(urllib.request.Request(base+'/',data=urllib.parse.urlencode(values).encode(),headers={'Origin':base})).read().decode()
                    post.get = lambda: op.open(base).read().decode()
                    return post
                a,b=browser(),browser()
                for post,name in ((a,'alice'),(b,'bobby')):
                    self.assertIn('Cerrar sesión',post(action='register',user=name,password='demo-password-123'))
                a_hash=re.search(r'[a-f0-9]{64}',a(action='safety',peer='bobby')).group()
                b_hash=re.search(r'[a-f0-9]{64}',b(action='safety',peer='alice')).group()
                self.assertEqual(a_hash,b_hash)
                a(action='trust',peer='bobby',safety=a_hash);b(action='trust',peer='alice',safety=b_hash)
                b(action='select', peer='alice')
                repo=SqliteRepository(db); repo.arm_interception('alice','bobby',time.time())
                a(action='send',peer='bobby',message='Prueba de entrega real')
                first=b(action='heartbeat')
                self.assertIn('mensaje alterado',first)
                self.assertNotIn('Prueba de entrega real',first)
                self.assertIn('mensaje alterado', b.get())
                self.assertEqual(len(repo.inspect_messages()),1)
                second=b(action='heartbeat')
                self.assertIn('Prueba de entrega real',second)
                self.assertIn('mensaje alterado',second)
                self.assertEqual(len(repo.inspect_messages()),0)
                import json
                alert_id = json.loads(second)['alert_id']
                self.assertNotIn('mensaje alterado', a.get())
                a(action='send',peer='bobby',message='Otro mensaje')
                with repo.connection() as connection:
                    message_id, encoded = connection.execute('SELECT id, envelope FROM messages').fetchone()
                    envelope = json.loads(encoded)
                    envelope['message']['nonce'] = crypto.b64(b'bad')
                    connection.execute('UPDATE messages SET envelope=? WHERE id=?', (json.dumps(envelope), message_id))
                self.assertIn('mensaje alterado', b(action='heartbeat'))
                next_page = b(action='dismiss_security_alert', alert_id=alert_id)
                self.assertNotIn('mensaje alterado', next_page)
                self.assertIn('mensaje recibido no es válido', next_page)
                next_alert = json.loads(b(action='heartbeat'))
                self.assertIn('mensaje recibido no es válido', next_alert['alert'])
                b(action='dismiss_security_alert', alert_id=next_alert['alert_id'])
                # El sobre defectuoso permanece y la siguiente recepción vuelve a advertirlo.
                self.assertNotIn('mensaje alterado', b(action='heartbeat'))
                self.assertEqual(repo.interception_status(time.time())['status'],'intercepted')
            finally:
                for proc in (ui,server):
                    if proc: proc.terminate();proc.wait(timeout=5);proc.stdout.close();proc.stderr.close()
