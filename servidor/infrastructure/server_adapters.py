"""Adaptadores de SQLite, Argon2id y verificación de paquetes para el servidor local."""
import base64, json, os, sqlite3, time
from securechat.domain.errors import ReusedNonceCounter
from securechat.domain.models import username
from securechat.infrastructure.hashing import sha256
from contextlib import contextmanager
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.exceptions import InvalidKey
from securechat.infrastructure.crypto import verify_bundle
from securechat.infrastructure import crypto
from securechat.infrastructure.hybrid_handshake import verify_hybrid_prekey

class ArgonHasher:
    def hash(self, password):
        salt = os.urandom(16)
        digest = Argon2id(salt=salt, length=32, iterations=3, lanes=4, memory_cost=65536).derive(password.encode())
        return base64.b64encode(salt + digest).decode()
    def verify(self, encoded, password):
        raw = base64.b64decode(encoded)
        try:
            Argon2id(salt=raw[:16], length=32, iterations=3, lanes=4, memory_cost=65536).verify(password.encode(), raw[16:]); return True
        except InvalidKey: return False

class BundleVerifier:
    def verify(self, bundle): verify_bundle(bundle)
    def verify_hybrid(self, record, pinned_bundle): verify_hybrid_prekey(crypto, record, pinned_bundle)

def _digest(token):
    return sha256(token.encode()).hex()

class SqliteRepository:
    def __init__(self, path):
        self.path = path
        with self.connection() as db:
            db.executescript('''CREATE TABLE IF NOT EXISTS users (name TEXT PRIMARY KEY, password_hash TEXT NOT NULL, bundle TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS hybrid_prekeys (username TEXT PRIMARY KEY, suite TEXT NOT NULL, record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS tokens (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS presence (username TEXT PRIMARY KEY, last_seen REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, recipient TEXT NOT NULL, sender TEXT NOT NULL, envelope TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS send_counters (sender TEXT NOT NULL, recipient TEXT NOT NULL, session_id TEXT NOT NULL, issued INTEGER NOT NULL, open_counter INTEGER, stored_counter INTEGER, stored_hash TEXT, PRIMARY KEY (sender, recipient, session_id));
            CREATE TABLE IF NOT EXISTS dr_send_slots (sender TEXT NOT NULL, recipient TEXT NOT NULL, session_id TEXT NOT NULL, dh TEXT NOT NULL, counter INTEGER NOT NULL, stored_hash TEXT, PRIMARY KEY (sender, recipient, session_id, dh, counter));
            CREATE TABLE IF NOT EXISTS demo_interception (id INTEGER PRIMARY KEY CHECK(id=1), sender TEXT NOT NULL, recipient TEXT NOT NULL, expires REAL NOT NULL, status TEXT NOT NULL, message_id INTEGER, original TEXT, altered TEXT, after_id INTEGER NOT NULL DEFAULT 0, target_id INTEGER);
            CREATE TABLE IF NOT EXISTS group_mail (id INTEGER PRIMARY KEY AUTOINCREMENT, group_id TEXT NOT NULL, sender TEXT NOT NULL, key_id TEXT NOT NULL, counter INTEGER NOT NULL, envelope TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS group_mail_pending (mail_id INTEGER NOT NULL, username TEXT NOT NULL, PRIMARY KEY (mail_id, username));
            CREATE TABLE IF NOT EXISTS group_send_slots (sender TEXT NOT NULL, group_id TEXT NOT NULL, key_id TEXT NOT NULL, counter INTEGER NOT NULL, digest TEXT NOT NULL, PRIMARY KEY (sender, group_id, key_id, counter));''')
            columns = [row[1] for row in db.execute('PRAGMA table_info(demo_interception)')]
            if 'target_id' not in columns:
                db.execute('ALTER TABLE demo_interception ADD COLUMN target_id INTEGER')
    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        try:
            with db:
                yield db
        finally:
            db.close()
    def create_user(self, name, password_hash, bundle):
        with self.connection() as db: db.execute('INSERT INTO users VALUES (?, ?, ?)', (name, password_hash, json.dumps(bundle)))
    def user(self, name):
        with self.connection() as db: row = db.execute('SELECT password_hash, bundle FROM users WHERE name=?', (name,)).fetchone()
        return {'password_hash': row[0], 'bundle': json.loads(row[1])} if row else None
    def save_hybrid_prekey(self, name, record):
        encoded = json.dumps(record, sort_keys=True, separators=(',', ':'))
        with self.connection() as db:
            db.execute('INSERT OR IGNORE INTO hybrid_prekeys (username,suite,record) VALUES (?,?,?)',
                       (name, record['suite'], encoded))
            stored = db.execute('SELECT suite, record FROM hybrid_prekeys WHERE username=?', (name,)).fetchone()
            if stored is None or stored[0] != record['suite'] or json.loads(stored[1]) != record:
                raise ValueError('A different hybrid prekey is already registered')
    def hybrid_prekey(self, name):
        with self.connection() as db:
            row = db.execute('SELECT record FROM hybrid_prekeys WHERE username=?', (name,)).fetchone()
        return json.loads(row[0]) if row else None
    def save_token(self, token, name, expires):
        with self.connection() as db: db.execute('INSERT INTO tokens VALUES (?, ?, ?)', (_digest(token), name, expires))
    def token_user(self, token, now):
        with self.connection() as db: row = db.execute('SELECT username FROM tokens WHERE token_hash=? AND expires>?', (_digest(token), now)).fetchone()
        return row[0] if row else None
    def _classic_send(self, message):
        body = message.get('message') if isinstance(message, dict) else None
        if not isinstance(body, dict): return None
        counter, session = body.get('counter'), body.get('session')
        if type(counter) is not int or not 0 <= counter < 2**64: return None
        if not isinstance(session, str) or not 0 < len(session) <= 128: return None
        return session, counter
    def reserve_send_counter(self, sender, recipient, session, counter):
        if not isinstance(session, str) or not 0 < len(session) <= 128 or type(counter) is not int or not 0 <= counter < 2**64:
            raise ValueError('Invalid send counter')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT issued, open_counter FROM send_counters WHERE sender=? AND recipient=? AND session_id=?', (sender, recipient, session)).fetchone()
            if row is None:
                if counter != 0: raise ReusedNonceCounter('Send counter was already used')
                db.execute('INSERT INTO send_counters (sender, recipient, session_id, issued, open_counter) VALUES (?,?,?,?,?)', (sender, recipient, session, 1, 0))
                return
            issued, open_counter = row
            if open_counter is not None or counter != issued:
                raise ReusedNonceCounter('Send counter was already used')
            updated = db.execute('UPDATE send_counters SET issued=?, open_counter=? WHERE sender=? AND recipient=? AND session_id=? AND issued=? AND open_counter IS NULL', (counter + 1, counter, sender, recipient, session, counter))
            if updated.rowcount != 1: raise ReusedNonceCounter('Send counter was already used')
    def _hex_id(self, value, size):
        if not isinstance(value, str) or len(value) != size or any(char not in '0123456789abcdef' for char in value):
            raise ValueError('Invalid DR send slot')
        return value
    def _dr_slot(self, message):
        body = message.get('message') if isinstance(message, dict) else None
        if not isinstance(body, dict) or body.get('protocol') != 'double-ratchet': return None
        packet = body.get('packet')
        header = packet.get('header') if isinstance(packet, dict) else None
        if not isinstance(header, dict): raise ValueError('Invalid DR send slot')
        number = header.get('n')
        if type(number) is not int or not 0 <= number < 2**64: raise ValueError('Invalid DR send slot')
        return self._hex_id(body.get('session_id'), 32), self._hex_id(header.get('dh'), 64), number
    def reserve_dr_send(self, sender, recipient, session, dh, counter):
        session, dh = self._hex_id(session, 32), self._hex_id(dh, 64)
        if type(counter) is not int or not 0 <= counter < 2**64: raise ValueError('Invalid DR send slot')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                db.execute('INSERT INTO dr_send_slots (sender, recipient, session_id, dh, counter, stored_hash) VALUES (?,?,?,?,?,NULL)', (sender, recipient, session, dh, counter))
            except sqlite3.IntegrityError as exc:
                raise ReusedNonceCounter('DR send slot was already used') from exc
    def enqueue(self, recipient, sender, message):
        classic = self._classic_send(message)
        slot = None if classic else self._dr_slot(message)
        encoded = json.dumps(message)
        digest = sha256(encoded.encode()).hex() if classic or slot else None
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            if classic:
                session, counter = classic
                row = db.execute('SELECT issued, open_counter, stored_counter, stored_hash FROM send_counters WHERE sender=? AND recipient=? AND session_id=?', (sender, recipient, session)).fetchone()
                if row and row[2] == counter and row[3] == digest:
                    found = db.execute('SELECT id FROM messages WHERE sender=? AND recipient=? AND envelope=?', (sender, recipient, encoded)).fetchone()
                    return found[0] if found else 0
                if row is None:
                    if counter != 0: raise ReusedNonceCounter('Send counter was already used')
                    try:
                        db.execute('INSERT INTO send_counters (sender, recipient, session_id, issued, open_counter, stored_counter, stored_hash) VALUES (?,?,?,?,NULL,?,?)', (sender, recipient, session, 1, counter, digest))
                    except sqlite3.IntegrityError as exc:
                        raise ReusedNonceCounter('Send counter was already used') from exc
                else:
                    issued, open_counter, _, _ = row
                    if open_counter == counter:
                        updated = db.execute('UPDATE send_counters SET open_counter=NULL, stored_counter=?, stored_hash=? WHERE sender=? AND recipient=? AND session_id=? AND open_counter=?', (counter, digest, sender, recipient, session, counter))
                    elif open_counter is None and counter == issued:
                        updated = db.execute('UPDATE send_counters SET issued=?, stored_counter=?, stored_hash=? WHERE sender=? AND recipient=? AND session_id=? AND issued=? AND open_counter IS NULL', (counter + 1, counter, digest, sender, recipient, session, counter))
                    else:
                        raise ReusedNonceCounter('Send counter was already used')
                    if updated.rowcount != 1: raise ReusedNonceCounter('Send counter was already used')
            elif slot:
                session, dh, counter = slot
                row = db.execute('SELECT stored_hash FROM dr_send_slots WHERE sender=? AND recipient=? AND session_id=? AND dh=? AND counter=?', (sender, recipient, session, dh, counter)).fetchone()
                if row and row[0] == digest:
                    found = db.execute('SELECT id FROM messages WHERE sender=? AND recipient=? AND envelope=?', (sender, recipient, encoded)).fetchone()
                    return found[0] if found else 0
                if row is None:
                    try:
                        db.execute('INSERT INTO dr_send_slots (sender, recipient, session_id, dh, counter, stored_hash) VALUES (?,?,?,?,?,?)', (sender, recipient, session, dh, counter, digest))
                    except sqlite3.IntegrityError as exc:
                        raise ReusedNonceCounter('DR send slot was already used') from exc
                elif row[0] is None:
                    updated = db.execute('UPDATE dr_send_slots SET stored_hash=? WHERE sender=? AND recipient=? AND session_id=? AND dh=? AND counter=? AND stored_hash IS NULL', (digest, sender, recipient, session, dh, counter))
                    if updated.rowcount != 1: raise ReusedNonceCounter('DR send slot was already used')
                else:
                    raise ReusedNonceCounter('DR send slot was already used')
            return db.execute('INSERT INTO messages (recipient,sender,envelope) VALUES (?,?,?)', (recipient, sender, encoded)).lastrowid
    def pending_counts(self, recipient):
        with self.connection() as db:
            rows = db.execute('SELECT sender, COUNT(*) FROM messages WHERE recipient=? GROUP BY sender', (recipient,)).fetchall()
        return {row[0]: row[1] for row in rows}
    def pending_kinds(self, recipient):
        with self.connection() as db:
            rows = db.execute('SELECT sender, envelope FROM messages WHERE recipient=?', (recipient,)).fetchall()
        found = {}
        for sender, raw in rows:
            kind = 'classic'
            try:
                message = json.loads(raw).get('message', {})
                if isinstance(message, dict) and isinstance(message.get('protocol'), str):
                    kind = message['protocol']
            except (TypeError, ValueError, json.JSONDecodeError):
                kind = 'classic'
            bucket = found.setdefault(sender, [])
            if kind not in bucket:
                bucket.append(kind)
        return found
    def inbox(self, recipient, only_sender=None):
        # Only a delivery copy is altered; the persisted envelope remains untouched.
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            query = 'SELECT id, sender, envelope FROM messages WHERE recipient=?'
            params = [recipient]
            if only_sender is not None:
                query += ' AND sender=?'
                params.append(only_sender)
            rows = db.execute(query + ' ORDER BY id', params).fetchall()
            config = db.execute('SELECT sender, recipient, expires, status, after_id, target_id FROM demo_interception WHERE id=1').fetchone()
            entries = [{'id': row[0], 'envelope': json.loads(row[2])} for row in rows]
            if config and config[3] == 'armed':
                if config[2] <= time.time():
                    db.execute("UPDATE demo_interception SET status='expired' WHERE id=1")
                elif config[1] == recipient:
                    for row, entry in zip(rows, entries):
                        if row[1] != config[0]:
                            continue
                        if config[5] is not None:
                            if row[0] != config[5]:
                                continue
                        elif row[0] <= config[4]:
                            continue
                        before = entry['envelope'].get('message', {}).get('ciphertext', '')
                        try:
                            raw = bytearray(base64.b64decode(before.encode('ascii'), altchars=b'-_', validate=True))
                            if len(raw) < 17: continue
                            raw[0] ^= 1
                            after = base64.urlsafe_b64encode(raw).decode('ascii')
                        except (ValueError, TypeError, UnicodeError):
                            continue
                        entry['envelope']['message']['ciphertext'] = after
                        db.execute("UPDATE demo_interception SET status='intercepted', message_id=?, original=?, altered=? WHERE id=1 AND status='armed'", (row[0], before, after))
                        break
            return entries

    def arm_interception(self, sender, recipient, now):
        username(sender); username(recipient)
        if sender == recipient: raise ValueError('Los usuarios deben ser diferentes')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            last_id = db.execute('SELECT COALESCE(MAX(id), 0) FROM messages').fetchone()[0]
            db.execute('INSERT OR REPLACE INTO demo_interception (id, sender, recipient, expires, status, message_id, original, altered, after_id, target_id) VALUES (1, ?, ?, ?, ?, NULL, NULL, NULL, ?, NULL)', (sender, recipient, now + 120, 'armed', last_id))
    def arm_pending_message(self, message_id, now):
        if type(message_id) is not int or message_id < 1:
            raise ValueError('Mensaje pendiente inválido')
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT sender, recipient FROM messages WHERE id=?', (message_id,)).fetchone()
            if row is None:
                raise LookupError('El mensaje ya no está pendiente')
            db.execute('INSERT OR REPLACE INTO demo_interception (id, sender, recipient, expires, status, message_id, original, altered, after_id, target_id) VALUES (1, ?, ?, ?, ?, NULL, NULL, NULL, ?, ?)', (row[0], row[1], now + 120, 'armed', message_id - 1, message_id))
    def cancel_interception(self):
        with self.connection() as db: db.execute('DELETE FROM demo_interception WHERE id=1')
    def interception_status(self, now):
        with self.connection() as db:
            row = db.execute('SELECT sender, recipient, expires, status, message_id, original, altered, target_id FROM demo_interception WHERE id=1').fetchone()
        if not row: return {'status': 'inactive'}
        state = 'expired' if row[3] == 'armed' and row[2] <= now else row[3]
        return {'sender': row[0], 'recipient': row[1], 'status': state, 'message_id': row[4], 'original': row[5], 'altered': row[6], 'target_id': row[7]}
    def store_group_mail(self, sender, group_id, key_id, counter, recipients, envelope):
        encoded = json.dumps(envelope, sort_keys=True, separators=(',', ':'))
        digest = sha256(encoded.encode()).hex()
        with self.connection() as db:
            db.execute('BEGIN IMMEDIATE')
            slot = db.execute('SELECT digest FROM group_send_slots WHERE sender=? AND group_id=? AND key_id=? AND counter=?', (sender, group_id, key_id, counter)).fetchone()
            if slot:
                if slot[0] != digest:
                    raise ReusedNonceCounter('Group send counter was already used')
                found = db.execute('SELECT id FROM group_mail WHERE sender=? AND group_id=? AND key_id=? AND counter=?', (sender, group_id, key_id, counter)).fetchone()
                return found[0] if found else 0
            mail_id = db.execute('INSERT INTO group_mail (group_id, sender, key_id, counter, envelope) VALUES (?,?,?,?,?)', (group_id, sender, key_id, counter, encoded)).lastrowid
            db.execute('INSERT INTO group_send_slots (sender, group_id, key_id, counter, digest) VALUES (?,?,?,?,?)', (sender, group_id, key_id, counter, digest))
            for member in recipients:
                db.execute('INSERT INTO group_mail_pending (mail_id, username) VALUES (?,?)', (mail_id, member))
            return mail_id
    def group_inbox(self, username, group_id=None):
        with self.connection() as db:
            query = 'SELECT m.id, m.envelope FROM group_mail m JOIN group_mail_pending p ON p.mail_id=m.id WHERE p.username=?'
            params = [username]
            if group_id is not None:
                query += ' AND m.group_id=?'
                params.append(group_id)
            rows = db.execute(query + ' ORDER BY m.id', params).fetchall()
        return [{'id': row[0], 'envelope': json.loads(row[1])} for row in rows]
    def group_pending(self, username):
        with self.connection() as db:
            rows = db.execute('SELECT m.group_id, COUNT(*) FROM group_mail m JOIN group_mail_pending p ON p.mail_id=m.id WHERE p.username=? GROUP BY m.group_id', (username,)).fetchall()
        return {row[0]: row[1] for row in rows}
    def acknowledge_group(self, username, mail_id):
        with self.connection() as db:
            db.execute('DELETE FROM group_mail_pending WHERE mail_id=? AND username=?', (mail_id, username))
            if db.execute('SELECT 1 FROM group_mail_pending WHERE mail_id=?', (mail_id,)).fetchone() is None:
                db.execute('DELETE FROM group_mail WHERE id=?', (mail_id,))
    def acknowledge(self, recipient, message_id):
        with self.connection() as db: db.execute('DELETE FROM messages WHERE recipient=? AND id=?', (recipient,message_id))
    def touch_presence(self, name, now):
        with self.connection() as db: db.execute('INSERT OR REPLACE INTO presence VALUES (?, ?)', (name, now))
    def clear_presence(self, name):
        with self.connection() as db: db.execute('DELETE FROM presence WHERE username=?', (name,))
    def is_online(self, name, now):
        with self.connection() as db: row = db.execute('SELECT 1 FROM presence WHERE username=? AND last_seen>?', (name, now - 35)).fetchone()
        return bool(row)
    def revoke_token(self, token):
        with self.connection() as db: db.execute('DELETE FROM tokens WHERE token_hash=?', (_digest(token),))
    def contacts(self, name, now):
        with self.connection() as db:
            rows = db.execute('SELECT name FROM users WHERE name != ? ORDER BY name', (name,)).fetchall()
        return [{'name': row[0], 'online': self.is_online(row[0], now)} for row in rows]
    def inspect_messages(self):
        with self.connection() as db:
            rows = db.execute('SELECT id, sender, recipient, envelope FROM messages ORDER BY id DESC LIMIT 50').fetchall()
        return [{'id': row[0], 'sender': row[1], 'recipient': row[2], 'envelope': json.loads(row[3])} for row in rows]
