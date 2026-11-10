"""Estado local cifrado con reemplazo atómico y detección de escrituras obsoletas."""
import json
import os
import re
import secrets
import stat
import tempfile
from contextlib import contextmanager

try:
    import fcntl
except ImportError:
    fcntl = None

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from securechat.infrastructure.crypto import b64, unb64

_LEGACY_AAD = b'securechat local v1'
_VERSIONED_AAD = b'securechat local v2\x00'


class StaleLocalStateError(OSError):
    """El estado cambió desde su lectura y debe volver a cargarse."""


def _canonical_path(path):
    absolute = os.path.abspath(os.fspath(path))
    return os.path.join(os.path.realpath(os.path.dirname(absolute)), os.path.basename(absolute))


class LocalState(dict):
    """Diccionario con una revisión transparente para la aplicación."""
    def __init__(self, data, path, revision):
        super().__init__(data)
        self._store_path = _canonical_path(path)
        self._store_revision = revision

    def adopt_saved_revision(self, other):
        if not isinstance(other, LocalState) or other._store_path != self._store_path:
            raise ValueError('Incompatible local state revision')
        self._store_revision = other._store_revision


def key(password, salt):
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode())


@contextmanager
def _writer_lock(path):
    if fcntl is None or not hasattr(os, 'O_NOFOLLOW'):
        raise OSError('El control seguro de concurrencia no está disponible')
    flags = os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW
    descriptor = os.open(path + '.lock', flags, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def load(path, password):
    path = _canonical_path(path)
    if not hasattr(os, 'O_NOFOLLOW'):
        raise OSError('El acceso seguro al estado no está disponible')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor) as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise OSError('El estado local no admite enlaces ni archivos especiales')
        payload = json.load(source)
    revision = payload.get('revision')
    if revision is None:
        aad = _LEGACY_AAD
    elif isinstance(revision, str) and re.fullmatch(r'[0-9a-f]{32}', revision):
        aad = _VERSIONED_AAD + revision.encode('ascii')
    else:
        raise ValueError('Revisión de estado local inválida')
    data = json.loads(AESGCM(key(password, unb64(payload['salt']))).decrypt(
        unb64(payload['nonce']), unb64(payload['ciphertext']), aad))
    if not isinstance(data, dict):
        raise ValueError('Estado local inválido')
    return LocalState(data, path, revision)


def save(path, password, data):
    path = _canonical_path(path)
    directory = os.path.dirname(path)
    os.makedirs(directory, exist_ok=True)
    with _writer_lock(path):
        exists = os.path.lexists(path)
        if exists:
            if not isinstance(data, LocalState) or data._store_path != path:
                raise StaleLocalStateError('El estado debe cargarse antes de modificarlo')
            current = load(path, password)
            if current._store_revision != data._store_revision:
                raise StaleLocalStateError('El estado cambió; es necesario recargarlo')
        elif isinstance(data, LocalState):
            raise StaleLocalStateError('El archivo cargado ya no existe')
        revision = secrets.token_hex(16)
        salt, nonce = os.urandom(16), os.urandom(12)
        encrypted = AESGCM(key(password, salt)).encrypt(
            nonce, json.dumps(data).encode(), _VERSIONED_AAD + revision.encode('ascii'))
        payload = json.dumps({'revision': revision, 'salt': b64(salt), 'nonce': b64(nonce),
                              'ciphertext': b64(encrypted)})
        fd, temporary = tempfile.mkstemp(dir=directory, prefix='.securechat-')
        try:
            with os.fdopen(fd, 'w') as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(directory, os.O_RDONLY | getattr(os, 'O_DIRECTORY', 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            if isinstance(data, LocalState):
                data._store_revision = revision
        finally:
            if os.path.exists(temporary): os.unlink(temporary)
