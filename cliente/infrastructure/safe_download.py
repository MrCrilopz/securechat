"""Guarda adjuntos locales con creación exclusiva y sin seguir enlaces simbólicos."""
import os
import stat
from pathlib import Path
from cliente.application.attachment import _name
from securechat.domain.models import username


def _directory(parent_fd, name, create=False):
    if create:
        try:
            os.mkdir(name, mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    return os.open(name, flags, dir_fd=parent_fd)


def save_download(home, user, filename, content):
    username(user)
    _name(filename)
    if not isinstance(content, bytes):
        raise ValueError('Contenido de adjunto inválido')
    if not all(hasattr(os, name) for name in ('O_DIRECTORY', 'O_NOFOLLOW')):
        raise OSError('La descarga segura no está disponible en este sistema')
    absolute_home = os.path.abspath(os.fspath(home))
    parts = Path(absolute_home).parts
    directory_fd = os.open(parts[0], os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in parts[1:]:
            next_fd = _directory(directory_fd, part)
            os.close(directory_fd)
            directory_fd = next_fd
        for part in ('descargas', user):
            next_fd = _directory(directory_fd, part, create=True)
            os.close(directory_fd)
            directory_fd = next_fd
            info = os.fstat(directory_fd)
            if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077:
                raise OSError('El directorio de descargas no es privado')
        stem, suffix = os.path.splitext(filename)
        for number in range(10000):
            chosen = filename if number == 0 else f'{stem} ({number}){suffix}'
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            try:
                fd = os.open(chosen, flags, 0o600, dir_fd=directory_fd)
                break
            except FileExistsError:
                continue
        else:
            raise OSError('No hay un nombre disponible para el archivo')
        with os.fdopen(fd, 'wb') as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.fsync(directory_fd)
        return os.path.join(absolute_home, 'descargas', user, chosen)
    finally:
        os.close(directory_fd)
