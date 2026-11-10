"""Escritura local exclusiva de adjuntos sin seguir enlaces simbólicos."""
import os
import pathlib
import tempfile
import unittest
from cliente.infrastructure.safe_download import save_download


class SafeDownloadTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = pathlib.Path(self.temp.name) / 'clientes'
        self.root.mkdir()

    def test_existing_files_never_overwritten(self):
        first = pathlib.Path(save_download(self.root, 'alice', 'documento.txt', b'first'))
        second = pathlib.Path(save_download(self.root, 'alice', 'documento.txt', b'second'))
        self.assertNotEqual(first, second)
        self.assertEqual(first.read_bytes(), b'first')
        self.assertEqual(second.read_bytes(), b'second')
        self.assertEqual(first.stat().st_mode & 0o777, 0o600)

    def test_symlink_destination_not_followed(self):
        outside = pathlib.Path(self.temp.name) / 'outside'
        outside.write_bytes(b'keep')
        directory = self.root / 'descargas' / 'alice'
        (self.root / 'descargas').mkdir(mode=0o700)
        directory.mkdir(mode=0o700)
        os.symlink(outside, directory / 'documento.txt')
        saved = pathlib.Path(save_download(self.root, 'alice', 'documento.txt', b'new'))
        self.assertEqual(outside.read_bytes(), b'keep')
        self.assertEqual(saved.read_bytes(), b'new')

    def test_symlink_directory_rejected(self):
        os.symlink(self.temp.name, self.root / 'descargas')
        with self.assertRaises((OSError, ValueError)):
            save_download(self.root, 'alice', 'documento.txt', b'new')

    def test_path_traversal_rejected(self):
        for filename in ('../escape', 'folder/file', 'folder\\file'):
            with self.subTest(filename=filename), self.assertRaises(ValueError):
                save_download(self.root, 'alice', filename, b'data')

    def test_symlink_in_home_ancestor_rejected(self):
        alias = pathlib.Path(self.temp.name) / 'alias'
        os.symlink(self.root, alias)
        with self.assertRaises(OSError):
            save_download(alias, 'alice', 'documento.txt', b'new')

    def test_shared_download_directory_rejected(self):
        directory = self.root / 'descargas'
        directory.mkdir(mode=0o700)
        directory.chmod(0o755)
        with self.assertRaises(OSError):
            save_download(self.root, 'alice', 'documento.txt', b'new')
