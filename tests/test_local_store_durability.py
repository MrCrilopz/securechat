"""Commit boundaries for atomic local state replacement."""
import os
import stat
import tempfile
import unittest
from unittest.mock import patch
from securechat.infrastructure import local_store

class LocalStoreDurabilityTest(unittest.TestCase):
    def test_fsyncs_file_before_replacement_then_directory(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, 'user.json'); kinds=[]
            real_fsync = os.fsync
            def track(fd):
                kinds.append('directory' if stat.S_ISDIR(os.fstat(fd).st_mode) else 'file')
                return real_fsync(fd)
            with patch('securechat.infrastructure.local_store.os.fsync', side_effect=track):
                local_store.save(path, 'example-password-123', {'counter': 1})
            self.assertEqual(kinds, ['file', 'directory'])
            self.assertEqual(local_store.load(path, 'example-password-123'), {'counter': 1})

    def test_directory_sync_failure_is_reported_even_if_replace_happened(self):
        with tempfile.TemporaryDirectory() as root:
            path = os.path.join(root, 'user.json'); local_store.save(path, 'example-password-123', {'counter': 0})
            real_fsync = os.fsync
            def fail_directory(fd):
                if stat.S_ISDIR(os.fstat(fd).st_mode): raise OSError('simulated directory failure')
                return real_fsync(fd)
            snapshot = local_store.load(path, 'example-password-123')
            snapshot['counter'] = 1
            with patch('securechat.infrastructure.local_store.os.fsync', side_effect=fail_directory):
                with self.assertRaises(OSError): local_store.save(path, 'example-password-123', snapshot)
            self.assertEqual(local_store.load(path, 'example-password-123'), {'counter': 1})
