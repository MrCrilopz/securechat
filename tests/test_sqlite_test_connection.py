import sqlite3
import tempfile
import unittest
from pathlib import Path

from tests.sqlite_test_connection import transaction


class TestSqliteTestConnection(unittest.TestCase):
    def test_commit_rollback_and_close(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'db.sqlite3'
            with transaction(path) as connection:
                connection.execute('CREATE TABLE example (value TEXT)')
                connection.execute("INSERT INTO example VALUES ('saved')")
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute('SELECT 1')
            with self.assertRaisesRegex(RuntimeError, 'failure'):
                with transaction(path) as connection:
                    connection.execute("INSERT INTO example VALUES ('rolled back')")
                    raise RuntimeError('failure')
            with self.assertRaises(sqlite3.ProgrammingError):
                connection.execute('SELECT 1')
            with transaction(path) as connection:
                self.assertEqual(connection.execute('SELECT value FROM example').fetchall(), [('saved',)])
