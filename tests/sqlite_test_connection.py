"""Temporary SQLite transactions that also release their connections."""
import sqlite3
from contextlib import closing, contextmanager


@contextmanager
def transaction(path):
    with closing(sqlite3.connect(path)) as connection:
        with connection:
            yield connection
