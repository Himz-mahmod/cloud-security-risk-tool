import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from database import get_connection


@pytest.fixture
def conn(tmp_path):
    """A fresh, isolated SQLite database for each test."""
    connection = get_connection(str(tmp_path / "test.db"))
    yield connection
    connection.close()
