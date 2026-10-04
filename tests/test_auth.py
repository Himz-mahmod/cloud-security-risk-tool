import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from auth import _hash_password, _verify_password, register_user, authenticate
from database import DISABLED_PASSWORD_HASH, create_user


def test_hash_and_verify_roundtrip():
    hashed = _hash_password("SuperSecret123")
    assert _verify_password("SuperSecret123", hashed) is True


def test_verify_rejects_wrong_password():
    hashed = _hash_password("SuperSecret123")
    assert _verify_password("WrongPassword", hashed) is False


def test_same_password_produces_different_hashes():
    # Different random salts should mean different stored hashes even
    # for the exact same password.
    assert _hash_password("SamePassword123") != _hash_password("SamePassword123")


def test_register_user_success(conn):
    assert register_user("tanvir", "StrongPass123", conn) is True


def test_register_user_rejects_short_password(conn):
    assert register_user("tanvir", "short1", conn) is False


def test_register_user_rejects_duplicate_username(conn):
    register_user("tanvir", "StrongPass123", conn)
    assert register_user("tanvir", "AnotherPass456", conn) is False


def test_usernames_are_case_insensitive(conn):
    register_user("Tanvir", "StrongPass123", conn)
    assert register_user("tanvir", "AnotherPass456", conn) is False
    assert authenticate("TANVIR", "StrongPass123", conn) is True


def test_authenticate_default_admin_account_created_on_first_run(conn):
    assert authenticate("admin", "changeme123", conn) is True


def test_authenticate_rejects_bad_password(conn):
    assert authenticate("admin", "wrongpassword", conn) is False


def test_authenticate_rejects_empty_credentials(conn):
    assert authenticate("", "", conn) is False


def test_authenticate_rejects_unknown_user(conn):
    assert authenticate("nonexistent_user", "whatever123", conn) is False


def test_disabled_placeholder_account_cannot_log_in(conn):
    create_user(conn, "ghost", DISABLED_PASSWORD_HASH)
    assert authenticate("ghost", DISABLED_PASSWORD_HASH, conn) is False
    assert authenticate("ghost", "anything123", conn) is False


def test_stored_value_is_a_hash_not_the_password(conn):
    register_user("tanvir", "StrongPass123", conn)
    stored = conn.execute(
        "SELECT password_hash FROM users WHERE username = 'tanvir'"
    ).fetchone()[0]
    assert "StrongPass123" not in stored
