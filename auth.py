"""
auth.py

Minimal authentication module for the Cloud Security Risk Assessment Tool.

Scope note: this is a lightweight, self-contained authentication layer
built for the CS 499 Software Design and Engineering enhancement. It
demonstrates secure password storage (salted PBKDF2 hashing, no plaintext
passwords anywhere) and session-gating for the Streamlit app. Accounts are
stored in the users table of the SQLite database (database.py). It is not a
production-grade identity system: there is no password reset flow, no
rate limiting/lockout, and no multi-factor authentication. In a real
deployment this would be replaced with a managed identity provider or a
proper auth library.
"""

import hashlib
import hmac
import secrets

from database import (
    DISABLED_PASSWORD_HASH,
    connection_scope,
    count_users,
    create_user,
    get_password_hash,
)

DEFAULT_ADMIN_USERNAME = "admin"
DEFAULT_ADMIN_PASSWORD = "changeme123"
PBKDF2_ITERATIONS = 100_000
MIN_PASSWORD_LENGTH = 8


def _hash_password(password: str, salt: bytes = None) -> str:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with a random 16-byte salt.
    Returns "salt_hex$hash_hex" so both pieces can be stored as one field.
    A random salt means two users with the same password never produce
    the same stored hash, which defeats precomputed rainbow-table attacks.
    """
    if salt is None:
        salt = secrets.token_bytes(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return f"{salt.hex()}${pwd_hash.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    """
    Verifies a password against a stored "salt_hex$hash_hex" string using
    a constant-time comparison (hmac.compare_digest) to avoid leaking
    timing information that could help an attacker guess the password.
    """
    try:
        salt_hex, hash_hex = stored.split("$")
    except (ValueError, AttributeError):
        return False
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    candidate = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return hmac.compare_digest(candidate, expected)


def ensure_default_admin(conn, commit: bool = True) -> None:
    """
    Seeds a default admin account when the users table is empty, so the
    app is usable right after cloning. The default password is
    intentionally weak and is meant to be changed immediately; it exists
    only so a reviewer can log in without extra setup.

    commit=False lets the migration script keep this insert inside its
    single all-or-nothing transaction.
    """
    if count_users(conn) == 0:
        create_user(
            conn,
            DEFAULT_ADMIN_USERNAME,
            _hash_password(DEFAULT_ADMIN_PASSWORD),
            commit=commit,
        )


def authenticate(username: str, password: str, conn=None) -> bool:
    """Returns True only if username/password match a stored account."""
    if not username or not password:
        return False
    with connection_scope(conn) as db:
        ensure_default_admin(db)
        stored = get_password_hash(db, username)
    if stored is None or stored == DISABLED_PASSWORD_HASH:
        return False
    return _verify_password(password, stored)


def register_user(username: str, password: str, conn=None) -> bool:
    """
    Registers a new user account. Returns False (and registers nothing)
    if the username is taken, the username/password is empty, or the
    password is shorter than MIN_PASSWORD_LENGTH. Usernames are
    case-insensitive, so "Admin" and "admin" are the same account.
    """
    if not username or not password:
        return False
    if len(password) < MIN_PASSWORD_LENGTH:
        return False
    with connection_scope(conn) as db:
        ensure_default_admin(db)
        return create_user(db, username, _hash_password(password))
