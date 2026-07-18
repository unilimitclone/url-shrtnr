"""
Cryptographic helpers — password hashing, token hashing, and PKCE.

Uses argon2 for passwords (via argon2-cffi) and SHA-256 for token hashing
and PKCE code-challenge derivation (RFC 7636).
"""

from __future__ import annotations

import base64
import hashlib

from argon2 import PasswordHasher

_password_hasher = PasswordHasher()


def hash_password(plain_password: str) -> str:
    """Hash *plain_password* with argon2id.

    Returns:
        Argon2 hash string (includes algorithm parameters and salt).
    """
    return _password_hasher.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verify *plain_password* against an argon2 *password_hash*.

    Returns:
        ``True`` if the password matches, ``False`` for any failure
        (wrong password, invalid hash, etc.).
    """
    try:
        _password_hasher.verify(password_hash, plain_password)
        return True
    except Exception:
        return False


def hash_token(token: str) -> str:
    """Return the hex-encoded SHA-256 digest of *token*.

    Used to hash OTP codes and secure tokens before storing them in the
    database so the plaintext is never persisted.

    Args:
        token: The plaintext token string to hash.

    Returns:
        64-character lowercase hex string.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def pkce_s256_challenge(code_verifier: str) -> str:
    """Derive the S256 PKCE code challenge for *code_verifier* (RFC 7636 §4.2).

    ``code_challenge = BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))``
    with no ``=`` padding.

    Returns:
        43-character base64url string.
    """
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
