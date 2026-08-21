"""Encryption and verification primitives for Offerwall respondent identities."""

import base64
import hashlib
import hmac
import secrets
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.contrib.auth import get_user_model
from django.utils.crypto import constant_time_compare


def normalize_respondent_email(value: str) -> str:
    return get_user_model().objects.normalize_email(str(value or "").strip()).lower()


@lru_cache(maxsize=4)
def _fernet(raw_key: str) -> Fernet:
    derived = hashlib.sha256(raw_key.encode("utf-8")).digest()
    return Fernet(base64.urlsafe_b64encode(derived))


def _identity_fernet() -> Fernet:
    raw_key = str(settings.RESPONDENT_EMAIL_ENCRYPTION_KEY or settings.SECRET_KEY).strip()
    return _fernet(raw_key)


def encrypt_respondent_value(value: str) -> str:
    return _identity_fernet().encrypt(str(value or "").encode("utf-8")).decode("ascii")


def decrypt_respondent_value(value: str) -> str:
    if not value:
        return ""
    try:
        return _identity_fernet().decrypt(str(value).encode("ascii")).decode("utf-8")
    except (InvalidToken, ValueError, UnicodeError):
        return ""


def respondent_email_hash(email: str) -> str:
    normalized = normalize_respondent_email(email)
    key = str(settings.RESPONDENT_EMAIL_ENCRYPTION_KEY or settings.SECRET_KEY).encode("utf-8")
    return hmac.new(key, normalized.encode("utf-8"), hashlib.sha256).hexdigest()


def generate_verification_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def verification_code_hash(profile_id, code: str) -> str:
    message = f"respondent-email:{profile_id}:{str(code or '').strip()}".encode("utf-8")
    return hmac.new(settings.SECRET_KEY.encode("utf-8"), message, hashlib.sha256).hexdigest()


def verification_code_matches(profile_id, code: str, expected_hash: str) -> bool:
    return bool(expected_hash) and constant_time_compare(
        verification_code_hash(profile_id, code),
        expected_hash,
    )
