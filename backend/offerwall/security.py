"""Cryptographic helpers for publisher entry links, API keys and postbacks."""

import hashlib
import hmac
import re
import secrets
from urllib.parse import urlencode

from django.conf import settings

from vendors.credentials import decrypt_secret, encrypt_secret


API_KEY_PREFIX = "ow_live_"
SIGNATURE_RE = re.compile(r"^[0-9a-f]{64}$")
NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{12,80}$")


def generate_signing_secret() -> str:
    return secrets.token_urlsafe(48)


def generate_api_key() -> tuple[str, str, str, str]:
    raw_key = f"{API_KEY_PREFIX}{secrets.token_urlsafe(36)}"
    return raw_key, raw_key[:16], raw_key[-4:], digest_api_key(raw_key)


def digest_api_key(raw_key: str) -> str:
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        str(raw_key or "").encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def encrypt_signing_secret(secret: str) -> str:
    return encrypt_secret(secret)


def decrypt_signing_secret(publisher) -> str:
    return decrypt_secret(publisher.encrypted_signing_secret)


def decrypt_placement_postback_secret(placement) -> str:
    return decrypt_secret(placement.encrypted_postback_secret)


def _hex_hmac(secret: str, payload: str) -> str:
    return hmac.new(
        secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def entry_payload(*, slug: str, external_user_id: str, timestamp: int, nonce: str) -> str:
    return "\n".join(("offerwall-entry-v1", slug, external_user_id, str(timestamp), nonce))


def sign_entry(publisher, *, external_user_id: str, timestamp: int, nonce: str) -> str:
    return _hex_hmac(
        decrypt_signing_secret(publisher),
        entry_payload(
            slug=publisher.slug,
            external_user_id=external_user_id,
            timestamp=timestamp,
            nonce=nonce,
        ),
    )


def verify_entry_signature(
    publisher, *, external_user_id: str, timestamp: int, nonce: str, signature: str
) -> bool:
    supplied = str(signature or "").strip().lower()
    if not SIGNATURE_RE.fullmatch(supplied) or not NONCE_RE.fullmatch(str(nonce or "")):
        return False
    expected = sign_entry(
        publisher,
        external_user_id=external_user_id,
        timestamp=timestamp,
        nonce=nonce,
    )
    return hmac.compare_digest(expected, supplied)


def sign_session(publisher, visit_public_id) -> str:
    return _hex_hmac(
        decrypt_signing_secret(publisher), f"offerwall-session-v1\n{visit_public_id}"
    )


def verify_session_signature(publisher, visit_public_id, signature: str) -> bool:
    supplied = str(signature or "").strip().lower()
    return bool(
        SIGNATURE_RE.fullmatch(supplied)
        and hmac.compare_digest(sign_session(publisher, visit_public_id), supplied)
    )


def sign_placement_access(placement) -> str:
    return _hex_hmac(
        decrypt_signing_secret(placement.publisher),
        f"offerwall-placement-v1\n{placement.public_id}",
    )


def verify_placement_access(placement, signature: str) -> bool:
    supplied = str(signature or "").strip().lower()
    return bool(
        SIGNATURE_RE.fullmatch(supplied)
        and hmac.compare_digest(sign_placement_access(placement), supplied)
    )


def sign_click(publisher, visit_public_id, survey_local_id: str) -> str:
    return _hex_hmac(
        decrypt_signing_secret(publisher),
        f"offerwall-click-v1\n{visit_public_id}\n{survey_local_id}",
    )


def verify_click_signature(
    publisher, visit_public_id, survey_local_id: str, signature: str
) -> bool:
    supplied = str(signature or "").strip().lower()
    return bool(
        SIGNATURE_RE.fullmatch(supplied)
        and hmac.compare_digest(
            sign_click(publisher, visit_public_id, survey_local_id), supplied
        )
    )


def sign_result(publisher, click_public_id) -> str:
    return _hex_hmac(
        decrypt_signing_secret(publisher), f"offerwall-result-v1\n{click_public_id}"
    )


def verify_result_signature(publisher, click_public_id, signature: str) -> bool:
    supplied = str(signature or "").strip().lower()
    return bool(
        SIGNATURE_RE.fullmatch(supplied)
        and hmac.compare_digest(sign_result(publisher, click_public_id), supplied)
    )


def postback_signature(secret: str, *, timestamp: int, event_id: str, body: bytes) -> str:
    digest = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(("offerwall-postback-v1", str(timestamp), event_id, digest))
    return _hex_hmac(secret, canonical)


def portal_payload(*, slug: str, timestamp: int, nonce: str) -> str:
    return "\n".join(("offerwall-portal-v1", slug, str(timestamp), nonce))


def sign_portal_access(publisher, *, timestamp: int, nonce: str) -> str:
    return _hex_hmac(
        decrypt_signing_secret(publisher),
        portal_payload(slug=publisher.slug, timestamp=timestamp, nonce=nonce),
    )


def verify_portal_access(
    publisher, *, timestamp: int, nonce: str, signature: str
) -> bool:
    supplied = str(signature or "").strip().lower()
    if not SIGNATURE_RE.fullmatch(supplied) or not NONCE_RE.fullmatch(str(nonce or "")):
        return False
    return hmac.compare_digest(
        sign_portal_access(publisher, timestamp=timestamp, nonce=nonce), supplied
    )


def signed_portal_query(publisher, *, timestamp: int, nonce: str) -> str:
    return urlencode(
        {
            "ts": timestamp,
            "nonce": nonce,
            "sig": sign_portal_access(publisher, timestamp=timestamp, nonce=nonce),
        }
    )


def signed_entry_query(
    publisher, *, external_user_id: str, timestamp: int, nonce: str
) -> str:
    return urlencode(
        {
            "uid": external_user_id,
            "ts": timestamp,
            "nonce": nonce,
            "sig": sign_entry(
                publisher,
                external_user_id=external_user_id,
                timestamp=timestamp,
                nonce=nonce,
            ),
        }
    )
