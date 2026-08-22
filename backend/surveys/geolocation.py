"""Cached entry-IP geolocation for market validation and vault enrichment.

The resolver prefers trusted proxy metadata, then an optional local MaxMind
City database, and finally a configurable JSON endpoint. Lookup failures are
fail-open: traffic is rejected only when a reliable country code was resolved.
"""

from __future__ import annotations

import hashlib
import logging
import threading
from pathlib import Path

import requests
from django.conf import settings
from django.core.cache import caches

from .survey_flow import get_request_ip


logger = logging.getLogger(__name__)
_http_thread_state = threading.local()
_maxmind_lock = threading.Lock()
_maxmind_identity = None
_maxmind_slot = None


class _MaxMindReaderSlot:
    def __init__(self, reader):
        self.reader = reader
        self.active = 0
        self.retired = False


def _close_maxmind_reader(reader) -> None:
    try:
        reader.close()
    except Exception:
        logger.warning("Could not close a retired GeoIP database reader", exc_info=True)


def _http_session() -> requests.Session:
    """Keep one connection pool per request-serving thread."""

    session = getattr(_http_thread_state, "session", None)
    if session is None:
        session = requests.Session()
        _http_thread_state.session = session
    return session


def _maxmind_city(database_path: Path, ip_value: str):
    """Reuse an open MMDB reader and replace it safely when the file changes."""

    global _maxmind_identity, _maxmind_slot

    identity = (str(database_path.resolve()), database_path.stat().st_mtime_ns)
    close_after_swap = None
    with _maxmind_lock:
        if _maxmind_slot is None or _maxmind_identity != identity:
            import geoip2.database

            replacement = _MaxMindReaderSlot(geoip2.database.Reader(identity[0]))
            previous = _maxmind_slot
            _maxmind_slot = replacement
            _maxmind_identity = identity
            if previous is not None:
                previous.retired = True
                if previous.active == 0:
                    close_after_swap = previous.reader
        slot = _maxmind_slot
        slot.active += 1
    if close_after_swap is not None:
        _close_maxmind_reader(close_after_swap)

    try:
        return slot.reader.city(ip_value)
    finally:
        close_after_lookup = None
        with _maxmind_lock:
            slot.active -= 1
            if slot.retired and slot.active == 0:
                close_after_lookup = slot.reader
        if close_after_lookup is not None:
            _close_maxmind_reader(close_after_lookup)


def _clean_country_code(value) -> str:
    code = str(value or "").strip().upper()
    return code if len(code) == 2 and code.isalpha() else ""


def _clean_postal_code(value) -> str:
    return str(value or "").strip()[:40]


def _cache_key(ip_value: str) -> str:
    digest = hashlib.sha256(ip_value.encode("utf-8")).hexdigest()
    return f"entry-geo:v2:{digest}"


def _from_maxmind(ip_value: str) -> dict:
    configured_path = str(settings.GEOIP_CITY_DB_PATH or "").strip()
    database_path = Path(configured_path) if configured_path else None
    if database_path is None or not database_path.is_file():
        return {}
    try:
        record = _maxmind_city(database_path, ip_value)
        return {
            "country_code": _clean_country_code(record.country.iso_code),
            "country": str(record.country.name or "")[:120],
            "postal_code": _clean_postal_code(record.postal.code),
            "source": "maxmind",
        }
    except Exception:
        logger.warning("Local GeoIP lookup failed", exc_info=True)
        return {}


def _from_http(ip_value: str) -> dict:
    endpoint = str(settings.GEOIP_LOOKUP_URL or "").strip()
    if not endpoint:
        return {}
    try:
        response = _http_session().get(
            endpoint.format(ip=ip_value),
            timeout=settings.GEOIP_LOOKUP_TIMEOUT_SECONDS,
            headers={"Accept": "application/json", "User-Agent": "ExchangeHub/1.0"},
        )
        response.raise_for_status()
        payload = response.json()
        if payload.get("success") is False:
            return {}
        return {
            "country_code": _clean_country_code(
                payload.get("country_code") or payload.get("countryCode")
            ),
            "country": str(payload.get("country") or payload.get("country_name") or "")[:120],
            "postal_code": _clean_postal_code(
                payload.get("postal") or payload.get("postal_code") or payload.get("zip")
            ),
            "source": "http",
        }
    except Exception:
        logger.warning("Remote GeoIP lookup failed for an entry request", exc_info=True)
        return {}


def resolve_entry_geolocation(request) -> dict:
    """Return cached country/postal metadata for the request's public IP."""

    ip_value = get_request_ip(request)
    if not ip_value:
        return {}
    cache = caches["default"]
    key = _cache_key(ip_value)
    try:
        cached = cache.get(key)
    except Exception:
        cached = None
    if isinstance(cached, dict):
        return cached

    trusted_header_code = (
        _clean_country_code(request.META.get("HTTP_CF_IPCOUNTRY"))
        if settings.TRUST_X_FORWARDED_FOR and settings.TRUST_CLOUDFLARE_HEADERS
        else ""
    )
    result = _from_maxmind(ip_value)
    if not result or not result.get("country_code") or not result.get("postal_code"):
        remote = _from_http(ip_value)
        if remote:
            result = {
                "country_code": result.get("country_code") or remote.get("country_code", ""),
                "country": result.get("country") or remote.get("country", ""),
                "postal_code": result.get("postal_code") or remote.get("postal_code", ""),
                "source": result.get("source") or remote.get("source", ""),
            }
    if trusted_header_code:
        result["country_code"] = trusted_header_code
        prior_source = result.get("source")
        result["source"] = "trusted_proxy" if not prior_source else f"trusted_proxy+{prior_source}"
    result = {
        "ip": ip_value,
        "country_code": _clean_country_code(result.get("country_code")),
        "country": str(result.get("country") or "")[:120],
        "postal_code": _clean_postal_code(result.get("postal_code")),
        "source": str(result.get("source") or "unknown")[:40],
    }
    try:
        cache_timeout = (
            settings.GEOIP_CACHE_TTL_SECONDS
            if result["country_code"]
            else settings.GEOIP_UNKNOWN_CACHE_TTL_SECONDS
        )
        cache.set(key, result, timeout=cache_timeout)
    except Exception:
        logger.warning("Could not cache entry GeoIP result", exc_info=True)
    return result


def survey_target_country_code(survey) -> str:
    """Return the survey's normalized two-letter target market, when known."""

    code = _clean_country_code(getattr(survey, "country_code", ""))
    if code:
        return code
    return _clean_country_code(getattr(survey, "country", ""))


def is_wrong_target_country(survey, location: dict) -> bool:
    expected = survey_target_country_code(survey)
    actual = _clean_country_code((location or {}).get("country_code"))
    return bool(settings.ENFORCE_SURVEY_TARGET_COUNTRY and expected and actual and expected != actual)


def geolocation_client_data(location: dict) -> dict:
    """Return the limited location fields allowed in entry audit JSON."""

    if not location:
        return {}
    return {
        "geo_country_code": location.get("country_code", ""),
        "geo_country": location.get("country", ""),
        "geo_postal_code": location.get("postal_code", ""),
        "geo_source": location.get("source", ""),
    }
