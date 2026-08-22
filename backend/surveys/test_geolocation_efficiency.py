"""Regression tests for GeoIP reader and HTTP connection reuse."""

import os
import threading
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import Mock, patch

from django.test import SimpleTestCase, override_settings

from . import geolocation


class GeolocationEfficiencyTests(SimpleTestCase):
    @override_settings(
        TRUST_X_FORWARDED_FOR=True,
        TRUST_CLOUDFLARE_HEADERS=False,
        GEOIP_CACHE_TTL_SECONDS=300,
        GEOIP_UNKNOWN_CACHE_TTL_SECONDS=45,
    )
    @patch("surveys.geolocation._from_http", return_value={})
    @patch(
        "surveys.geolocation._from_maxmind",
        return_value={"country_code": "IN", "country": "India", "postal_code": ""},
    )
    def test_untrusted_cloudflare_country_header_cannot_override_geoip(
        self,
        _maxmind,
        _http,
    ):
        cache = Mock()
        cache.get.return_value = None
        request = SimpleNamespace(
            META={
                "REMOTE_ADDR": "127.0.0.1",
                "HTTP_X_FORWARDED_FOR": "8.8.8.8",
                "HTTP_CF_CONNECTING_IP": "1.1.1.1",
                "HTTP_CF_IPCOUNTRY": "US",
            }
        )

        with patch.object(geolocation, "caches", {"default": cache}):
            result = geolocation.resolve_entry_geolocation(request)

        self.assertEqual(result["ip"], "8.8.8.8")
        self.assertEqual(result["country_code"], "IN")
        self.assertNotIn("trusted_proxy", result["source"])
        cache.set.assert_called_once_with(
            geolocation._cache_key("8.8.8.8"), result, timeout=300
        )

    @override_settings(
        TRUST_X_FORWARDED_FOR=True,
        TRUST_CLOUDFLARE_HEADERS=False,
        GEOIP_CACHE_TTL_SECONDS=300,
        GEOIP_UNKNOWN_CACHE_TTL_SECONDS=45,
    )
    @patch("surveys.geolocation._from_http", return_value={})
    @patch("surveys.geolocation._from_maxmind", return_value={})
    def test_unknown_country_is_cached_only_briefly(self, _maxmind, _http):
        cache = Mock()
        cache.get.return_value = None
        request = SimpleNamespace(
            META={
                "REMOTE_ADDR": "127.0.0.1",
                "HTTP_X_FORWARDED_FOR": "8.8.4.4",
            }
        )

        with patch.object(geolocation, "caches", {"default": cache}):
            result = geolocation.resolve_entry_geolocation(request)

        self.assertEqual(result["country_code"], "")
        cache.set.assert_called_once_with(
            geolocation._cache_key("8.8.4.4"), result, timeout=45
        )

    @patch("surveys.geolocation.requests.Session")
    def test_remote_lookup_session_is_reused_within_a_worker_thread(self, session_class):
        with patch.object(geolocation, "_http_thread_state", threading.local()):
            first = geolocation._http_session()
            second = geolocation._http_session()

        self.assertIs(first, second)
        session_class.assert_called_once_with()

    @override_settings(
        GEOIP_LOOKUP_URL="https://geo.example.test/{ip}",
        GEOIP_LOOKUP_TIMEOUT_SECONDS=2.5,
    )
    @patch("surveys.geolocation._http_session")
    def test_remote_lookup_uses_the_pooled_session(self, session_factory):
        response = Mock()
        response.json.return_value = {
            "country_code": "IN",
            "country": "India",
            "postal": "110001",
        }
        session_factory.return_value.get.return_value = response

        result = geolocation._from_http("203.0.113.9")

        self.assertEqual(result["country_code"], "IN")
        session_factory.return_value.get.assert_called_once_with(
            "https://geo.example.test/203.0.113.9",
            timeout=2.5,
            headers={"Accept": "application/json", "User-Agent": "ExchangeHub/1.0"},
        )

    @patch("geoip2.database.Reader")
    def test_maxmind_reader_is_reused_and_reopened_only_after_file_change(self, reader_class):
        first_reader = Mock()
        second_reader = Mock()
        reader_class.side_effect = [first_reader, second_reader]

        with TemporaryDirectory() as directory:
            database_path = Path(directory) / "GeoLite2-City.mmdb"
            database_path.write_bytes(b"test-database")
            initial_stat = database_path.stat()
            with (
                patch.object(geolocation, "_maxmind_identity", None),
                patch.object(geolocation, "_maxmind_slot", None),
            ):
                geolocation._maxmind_city(database_path, "203.0.113.1")
                geolocation._maxmind_city(database_path, "203.0.113.2")

                os.utime(
                    database_path,
                    ns=(initial_stat.st_atime_ns, initial_stat.st_mtime_ns + 1_000_000_000),
                )
                geolocation._maxmind_city(database_path, "203.0.113.3")

        self.assertEqual(reader_class.call_count, 2)
        self.assertEqual(first_reader.city.call_count, 2)
        first_reader.close.assert_called_once_with()
        second_reader.city.assert_called_once_with("203.0.113.3")

    @patch("geoip2.database.Reader")
    def test_reader_replacement_does_not_close_an_inflight_lookup(self, reader_class):
        lookup_started = threading.Event()
        finish_lookup = threading.Event()
        first_reader = Mock()
        second_reader = Mock()

        def blocking_lookup(_ip_value):
            lookup_started.set()
            finish_lookup.wait(timeout=5)
            return Mock()

        first_reader.city.side_effect = blocking_lookup
        second_reader.city.return_value = Mock()
        reader_class.side_effect = [first_reader, second_reader]

        with TemporaryDirectory() as directory:
            database_path = Path(directory) / "GeoLite2-City.mmdb"
            database_path.write_bytes(b"test-database")
            initial_stat = database_path.stat()
            with (
                patch.object(geolocation, "_maxmind_identity", None),
                patch.object(geolocation, "_maxmind_slot", None),
            ):
                worker = threading.Thread(
                    target=geolocation._maxmind_city,
                    args=(database_path, "203.0.113.1"),
                )
                worker.start()
                self.assertTrue(lookup_started.wait(timeout=2))
                try:
                    os.utime(
                        database_path,
                        ns=(
                            initial_stat.st_atime_ns,
                            initial_stat.st_mtime_ns + 1_000_000_000,
                        ),
                    )
                    geolocation._maxmind_city(database_path, "203.0.113.2")
                    first_reader.close.assert_not_called()
                finally:
                    finish_lookup.set()
                    worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        first_reader.close.assert_called_once_with()
