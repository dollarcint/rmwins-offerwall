import json
from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from django.test import RequestFactory, TestCase, override_settings
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone

from surveys.models import Survey, SurveyAttempt
from vendors.models import Client

from .models import (
    OfferClick,
    OfferOverride,
    PostbackDelivery,
    Publisher,
    PublisherPayoutRequest,
    RewardLedgerEntry,
    WallVisit,
)
from .security import (
    decrypt_signing_secret,
    sign_click,
    sign_entry,
    sign_portal_access,
    sign_result,
    sign_session,
)
from .services import (
    create_offer_click,
    create_wall_visit,
    offer_catalog,
    process_attempt_outcome,
)
from .tasks import _validated_callback_url, deliver_postback_task
from .wallet import request_withdrawal, transition_payout, wallet_summary


OFFERWALL_SETTINGS = {
    "OFFERWALL_ENABLED": True,
    "OFFERWALL_PUBLIC_BASE_URL": "http://testserver",
    "PUBLIC_APP_BASE_URL": "http://testserver",
    "OFFERWALL_ENTRY_TTL_SECONDS": 900,
    "OFFERWALL_ENTRY_FUTURE_SKEW_SECONDS": 60,
    "OFFERWALL_VISIT_TTL_SECONDS": 7200,
    "OFFERWALL_ENTRY_RATE_LIMIT_PER_MINUTE": 1000,
    "OFFERWALL_API_RATE_LIMIT_PER_MINUTE": 1000,
    "OFFERWALL_PORTAL_LINK_TTL_SECONDS": 900,
    "OFFERWALL_PORTAL_SESSION_TTL_SECONDS": 43200,
    "OFFERWALL_MINIMUM_PAYOUT": Decimal("1.00"),
}


@override_settings(**OFFERWALL_SETTINGS)
class OfferwallFlowTests(TestCase):
    def setUp(self):
        self.publisher = Publisher.objects.create(
            name="Acme Rewards",
            slug="acme-rewards",
            payout_percent=Decimal("70.00"),
        )
        self.api_key = self.publisher._generated_api_key
        self.client_record = Client.objects.create(
            code="manual-buyer", name="Manual Buyer", provider_code="manual"
        )
        self.survey = Survey.objects.create(
            client=self.client_record,
            source_key="manual-offer-1",
            inventory_source=Survey.InventorySource.MANUAL,
            company_name="Manual Buyer",
            name="Consumer technology survey",
            status=Survey.Status.LIVE,
            sample_size=100,
            remaining=80,
            cpi=Decimal("5.00"),
            loi=8,
            incidence_rate=Decimal("45.00"),
            country_code="US",
            survey_type="B2C",
            device_type="All",
            entry_link="https://surveys.example.test/start?rid=placeholder",
            manual_rid_parameter="rid",
        )
        self.factory = RequestFactory()

    def _visit(self, *, user_id="user-100", nonce="nonce_for_test_12345"):
        return create_wall_visit(
            self.publisher,
            external_user_id=user_id,
            nonce=nonce,
            entry_timestamp=timezone.now(),
        )

    def _click(self, *, visit=None):
        visit = visit or self._visit()
        request = self.factory.get("/", HTTP_USER_AGENT="Mozilla/5.0")
        return create_offer_click(visit=visit, survey=self.survey, request=request)[0]

    def test_publisher_generates_one_way_api_key_and_encrypted_signing_secret(self):
        self.assertTrue(self.api_key.startswith("ow_live_"))
        self.assertNotIn(self.api_key, self.publisher.api_key_hash)
        raw_secret = decrypt_signing_secret(self.publisher)
        self.assertGreaterEqual(len(raw_secret), 32)
        self.assertNotEqual(self.publisher.encrypted_signing_secret, raw_secret)

    def test_signed_entry_creates_canonical_session_and_rejects_tampering(self):
        timestamp = int(timezone.now().timestamp())
        nonce = "publisher_nonce_12345"
        signature = sign_entry(
            self.publisher,
            external_user_id="member-7",
            timestamp=timestamp,
            nonce=nonce,
        )
        entry = reverse("offerwall:entry", kwargs={"publisher_slug": self.publisher.slug})
        response = self.client.get(
            entry,
            {"uid": "member-7", "ts": timestamp, "nonce": nonce, "sig": signature},
        )
        self.assertEqual(response.status_code, 302)
        visit = WallVisit.objects.get()
        self.assertIn(str(visit.public_id), response["Location"])
        self.assertIn("sig=", response["Location"])

        tampered = self.client.get(
            entry,
            {"uid": "member-8", "ts": timestamp, "nonce": nonce, "sig": signature},
        )
        self.assertEqual(tampered.status_code, 403)
        self.assertEqual(WallVisit.objects.count(), 1)

    def test_expired_entry_is_rejected(self):
        timestamp = int((timezone.now() - timedelta(hours=1)).timestamp())
        nonce = "expired_nonce_12345"
        signature = sign_entry(
            self.publisher,
            external_user_id="member-7",
            timestamp=timestamp,
            nonce=nonce,
        )
        response = self.client.get(
            reverse("offerwall:entry", kwargs={"publisher_slug": self.publisher.slug}),
            {"uid": "member-7", "ts": timestamp, "nonce": nonce, "sig": signature},
        )
        self.assertEqual(response.status_code, 403)

    def test_catalog_defaults_to_all_live_eligible_offers_and_allows_exclusion(self):
        visit = self._visit()
        offers = offer_catalog(self.publisher, visit)
        self.assertEqual([offer["id"] for offer in offers], [self.survey.local_id])
        self.assertEqual(offers[0]["reward"], Decimal("3.50"))

        OfferOverride.objects.create(
            publisher=self.publisher, survey=self.survey, is_excluded=True
        )
        self.assertEqual(offer_catalog(self.publisher, visit), [])

    def test_override_changes_title_reward_and_featured_sort(self):
        visit = self._visit()
        OfferOverride.objects.create(
            publisher=self.publisher,
            survey=self.survey,
            title_override="Premium study",
            payout_percent_override=Decimal("80.00"),
            featured=True,
        )
        offer = offer_catalog(self.publisher, visit)[0]
        self.assertEqual(offer["title"], "Premium study")
        self.assertEqual(offer["reward"], Decimal("4.00"))
        self.assertTrue(offer["featured"])

    def test_signed_click_creates_attribution_and_is_idempotent(self):
        visit = self._visit()
        signature = sign_click(self.publisher, visit.public_id, self.survey.local_id)
        url = reverse(
            "offerwall:click",
            kwargs={"visit_id": visit.public_id, "survey_id": self.survey.local_id},
        )
        first = self.client.get(url, {"sig": signature})
        second = self.client.get(url, {"sig": signature})
        self.assertEqual(first.status_code, 302)
        self.assertEqual(second.status_code, 302)
        self.assertEqual(OfferClick.objects.count(), 1)
        self.assertEqual(SurveyAttempt.objects.count(), 1)
        click = OfferClick.objects.get()
        self.assertEqual(click.external_user_id, "user-100")
        self.assertEqual(click.payout_snapshot, Decimal("3.50"))
        self.assertTrue(click.publisher.service_user_id)
        self.assertIn(click.attempt.rid, first["Location"])

    def test_verified_completion_credits_once_and_unverified_completion_does_not(self):
        click = self._click()
        click.attempt.status = SurveyAttempt.Status.COMPLETED
        click.attempt.status_source = "innovatemr_s2s"
        click.attempt.is_verified = False
        click.attempt.save(update_fields=["status", "status_source", "is_verified", "updated_at"])
        process_attempt_outcome(click.attempt_id)
        self.assertFalse(RewardLedgerEntry.objects.exists())

        click.attempt.is_verified = True
        click.attempt.save(update_fields=["is_verified", "updated_at"])
        process_attempt_outcome(click.attempt_id)
        process_attempt_outcome(click.attempt_id)
        credit = RewardLedgerEntry.objects.get(entry_type=RewardLedgerEntry.EntryType.CREDIT)
        self.assertEqual(credit.amount, Decimal("3.50"))
        self.assertEqual(RewardLedgerEntry.objects.count(), 1)
        delivery = PostbackDelivery.objects.get(event_type="complete")
        self.assertEqual(delivery.status, PostbackDelivery.Status.SKIPPED)
        self.assertTrue(delivery.payload["credited"])

    def test_same_publisher_user_and_offer_cannot_receive_second_credit(self):
        first_click = self._click()
        second_visit = self._visit(nonce="second_nonce_for_test", user_id="user-100")
        second_click = self._click(visit=second_visit)

        first_click.attempt.status = SurveyAttempt.Status.COMPLETED
        first_click.attempt.status_source = "innovatemr_s2s"
        first_click.attempt.is_verified = True
        first_click.attempt.save(update_fields=["status", "status_source", "is_verified", "updated_at"])
        process_attempt_outcome(first_click.attempt_id)

        second_click.attempt.status = SurveyAttempt.Status.COMPLETED
        second_click.attempt.status_source = "innovatemr_s2s"
        second_click.attempt.is_verified = True
        second_click.attempt.save(update_fields=["status", "status_source", "is_verified", "updated_at"])
        process_attempt_outcome(second_click.attempt_id)

        self.assertEqual(
            RewardLedgerEntry.objects.filter(entry_type="credit").count(), 1
        )
        second_delivery = PostbackDelivery.objects.get(
            click=second_click, event_type="complete"
        )
        self.assertFalse(second_delivery.payload["credited"])
        self.assertEqual(offer_catalog(self.publisher, second_visit), [])

    def test_reversal_payload_contains_negative_amount(self):
        click = self._click()
        click.attempt.status = SurveyAttempt.Status.COMPLETED
        click.attempt.status_source = "innovatemr_s2s"
        click.attempt.is_verified = True
        click.attempt.save(update_fields=["status", "status_source", "is_verified", "updated_at"])
        process_attempt_outcome(click.attempt_id)

        click.attempt.status = SurveyAttempt.Status.QUALITY_TERMINATED
        click.attempt.status_source = "innovatemr_s2s"
        click.attempt.save(update_fields=["status", "status_source", "updated_at"])
        process_attempt_outcome(click.attempt_id)
        reversal = RewardLedgerEntry.objects.get(entry_type="reversal")
        delivery = PostbackDelivery.objects.get(click=click, event_type="reversal")
        self.assertEqual(reversal.amount, Decimal("3.50"))
        self.assertEqual(delivery.payload["amount"], "-3.50")

    def test_result_page_requires_signature(self):
        click = self._click()
        url = reverse("offerwall:result", kwargs={"click_id": click.public_id})
        self.assertEqual(self.client.get(url, {"sig": "0" * 64}).status_code, 403)
        response = self.client.get(url, {"sig": sign_result(self.publisher, click.public_id)})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Result pending")

    def test_inventory_api_authenticates_and_returns_signed_clicks(self):
        unauthorized = self.client.get(reverse("offerwall:offers-api"), {"uid": "member-7"})
        self.assertEqual(unauthorized.status_code, 401)
        response = self.client.get(
            reverse("offerwall:offers-api"),
            {"uid": "member-7"},
            HTTP_X_OFFERWALL_KEY=self.api_key,
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["publisher"]["slug"], self.publisher.slug)
        self.assertEqual(len(payload["offers"]), 1)
        parsed = urlsplit(payload["offers"][0]["click_url"])
        self.assertEqual(len(parse_qs(parsed.query)["sig"][0]), 64)

    def test_anonymous_root_is_offerwall_landing(self):
        response = self.client.get(reverse("home"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Publisher-powered survey inventory")

    def _credit_click(self):
        click = self._click()
        click.attempt.status = SurveyAttempt.Status.COMPLETED
        click.attempt.status_source = "innovatemr_s2s"
        click.attempt.is_verified = True
        click.attempt.save(
            update_fields=["status", "status_source", "is_verified", "updated_at"]
        )
        process_attempt_outcome(click.attempt_id)
        return click

    def test_wallet_reserves_withdrawal_and_tracks_paid_balance(self):
        self._credit_click()
        initial = wallet_summary(self.publisher)
        self.assertEqual(initial["net_earnings"], Decimal("3.50"))
        self.assertEqual(initial["available"], Decimal("3.50"))

        payout = request_withdrawal(
            self.publisher,
            amount="2.00",
            payout_method="Bank transfer",
            publisher_note="Primary account",
        )
        reserved = wallet_summary(self.publisher)
        self.assertEqual(reserved["reserved"], Decimal("2.00"))
        self.assertEqual(reserved["available"], Decimal("1.50"))

        payout = transition_payout(payout, PublisherPayoutRequest.Status.APPROVED)
        payout = transition_payout(payout, PublisherPayoutRequest.Status.PROCESSING)
        with self.assertRaisesMessage(ValidationError, "payment reference"):
            transition_payout(payout, PublisherPayoutRequest.Status.PAID)
        transition_payout(
            payout,
            PublisherPayoutRequest.Status.PAID,
            payment_reference="BANK-123",
        )
        paid = wallet_summary(self.publisher)
        self.assertEqual(paid["reserved"], Decimal("0.00"))
        self.assertEqual(paid["paid"], Decimal("2.00"))
        self.assertEqual(paid["available"], Decimal("1.50"))

    def test_rejected_withdrawal_releases_balance_and_overspend_is_blocked(self):
        self._credit_click()
        with self.assertRaisesMessage(ValidationError, "exceeds"):
            request_withdrawal(
                self.publisher, amount="4.00", payout_method="Wise"
            )
        payout = request_withdrawal(
            self.publisher, amount="3.00", payout_method="Wise"
        )
        self.assertEqual(wallet_summary(self.publisher)["available"], Decimal("0.50"))
        transition_payout(payout, PublisherPayoutRequest.Status.REJECTED)
        self.assertEqual(wallet_summary(self.publisher)["available"], Decimal("3.50"))

    def test_signed_portal_access_is_one_time_and_creates_private_session(self):
        timestamp = int(timezone.now().timestamp())
        nonce = "portal_nonce_unique_123"
        signature = sign_portal_access(
            self.publisher, timestamp=timestamp, nonce=nonce
        )
        access_url = reverse(
            "offerwall:publisher-access",
            kwargs={"publisher_slug": self.publisher.slug},
        )
        params = {"ts": timestamp, "nonce": nonce, "sig": signature}
        response = self.client.get(access_url, params)
        self.assertRedirects(
            response, reverse("offerwall:publisher-dashboard"), fetch_redirect_response=False
        )
        dashboard = self.client.get(reverse("offerwall:publisher-dashboard"))
        self.assertEqual(dashboard.status_code, 200)
        self.assertContains(dashboard, "Available balance")
        self.assertContains(dashboard, self.publisher.name)

        replay_client = self.client_class()
        replay = replay_client.get(access_url, params)
        self.assertEqual(replay.status_code, 403)

    def test_portal_rejects_expired_or_tampered_access(self):
        timestamp = int((timezone.now() - timedelta(hours=1)).timestamp())
        nonce = "expired_portal_nonce_123"
        signature = sign_portal_access(
            self.publisher, timestamp=timestamp, nonce=nonce
        )
        url = reverse(
            "offerwall:publisher-access",
            kwargs={"publisher_slug": self.publisher.slug},
        )
        self.assertEqual(
            self.client.get(
                url, {"ts": timestamp, "nonce": nonce, "sig": signature}
            ).status_code,
            403,
        )
        current = int(timezone.now().timestamp())
        self.assertEqual(
            self.client.get(
                url,
                {
                    "ts": current,
                    "nonce": "tampered_portal_nonce",
                    "sig": "0" * 64,
                },
            ).status_code,
            403,
        )

    def test_portal_submits_withdrawal_and_wallet_api_reports_it(self):
        self._credit_click()
        timestamp = int(timezone.now().timestamp())
        nonce = "withdraw_portal_nonce_123"
        access_url = reverse(
            "offerwall:publisher-access",
            kwargs={"publisher_slug": self.publisher.slug},
        )
        self.client.get(
            access_url,
            {
                "ts": timestamp,
                "nonce": nonce,
                "sig": sign_portal_access(
                    self.publisher, timestamp=timestamp, nonce=nonce
                ),
            },
        )
        response = self.client.post(
            reverse("offerwall:publisher-withdrawal"),
            {
                "amount": "2.50",
                "payout_method": "PayPal",
                "publisher_note": "Finance account",
            },
        )
        self.assertRedirects(
            response, reverse("offerwall:publisher-dashboard"), fetch_redirect_response=False
        )
        payout = PublisherPayoutRequest.objects.get()
        self.assertEqual(payout.amount, Decimal("2.50"))
        self.assertEqual(payout.status, PublisherPayoutRequest.Status.PENDING)

        api_response = self.client.get(
            reverse("offerwall:wallet-api"),
            HTTP_X_OFFERWALL_KEY=self.api_key,
        )
        self.assertEqual(api_response.status_code, 200)
        payload = api_response.json()
        self.assertEqual(payload["wallet"]["available"], "1.00")
        self.assertEqual(payload["payout_requests"][0]["id"], str(payout.public_id))


@override_settings(
    DEBUG=False,
    OFFERWALL_POSTBACK_TIMEOUT_SECONDS=3,
    OFFERWALL_POSTBACK_MAX_ATTEMPTS=2,
)
class OfferwallPostbackSecurityTests(TestCase):
    def setUp(self):
        self.publisher = Publisher.objects.create(
            name="Secure Publisher",
            slug="secure-publisher",
            callback_url="https://publisher.example.test/postback",
            postback_enabled=True,
        )
        client_record = Client.objects.create(code="buyer", name="Buyer")
        survey = Survey.objects.create(
            client=client_record,
            source_key="secure-1",
            inventory_source=Survey.InventorySource.MANUAL,
            name="Secure survey",
            remaining=10,
            cpi=Decimal("2.00"),
            entry_link="https://surveys.example.test/start",
        )
        visit = create_wall_visit(
            self.publisher,
            external_user_id="member-9",
            nonce="security_nonce_12345",
            entry_timestamp=timezone.now(),
        )
        request = RequestFactory().get("/", HTTP_USER_AGENT="Mozilla/5.0")
        self.click = create_offer_click(visit=visit, survey=survey, request=request)[0]
        self.delivery = PostbackDelivery.objects.create(
            publisher=self.publisher,
            click=self.click,
            event_type="complete",
            callback_url=self.publisher.callback_url,
            payload={"event": "complete", "event_id": "test-event"},
        )

    @patch("offerwall.tasks.socket.getaddrinfo")
    def test_private_callback_resolution_is_blocked(self, getaddrinfo):
        getaddrinfo.return_value = [(2, 1, 6, "", ("127.0.0.1", 443))]
        with self.assertRaisesMessage(ValueError, "non-public"):
            _validated_callback_url(self.publisher.callback_url)

    @patch("offerwall.tasks.requests.post")
    @patch("offerwall.tasks.socket.getaddrinfo")
    def test_postback_is_signed_and_delivered_without_redirects(self, getaddrinfo, post):
        getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
        post.return_value.status_code = 204
        result = deliver_postback_task(self.delivery.pk)
        self.assertEqual(result["status"], "delivered")
        kwargs = post.call_args.kwargs
        self.assertFalse(kwargs["allow_redirects"])
        self.assertEqual(kwargs["timeout"], 3)
        self.assertTrue(kwargs["headers"]["X-Offerwall-Signature"].startswith("sha256="))
        self.assertEqual(json.loads(kwargs["data"]), self.delivery.payload)
        self.delivery.refresh_from_db()
        self.assertEqual(self.delivery.status, PostbackDelivery.Status.DELIVERED)
        self.assertEqual(self.delivery.attempt_count, 1)
