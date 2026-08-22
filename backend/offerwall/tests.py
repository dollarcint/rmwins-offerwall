from datetime import timedelta
from decimal import Decimal
import re
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

from django.contrib.auth import get_user_model
from django.core import mail
from django.test import RequestFactory, TestCase, override_settings
from django.core.exceptions import ValidationError
from django.urls import reverse
from django.utils import timezone

from surveys.models import Survey, SurveyAttempt
from vendors.models import Client

from .models import (
    OfferClick,
    OfferConversion,
    OfferConversionEvent,
    OfferOverride,
    OfferwallAdminPortalAccount,
    PlacementEventPostback,
    PostbackDelivery,
    Publisher,
    PublisherPlacement,
    PublisherPortalAccount,
    PublisherPayoutRequest,
    RespondentProfile,
    RewardLedgerEntry,
    WallVisit,
)
from .security import (
    decrypt_placement_postback_secret,
    decrypt_signing_secret,
    sign_click,
    sign_entry,
    sign_portal_access,
    sign_result,
    sign_session,
)
from .services import (
    approve_conversion,
    create_offer_click,
    create_wall_visit,
    offer_catalog,
    process_attempt_outcome,
    reject_conversion,
    release_due_conversions,
    session_url,
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
    "OFFERWALL_VERIFICATION_TTL_SECONDS": 900,
    "OFFERWALL_VERIFICATION_RESEND_SECONDS": 60,
    "OFFERWALL_VERIFICATION_MAX_ATTEMPTS": 5,
    "OFFERWALL_RESPONDENT_STATE_TTL_SECONDS": 7200,
    "EMAIL_BACKEND": "django.core.mail.backends.locmem.EmailBackend",
    "DEFAULT_FROM_EMAIL": "test@rmwins.example",
}


@override_settings(**OFFERWALL_SETTINGS)
class OfferwallFlowTests(TestCase):
    def setUp(self):
        self.publisher = Publisher.objects.create(
            name="Acme Rewards",
            slug="acme-rewards",
            payout_percent=Decimal("70.00"),
            reward_hold_hours=0,
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

    def _verified_respondent(self, *, sid, placement, email=None):
        profile = RespondentProfile(
            publisher=self.publisher,
            external_user_id=sid,
            age=30,
            gender=RespondentProfile.Gender.PREFER_NOT_TO_SAY,
            first_placement=placement,
            last_placement=placement,
            is_email_verified=True,
            email_verified_at=timezone.now(),
        )
        profile.set_identity(
            full_name=f"Respondent {sid}",
            email=email or f"{sid}@respondent.example",
        )
        profile.save()
        return profile

    def test_publisher_generates_one_way_api_key_and_encrypted_signing_secret(self):
        self.assertTrue(self.api_key.startswith("ow_live_"))
        self.assertNotIn(self.api_key, self.publisher.api_key_hash)
        raw_secret = decrypt_signing_secret(self.publisher)
        self.assertGreaterEqual(len(raw_secret), 32)
        self.assertNotEqual(self.publisher.encrypted_signing_secret, raw_secret)

    def test_publisher_codes_use_a_dedicated_sequential_database_number(self):
        second = Publisher.objects.create(
            name="Second Publisher",
            slug="second-publisher",
        )
        self.assertEqual(self.publisher.publisher_number, 1)
        self.assertEqual(self.publisher.publisher_code, "1")
        self.assertEqual(second.publisher_number, 2)
        self.assertEqual(second.publisher_code, "2")

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

    def test_saved_iframe_visit_requires_country_and_uses_strict_market_filter(self):
        placement = PublisherPlacement.objects.create(
            publisher=self.publisher,
            name="Country guarded wall",
            website_name="Country Site",
            website_url="https://country.example.test",
        )
        unknown_profile = self._verified_respondent(
            sid="unknown-country-user",
            placement=placement,
        )
        unknown_visit = create_wall_visit(
            self.publisher,
            external_user_id="unknown-country-user",
            nonce="unknown_country_nonce",
            entry_timestamp=timezone.now(),
            placement=placement,
            respondent=unknown_profile,
        )
        self.assertEqual(offer_catalog(self.publisher, unknown_visit), [])

        india_profile = self._verified_respondent(
            sid="india-user",
            placement=placement,
        )
        wrong_country_visit = create_wall_visit(
            self.publisher,
            external_user_id="india-user",
            nonce="india_country_nonce",
            entry_timestamp=timezone.now(),
            placement=placement,
            respondent=india_profile,
        )
        wrong_country_visit.country_code = "IN"
        wrong_country_visit.save(update_fields=["country_code"])
        self.assertEqual(offer_catalog(self.publisher, wrong_country_visit), [])

        us_profile = self._verified_respondent(
            sid="us-user",
            placement=placement,
        )
        matching_visit = create_wall_visit(
            self.publisher,
            external_user_id="us-user",
            nonce="us_country_nonce",
            entry_timestamp=timezone.now(),
            placement=placement,
            respondent=us_profile,
        )
        matching_visit.country_code = "US"
        matching_visit.save(update_fields=["country_code"])
        self.assertEqual(
            [offer["id"] for offer in offer_catalog(self.publisher, matching_visit)],
            [self.survey.local_id],
        )

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

    def test_reward_hold_keeps_balance_pending_until_scheduler_release(self):
        self.publisher.reward_hold_hours = 24
        self.publisher.save(update_fields=["reward_hold_hours", "updated_at"])
        click = self._click()
        click.attempt.status = SurveyAttempt.Status.COMPLETED
        click.attempt.status_source = "innovatemr_s2s"
        click.attempt.is_verified = True
        click.attempt.save(
            update_fields=["status", "status_source", "is_verified", "updated_at"]
        )
        process_attempt_outcome(click.attempt_id)

        conversion = OfferConversion.objects.get(click=click)
        credit = RewardLedgerEntry.objects.get(
            click=click, entry_type=RewardLedgerEntry.EntryType.CREDIT
        )
        self.assertEqual(conversion.status, OfferConversion.Status.PENDING)
        self.assertEqual(credit.status, RewardLedgerEntry.Status.PENDING)
        self.assertFalse(PostbackDelivery.objects.filter(click=click).exists())
        pending_wallet = wallet_summary(self.publisher)
        self.assertEqual(pending_wallet["pending"], Decimal("3.50"))
        self.assertEqual(pending_wallet["available"], Decimal("0.00"))

        conversion.hold_until = timezone.now() - timedelta(seconds=1)
        conversion.save(update_fields=["hold_until", "updated_at"])
        self.assertEqual(release_due_conversions(), 1)
        self.assertEqual(release_due_conversions(), 0)

        conversion.refresh_from_db()
        credit.refresh_from_db()
        click.refresh_from_db()
        self.assertEqual(conversion.status, OfferConversion.Status.APPROVED)
        self.assertEqual(credit.status, RewardLedgerEntry.Status.AVAILABLE)
        self.assertIsNotNone(credit.released_at)
        self.assertIsNotNone(click.credited_at)
        self.assertTrue(
            PostbackDelivery.objects.filter(click=click, event_type="complete").exists()
        )
        released_wallet = wallet_summary(self.publisher)
        self.assertEqual(released_wallet["pending"], Decimal("0.00"))
        self.assertEqual(released_wallet["available"], Decimal("3.50"))

    def test_manual_rejection_voids_pending_reward_with_audit_events(self):
        self.publisher.reward_hold_hours = 24
        self.publisher.risk_review_threshold = 10
        self.publisher.save(
            update_fields=[
                "reward_hold_hours",
                "risk_review_threshold",
                "updated_at",
            ]
        )
        click = self._click()
        click.attempt.status = SurveyAttempt.Status.COMPLETED
        click.attempt.status_source = "innovatemr_s2s"
        click.attempt.is_verified = True
        click.attempt.save(
            update_fields=["status", "status_source", "is_verified", "updated_at"]
        )
        process_attempt_outcome(click.attempt_id)
        conversion = OfferConversion.objects.get(click=click)
        self.assertTrue(conversion.requires_manual_review)
        self.assertGreaterEqual(conversion.risk_score, 10)

        reject_conversion(conversion.pk, reason="Velocity review failed")
        conversion.refresh_from_db()
        credit = RewardLedgerEntry.objects.get(
            click=click, entry_type=RewardLedgerEntry.EntryType.CREDIT
        )
        self.assertEqual(conversion.status, OfferConversion.Status.REJECTED)
        self.assertEqual(credit.status, RewardLedgerEntry.Status.VOIDED)
        self.assertTrue(
            RewardLedgerEntry.objects.filter(
                click=click, entry_type=RewardLedgerEntry.EntryType.REVERSAL
            ).exists()
        )
        self.assertEqual(wallet_summary(self.publisher)["available"], Decimal("0.00"))
        self.assertEqual(
            list(conversion.events.values_list("event_type", flat=True)),
            [OfferConversionEvent.EventType.CREATED, OfferConversionEvent.EventType.REJECTED],
        )
        with self.assertRaisesMessage(ValueError, "rejected"):
            approve_conversion(conversion.pk)
        process_attempt_outcome(click.attempt_id)
        self.assertEqual(
            RewardLedgerEntry.objects.filter(click=click).count(),
            2,
        )

    def test_admin_conversion_queue_can_release_manual_review(self):
        self.publisher.reward_hold_hours = 24
        self.publisher.risk_review_threshold = 0
        self.publisher.save(
            update_fields=[
                "reward_hold_hours",
                "risk_review_threshold",
                "updated_at",
            ]
        )
        click = self._click()
        click.attempt.status = SurveyAttempt.Status.COMPLETED
        click.attempt.status_source = "innovatemr_s2s"
        click.attempt.is_verified = True
        click.attempt.save(
            update_fields=["status", "status_source", "is_verified", "updated_at"]
        )
        process_attempt_outcome(click.attempt_id)
        conversion = OfferConversion.objects.get(click=click)
        admin_user = get_user_model().objects.create_user(
            username="conversion-admin",
            password="Conversion-Admin-9472",
            is_staff=True,
        )
        OfferwallAdminPortalAccount.objects.create(
            user=admin_user, must_change_password=False
        )
        self.client.post(
            reverse("offerwall:admin-login"),
            {"username": admin_user.username, "password": "Conversion-Admin-9472"},
        )
        queue = self.client.get(reverse("offerwall:admin-conversions"))
        self.assertEqual(queue.status_code, 200)
        self.assertContains(queue, conversion.source_transaction_id)
        self.assertContains(queue, "Manual review")

        response = self.client.post(
            reverse("offerwall:admin-conversions"),
            {
                "conversion_id": conversion.public_id,
                "action": "approve",
                "reason": "Reviewed against provider record",
            },
        )
        self.assertRedirects(
            response,
            reverse("offerwall:admin-conversions"),
            fetch_redirect_response=False,
        )
        conversion.refresh_from_db()
        self.assertEqual(conversion.status, OfferConversion.Status.APPROVED)
        self.assertEqual(conversion.decided_by, admin_user)
        self.assertEqual(wallet_summary(self.publisher)["available"], Decimal("3.50"))

    def test_result_page_requires_signature(self):
        click = self._click()
        url = reverse("offerwall:result", kwargs={"click_id": click.public_id})
        self.assertEqual(self.client.get(url, {"sig": "0" * 64}).status_code, 403)
        response = self.client.get(url, {"sig": sign_result(self.publisher, click.public_id)})
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Result pending")

    def test_inventory_api_authenticates_and_returns_signed_clicks(self):
        placement = PublisherPlacement.objects.create(
            publisher=self.publisher,
            name="API wall",
            website_name="API Site",
            website_url="https://api-site.example.test",
        )
        query = {
            "pubid": self.publisher.publisher_code,
            "app_id": placement.app_id,
        }
        unauthorized = self.client.get(reverse("offerwall:offers-api"), query)
        self.assertEqual(unauthorized.status_code, 401)
        response = self.client.get(
            reverse("offerwall:offers-api"),
            query,
            HTTP_X_OFFERWALL_KEY=self.api_key,
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["code"], 200)
        self.assertEqual(payload["data"]["query"]["pubid"], self.publisher.publisher_code)
        self.assertEqual(payload["data"]["query"]["appid"], placement.app_id)
        self.assertRegex(placement.app_id, r"^RMW_APP_[0-9A-F]{32}$")
        offers = payload["data"]["response"]["offers"]
        self.assertEqual(len(offers), 1)
        parsed = urlsplit(offers[0]["offer_url_easy"])
        self.assertEqual(parse_qs(parsed.query)["app_id"], [placement.app_id])
        self.assertEqual(parse_qs(parsed.query)["uid"], ["{SID}"])

    def test_anonymous_root_is_offerwall_landing(self):
        response = self.client.get(reverse("home"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Create supplier account")
        self.assertContains(response, reverse("offerwall:supplier-login"))
        self.assertContains(response, reverse("offerwall:supplier-signup"))

    def test_offerwall_admin_login_requires_portal_membership_and_forces_password_change(self):
        admin_user = get_user_model().objects.create_user(
            username="admin-portal-owner",
            email="admin@rmwins.example",
            password="Temporary-Admin-9831",
            is_staff=True,
            is_superuser=True,
        )
        account = OfferwallAdminPortalAccount.objects.create(user=admin_user)

        response = self.client.post(
            reverse("offerwall:admin-login"),
            {
                "username": admin_user.username,
                "password": "Temporary-Admin-9831",
            },
        )
        self.assertRedirects(
            response,
            reverse("offerwall:admin-password-change"),
            fetch_redirect_response=False,
        )
        self.assertNotIn("_auth_user_id", self.client.session)
        self.assertRedirects(
            self.client.get(reverse("offerwall:admin-dashboard")),
            reverse("offerwall:admin-password-change"),
            fetch_redirect_response=False,
        )

        weak = self.client.post(
            reverse("offerwall:admin-password-change"),
            {
                "current_password": "Temporary-Admin-9831",
                "new_password1": "short1",
                "new_password2": "short1",
            },
        )
        self.assertEqual(weak.status_code, 200)
        self.assertContains(weak, "Use at least 12 characters")

        changed = self.client.post(
            reverse("offerwall:admin-password-change"),
            {
                "current_password": "Temporary-Admin-9831",
                "new_password1": "Private-RMWins-4086",
                "new_password2": "Private-RMWins-4086",
            },
        )
        self.assertRedirects(
            changed,
            reverse("offerwall:admin-dashboard"),
            fetch_redirect_response=False,
        )
        account.refresh_from_db()
        self.assertFalse(account.must_change_password)
        self.assertTrue(admin_user.__class__.objects.get(pk=admin_user.pk).check_password("Private-RMWins-4086"))

        dashboard = self.client.get(reverse("offerwall:admin-dashboard"))
        self.assertEqual(dashboard.status_code, 200)
        self.assertContains(dashboard, "Offerwall performance")
        self.assertContains(dashboard, reverse("offerwall:admin-inventory"))
        self.assertContains(dashboard, reverse("offerwall:admin-suppliers"))
        self.assertContains(dashboard, reverse("offerwall:admin-activity"))

    def test_offerwall_admin_login_rejects_supplier_and_unregistered_staff_accounts(self):
        supplier_user = get_user_model().objects.create_user(
            username="admin-route-supplier",
            email="supplier-admin-route@example.test",
            password="Supplier-Password-9472",
        )
        supplier_publisher = Publisher.objects.create(
            name="Admin Route Supplier",
            slug="admin-route-supplier",
            is_active=True,
        )
        PublisherPortalAccount.objects.create(
            user=supplier_user,
            publisher=supplier_publisher,
            contact_name="Supplier Owner",
            business_email="supplier-admin-route@example.test",
            phone="+1 555 0100",
            country="United States",
            status=PublisherPortalAccount.Status.APPROVED,
        )
        staff_user = get_user_model().objects.create_user(
            username="legacy-staff-only",
            password="Legacy-Staff-9472",
            is_staff=True,
        )

        for username, password in (
            (supplier_user.username, "Supplier-Password-9472"),
            (staff_user.username, "Legacy-Staff-9472"),
        ):
            response = self.client.post(
                reverse("offerwall:admin-login"),
                {"username": username, "password": password},
            )
            self.assertEqual(response.status_code, 200)
            self.assertContains(response, "Username or password is incorrect")
            self.assertRedirects(
                self.client.get(reverse("offerwall:admin-dashboard")),
                reverse("offerwall:admin-login"),
                fetch_redirect_response=False,
            )

    def test_offerwall_admin_modules_show_inventory_activity_and_update_cut(self):
        admin_user = get_user_model().objects.create_user(
            username="dashboard-admin",
            password="Dashboard-Admin-9472",
            is_staff=True,
        )
        OfferwallAdminPortalAccount.objects.create(
            user=admin_user,
            must_change_password=False,
        )
        self.client.post(
            reverse("offerwall:admin-login"),
            {"username": admin_user.username, "password": "Dashboard-Admin-9472"},
        )
        click = self._click()
        click.status = SurveyAttempt.Status.COMPLETED
        click.is_verified = True
        click.source_cpi_snapshot = Decimal("5.00")
        click.payout_snapshot = Decimal("3.50")
        click.save(
            update_fields=[
                "status",
                "is_verified",
                "source_cpi_snapshot",
                "payout_snapshot",
                "updated_at",
            ]
        )

        dashboard = self.client.get(reverse("offerwall:admin-dashboard"), {"range": "30d"})
        self.assertEqual(dashboard.status_code, 200)
        self.assertContains(dashboard, "Traffic trend")
        self.assertContains(dashboard, "Country performance")
        self.assertEqual(dashboard.context["dashboard_counts"]["clicks"], 1)
        self.assertEqual(dashboard.context["dashboard_counts"]["completes"], 1)
        self.assertEqual(dashboard.context["platform_margin"], Decimal("1.50"))
        self.assertEqual(sum(row["clicks"] for row in dashboard.context["trend"]["rows"]), 1)

        inventory = self.client.get(reverse("offerwall:admin-inventory"), {"country": "US"})
        self.assertEqual(inventory.status_code, 200)
        self.assertContains(inventory, self.survey.local_id)
        self.assertContains(inventory, "US")

        suppliers = self.client.get(reverse("offerwall:admin-suppliers"))
        self.assertEqual(suppliers.status_code, 200)
        self.assertContains(suppliers, "70.00")
        self.assertContains(suppliers, "30.00%")
        changed = self.client.post(
            reverse("offerwall:admin-suppliers"),
            {"publisher_id": self.publisher.public_id, "payout_percent": "65.50"},
        )
        self.assertRedirects(
            changed,
            reverse("offerwall:admin-suppliers"),
            fetch_redirect_response=False,
        )
        self.publisher.refresh_from_db()
        self.assertEqual(self.publisher.payout_percent, Decimal("65.50"))

        activity = self.client.get(reverse("offerwall:admin-activity"))
        self.assertEqual(activity.status_code, 200)
        self.assertContains(activity, "Offer activity")

    def test_supplier_registration_creates_pending_inactive_account(self):
        response = self.client.post(
            reverse("offerwall:supplier-signup"),
            {
                "company_name": "New Traffic Company",
                "contact_name": "Asha Verma",
                "business_email": "asha@newtraffic.example",
                "phone": "+91 90000 00000",
                "website": "https://newtraffic.example",
                "country": "India",
                "username": "newtrafficowner",
                "password1": "Strong-Pass-893!",
                "password2": "Strong-Pass-893!",
                "accept_terms": "on",
            },
        )
        self.assertRedirects(
            response,
            reverse("offerwall:publisher-dashboard"),
            fetch_redirect_response=False,
        )
        account = PublisherPortalAccount.objects.select_related("publisher", "user").get(
            user__username="newtrafficowner"
        )
        self.assertEqual(account.status, PublisherPortalAccount.Status.PENDING)
        self.assertFalse(account.publisher.is_active)
        self.assertEqual(account.user.email, "asha@newtraffic.example")
        self.assertNotIn("_auth_user_id", self.client.session)
        status_page = self.client.get(reverse("offerwall:publisher-dashboard"))
        self.assertContains(status_page, "application is under review")
        self.assertContains(status_page, "New Traffic Company")

    def test_approved_supplier_can_login_with_email_and_open_wallet(self):
        user = get_user_model().objects.create_user(
            username="approvedsupplier",
            email="owner@approved.example",
            password="Strong-Pass-893!",
        )
        publisher = Publisher.objects.create(
            name="Approved Supplier",
            slug="approved-supplier",
            is_active=True,
        )
        PublisherPortalAccount.objects.create(
            user=user,
            publisher=publisher,
            contact_name="Approved Owner",
            business_email="owner@approved.example",
            phone="+1 555 100 2000",
            country="United States",
            status=PublisherPortalAccount.Status.APPROVED,
        )
        response = self.client.post(
            reverse("offerwall:supplier-login"),
            {
                "identity": "owner@approved.example",
                "password": "Strong-Pass-893!",
                "remember_me": "on",
            },
        )
        self.assertRedirects(
            response,
            reverse("offerwall:publisher-dashboard"),
            fetch_redirect_response=False,
        )
        dashboard = self.client.get(reverse("offerwall:publisher-dashboard"))
        self.assertContains(dashboard, "Available balance")
        self.assertContains(dashboard, "Approved Supplier")
        home = self.client.get(reverse("home"))
        self.assertEqual(home.status_code, 200)
        self.assertContains(home, "Create supplier account")
        internal_page = self.client.get(reverse("projects"))
        self.assertEqual(internal_page.status_code, 302)
        self.assertIn("/login/", internal_page["Location"])

    def test_supplier_login_rejects_workspace_account_without_publisher(self):
        get_user_model().objects.create_user(
            username="workspace-only",
            email="workspace@example.test",
            password="Strong-Pass-893!",
        )
        response = self.client.post(
            reverse("offerwall:supplier-login"),
            {"identity": "workspace-only", "password": "Strong-Pass-893!"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Username/email or password is incorrect")
        self.assertNotIn("_auth_user_id", self.client.session)

    def test_internal_operations_page_approves_supplier_registration(self):
        operator = get_user_model().objects.create_user(
            username="offerwall-operator",
            password="Strong-Pass-893!",
            is_staff=True,
        )
        supplier_user = get_user_model().objects.create_user(
            username="pending-owner",
            email="pending@example.test",
            password="Strong-Pass-893!",
        )
        pending_publisher = Publisher.objects.create(
            name="Pending Supplier",
            slug="pending-supplier",
            is_active=False,
        )
        registration = PublisherPortalAccount.objects.create(
            user=supplier_user,
            publisher=pending_publisher,
            contact_name="Pending Owner",
            business_email="pending@example.test",
            phone="+91 90000 11111",
            country="India",
        )
        self.assertRedirects(
            self.client.get(reverse("offerwall:operations")),
            f"/login/?next={reverse('offerwall:operations')}",
            fetch_redirect_response=False,
        )
        self.client.force_login(operator)
        page = self.client.get(reverse("offerwall:operations"))
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Pending Supplier")
        response = self.client.post(
            reverse("offerwall:operations-action"),
            {
                "action": "approve-registration",
                "registration_id": registration.pk,
            },
        )
        self.assertRedirects(
            response, reverse("offerwall:operations"), fetch_redirect_response=False
        )
        registration.refresh_from_db()
        pending_publisher.refresh_from_db()
        self.assertEqual(registration.status, PublisherPortalAccount.Status.APPROVED)
        self.assertEqual(registration.reviewed_by, operator)
        self.assertTrue(pending_publisher.is_active)

        self.client.logout()
        login_response = self.client.post(
            reverse("offerwall:supplier-login"),
            {
                "identity": "pending@example.test",
                "password": "Strong-Pass-893!",
            },
        )
        self.assertRedirects(
            login_response,
            reverse("offerwall:publisher-dashboard"),
            fetch_redirect_response=False,
        )
        self.assertContains(
            self.client.get(reverse("offerwall:publisher-dashboard")),
            "Available balance",
        )

        self.client.force_login(operator)

        old_api_hash = pending_publisher.api_key_hash
        self.client.post(
            reverse("offerwall:operations-action"),
            {"action": "rotate-api-key", "publisher_id": pending_publisher.pk},
        )
        pending_publisher.refresh_from_db()
        self.assertNotEqual(pending_publisher.api_key_hash, old_api_hash)

    def test_enabling_pending_supplier_also_approves_registration(self):
        operator = get_user_model().objects.create_user(
            username="enable-operator",
            password="Strong-Pass-893!",
            is_staff=True,
        )
        supplier_user = get_user_model().objects.create_user(
            username="enable-owner",
            email="enable@example.test",
            password="Strong-Pass-893!",
        )
        publisher = Publisher.objects.create(
            name="Enable Supplier",
            slug="enable-supplier",
            is_active=True,
        )
        registration = PublisherPortalAccount.objects.create(
            user=supplier_user,
            publisher=publisher,
            contact_name="Enable Owner",
            business_email="enable@example.test",
            phone="+91 90000 22222",
            country="India",
        )
        self.client.force_login(operator)

        page = self.client.get(reverse("offerwall:operations"))
        self.assertContains(page, "Approve registration")
        response = self.client.post(
            reverse("offerwall:operations-action"),
            {"action": "toggle-publisher", "publisher_id": publisher.pk},
        )
        self.assertRedirects(
            response, reverse("offerwall:operations"), fetch_redirect_response=False
        )

        registration.refresh_from_db()
        publisher.refresh_from_db()
        self.assertEqual(registration.status, PublisherPortalAccount.Status.APPROVED)
        self.assertEqual(registration.reviewed_by, operator)
        self.assertTrue(publisher.is_active)

    def _open_supplier_session(self, publisher=None, *, suffix="portal"):
        publisher = publisher or self.publisher
        user = get_user_model().objects.create_user(
            username=f"supplier-{suffix}",
            email=f"supplier-{suffix}@example.test",
            password="Strong-Pass-893!",
        )
        PublisherPortalAccount.objects.create(
            user=user,
            publisher=publisher,
            contact_name="Supplier Owner",
            business_email=f"supplier-{suffix}@example.test",
            phone="+91 90000 33333",
            country="India",
            status=PublisherPortalAccount.Status.APPROVED,
        )
        session = self.client.session
        session["offerwall_supplier_publisher_id"] = str(publisher.public_id)
        session.save()
        return user

    def test_supplier_can_view_and_update_general_details(self):
        user = self._open_supplier_session(suffix="general")
        account = PublisherPortalAccount.objects.get(user=user)
        url = reverse("offerwall:publisher-general-details")

        page = self.client.get(url)
        self.assertEqual(page.status_code, 200)
        self.assertContains(page, "Company information")
        self.assertContains(page, f"#{self.publisher.publisher_code}")
        self.assertContains(page, user.username)

        response = self.client.post(
            url,
            {
                "company_name": "Acme Audience Network",
                "contact_name": "Maya Singh",
                "job_title": "Partnerships Lead",
                "business_email": "maya@acme-audience.example",
                "phone": "+91 99999 22222",
                "website": "https://acme-audience.example",
                "country": "India",
                "state": "Delhi",
                "city": "New Delhi",
                "postal_code": "110001",
                "address_line": "12 Research Avenue",
            },
        )
        self.assertRedirects(response, url, fetch_redirect_response=False)

        account.refresh_from_db()
        self.publisher.refresh_from_db()
        user.refresh_from_db()
        self.assertEqual(self.publisher.name, "Acme Audience Network")
        self.assertEqual(account.contact_name, "Maya Singh")
        self.assertEqual(account.job_title, "Partnerships Lead")
        self.assertEqual(account.city, "New Delhi")
        self.assertEqual(account.address_line, "12 Research Avenue")
        self.assertEqual(user.email, "maya@acme-audience.example")
        self.assertEqual(user.username, "supplier-general")

    def test_general_details_rejects_another_accounts_email(self):
        self._open_supplier_session(suffix="general-duplicate")
        other_user = get_user_model().objects.create_user(
            username="other-supplier",
            email="owned@other.example",
            password="Strong-Pass-893!",
        )
        other_publisher = Publisher.objects.create(
            name="Other Supplier",
            slug="other-supplier",
            is_active=True,
        )
        PublisherPortalAccount.objects.create(
            user=other_user,
            publisher=other_publisher,
            contact_name="Other Owner",
            business_email="owned@other.example",
            country="India",
            status=PublisherPortalAccount.Status.APPROVED,
        )

        response = self.client.post(
            reverse("offerwall:publisher-general-details"),
            {
                "company_name": self.publisher.name,
                "contact_name": "Supplier Owner",
                "business_email": "owned@other.example",
                "phone": "+91 90000 33333",
                "website": "",
                "country": "India",
                "state": "",
                "city": "",
                "postal_code": "",
                "address_line": "",
                "job_title": "",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "belongs to another account")

    def test_supplier_can_create_placement_and_copy_iframe(self):
        self._open_supplier_session(suffix="placement")
        response = self.client.post(
            reverse("offerwall:publisher-placements"),
            {
                "platform": PublisherPlacement.Platform.WEB,
                "website_url": "https://rewards.example.test",
            },
        )
        placement = PublisherPlacement.objects.get(publisher=self.publisher)
        self.assertRedirects(
            response,
            reverse("offerwall:publisher-placements"),
            fetch_redirect_response=False,
        )
        self.assertEqual(placement.currency, "USD")
        self.assertEqual(placement.name, "Rewards")
        self.assertEqual(placement.website_name, "Rewards")
        self.assertFalse(placement.postback_enabled)
        page = self.client.get(reverse("offerwall:publisher-placements"))
        self.assertContains(page, "Placement")
        self.assertContains(page, "Total Revenue")
        self.assertContains(page, placement.app_id)
        self.assertContains(page, "Settings")
        self.assertContains(page, "Respondents")
        self.assertContains(page, "Survey results")
        self.assertNotContains(page, "Open-ended answers")
        self.assertNotContains(page, ">Leads</a>")
        self.assertNotContains(page, "Wallet Ledger")
        self.assertNotContains(page, "Developer Docs")
        settings_page = self.client.get(
            reverse(
                "offerwall:publisher-placement-edit",
                kwargs={"placement_id": placement.public_id},
            )
        )
        self.assertContains(settings_page, "Quick Integrations")
        self.assertContains(settings_page, "Copy Code")
        self.assertContains(settings_page, f"embed/app/{placement.app_id}/")
        self.assertContains(settings_page, "embed.js?v=1")
        self.assertContains(settings_page, "Preview Direct iFrame")
        self.assertContains(settings_page, "RM Wins Offer Wall preview")
        self.assertNotContains(settings_page, "clipboard-write")

    def test_supplier_can_configure_all_placement_settings(self):
        self._open_supplier_session(suffix="settings")
        placement = PublisherPlacement.objects.create(
            publisher=self.publisher,
            name="Settings wall",
            website_name="Settings Site",
            website_url="https://settings.example.test",
        )
        edit_url = reverse(
            "offerwall:publisher-placement-edit",
            kwargs={"placement_id": placement.public_id},
        )
        response = self.client.post(
            edit_url,
            {
                "form_type": "general",
                "traffic_type": PublisherPlacement.TrafficType.BOTH,
                "allowed_domains": "rewards.example.test\napp.example.test",
            },
        )
        self.assertEqual(response.status_code, 302)
        response = self.client.post(
            edit_url,
            {
                "form_type": "currency",
                "currency_name": "Coins",
                "user_revenue_share": "80",
                "currency_multiplier": "25",
                "reward_rounding_precision": "2",
            },
        )
        self.assertEqual(response.status_code, 302)
        response = self.client.post(
            edit_url,
            {
                "form_type": "postback",
                "postback_enabled": "on",
                "postback_url": "https://publisher.example.test/global?uid={SID}&status={STATUS}",
                "whitelist_postback_ip": "on",
                "respondent_id_parameter": "SID",
                "campaign_id_parameter": "campaign_id",
                "affiliate_sub_parameter": "sid2",
            },
        )
        self.assertEqual(response.status_code, 302)
        response = self.client.post(
            edit_url,
            {
                "form_type": "design",
                "active_content_types": ["offers", "survey"],
            },
        )
        self.assertEqual(response.status_code, 302)
        placement.refresh_from_db()
        self.assertEqual(placement.traffic_type, PublisherPlacement.TrafficType.BOTH)
        self.assertEqual(
            placement.allowed_domains,
            "rewards.example.test\napp.example.test",
        )
        self.assertEqual(placement.currency_name, "Coins")
        self.assertEqual(placement.display_reward(Decimal("2.00")), Decimal("40.00"))
        self.assertTrue(placement.postback_enabled)
        self.assertEqual(placement.active_content_types, ["offers", "survey"])

        add_rule_url = reverse(
            "offerwall:publisher-placement-event-postback-add",
            kwargs={"placement_id": placement.public_id},
        )
        response = self.client.post(
            add_rule_url,
            {
                "survey_id": self.survey.local_id,
                "event_type": "complete",
                "event_name": "Survey complete",
                "callback_url": "https://publisher.example.test/complete/{OFFERID}?uid={SID}",
            },
        )
        self.assertEqual(response.status_code, 302)
        rule = PlacementEventPostback.objects.get(placement=placement)
        self.assertEqual(rule.survey, self.survey)

        visit = create_wall_visit(
            self.publisher,
            external_user_id="settings-user",
            nonce="settings_event_nonce",
            entry_timestamp=timezone.now(),
            placement=placement,
        )
        click = self._click(visit=visit)
        click.attempt.status = SurveyAttempt.Status.COMPLETED
        click.attempt.status_source = "innovatemr_s2s"
        click.attempt.is_verified = True
        click.attempt.save(
            update_fields=["status", "status_source", "is_verified", "updated_at"]
        )
        process_attempt_outcome(click.attempt_id)
        delivery = PostbackDelivery.objects.get(click=click, event_type="complete")
        self.assertIn(f"/complete/{self.survey.local_id}", delivery.callback_url)
        self.assertIn("uid=settings-user", delivery.callback_url)

    def test_inventory_api_accepts_bearer_key_and_placement_app_id(self):
        placement = PublisherPlacement.objects.create(
            publisher=self.publisher,
            name="API wall",
            website_name="API Site",
            website_url="https://api-site.example.test",
            currency_name="Coins",
            currency_multiplier=Decimal("20.000000"),
        )
        response = self.client.get(
            reverse("offerwall:offers-api"),
            {
                "pubid": self.publisher.publisher_code,
                "app_id": placement.app_id,
            },
            HTTP_AUTHORIZATION=f"Bearer {self.api_key}",
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["data"]["query"]["appid"], placement.app_id)
        self.assertEqual(payload["data"]["response"]["currency_name"], "Coins")
        self.assertEqual(payload["data"]["response"]["offers"][0]["payout"], 70.0)

    def test_api_offer_tracking_creates_attributed_click(self):
        placement = PublisherPlacement.objects.create(
            publisher=self.publisher,
            name="Tracking wall",
            website_name="Tracking Site",
            website_url="https://tracking.example.test",
        )
        response = self.client.get(
            reverse("offerwall:offer-click-tracking"),
            {
                "app_id": placement.app_id,
                "offer_id": self.survey.local_id,
                "uid": "member-api-9",
                "sid": "click-44",
                "sid2": "source-2",
                "sid3": "source-3",
                "sid4": "source-4",
                "sid5": "source-5",
                "gaid": "android-ad-id",
            },
        )
        self.assertEqual(response.status_code, 302)
        self.assertIn("/survey/start?rid=", response["Location"])
        visit = WallVisit.objects.get(external_user_id="member-api-9")
        self.assertEqual(visit.placement, placement)
        self.assertEqual(visit.external_campaign_id, "click-44")
        self.assertEqual(visit.affiliate_sub_id, "source-2")
        self.assertEqual(visit.affiliate_sub_id_3, "source-3")
        self.assertEqual(visit.affiliate_sub_id_4, "source-4")
        self.assertEqual(visit.affiliate_sub_id_5, "source-5")
        self.assertEqual(visit.gaid, "android-ad-id")
        self.assertTrue(OfferClick.objects.filter(visit=visit, survey=self.survey).exists())

    @patch(
        "offerwall.services.resolve_entry_geolocation",
        return_value={"country_code": "US"},
    )
    def test_placement_embed_creates_placement_attributed_visit(self, _geolocation):
        placement = PublisherPlacement.objects.create(
            publisher=self.publisher,
            name="Embedded wall",
            website_name="Publisher Site",
            website_url="https://publisher.example.test",
            currency="PTS",
            currency_multiplier=Decimal("100.000000"),
        )
        path = reverse(
            "offerwall:placement-embed",
            kwargs={"placement_id": placement.public_id},
        )
        preview = self.client.get(path)
        self.assertEqual(preview.status_code, 200)
        self.assertContains(preview, "Placement active")
        self.assertNotIn("X-Frame-Options", preview)

        self._verified_respondent(
            sid="member-100",
            placement=placement,
            email="member-100@example.test",
        )
        response = self.client.get(
            f"{path}?uid=member-100&campaign_id=summer&subid=home",
            HTTP_REFERER="https://publisher.example.test/rewards",
        )
        self.assertEqual(response.status_code, 200)
        self.assertNotIn("Location", response)
        self.assertContains(response, self.survey.name)
        visit = WallVisit.objects.get(external_user_id="member-100")
        self.assertEqual(visit.placement, placement)
        self.assertEqual(visit.external_campaign_id, "summer")
        self.assertEqual(visit.affiliate_sub_id, "home")
        offer = offer_catalog(self.publisher, visit)[0]
        self.assertEqual(offer["reward"], Decimal("350.000000"))
        self.assertEqual(offer["currency"], "PTS")
        session_location = urlsplit(session_url(visit))
        session_page = self.client.get(f"{session_location.path}?{session_location.query}")
        self.assertEqual(session_page.status_code, 200)
        self.assertNotIn("X-Frame-Options", session_page)

        direct_visit = create_wall_visit(
            self.publisher,
            external_user_id="signed-direct-user",
            nonce="signed-direct-nonce",
            entry_timestamp=timezone.now(),
        )
        direct_session = self.client.get(
            reverse("offerwall:session", kwargs={"visit_id": direct_visit.public_id}),
            {"sig": sign_session(self.publisher, direct_visit.public_id)},
        )
        self.assertEqual(direct_session["X-Frame-Options"], "DENY")

        direct = self.client.get(
            path,
            {
                "SID": "member-direct",
                "campaign_id": "winter",
                "subid": "cta",
            },
        )
        self.assertContains(direct, "Tell us about yourself")
        self._verified_respondent(
            sid="member-direct",
            placement=placement,
            email="member-direct@example.test",
        )
        direct = self.client.get(
            path,
            {
                "SID": "member-direct",
                "campaign_id": "winter",
                "subid": "cta",
            },
        )
        self.assertEqual(direct.status_code, 200)
        self.assertNotIn("Location", direct)
        direct_visit = WallVisit.objects.get(external_user_id="member-direct")
        self.assertEqual(direct_visit.external_campaign_id, "winter")
        self.assertEqual(direct_visit.affiliate_sub_id, "cta")

    @patch(
        "offerwall.services.resolve_entry_geolocation",
        return_value={"country_code": "US"},
    )
    def test_direct_app_iframe_enforces_domains_and_ignores_sid_placeholder(
        self, _geolocation
    ):
        placement = PublisherPlacement.objects.create(
            publisher=self.publisher,
            name="Direct frame",
            website_name="Publisher Site",
            website_url="https://publisher.example.test",
            allowed_domains="*.partner.example.test",
        )
        path = reverse(
            "offerwall:placement-app-embed",
            kwargs={"app_id": placement.app_id},
        )
        preview = self.client.get(
            path,
            {"SID": "{SID}"},
            HTTP_REFERER="https://publisher.example.test/rewards",
        )
        self.assertEqual(preview.status_code, 200)
        self.assertFalse(WallVisit.objects.filter(placement=placement).exists())
        self.assertNotIn("X-Frame-Options", preview)
        self.assertIn(
            "https://publisher.example.test",
            preview["Content-Security-Policy"],
        )
        self.assertIn(
            "https://*.partner.example.test",
            preview["Content-Security-Policy"],
        )

        denied = self.client.get(
            path,
            {"SID": "stolen-user"},
            HTTP_REFERER="https://unapproved.example.test/page",
        )
        self.assertEqual(denied.status_code, 403)
        self.assertFalse(WallVisit.objects.filter(placement=placement).exists())

        self._verified_respondent(
            sid="partner-user",
            placement=placement,
            email="partner-user@example.test",
        )
        allowed = self.client.get(
            path,
            {"SID": "partner-user"},
            HTTP_REFERER="https://rewards.partner.example.test/page",
        )
        self.assertEqual(allowed.status_code, 200)
        self.assertNotIn("Location", allowed)
        visit = WallVisit.objects.get(placement=placement)
        self.assertEqual(visit.external_user_id, "partner-user")
        self.assertContains(allowed, self.survey.name)
        self.assertNotIn("X-Frame-Options", allowed)
        self.assertIn(
            "https://*.partner.example.test",
            allowed["Content-Security-Policy"],
        )

    @patch(
        "offerwall.services.resolve_entry_geolocation",
        return_value={"country_code": "US"},
    )
    def test_iframe_onboards_verifies_lists_and_bans_respondent(self, _geolocation):
        placement = PublisherPlacement.objects.create(
            publisher=self.publisher,
            name="Onboarding wall",
            website_name="Onboarding Site",
            website_url="https://publisher.example.test",
        )
        path = reverse(
            "offerwall:placement-app-embed",
            kwargs={"app_id": placement.app_id},
        )
        iframe_url = f"{path}?SID=omega-new"

        registration = self.client.get(iframe_url)
        self.assertEqual(registration.status_code, 200)
        self.assertContains(registration, "Tell us about yourself")
        self.assertFalse(WallVisit.objects.filter(placement=placement).exists())
        state = registration.context["respondent_state"]

        submitted = self.client.post(
            iframe_url,
            {
                "action": "register",
                "respondent_state": state,
                "full_name": "Omega Respondent",
                "email": "omega.respondent@example.test",
                "age": "29",
                "gender": RespondentProfile.Gender.NON_BINARY,
                "consent": "on",
            },
        )
        self.assertEqual(submitted.status_code, 200)
        self.assertContains(submitted, "Verify your email")
        self.assertEqual(len(mail.outbox), 1)
        profile = RespondentProfile.objects.get(external_user_id="omega-new")
        self.assertEqual(profile.full_name, "Omega Respondent")
        self.assertEqual(profile.email, "omega.respondent@example.test")
        self.assertNotIn("omega.respondent", profile.encrypted_email)
        self.assertFalse(profile.is_email_verified)
        self.assertFalse(WallVisit.objects.filter(respondent=profile).exists())

        code_match = re.search(r"code is: (\d{6})", mail.outbox[0].body)
        self.assertIsNotNone(code_match)
        verified = self.client.post(
            iframe_url,
            {
                "action": "verify",
                "respondent_state": submitted.context["respondent_state"],
                "code": code_match.group(1),
            },
        )
        self.assertEqual(verified.status_code, 200)
        self.assertContains(verified, self.survey.name)
        profile.refresh_from_db()
        self.assertTrue(profile.is_email_verified)
        self.assertIsNotNone(profile.email_verified_at)
        visit = WallVisit.objects.get(respondent=profile)
        self.assertEqual(visit.external_user_id, "omega-new")

        self._open_supplier_session(suffix="respondent-management")
        respondents_url = reverse(
            "offerwall:publisher-section", args=["respondents"]
        )
        respondents_page = self.client.get(respondents_url)
        self.assertContains(respondents_page, "Omega Respondent")
        self.assertContains(respondents_page, "omega.respondent@example.test")
        self.assertContains(respondents_page, "Email verified")
        self.assertContains(respondents_page, self.publisher.name)

        action_url = reverse(
            "offerwall:publisher-respondent-action",
            kwargs={"respondent_id": profile.public_id},
        )
        banned = self.client.post(
            action_url,
            {"action": "ban", "reason": "Quality review"},
        )
        self.assertEqual(banned.status_code, 302)
        profile.refresh_from_db()
        self.assertTrue(profile.is_banned)
        blocked = self.client.get(iframe_url)
        self.assertEqual(blocked.status_code, 403)
        self.assertContains(blocked, "Account access paused", status_code=403)

        unbanned = self.client.post(action_url, {"action": "unban"})
        self.assertEqual(unbanned.status_code, 302)
        profile.refresh_from_db()
        self.assertFalse(profile.is_banned)
        restored = self.client.get(iframe_url)
        self.assertEqual(restored.status_code, 200)
        self.assertContains(restored, self.survey.name)

    def test_supplier_can_delete_own_placement(self):
        self._open_supplier_session(suffix="lifecycle")
        placement = PublisherPlacement.objects.create(
            publisher=self.publisher,
            name="Lifecycle wall",
            website_name="Publisher Site",
            website_url="https://publisher.example.test",
        )
        action_url = reverse(
            "offerwall:publisher-placement-action",
            kwargs={"placement_id": placement.public_id},
        )
        response = self.client.post(action_url, {"action": "delete"})
        self.assertRedirects(
            response,
            reverse("offerwall:publisher-placements"),
            fetch_redirect_response=False,
        )
        self.assertFalse(PublisherPlacement.objects.filter(pk=placement.pk).exists())

    def test_placement_postback_uses_placement_url_key_and_tracking_values(self):
        placement = PublisherPlacement.objects.create(
            publisher=self.publisher,
            name="Callback wall",
            website_name="Publisher Site",
            website_url="https://publisher.example.test",
            postback_enabled=True,
            postback_url="https://publisher.example.test/placement-callback",
            currency="PTS",
            currency_multiplier=Decimal("100.000000"),
        )
        self.assertGreaterEqual(len(decrypt_placement_postback_secret(placement)), 32)
        visit = create_wall_visit(
            self.publisher,
            external_user_id="member-callback",
            nonce="placement_callback_nonce",
            entry_timestamp=timezone.now(),
            placement=placement,
            external_campaign_id="campaign-88",
            affiliate_sub_id="homepage",
        )
        click = self._click(visit=visit)
        click.attempt.status = SurveyAttempt.Status.COMPLETED
        click.attempt.status_source = "innovatemr_s2s"
        click.attempt.is_verified = True
        click.attempt.save(
            update_fields=["status", "status_source", "is_verified", "updated_at"]
        )
        process_attempt_outcome(click.attempt_id)
        delivery = PostbackDelivery.objects.get(event_type="complete")
        self.assertEqual(delivery.placement, placement)
        self.assertEqual(delivery.callback_url, placement.postback_url)
        self.assertEqual(delivery.status, PostbackDelivery.Status.PENDING)
        self.assertEqual(delivery.payload["placement_id"], str(placement.public_id))
        self.assertEqual(delivery.payload["campaign_id"], "campaign-88")
        self.assertEqual(delivery.payload["affiliate_sub"], "homepage")
        self.assertEqual(delivery.payload["payout_amount"], "3.50")
        self.assertEqual(delivery.payload["reward_amount"], "350.00")
        self.assertEqual(delivery.payload["reward_currency"], "PTS")

    def test_supplier_placement_list_is_publisher_scoped(self):
        self._open_supplier_session(suffix="scope")
        PublisherPlacement.objects.create(
            publisher=self.publisher,
            name="Owned placement",
            website_name="Owned Site",
            website_url="https://owned.example.test",
        )
        other = Publisher.objects.create(name="Other Publisher", slug="other-publisher")
        PublisherPlacement.objects.create(
            publisher=other,
            name="Private other placement",
            website_name="Other Site",
            website_url="https://other.example.test",
        )
        response = self.client.get(reverse("offerwall:publisher-placements"))
        self.assertContains(response, "Owned Site")
        self.assertNotContains(response, "Other Site")

    def test_supplier_placeholder_section_uses_portal_shell(self):
        self._open_supplier_session(suffix="placeholder")
        response = self.client.get(
            reverse("offerwall:publisher-section", kwargs={"section": "reports"})
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Conversion reports")
        self.assertContains(response, "Financial conversion ledger")
        self.assertContains(response, "Placements")

    def test_supplier_survey_results_are_filterable_and_show_clean_outcomes(self):
        self._open_supplier_session(suffix="survey-results")
        placement = PublisherPlacement.objects.create(
            publisher=self.publisher,
            name="Results wall",
            website_name="Results Site",
            website_url="https://results.example.test",
        )
        visit = create_wall_visit(
            self.publisher,
            external_user_id="member-results-77",
            nonce="results_report_nonce",
            entry_timestamp=timezone.now(),
            placement=placement,
            external_campaign_id="campaign-report",
            affiliate_sub_id="homepage",
        )
        click = self._click(visit=visit)
        click.attempt.status = SurveyAttempt.Status.TERMINATED
        click.attempt.status_source = "innovatemr_s2s"
        click.attempt.loi_seconds = 74
        click.attempt.upstream_transaction_data = {
            "termReason": "Profile mismatch",
            "termReasonCategory": "Demographic",
        }
        click.attempt.save(
            update_fields=[
                "status",
                "status_source",
                "loi_seconds",
                "upstream_transaction_data",
                "updated_at",
            ]
        )
        process_attempt_outcome(click.attempt_id)

        response = self.client.get(
            reverse(
                "offerwall:publisher-section",
                kwargs={"section": "survey-results"},
            ),
            {
                "q": "member-results",
                "status": "terminated",
                "placement": str(placement.public_id),
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Survey results")
        self.assertContains(response, "member-results-77")
        self.assertContains(response, "Results Site")
        self.assertContains(response, "Profile mismatch")
        self.assertContains(response, "Demographic")
        self.assertContains(response, "74 sec")
        self.assertNotContains(response, self.survey.source_key)

    def test_supplier_survey_results_csv_exports_verified_publisher_reward(self):
        self._open_supplier_session(suffix="survey-results-csv")
        click = self._credit_click()
        response = self.client.get(
            reverse(
                "offerwall:publisher-section",
                kwargs={"section": "survey-results"},
            ),
            {"q": click.external_user_id, "status": "completed", "export": "csv"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response["Content-Type"], "text/csv; charset=utf-8")
        self.assertIn("attachment", response["Content-Disposition"])
        payload = b"".join(response.streaming_content).decode("utf-8")
        self.assertIn("Respondent ID", payload)
        self.assertIn(click.external_user_id, payload)
        self.assertIn("Completed", payload)
        self.assertIn("3.50", payload)
        self.assertNotIn(self.survey.source_key, payload)

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

    @patch("offerwall.tasks.requests.get")
    @patch("offerwall.tasks.socket.getaddrinfo")
    def test_postback_requires_body_one_and_disables_redirects(self, getaddrinfo, get):
        getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
        get.return_value.status_code = 200
        get.return_value.text = "1"
        result = deliver_postback_task(self.delivery.pk)
        self.assertEqual(result["status"], "delivered")
        kwargs = get.call_args.kwargs
        self.assertFalse(kwargs["allow_redirects"])
        self.assertEqual(kwargs["timeout"], 3)
        self.assertEqual(kwargs["headers"]["User-Agent"], "RMWins-Offerwall/1.0")
        self.delivery.refresh_from_db()
        self.assertEqual(self.delivery.status, PostbackDelivery.Status.DELIVERED)
        self.assertEqual(self.delivery.attempt_count, 1)

    @patch("offerwall.tasks.requests.get")
    @patch("offerwall.tasks.socket.getaddrinfo")
    def test_placement_delivery_renders_hmac_sig_macro(self, getaddrinfo, get):
        placement = PublisherPlacement.objects.create(
            publisher=self.publisher,
            name="Secure placement",
            website_name="Rewards",
            website_url="https://publisher.example.test",
            postback_enabled=True,
            postback_url="https://publisher.example.test/placement-postback?sig={SIG}",
        )
        self.delivery.placement = placement
        self.delivery.callback_url = placement.postback_url
        self.delivery.save(update_fields=["placement", "callback_url", "updated_at"])
        getaddrinfo.return_value = [(2, 1, 6, "", ("93.184.216.34", 443))]
        get.return_value.status_code = 200
        get.return_value.text = "1"

        result = deliver_postback_task(self.delivery.pk)

        self.assertEqual(result["status"], "delivered")
        called_url = get.call_args.args[0]
        self.assertNotIn("{SIG}", called_url)
        self.assertEqual(len(parse_qs(urlsplit(called_url).query)["sig"][0]), 64)
