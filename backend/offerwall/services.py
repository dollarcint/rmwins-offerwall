"""Offer catalog, session, attribution, ledger and postback orchestration."""

import hashlib
import hmac
import logging
import secrets
from datetime import timedelta
from decimal import Decimal, ROUND_HALF_UP
from urllib.parse import quote

from django.conf import settings
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.db.models import Q
from django.urls import reverse
from django.utils import timezone

from surveys.geolocation import resolve_entry_geolocation
from surveys.models import Survey, SurveyAttempt
from surveys.outcomes import provider_outcome
from surveys.survey_flow import create_attempt, get_request_client_data, get_request_ip

from .models import (
    OfferClick,
    OfferOverride,
    PlacementEventPostback,
    PostbackDelivery,
    Publisher,
    PublisherPortalAccount,
    RewardLedgerEntry,
    WallVisit,
)
from .security import sign_click, sign_result, sign_session


logger = logging.getLogger(__name__)
MONEY_QUANTUM = Decimal("0.01")
FINAL_STATUSES = {
    SurveyAttempt.Status.COMPLETED,
    SurveyAttempt.Status.TERMINATED,
    SurveyAttempt.Status.OVER_QUOTA,
    SurveyAttempt.Status.QUALITY_TERMINATED,
}
LOCAL_AUTHORITATIVE_SOURCES = {"local_prescreener", "local_country_guard"}


def review_publisher_registration(
    account: PublisherPortalAccount,
    status: str,
    *,
    reviewer=None,
    admin_note: str = "",
) -> PublisherPortalAccount:
    """Approve or reject a supplier application and keep activation in sync."""

    allowed = {
        PublisherPortalAccount.Status.APPROVED,
        PublisherPortalAccount.Status.REJECTED,
    }
    if status not in allowed:
        raise ValueError("Supplier registration status is not reviewable.")
    with transaction.atomic():
        locked = (
            PublisherPortalAccount.objects.select_for_update()
            .select_related("publisher")
            .get(pk=account.pk)
        )
        locked.status = status
        locked.reviewed_by = reviewer
        locked.reviewed_at = timezone.now()
        locked.admin_note = str(admin_note or locked.admin_note or "").strip()[:500]
        locked.save(
            update_fields=[
                "status",
                "reviewed_by",
                "reviewed_at",
                "admin_note",
                "updated_at",
            ]
        )
        should_be_active = status == PublisherPortalAccount.Status.APPROVED
        if locked.publisher.is_active != should_be_active:
            locked.publisher.is_active = should_be_active
            locked.publisher.save(update_fields=["is_active", "updated_at"])
        return locked


def public_base_url() -> str:
    return (
        str(getattr(settings, "OFFERWALL_PUBLIC_BASE_URL", "") or "").strip().rstrip("/")
        or str(settings.PUBLIC_APP_BASE_URL or "").strip().rstrip("/")
    )


def absolute_url(path: str) -> str:
    base = public_base_url()
    return f"{base}{path}" if base else path


def hash_ip(ip_value: str | None) -> str:
    if not ip_value:
        return ""
    return hmac.new(
        settings.SECRET_KEY.encode("utf-8"),
        str(ip_value).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def ensure_service_user(publisher: Publisher):
    if publisher.service_user_id:
        user = publisher.service_user
        if not user.is_active:
            user.is_active = True
            user.save(update_fields=["is_active"])
        return user
    username = f"ow_{publisher.public_id.hex[:24]}"
    user, created = get_user_model().objects.get_or_create(
        username=username,
        defaults={
            "first_name": publisher.name[:150],
            "last_name": "Offerwall Service",
            "is_active": True,
            "is_staff": False,
            "is_superuser": False,
        },
    )
    if created:
        user.set_unusable_password()
        user.save(update_fields=["password"])
    Publisher.objects.filter(pk=publisher.pk, service_user__isnull=True).update(service_user=user)
    publisher.service_user = user
    return user


def payout_percent_for(publisher: Publisher, override: OfferOverride | None) -> Decimal:
    if override and override.payout_percent_override is not None:
        return override.payout_percent_override
    return publisher.payout_percent


def payout_for(survey: Survey, publisher: Publisher, override: OfferOverride | None):
    if survey.cpi is None:
        return None
    payout = (survey.cpi * payout_percent_for(publisher, override)) / Decimal("100")
    return payout.quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def eligible_surveys(publisher: Publisher, visit: WallVisit):
    queryset = (
        Survey.objects.select_related("client", "integration")
        .filter(status=Survey.Status.LIVE, remaining__gt=0, cpi__gt=0)
        .filter(Q(client__isnull=True) | Q(client__is_active=True))
        .filter(
            ~Q(entry_link="")
            | Q(integration__provider_code__in=("rfg", "cint"), integration__is_active=True)
        )
        .exclude(offerwall_overrides__publisher=publisher, offerwall_overrides__is_excluded=True)
        .distinct()
    )
    country_code = str(visit.country_code or "").strip().upper()
    if country_code:
        queryset = queryset.filter(
            Q(country_code="") | Q(country_code__iexact=country_code) | Q(country__iexact=country_code)
        )
    device = str(visit.device or "").strip()
    if device and device != "Unknown":
        queryset = queryset.filter(
            Q(device_type="")
            | Q(device_type__icontains="all")
            | Q(device_type__icontains=device)
        )
    queryset = queryset.exclude(
        offerwall_ledger__publisher=publisher,
        offerwall_ledger__external_user_id=visit.external_user_id,
        offerwall_ledger__entry_type=RewardLedgerEntry.EntryType.CREDIT,
    )
    return queryset.order_by("-cpi", "loi", "local_id")


def offer_catalog(publisher: Publisher, visit: WallVisit) -> list[dict]:
    if visit.placement_id and not (
        set(visit.placement.active_content_types or [])
        & {"offers", "survey", "live_survey"}
    ):
        return []
    overrides = {
        item.survey_id: item
        for item in OfferOverride.objects.filter(publisher=publisher).select_related("survey")
    }
    offers = []
    for survey in eligible_surveys(publisher, visit):
        override = overrides.get(survey.pk)
        payout = payout_for(survey, publisher, override)
        display_reward = payout
        display_currency = publisher.currency
        if visit.placement_id and payout is not None:
            display_reward = visit.placement.display_reward(payout)
            display_currency = visit.placement.currency_name
        click_path = reverse(
            "offerwall:click",
            kwargs={"visit_id": visit.public_id, "survey_id": survey.local_id},
        )
        signature = sign_click(publisher, visit.public_id, survey.local_id)
        offers.append(
            {
                "id": survey.local_id,
                "title": (override.title_override if override else "") or survey.name or f"Survey {survey.local_id}",
                "client": survey.client.name if survey.client_id else survey.company_name,
                "reward": display_reward,
                "currency": display_currency,
                "loi": survey.loi,
                "incidence_rate": survey.incidence_rate,
                "country": survey.country_code or survey.country,
                "device": survey.device_type,
                "survey_type": survey.survey_type,
                "featured": bool(override and override.featured),
                "click_url": f"{click_path}?sig={signature}",
            }
        )
    return sorted(
        offers,
        key=lambda item: (
            not item["featured"],
            -(item["reward"] or Decimal("0")),
            item["loi"] if item["loi"] is not None else 10**9,
            item["id"],
        ),
    )


def create_wall_visit(
    publisher: Publisher,
    *,
    external_user_id: str,
    nonce: str,
    entry_timestamp,
    request=None,
    placement=None,
    external_campaign_id="",
    affiliate_sub_id="",
    affiliate_sub_id_3="",
    affiliate_sub_id_4="",
    affiliate_sub_id_5="",
    idfa="",
    gaid="",
) -> WallVisit:
    location = resolve_entry_geolocation(request) if request is not None else {}
    client_data = get_request_client_data(request) if request is not None else {}
    now = timezone.now()
    defaults = {
        "external_user_id": external_user_id,
        "placement": placement,
        "external_campaign_id": str(external_campaign_id or "").strip()[:160],
        "affiliate_sub_id": str(affiliate_sub_id or "").strip()[:160],
        "affiliate_sub_id_3": str(affiliate_sub_id_3 or "").strip()[:160],
        "affiliate_sub_id_4": str(affiliate_sub_id_4 or "").strip()[:160],
        "affiliate_sub_id_5": str(affiliate_sub_id_5 or "").strip()[:160],
        "idfa": str(idfa or "").strip()[:160],
        "gaid": str(gaid or "").strip()[:160],
        "entry_timestamp": entry_timestamp,
        "expires_at": now + timedelta(seconds=settings.OFFERWALL_VISIT_TTL_SECONDS),
        "country_code": str(location.get("country_code") or "")[:8],
        "device": str(client_data.get("device") or "")[:40],
        "ip_hash": hash_ip(get_request_ip(request) if request is not None else None),
        "user_agent": str(client_data.get("user_agent") or "")[:500],
    }
    with transaction.atomic():
        visit, created = WallVisit.objects.select_for_update().get_or_create(
            publisher=publisher,
            entry_nonce=nonce,
            defaults=defaults,
        )
        if not created:
            if visit.external_user_id != external_user_id:
                raise ValueError("This signed entry nonce belongs to another user.")
            if visit.expires_at <= now:
                raise ValueError("This offerwall session has expired.")
            visit.last_seen_at = now
            visit.save(update_fields=["last_seen_at"])
    return visit


def create_api_visit(
    publisher: Publisher,
    *,
    external_user_id: str,
    request=None,
    placement=None,
    external_campaign_id="",
    affiliate_sub_id="",
    affiliate_sub_id_3="",
    affiliate_sub_id_4="",
    affiliate_sub_id_5="",
    idfa="",
    gaid="",
) -> WallVisit:
    return create_wall_visit(
        publisher,
        external_user_id=external_user_id,
        nonce=secrets.token_urlsafe(24),
        entry_timestamp=timezone.now(),
        request=request,
        placement=placement,
        external_campaign_id=external_campaign_id,
        affiliate_sub_id=affiliate_sub_id,
        affiliate_sub_id_3=affiliate_sub_id_3,
        affiliate_sub_id_4=affiliate_sub_id_4,
        affiliate_sub_id_5=affiliate_sub_id_5,
        idfa=idfa,
        gaid=gaid,
    )


def session_url(visit: WallVisit) -> str:
    path = reverse("offerwall:session", kwargs={"visit_id": visit.public_id})
    return absolute_url(f"{path}?sig={sign_session(visit.publisher, visit.public_id)}")


def result_url(click: OfferClick) -> str:
    path = reverse("offerwall:result", kwargs={"click_id": click.public_id})
    return absolute_url(f"{path}?sig={sign_result(click.publisher, click.public_id)}")


def result_url_for_attempt(attempt: SurveyAttempt) -> str:
    try:
        click = OfferClick.objects.select_related("publisher").get(attempt=attempt)
    except OfferClick.DoesNotExist:
        return ""
    return result_url(click)


def create_offer_click(*, visit: WallVisit, survey: Survey, request) -> tuple[OfferClick, bool]:
    publisher = visit.publisher
    service_user = ensure_service_user(publisher)
    override = OfferOverride.objects.filter(publisher=publisher, survey=survey).first()
    if override and override.is_excluded:
        raise ValueError("This offer is not available for the publisher.")
    if not eligible_surveys(publisher, visit).filter(pk=survey.pk).exists():
        raise ValueError("This offer is no longer eligible.")
    existing = OfferClick.objects.select_related("attempt", "publisher", "visit").filter(
        visit=visit, survey=survey
    ).first()
    if existing:
        return existing, False

    client_data = get_request_client_data(request)
    try:
        with transaction.atomic():
            attempt = create_attempt(
                survey,
                service_user,
                get_request_ip(request),
                client_data=client_data,
                supplier_respondent_id=visit.external_user_id,
            )
            percent = payout_percent_for(publisher, override)
            click = OfferClick.objects.create(
                visit=visit,
                publisher=publisher,
                survey=survey,
                attempt=attempt,
                external_user_id=visit.external_user_id,
                source_cpi_snapshot=survey.cpi,
                payout_percent_snapshot=percent,
                payout_snapshot=payout_for(survey, publisher, override),
                currency=publisher.currency,
                status=attempt.status,
            )
            return click, True
    except IntegrityError:
        return OfferClick.objects.select_related("attempt", "publisher", "visit").get(
            visit=visit, survey=survey
        ), False


def _postback_payload(click, attempt, event_type, ledger_entry, *, credited):
    outcome = provider_outcome(attempt)
    amount = Decimal("0.00")
    if ledger_entry:
        amount = (
            -ledger_entry.amount
            if event_type == "reversal"
            else ledger_entry.amount if credited else amount
        )
    placement = click.visit.placement if click.visit_id else None
    reward_amount = amount
    reward_currency = click.currency
    if placement:
        reward_amount = placement.display_reward(amount)
        reward_currency = placement.currency_name
    return {
        "event": event_type,
        "event_id": "",
        "publisher": click.publisher.slug,
        "user_id": click.external_user_id,
        "offer_id": click.survey.local_id,
        "click_id": str(click.public_id),
        "transaction_id": str(ledger_entry.public_id) if ledger_entry else "",
        "status": "2" if event_type == "reversal" else "1",
        "status_label": attempt.get_status_display(),
        "term_reason": outcome.get("reason", ""),
        "term_category": outcome.get("category", ""),
        "credited": bool(credited),
        "amount": str(amount),
        "currency": click.currency,
        "payout_amount": str(amount),
        "payout_currency": click.currency,
        "reward_amount": str(reward_amount),
        "reward_currency": reward_currency,
        "placement_id": str(placement.public_id) if placement else "",
        "placement_name": placement.name if placement else "",
        "app_id": placement.app_id if placement else "",
        "traffic_type": placement.traffic_type if placement else "",
        "campaign_id": click.visit.external_campaign_id,
        "affiliate_sub": click.visit.affiliate_sub_id,
        "affiliate_sub_3": click.visit.affiliate_sub_id_3,
        "affiliate_sub_4": click.visit.affiliate_sub_id_4,
        "affiliate_sub_5": click.visit.affiliate_sub_id_5,
        "idfa": click.visit.idfa,
        "gaid": click.visit.gaid,
        "ip": str(attempt.initiation_ip or ""),
        "verified": bool(attempt.is_verified),
        "occurred_at": timezone.now().isoformat(),
    }


def _render_postback_url(template, payload):
    values = {
        "{app_id}": payload.get("app_id", ""),
        "{SID}": payload.get("user_id", ""),
        "{OFFERID}": payload.get("offer_id", ""),
        "{STATUS}": payload.get("status", ""),
        "{PAYOUT}": payload.get("reward_amount", ""),
        "{PUBPAYOUT}": payload.get("payout_amount", ""),
        "{SID2}": payload.get("affiliate_sub", ""),
        "{SID3}": payload.get("affiliate_sub_3", ""),
        "{SID4}": payload.get("affiliate_sub_4", ""),
        "{SID5}": payload.get("affiliate_sub_5", ""),
        "{eventid}": payload.get("event_id", ""),
        "{eventname}": payload.get("event", ""),
        "{offername}": payload.get("offer_name", ""),
        "{IP}": payload.get("ip", ""),
        "{TransactionID}": payload.get("transaction_id", ""),
        "{idfa}": payload.get("idfa", ""),
        "{gaid}": payload.get("gaid", ""),
    }
    rendered = str(template or "")
    for macro, value in values.items():
        rendered = rendered.replace(macro, quote(str(value or ""), safe=""))
    return rendered


def _enqueue_postback(delivery_id):
    try:
        from .tasks import deliver_postback_task

        deliver_postback_task.delay(delivery_id)
    except Exception:
        logger.exception("Could not enqueue Offerwall postback delivery=%s", delivery_id)


def _create_postback(click, attempt, event_type, ledger_entry=None, *, credited=False):
    publisher = click.publisher
    placement = click.visit.placement if click.visit_id else None
    specific_rule = None
    if placement:
        specific_rule = (
            PlacementEventPostback.objects.filter(
                placement=placement,
                event_type=event_type,
                is_active=True,
            )
            .filter(Q(survey=click.survey) | Q(survey__isnull=True))
            .order_by("-survey_id", "-created_at")
            .first()
        )
    placement_template = (
        specific_rule.callback_url
        if specific_rule
        else placement.postback_url if placement else ""
    )
    placement_callback = bool(
        placement and placement.postback_enabled and placement_template
    )
    callback_url = (
        placement_template
        if placement_callback
        else publisher.callback_url
    )
    status = (
        PostbackDelivery.Status.PENDING
        if placement_callback
        or (publisher.postback_enabled and publisher.callback_url)
        else PostbackDelivery.Status.SKIPPED
    )
    delivery, created = PostbackDelivery.objects.get_or_create(
        click=click,
        event_type=event_type,
        defaults={
            "publisher": publisher,
            "placement": placement if placement_callback else None,
            "ledger_entry": ledger_entry,
            "callback_url": callback_url,
            "status": status,
            "payload": {},
        },
    )
    if not created:
        return delivery
    payload = _postback_payload(
        click, attempt, event_type, ledger_entry, credited=credited
    )
    payload["event_id"] = str(delivery.public_id)
    payload["offer_name"] = click.survey.name or f"Survey {click.survey.local_id}"
    delivery.payload = payload
    delivery.callback_url = _render_postback_url(callback_url, payload)
    delivery.save(update_fields=["payload", "callback_url", "updated_at"])
    if status == PostbackDelivery.Status.PENDING:
        transaction.on_commit(lambda: _enqueue_postback(delivery.pk), robust=True)
    return delivery


def _create_credit(click: OfferClick):
    if click.payout_snapshot is None:
        return None, False
    try:
        with transaction.atomic():
            entry, created = RewardLedgerEntry.objects.get_or_create(
                click=click,
                entry_type=RewardLedgerEntry.EntryType.CREDIT,
                defaults={
                    "publisher": click.publisher,
                    "survey": click.survey,
                    "external_user_id": click.external_user_id,
                    "amount": click.payout_snapshot,
                    "currency": click.currency,
                    "idempotency_key": f"offerwall-credit:{click.public_id}",
                    "reason": "Verified survey completion",
                },
            )
            return entry, created or entry.click_id == click.pk
    except IntegrityError:
        entry = RewardLedgerEntry.objects.filter(
            publisher=click.publisher,
            external_user_id=click.external_user_id,
            survey=click.survey,
            entry_type=RewardLedgerEntry.EntryType.CREDIT,
        ).first()
        return entry, bool(entry and entry.click_id == click.pk)


def _create_reversal(click: OfferClick, credit: RewardLedgerEntry):
    return RewardLedgerEntry.objects.get_or_create(
        click=click,
        entry_type=RewardLedgerEntry.EntryType.REVERSAL,
        defaults={
            "publisher": click.publisher,
            "survey": click.survey,
            "external_user_id": click.external_user_id,
            "amount": credit.amount,
            "currency": credit.currency,
            "idempotency_key": f"offerwall-reversal:{click.public_id}",
            "reason": "Previously credited completion was reversed",
        },
    )


def process_attempt_outcome(attempt_id: int):
    """Idempotently synchronize a provider decision into click, ledger and postback state."""

    with transaction.atomic():
        click = (
            OfferClick.objects.select_for_update()
            .select_related("publisher", "survey", "attempt")
            .filter(attempt_id=attempt_id)
            .first()
        )
        if not click:
            return None
        attempt = click.attempt
        click.status = attempt.status
        click.is_verified = attempt.is_verified
        click.save(update_fields=["status", "is_verified", "updated_at"])

        authoritative = bool(
            attempt.is_verified or attempt.status_source in LOCAL_AUTHORITATIVE_SOURCES
        )
        if attempt.status == SurveyAttempt.Status.COMPLETED and attempt.is_verified:
            credit, credited = _create_credit(click)
            if credited and credit and click.credited_at is None:
                click.credited_at = credit.created_at or timezone.now()
                click.save(update_fields=["credited_at", "updated_at"])
            _create_postback(
                click,
                attempt,
                "complete",
                credit if credited else None,
                credited=credited,
            )
            return click

        credit = RewardLedgerEntry.objects.filter(
            click=click, entry_type=RewardLedgerEntry.EntryType.CREDIT
        ).first()
        if credit and attempt.status != SurveyAttempt.Status.COMPLETED and authoritative:
            reversal, _ = _create_reversal(click, credit)
            _create_postback(
                click, attempt, "reversal", reversal, credited=False
            )
        return click
