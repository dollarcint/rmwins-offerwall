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
    OfferConversion,
    OfferConversionEvent,
    OfferOverride,
    OfferwallInventoryRule,
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


def payout_percent_for(
    publisher: Publisher,
    override: OfferOverride | None,
    *,
    survey: Survey | None = None,
) -> Decimal:
    """Resolve supplier share using supplier override, survey cut, then supplier default."""

    if override and override.payout_percent_override is not None:
        return override.payout_percent_override
    if survey is not None:
        try:
            rule = survey.offerwall_inventory_rule
        except OfferwallInventoryRule.DoesNotExist:
            rule = None
        if rule and rule.platform_cut_percent is not None:
            return Decimal("100.00") - rule.platform_cut_percent
    return publisher.payout_percent


def payout_for(survey: Survey, publisher: Publisher, override: OfferOverride | None):
    if survey.cpi is None:
        return None
    payout = (
        survey.cpi * payout_percent_for(publisher, override, survey=survey)
    ) / Decimal("100")
    return payout.quantize(MONEY_QUANTUM, rounding=ROUND_HALF_UP)


def eligible_surveys(publisher: Publisher, visit: WallVisit):
    queryset = (
        Survey.objects.select_related("client", "integration", "offerwall_inventory_rule")
        .filter(status=Survey.Status.LIVE, remaining__gt=0, cpi__gt=0)
        .filter(Q(client__isnull=True) | Q(client__is_active=True))
        .filter(
            ~Q(entry_link="")
            | Q(integration__provider_code__in=("rfg", "cint"), integration__is_active=True)
        )
        .exclude(offerwall_inventory_rule__is_enabled=False)
        .exclude(offerwall_overrides__publisher=publisher, offerwall_overrides__is_excluded=True)
        .distinct()
    )
    country_code = str(visit.country_code or "").strip().upper()
    if visit.pk and visit.placement_id and visit.respondent_id and not country_code:
        # A real iframe visit must never fall back to the unfiltered catalog.
        # Inventory API previews use an unsaved visit and may still explicitly
        # request country=All, but respondent traffic is fail-closed until its
        # market has been resolved from the entry IP.
        return queryset.none()
    if country_code:
        queryset = queryset.filter(
            Q(country_code__iexact=country_code)
            | Q(country_code="", country__iexact=country_code)
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
    respondent=None,
) -> WallVisit:
    location = resolve_entry_geolocation(request) if request is not None else {}
    client_data = get_request_client_data(request) if request is not None else {}
    now = timezone.now()
    defaults = {
        "external_user_id": external_user_id,
        "placement": placement,
        "respondent": respondent,
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
    respondent=None,
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
        respondent=respondent,
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
    if visit.respondent_id and visit.respondent.is_banned:
        raise ValueError("This respondent account is blocked.")
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
            percent = payout_percent_for(publisher, override, survey=survey)
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


def _conversion_transaction_ids(attempt):
    payload = attempt.upstream_transaction_data or {}
    if not isinstance(payload, dict):
        payload = {}
    transaction_id = next(
        (
            str(payload.get(key) or "").strip()
            for key in (
                "transaction_id",
                "transactionId",
                "transactionID",
                "txid",
                "tx_id",
                "supplier_transaction_id",
            )
            if str(payload.get(key) or "").strip()
        ),
        "",
    )
    reference_id = next(
        (
            str(payload.get(key) or "").strip()
            for key in ("reference_id", "referenceId", "ref", "original_transaction_id")
            if str(payload.get(key) or "").strip()
        ),
        "",
    )
    return (transaction_id or attempt.pid or attempt.rid)[:160], reference_id[:160]


def _conversion_risk(click, attempt):
    """Return a deterministic first-pass score; it never auto-rejects traffic."""

    score = 0
    reasons = []
    visit = click.visit
    respondent = visit.respondent if visit.respondent_id else None

    def add(points, code, message):
        nonlocal score
        score += points
        reasons.append({"code": code, "points": points, "message": message})

    if respondent is None:
        add(10, "identity_unlinked", "No verified Offerwall respondent profile is linked.")
    elif respondent.is_banned:
        add(100, "respondent_banned", "The respondent was banned before conversion review.")
    elif not respondent.is_email_verified:
        add(35, "email_unverified", "The respondent email is not verified.")

    visit_country = str(visit.country_code or "").strip().upper()
    survey_country = str(click.survey.country_code or "").strip().upper()
    if not visit_country:
        add(15, "country_unknown", "The respondent country could not be resolved.")
    elif survey_country and visit_country != survey_country:
        add(60, "country_mismatch", "Respondent and survey countries do not match.")

    if visit.ip_hash:
        distinct_users = (
            WallVisit.objects.filter(
                publisher=click.publisher,
                ip_hash=visit.ip_hash,
                created_at__gte=timezone.now() - timedelta(hours=24),
            )
            .values("external_user_id")
            .distinct()
            .count()
        )
        if distinct_users >= 4:
            add(30, "shared_ip_velocity", "Four or more respondent IDs used this IP in 24 hours.")

    recent_clicks = OfferClick.objects.filter(
        publisher=click.publisher,
        external_user_id=click.external_user_id,
        created_at__gte=timezone.now() - timedelta(minutes=10),
    ).count()
    if recent_clicks >= 8:
        add(25, "click_velocity", "The respondent opened at least eight offers in ten minutes.")

    if attempt.loi_seconds is not None and click.survey.loi:
        expected_seconds = int(click.survey.loi) * 60
        minimum_seconds = max(30, int(expected_seconds * 0.25))
        if int(attempt.loi_seconds) < minimum_seconds:
            add(35, "impossible_loi", "Completion time is below 25% of the expected LOI.")

    return min(score, 100), reasons


def _conversion_event(conversion, event_type, *, payload=None):
    return OfferConversionEvent.objects.get_or_create(
        idempotency_key=f"conversion:{conversion.public_id}:{event_type}",
        defaults={
            "conversion": conversion,
            "event_type": event_type,
            "payload": payload or {},
        },
    )[0]


def _ensure_conversion(click, attempt):
    transaction_id, reference_id = _conversion_transaction_ids(attempt)
    risk_score, risk_reasons = _conversion_risk(click, attempt)
    hold_until = timezone.now() + timedelta(hours=click.publisher.reward_hold_hours)
    try:
        with transaction.atomic():
            conversion, created = OfferConversion.objects.get_or_create(
                click=click,
                defaults={
                    "publisher": click.publisher,
                    "placement": click.visit.placement,
                    "survey": click.survey,
                    "external_user_id": click.external_user_id,
                    "source_transaction_id": transaction_id,
                    "source_reference_id": reference_id,
                    "source_amount": click.source_cpi_snapshot or Decimal("0.00"),
                    "supplier_amount": click.payout_snapshot or Decimal("0.00"),
                    "currency": click.currency,
                    "risk_score": risk_score,
                    "risk_reasons": risk_reasons,
                    "requires_manual_review": (
                        risk_score >= click.publisher.risk_review_threshold
                    ),
                    "hold_until": hold_until,
                },
            )
    except IntegrityError:
        logger.warning(
            "Rejected duplicate Offerwall conversion transaction publisher=%s transaction=%s click=%s",
            click.publisher_id,
            transaction_id,
            click.public_id,
        )
        return None
    if created:
        _conversion_event(
            conversion,
            OfferConversionEvent.EventType.CREATED,
            payload={
                "risk_score": risk_score,
                "risk_reasons": risk_reasons,
                "hold_until": hold_until.isoformat(),
                "requires_manual_review": conversion.requires_manual_review,
            },
        )
    return conversion


def _create_credit(click: OfferClick, conversion: OfferConversion):
    if click.payout_snapshot is None:
        return None, False
    try:
        with transaction.atomic():
            entry, created = RewardLedgerEntry.objects.get_or_create(
                click=click,
                entry_type=RewardLedgerEntry.EntryType.CREDIT,
                defaults={
                    "publisher": click.publisher,
                    "conversion": conversion,
                    "survey": click.survey,
                    "external_user_id": click.external_user_id,
                    "status": RewardLedgerEntry.Status.PENDING,
                    "amount": click.payout_snapshot,
                    "currency": click.currency,
                    "idempotency_key": f"offerwall-credit:{click.public_id}",
                    "reason": "Verified conversion pending release",
                    "available_at": conversion.hold_until,
                },
            )
            if entry.click_id == click.pk and entry.conversion_id is None:
                entry.conversion = conversion
                entry.save(update_fields=["conversion"])
            return entry, created or entry.click_id == click.pk
    except IntegrityError:
        entry = RewardLedgerEntry.objects.filter(
            publisher=click.publisher,
            external_user_id=click.external_user_id,
            survey=click.survey,
            entry_type=RewardLedgerEntry.EntryType.CREDIT,
        ).first()
        return entry, bool(entry and entry.click_id == click.pk)


def _create_reversal(click: OfferClick, credit: RewardLedgerEntry, conversion):
    return RewardLedgerEntry.objects.get_or_create(
        click=click,
        entry_type=RewardLedgerEntry.EntryType.REVERSAL,
        defaults={
            "publisher": click.publisher,
            "conversion": conversion,
            "survey": click.survey,
            "external_user_id": click.external_user_id,
            "status": RewardLedgerEntry.Status.AVAILABLE,
            "amount": credit.amount,
            "currency": credit.currency,
            "idempotency_key": f"offerwall-reversal:{click.public_id}",
            "reason": "Previously credited completion was reversed",
            "available_at": timezone.now(),
            "released_at": timezone.now(),
        },
    )


def approve_conversion(conversion_id, *, reviewer=None, reason=""):
    """Release a pending conversion once; safe for scheduler and manual review."""

    with transaction.atomic():
        conversion = (
            OfferConversion.objects.select_for_update()
            .select_related("click", "click__attempt", "publisher", "survey")
            .get(pk=conversion_id)
        )
        if conversion.status == OfferConversion.Status.APPROVED:
            return conversion
        if conversion.status != OfferConversion.Status.PENDING:
            raise ValueError(f"A {conversion.get_status_display().lower()} conversion cannot be approved.")
        credit = RewardLedgerEntry.objects.select_for_update().get(
            conversion=conversion,
            entry_type=RewardLedgerEntry.EntryType.CREDIT,
        )
        now = timezone.now()
        credit.status = RewardLedgerEntry.Status.AVAILABLE
        credit.available_at = credit.available_at or now
        credit.released_at = now
        credit.reason = "Verified conversion released"
        credit.save(
            update_fields=["status", "available_at", "released_at", "reason"]
        )
        if conversion.click.credited_at is None:
            conversion.click.credited_at = now
            conversion.click.save(update_fields=["credited_at", "updated_at"])
        conversion.status = OfferConversion.Status.APPROVED
        conversion.requires_manual_review = False
        conversion.approved_at = now
        conversion.decided_by = reviewer
        conversion.decision_reason = str(reason or "Automatic hold completed")[:500]
        conversion.save(
            update_fields=[
                "status",
                "requires_manual_review",
                "approved_at",
                "decided_by",
                "decision_reason",
                "updated_at",
            ]
        )
        _conversion_event(
            conversion,
            OfferConversionEvent.EventType.APPROVED,
            payload={
                "reason": conversion.decision_reason,
                "reviewer_id": reviewer.pk if reviewer else None,
            },
        )
        _create_postback(
            conversion.click,
            conversion.click.attempt,
            "complete",
            credit,
            credited=True,
        )
        return conversion


def reject_conversion(conversion_id, *, reviewer=None, reason=""):
    """Reject a pending conversion and preserve a balanced audit ledger."""

    rejection_reason = str(reason or "Rejected during conversion review").strip()[:500]
    with transaction.atomic():
        conversion = (
            OfferConversion.objects.select_for_update()
            .select_related("click", "publisher", "survey")
            .get(pk=conversion_id)
        )
        if conversion.status == OfferConversion.Status.REJECTED:
            return conversion
        if conversion.status != OfferConversion.Status.PENDING:
            raise ValueError(f"A {conversion.get_status_display().lower()} conversion cannot be rejected.")
        credit = RewardLedgerEntry.objects.select_for_update().get(
            conversion=conversion,
            entry_type=RewardLedgerEntry.EntryType.CREDIT,
        )
        now = timezone.now()
        credit.status = RewardLedgerEntry.Status.VOIDED
        credit.reason = rejection_reason
        credit.save(update_fields=["status", "reason"])
        _create_reversal(conversion.click, credit, conversion)
        conversion.status = OfferConversion.Status.REJECTED
        conversion.rejected_at = now
        conversion.decided_by = reviewer
        conversion.decision_reason = rejection_reason
        conversion.save(
            update_fields=[
                "status",
                "rejected_at",
                "decided_by",
                "decision_reason",
                "updated_at",
            ]
        )
        _conversion_event(
            conversion,
            OfferConversionEvent.EventType.REJECTED,
            payload={
                "reason": rejection_reason,
                "reviewer_id": reviewer.pk if reviewer else None,
            },
        )
        return conversion


def _reverse_conversion(conversion, attempt, credit):
    was_approved = conversion.status == OfferConversion.Status.APPROVED
    if conversion.status in {OfferConversion.Status.REVERSED, OfferConversion.Status.REJECTED}:
        return conversion
    now = timezone.now()
    credit.status = RewardLedgerEntry.Status.VOIDED
    credit.reason = "Previously credited completion was reversed"
    credit.save(update_fields=["status", "reason"])
    reversal, _ = _create_reversal(conversion.click, credit, conversion)
    conversion.status = (
        OfferConversion.Status.REVERSED if was_approved else OfferConversion.Status.REJECTED
    )
    conversion.reversed_at = now if was_approved else None
    conversion.rejected_at = None if was_approved else now
    conversion.decision_reason = "Authoritative provider outcome reversed the completion"
    conversion.save(
        update_fields=[
            "status",
            "reversed_at",
            "rejected_at",
            "decision_reason",
            "updated_at",
        ]
    )
    event_type = (
        OfferConversionEvent.EventType.REVERSED
        if was_approved
        else OfferConversionEvent.EventType.REJECTED
    )
    _conversion_event(conversion, event_type, payload={"status": attempt.status})
    if was_approved:
        _create_postback(
            conversion.click,
            attempt,
            "reversal",
            reversal,
            credited=False,
        )
    return conversion


def release_due_conversions(*, limit=200):
    due_ids = list(
        OfferConversion.objects.filter(
            status=OfferConversion.Status.PENDING,
            requires_manual_review=False,
            hold_until__lte=timezone.now(),
        )
        .order_by("hold_until", "pk")
        .values_list("pk", flat=True)[:limit]
    )
    released = 0
    for conversion_id in due_ids:
        try:
            approve_conversion(conversion_id, reason="Automatic hold completed")
        except (OfferConversion.DoesNotExist, RewardLedgerEntry.DoesNotExist, ValueError):
            logger.exception("Could not release Offerwall conversion=%s", conversion_id)
        else:
            released += 1
    return released


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
            conversion = _ensure_conversion(click, attempt)
            if conversion is None:
                return click
            if conversion.status in {
                OfferConversion.Status.APPROVED,
                OfferConversion.Status.REJECTED,
                OfferConversion.Status.REVERSED,
            }:
                return click
            credit, credited = _create_credit(click, conversion)
            if not credited or credit is None:
                conversion.status = OfferConversion.Status.REJECTED
                conversion.rejected_at = timezone.now()
                conversion.decision_reason = "Duplicate or non-payable completion"
                conversion.save(
                    update_fields=["status", "rejected_at", "decision_reason", "updated_at"]
                )
                _conversion_event(
                    conversion,
                    OfferConversionEvent.EventType.REJECTED,
                    payload={"reason": conversion.decision_reason},
                )
                _create_postback(
                    click,
                    attempt,
                    "complete",
                    None,
                    credited=False,
                )
                return click
            if conversion.requires_manual_review or conversion.hold_until > timezone.now():
                return click
            approve_conversion(conversion.pk, reason="Immediate verified release")
            return click

        credit = RewardLedgerEntry.objects.filter(
            click=click, entry_type=RewardLedgerEntry.EntryType.CREDIT
        ).first()
        if credit and attempt.status != SurveyAttempt.Status.COMPLETED and authoritative:
            conversion = getattr(click, "conversion", None) or _ensure_conversion(click, attempt)
            if conversion is None:
                return click
            if credit.conversion_id is None:
                credit.conversion = conversion
                credit.save(update_fields=["conversion"])
            _reverse_conversion(conversion, attempt, credit)
        return click
