"""Public signed wall, offer clicks, result pages and publisher inventory API."""

import re
from datetime import datetime, timezone as datetime_timezone
from decimal import Decimal

from django.conf import settings
from django.core.cache import caches
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.views.decorators.http import require_GET

from surveys.models import Survey, SurveyAttempt

from .models import OfferClick, Publisher, RewardLedgerEntry, WallVisit
from .security import (
    digest_api_key,
    verify_click_signature,
    verify_entry_signature,
    verify_result_signature,
    verify_session_signature,
)
from .services import (
    create_api_visit,
    create_offer_click,
    create_wall_visit,
    offer_catalog,
    process_attempt_outcome,
    result_url,
    session_url,
)


USER_ID_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,160}$")


def _no_store(response):
    response["Cache-Control"] = "no-store, private, max-age=0"
    response["Pragma"] = "no-cache"
    return response


def _error(request, title, message, *, status=400):
    return _no_store(
        render(
            request,
            "offerwall/error.html",
            {"title": title, "message": message},
            status=status,
        )
    )


def _rate_limited(request, scope: str, limit: int) -> bool:
    forwarded = request.META.get("REMOTE_ADDR", "unknown")
    bucket = int(timezone.now().timestamp()) // 60
    key = f"offerwall-rate:{scope}:{forwarded}:{bucket}"
    cache = caches["default"]
    try:
        if cache.add(key, 1, timeout=90):
            return False
        return cache.incr(key) > limit
    except Exception:
        return False


@require_GET
def landing(request):
    return _no_store(
        render(
            request,
            "offerwall/landing.html",
            {
                "active_publishers": Publisher.objects.filter(is_active=True).count(),
                "active_offers": Survey.objects.filter(
                    status=Survey.Status.LIVE, remaining__gt=0, cpi__gt=0
                ).count(),
            },
        )
    )


@require_GET
def wall_entry(request, publisher_slug):
    if _rate_limited(request, "entry", settings.OFFERWALL_ENTRY_RATE_LIMIT_PER_MINUTE):
        return _error(request, "Too many requests", "Please wait a minute and try again.", status=429)
    publisher = get_object_or_404(Publisher, slug=publisher_slug, is_active=True)
    external_user_id = str(request.GET.get("uid") or "").strip()
    nonce = str(request.GET.get("nonce") or "").strip()
    signature = str(request.GET.get("sig") or "").strip()
    timestamp_value = str(request.GET.get("ts") or "").strip()
    if not USER_ID_RE.fullmatch(external_user_id) or not timestamp_value.isdigit():
        return _error(request, "Invalid offerwall link", "The signed publisher link is incomplete.")
    timestamp = int(timestamp_value)
    if not verify_entry_signature(
        publisher,
        external_user_id=external_user_id,
        timestamp=timestamp,
        nonce=nonce,
        signature=signature,
    ):
        return _error(request, "Invalid offerwall link", "The publisher signature is invalid.", status=403)

    now = timezone.now()
    existing = WallVisit.objects.filter(publisher=publisher, entry_nonce=nonce).first()
    age_seconds = int(now.timestamp()) - timestamp
    outside_entry_window = (
        age_seconds > settings.OFFERWALL_ENTRY_TTL_SECONDS
        or age_seconds < -settings.OFFERWALL_ENTRY_FUTURE_SKEW_SECONDS
    )
    if outside_entry_window and not (
        existing
        and existing.external_user_id == external_user_id
        and existing.expires_at > now
    ):
        return _error(request, "Offerwall link expired", "Request a fresh signed link from the publisher.", status=403)
    try:
        entry_at = datetime.fromtimestamp(timestamp, tz=datetime_timezone.utc)
        visit = create_wall_visit(
            publisher,
            external_user_id=external_user_id,
            nonce=nonce,
            entry_timestamp=entry_at,
            request=request,
        )
    except (OverflowError, OSError, ValueError) as exc:
        return _error(request, "Invalid offerwall session", str(exc), status=403)
    return _no_store(HttpResponseRedirect(session_url(visit)))


def _active_visit_or_error(request, visit_id, signature):
    visit = get_object_or_404(
        WallVisit.objects.select_related("publisher"), public_id=visit_id
    )
    if not visit.publisher.is_active:
        return None, _error(request, "Offerwall unavailable", "This publisher is inactive.", status=403)
    if visit.expires_at <= timezone.now():
        return None, _error(request, "Offerwall session expired", "Request a fresh link from the publisher.", status=403)
    if not verify_session_signature(visit.publisher, visit.public_id, signature):
        return None, _error(request, "Invalid offerwall session", "The session signature is invalid.", status=403)
    WallVisit.objects.filter(pk=visit.pk).update(last_seen_at=timezone.now())
    return visit, None


@require_GET
def wall_session(request, visit_id):
    visit, error = _active_visit_or_error(request, visit_id, request.GET.get("sig", ""))
    if error:
        return error
    offers = offer_catalog(visit.publisher, visit)
    response = render(
        request,
        "offerwall/wall.html",
        {
            "publisher": visit.publisher,
            "visit": visit,
            "offers": offers,
            "offer_count": len(offers),
        },
    )
    return _no_store(response)


@require_GET
def click_offer(request, visit_id, survey_id):
    visit = get_object_or_404(
        WallVisit.objects.select_related("publisher"), public_id=visit_id
    )
    if visit.expires_at <= timezone.now() or not visit.publisher.is_active:
        return _error(request, "Offer unavailable", "This offerwall session has expired.", status=403)
    if not verify_click_signature(
        visit.publisher, visit.public_id, survey_id, request.GET.get("sig", "")
    ):
        return _error(request, "Invalid offer link", "The offer signature is invalid.", status=403)
    survey = get_object_or_404(Survey.objects.select_related("client", "integration"), local_id=survey_id)
    try:
        click, created = create_offer_click(visit=visit, survey=survey, request=request)
    except ValueError as exc:
        return _error(request, "Offer unavailable", str(exc), status=409)
    if not created and click.attempt.status != SurveyAttempt.Status.INITIATED:
        return _no_store(HttpResponseRedirect(result_url(click)))
    return _no_store(
        HttpResponseRedirect(f"{reverse('survey-start')}?rid={click.attempt.rid}")
    )


@require_GET
def result(request, click_id):
    click = get_object_or_404(
        OfferClick.objects.select_related("publisher", "survey", "attempt", "visit"),
        public_id=click_id,
    )
    if not verify_result_signature(click.publisher, click.public_id, request.GET.get("sig", "")):
        return _error(request, "Invalid result link", "The result signature is invalid.", status=403)
    process_attempt_outcome(click.attempt_id)
    click.refresh_from_db()
    credit = RewardLedgerEntry.objects.filter(
        click=click, entry_type=RewardLedgerEntry.EntryType.CREDIT
    ).first()
    state = "pending"
    title = "Result pending"
    message = "The provider result is still being verified. No reward has been credited yet."
    if click.status == SurveyAttempt.Status.COMPLETED and credit:
        state = "success"
        title = "Offer completed"
        message = "The verified completion was credited successfully."
    elif click.status == SurveyAttempt.Status.COMPLETED:
        title = "Completion awaiting verification"
        message = "The completion has not produced a new verified credit yet."
    elif click.status in {
        SurveyAttempt.Status.TERMINATED,
        SurveyAttempt.Status.OVER_QUOTA,
        SurveyAttempt.Status.QUALITY_TERMINATED,
    }:
        state = "no-credit"
        title = click.attempt.get_status_display()
        message = "This attempt did not qualify for a reward. You can choose another offer."
    response = render(
        request,
        "offerwall/result.html",
        {
            "click": click,
            "credit": credit,
            "state": state,
            "title": title,
            "message": message,
            "wall_url": session_url(click.visit) if click.visit.expires_at > timezone.now() else "",
        },
    )
    return _no_store(response)


def _publisher_from_api_key(request):
    raw_key = str(request.headers.get("X-Offerwall-Key") or "").strip()
    if not 20 <= len(raw_key) <= 200:
        return None
    publisher = Publisher.objects.filter(
        api_key_hash=digest_api_key(raw_key), is_active=True
    ).first()
    if publisher:
        Publisher.objects.filter(pk=publisher.pk).update(api_key_last_used_at=timezone.now())
    return publisher


@require_GET
def offers_api(request):
    if _rate_limited(request, "api", settings.OFFERWALL_API_RATE_LIMIT_PER_MINUTE):
        return _no_store(JsonResponse({"error": "Rate limit exceeded."}, status=429))
    publisher = _publisher_from_api_key(request)
    if not publisher:
        return _no_store(JsonResponse({"error": "Invalid Offerwall API key."}, status=401))
    external_user_id = str(request.GET.get("uid") or "").strip()
    if not USER_ID_RE.fullmatch(external_user_id):
        return _no_store(JsonResponse({"error": "A valid uid is required."}, status=400))
    visit = create_api_visit(publisher, external_user_id=external_user_id, request=request)
    offers = offer_catalog(publisher, visit)
    response_offers = [
        {
            **item,
            "reward": str(item["reward"] if item["reward"] is not None else Decimal("0.00")),
            "incidence_rate": str(item["incidence_rate"]) if item["incidence_rate"] is not None else None,
            "click_url": request.build_absolute_uri(item["click_url"]),
        }
        for item in offers
    ]
    return _no_store(
        JsonResponse(
            {
                "publisher": {
                    "name": publisher.name,
                    "slug": publisher.slug,
                    "currency": publisher.currency,
                },
                "user_id": external_user_id,
                "session_url": session_url(visit),
                "expires_at": visit.expires_at.isoformat(),
                "offers": response_offers,
            }
        )
    )
