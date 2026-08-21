"""Signed, retryable publisher postback delivery."""

import ipaddress
import json
import socket
from datetime import timedelta
from urllib.parse import urlsplit

import requests
from celery import shared_task
from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .models import PostbackDelivery
from .security import decrypt_signing_secret, postback_signature


def _validated_callback_url(url: str) -> str:
    parsed = urlsplit(str(url or "").strip())
    allowed_schemes = {"http", "https"} if settings.DEBUG else {"https"}
    if parsed.scheme not in allowed_schemes or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Publisher callback URL must be a clean HTTPS URL.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    addresses = {
        ipaddress.ip_address(item[4][0])
        for item in socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    }
    if not addresses or any(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
        for address in addresses
    ):
        raise ValueError("Publisher callback URL resolves to a non-public address.")
    return parsed.geturl()


@shared_task(
    bind=True,
    name="offerwall.deliver_postback",
    autoretry_for=(),
    soft_time_limit=25,
    time_limit=30,
)
def deliver_postback_task(self, delivery_id):
    with transaction.atomic():
        delivery = (
            PostbackDelivery.objects.select_for_update()
            .select_related("publisher")
            .get(pk=delivery_id)
        )
        if delivery.status in {
            PostbackDelivery.Status.DELIVERED,
            PostbackDelivery.Status.SKIPPED,
        }:
            return {"status": delivery.status, "attempts": delivery.attempt_count}
        if not delivery.publisher.is_active or not delivery.publisher.postback_enabled:
            delivery.status = PostbackDelivery.Status.SKIPPED
            delivery.last_error = "Publisher postbacks are disabled."
            delivery.save(update_fields=["status", "last_error", "updated_at"])
            return {"status": delivery.status, "attempts": delivery.attempt_count}
        delivery.attempt_count += 1
        delivery.next_attempt_at = None
        delivery.save(update_fields=["attempt_count", "next_attempt_at", "updated_at"])
        attempt_number = delivery.attempt_count
        callback_url = delivery.callback_url
        payload = delivery.payload
        publisher = delivery.publisher

    try:
        callback_url = _validated_callback_url(callback_url)
        body = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        timestamp = int(timezone.now().timestamp())
        signature = postback_signature(
            decrypt_signing_secret(publisher),
            timestamp=timestamp,
            event_id=str(delivery.public_id),
            body=body,
        )
        response = requests.post(
            callback_url,
            data=body,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "RMWins-Offerwall/1.0",
                "X-Offerwall-Event": str(delivery.public_id),
                "X-Offerwall-Timestamp": str(timestamp),
                "X-Offerwall-Signature": f"sha256={signature}",
            },
            timeout=settings.OFFERWALL_POSTBACK_TIMEOUT_SECONDS,
            allow_redirects=False,
        )
        response_code = response.status_code
        if not 200 <= response_code < 300:
            raise requests.HTTPError(f"Publisher returned HTTP {response_code}")
    except Exception as exc:
        max_attempts = settings.OFFERWALL_POSTBACK_MAX_ATTEMPTS
        countdown = min(3600, 30 * (2 ** max(0, attempt_number - 1)))
        with transaction.atomic():
            delivery = PostbackDelivery.objects.select_for_update().get(pk=delivery_id)
            delivery.status = PostbackDelivery.Status.FAILED
            delivery.response_code = locals().get("response_code")
            delivery.last_error = str(exc)[:2000]
            delivery.next_attempt_at = (
                timezone.now() + timedelta(seconds=countdown)
                if attempt_number < max_attempts
                else None
            )
            delivery.save(
                update_fields=[
                    "status",
                    "response_code",
                    "last_error",
                    "next_attempt_at",
                    "updated_at",
                ]
            )
        if attempt_number < max_attempts:
            raise self.retry(exc=exc, countdown=countdown, max_retries=max_attempts - 1)
        return {"status": "failed", "attempts": attempt_number}

    with transaction.atomic():
        delivery = PostbackDelivery.objects.select_for_update().get(pk=delivery_id)
        delivery.status = PostbackDelivery.Status.DELIVERED
        delivery.response_code = response_code
        delivery.last_error = ""
        delivery.next_attempt_at = None
        delivery.delivered_at = timezone.now()
        delivery.save(
            update_fields=[
                "status",
                "response_code",
                "last_error",
                "next_attempt_at",
                "delivered_at",
                "updated_at",
            ]
        )
    return {"status": "delivered", "attempts": attempt_number}
