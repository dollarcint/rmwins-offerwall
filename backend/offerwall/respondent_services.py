"""Respondent onboarding, verification email, and verification state transitions."""

from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.mail import send_mail
from django.db import transaction
from django.utils import timezone

from .models import RespondentProfile
from .respondent_security import (
    generate_verification_code,
    verification_code_hash,
    verification_code_matches,
)


def issue_respondent_verification(profile: RespondentProfile, *, force=False) -> None:
    now = timezone.now()
    if (
        not force
        and profile.verification_sent_at
        and profile.verification_sent_at
        > now - timedelta(seconds=settings.OFFERWALL_VERIFICATION_RESEND_SECONDS)
    ):
        raise ValidationError("Please wait before requesting another verification code.")

    code = generate_verification_code()
    profile.verification_code_hash = verification_code_hash(profile.public_id, code)
    profile.verification_sent_at = now
    profile.verification_expires_at = now + timedelta(
        seconds=settings.OFFERWALL_VERIFICATION_TTL_SECONDS
    )
    profile.verification_attempts = 0
    profile.save(
        update_fields=[
            "verification_code_hash",
            "verification_sent_at",
            "verification_expires_at",
            "verification_attempts",
            "updated_at",
        ]
    )

    minutes = max(1, settings.OFFERWALL_VERIFICATION_TTL_SECONDS // 60)
    send_mail(
        subject="Verify your RM Wins survey account",
        message=(
            f"Hello {profile.full_name},\n\n"
            f"Your RM Wins verification code is: {code}\n\n"
            f"This code expires in {minutes} minutes. Do not share it with anyone.\n\n"
            f"Supplier: {profile.publisher.name}\n"
            "If you did not request this code, you can ignore this email."
        ),
        from_email=settings.DEFAULT_FROM_EMAIL,
        recipient_list=[profile.email],
        fail_silently=False,
    )


def verify_respondent_code(profile: RespondentProfile, code: str) -> RespondentProfile:
    with transaction.atomic():
        locked = RespondentProfile.objects.select_for_update().get(pk=profile.pk)
        now = timezone.now()
        if locked.is_email_verified:
            return locked
        if locked.verification_attempts >= settings.OFFERWALL_VERIFICATION_MAX_ATTEMPTS:
            raise ValidationError("Too many incorrect attempts. Request a new code.")
        if not locked.verification_expires_at or locked.verification_expires_at <= now:
            raise ValidationError("This code has expired. Request a new code.")
        if not verification_code_matches(
            locked.public_id,
            code,
            locked.verification_code_hash,
        ):
            locked.verification_attempts += 1
            locked.save(update_fields=["verification_attempts", "updated_at"])
            raise ValidationError("The verification code is incorrect.")

        locked.is_email_verified = True
        locked.email_verified_at = now
        locked.verification_code_hash = ""
        locked.verification_expires_at = None
        locked.verification_attempts = 0
        locked.save(
            update_fields=[
                "is_email_verified",
                "email_verified_at",
                "verification_code_hash",
                "verification_expires_at",
                "verification_attempts",
                "updated_at",
            ]
        )
        return locked
