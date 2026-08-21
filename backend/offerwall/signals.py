"""Keep Offerwall accounting synchronized with authoritative survey outcomes."""

import logging

from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

from surveys.models import SurveyAttempt


logger = logging.getLogger(__name__)


def _synchronize(attempt_id):
    try:
        from .services import process_attempt_outcome

        process_attempt_outcome(attempt_id)
    except Exception:
        logger.exception("Could not synchronize Offerwall attempt=%s", attempt_id)


@receiver(post_save, sender=SurveyAttempt)
def synchronize_offerwall_attempt(sender, instance, **kwargs):
    if not hasattr(instance, "offerwall_click"):
        return
    transaction.on_commit(lambda: _synchronize(instance.pk), robust=True)
