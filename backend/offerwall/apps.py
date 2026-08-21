from django.apps import AppConfig


class OfferwallConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "offerwall"
    verbose_name = "RM Wins Offerwall"

    def ready(self):
        from . import signals  # noqa: F401
