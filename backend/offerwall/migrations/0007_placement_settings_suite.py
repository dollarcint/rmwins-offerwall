import decimal
import uuid

import django.core.validators
import django.db.models.deletion
import offerwall.models
from django.db import migrations, models


def seed_currency_names(apps, schema_editor):
    Placement = apps.get_model("offerwall", "PublisherPlacement")
    for placement in Placement.objects.all().only("pk", "currency").iterator():
        Placement.objects.filter(pk=placement.pk).update(
            currency_name=placement.currency or "Points"
        )


class Migration(migrations.Migration):
    dependencies = [("offerwall", "0006_opinionuniverse_placement_platforms")]

    operations = [
        migrations.AddField(
            model_name="publisherplacement",
            name="active_content_types",
            field=models.JSONField(default=offerwall.models.default_placement_content_types),
        ),
        migrations.AddField(
            model_name="publisherplacement",
            name="currency_icon",
            field=models.FileField(blank=True, upload_to=offerwall.models.placement_currency_icon_path),
        ),
        migrations.AddField(
            model_name="publisherplacement",
            name="currency_name",
            field=models.CharField(default="Points", max_length=16),
        ),
        migrations.AddField(
            model_name="publisherplacement",
            name="header_logo",
            field=models.FileField(blank=True, upload_to=offerwall.models.placement_header_logo_path),
        ),
        migrations.AddField(
            model_name="publisherplacement",
            name="postback_email_opt_out",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="publisherplacement",
            name="reward_rounding_precision",
            field=models.PositiveSmallIntegerField(
                choices=[
                    (1, "1 decimal place"),
                    (2, "2 decimal places"),
                    (3, "3 decimal places"),
                    (4, "4 decimal places"),
                ],
                default=2,
            ),
        ),
        migrations.AddField(
            model_name="publisherplacement",
            name="traffic_type",
            field=models.CharField(
                choices=[
                    ("incent", "Rewarded"),
                    ("non_incent", "Non-rewarded"),
                    ("both", "All sources"),
                ],
                default="incent",
                max_length=12,
            ),
        ),
        migrations.AddField(
            model_name="publisherplacement",
            name="user_revenue_share",
            field=models.DecimalField(
                decimal_places=2,
                default=decimal.Decimal("100.00"),
                max_digits=5,
                validators=[
                    django.core.validators.MinValueValidator(decimal.Decimal("0.00")),
                    django.core.validators.MaxValueValidator(decimal.Decimal("100.00")),
                ],
            ),
        ),
        migrations.AddField(
            model_name="publisherplacement",
            name="whitelist_postback_ip",
            field=models.BooleanField(default=True),
        ),
        migrations.AlterField(
            model_name="publisherplacement",
            name="postback_url",
            field=models.CharField(
                blank=True,
                help_text="Optional placement-specific HTTPS outcome endpoint with supported macros.",
                max_length=2000,
            ),
        ),
        migrations.RunPython(seed_currency_names, migrations.RunPython.noop),
        migrations.CreateModel(
            name="PlacementEventPostback",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("public_id", models.UUIDField(default=uuid.uuid4, editable=False, unique=True)),
                (
                    "event_type",
                    models.CharField(
                        choices=[
                            ("complete", "Completed"),
                            ("terminate", "Terminated"),
                            ("over_quota", "Over quota"),
                            ("quality_terminate", "Quality terminated"),
                            ("reversal", "Reversal"),
                        ],
                        max_length=24,
                    ),
                ),
                ("event_name", models.CharField(blank=True, max_length=120)),
                ("callback_url", models.CharField(max_length=2000)),
                ("is_active", models.BooleanField(db_index=True, default=True)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "placement",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="event_postbacks",
                        to="offerwall.publisherplacement",
                    ),
                ),
                (
                    "survey",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="offerwall_event_postbacks",
                        to="surveys.survey",
                    ),
                ),
            ],
            options={
                "ordering": ["-created_at"],
                "indexes": [
                    models.Index(
                        fields=["placement", "event_type", "is_active"],
                        name="placement_event_postback_idx",
                    )
                ],
            },
        ),
    ]
