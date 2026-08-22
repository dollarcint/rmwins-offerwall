from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("offerwall", "0016_publisher_operational_status"),
        ("surveys", "0028_survey_created_by_survey_inventory_source_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="publisherplacement",
            name="allowed_country_codes",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text=(
                    "Optional ISO alpha-2 country allowlist. Empty allows every "
                    "survey market."
                ),
            ),
        ),
        migrations.AddField(
            model_name="publisherplacement",
            name="allowed_device_types",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text=(
                    "Optional placement device allowlist. Empty allows every "
                    "detected device."
                ),
            ),
        ),
        migrations.CreateModel(
            name="PlacementOfferOverride",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("is_excluded", models.BooleanField(db_index=True, default=False)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "placement",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="offer_overrides",
                        to="offerwall.publisherplacement",
                    ),
                ),
                (
                    "survey",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="offerwall_placement_overrides",
                        to="surveys.survey",
                    ),
                ),
            ],
            options={"ordering": ["placement", "survey"]},
        ),
        migrations.AddConstraint(
            model_name="placementofferoverride",
            constraint=models.UniqueConstraint(
                fields=("placement", "survey"),
                name="unique_placement_offer_override",
            ),
        ),
    ]
