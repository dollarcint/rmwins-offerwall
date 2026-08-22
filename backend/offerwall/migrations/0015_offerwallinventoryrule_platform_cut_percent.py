from decimal import Decimal

from django.core.validators import MaxValueValidator, MinValueValidator
from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("offerwall", "0014_offerwallinventoryrule_and_more"),
    ]

    operations = [
        migrations.AddField(
            model_name="offerwallinventoryrule",
            name="platform_cut_percent",
            field=models.DecimalField(
                blank=True,
                decimal_places=2,
                help_text=(
                    "Optional survey-level RM Wins cut. Blank falls back to the "
                    "supplier's default payout percentage."
                ),
                max_digits=5,
                null=True,
                validators=[
                    MinValueValidator(Decimal("0.00")),
                    MaxValueValidator(Decimal("100.00")),
                ],
            ),
        ),
    ]
