# Generated by Django 5.0.6 on 2024-09-03 12:48

from django.conf import settings
from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RenameModel(
            old_name="financial_goals",
            new_name="FinancialGoals",
        ),
        migrations.RenameModel(
            old_name="risk_profile",
            new_name="RiskProfile",
        ),
    ]