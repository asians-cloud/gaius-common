# Generated by Django 5.0.6 on 2024-06-11 10:12

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("common", "0002_alter_tguser_value"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ChangeLog",
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
                (
                    "model_name",
                    models.CharField(max_length=100, verbose_name="Model Name"),
                ),
                (
                    "instance_id",
                    models.PositiveIntegerField(verbose_name="Instance ID"),
                ),
                (
                    "field_name",
                    models.CharField(max_length=100, verbose_name="Field Name"),
                ),
                ("old_value", models.TextField(verbose_name="Old Value")),
                ("new_value", models.TextField(verbose_name="New Value")),
                (
                    "timestamp",
                    models.DateTimeField(auto_now_add=True, verbose_name="Timestamp"),
                ),
                (
                    "type",
                    models.PositiveIntegerField(
                        choices=[(1, "create"), (2, "update")],
                        default=1,
                        verbose_name="Type",
                    ),
                ),
                (
                    "hostname",
                    models.CharField(
                        blank=True, max_length=255, null=True, verbose_name="Hostname"
                    ),
                ),
                (
                    "api_endpoint",
                    models.CharField(
                        blank=True,
                        max_length=100,
                        null=True,
                        verbose_name="API Endpoint",
                    ),
                ),
                (
                    "ip_address",
                    models.CharField(
                        blank=True, max_length=50, null=True, verbose_name="IP Address"
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="changelog_users",
                        to=settings.AUTH_USER_MODEL,
                        verbose_name="User",
                    ),
                ),
            ],
        ),
    ]