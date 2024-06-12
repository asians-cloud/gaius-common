from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class TGUser(models.Model):
    name = models.TextField(unique=True, blank=True, null=True)
    value = models.TextField(default="",null=False)

    def __str__(self):
        return str(self.name)



CHANGE_LOG_CREATE = 1
CHANGE_LOG_UPDATE = 2
CHANGE_LOG_TYPE_CHOICES = (
    (CHANGE_LOG_CREATE, 'create'),
    (CHANGE_LOG_UPDATE, 'update'),
)

class ChangeLog(models.Model):

    model_name = models.CharField(
        max_length=100,
        verbose_name='Model Name'
    )
    instance_id = models.CharField(
        max_length=255,
        verbose_name='Instance ID'
    )
    field_name = models.CharField(
        max_length=100,
        verbose_name='Field Name'
    )
    old_value = models.TextField(
        verbose_name='Old Value'
    )
    new_value = models.TextField(
        verbose_name='New Value'
    )
    timestamp = models.DateTimeField(
        auto_now_add=True,
        verbose_name='Timestamp'
    )
    type = models.PositiveIntegerField(
        choices=CHANGE_LOG_TYPE_CHOICES,
        default=CHANGE_LOG_CREATE,
        verbose_name='Type'
    )
    hostname = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        verbose_name='Hostname'
    )
    api_endpoint = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        verbose_name='API Endpoint'
    )
    user = models.CharField(
        max_length=255,
        blank=True,
        null=True,
        verbose_name='User'
    )
    ip_address = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        verbose_name='IP Address'
    )

    def __str__(self):
        return f"{self.model_name} - {self.field_name}"