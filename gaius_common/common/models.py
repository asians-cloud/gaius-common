from django.db import models

# Create your models here.
class TGUser(models.Model):
    name = models.TextField(unique=True, blank=True, null=True)
    value = models.TextField(blank=True, null=True)
