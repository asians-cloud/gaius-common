from django.db import models
from django.contrib.auth.models import User

# Create your models here.
class TGUser(models.Model):
    name = models.TextField(unique=True, blank=True, null=True)
    value = models.TextField(default="",null=False)

    def __str__(self):
        return str(self.name)
