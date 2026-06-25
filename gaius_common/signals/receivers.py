import logging

from django.contrib.auth.models import User
from django.db.models.signals import pre_save
from django.dispatch import receiver

from gaius_common.utils import update_lastname_keycloak

logger = logging.getLogger(__name__)


@receiver(pre_save, sender=User)
def update_keycloak(sender, instance, **kwargs):
    if instance.id:
        try:
            user = instance
            if user.last_name == "Caesar":
                cname = user.username.split("-")[0]
                update_lastname_keycloak(cname)
                user.last_name = cname
        except Exception:
            # Never block the save on a Keycloak-sync failure, but don't
            # swallow it silently either.
            logger.exception(
                "Failed to sync last name to Keycloak for user %s", instance.pk
            )
