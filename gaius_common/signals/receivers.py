from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from gaius_common.utils import update_lastname_keycloak

import logging

logger = logging.getLogger(__name__)

CHANGE_LOG_CREATE = "create"
CHANGE_LOG_UPDATE = "update"

@receiver(pre_save, sender=User)
def update_keycloak(sender, instance, **kwargs):
    if instance.id:
        try:
            user = instance
            if user.last_name == 'Caesar':
                cname = user.username.split('-')[0]
                update_lastname_keycloak(cname)
                user.last_name = cname
        except:
            pass