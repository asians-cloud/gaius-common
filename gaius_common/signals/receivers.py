from django.db.models.signals import pre_save
from django.dispatch import receiver
from django.contrib.auth.models import User

from gaius_common.utils import update_lastname_keycloak


@receiver(pre_save, sender=User)
def update_keycloak(sender, instance, **kwargs):
    if User.objects.filter(id=instance.id).exists():
        user = instance
        try:
            cname = user.username.split('-')[0]
            update_lastname_keycloak(cname)
        except:
            pass

