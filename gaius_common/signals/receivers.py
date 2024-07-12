from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.conf import settings
from gaius_common.utils import update_lastname_keycloak
from gaius_common.middleware.changeLog import get_current_request
from elasticsearch import Elasticsearch
from config.celery_app import app
import logging

logger = logging.getLogger(__name__)

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


@receiver(pre_save)
def capture_old_values(sender, instance, **kwargs):
    if instance.pk:
        try:
            old_instance = sender.objects.get(pk=instance.pk)
            for field in instance._meta.fields:
                old_value = getattr(old_instance, field.attname)
                setattr(instance, f"old_{field.attname}", old_value)
        except sender.DoesNotExist:
            pass

@receiver(post_save)
def trigger_track_changes(sender, instance, created, **kwargs):
    try:
        request = get_current_request()
        request_meta = {
            'request_id': request.request_id if request else None,
            'hostname': request.headers.get('Origin') if request else 'Unknown',
            'api_endpoint': request.path if request else 'Unknown',
            'ip_address': request.META.get('REMOTE_ADDR') if request else 'Unknown',
            'user': request.user.email if request and request.user.is_authenticated and request.user.email else 'Anonymous'
        }

        field_changes = {}
        if instance.pk:
            try:
                old_instance = sender.objects.get(pk=instance.pk)
                for field in instance._meta.fields:
                    old_value = getattr(old_instance, field.attname)
                    new_value = getattr(instance, field.attname)
                    if old_value != new_value:
                        field_changes[field.name] = (old_value, new_value)
            except sender.DoesNotExist:
                pass


        app.send_task(
            'common.track_changes',
            kwargs={
                'sender': sender.__name__,
                'instance_id': instance.pk,
                'created': created,
                'field_changes': field_changes,
                'request_meta': request_meta,
            }
        )
    except Exception as e:
        logger.error(f"Error triggering track_changes task: {e}")