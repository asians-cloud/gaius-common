from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from django.conf import settings
from gaius_common.utils import update_lastname_keycloak
from gaius_common.middleware.changeLog import get_current_request
from elasticsearch import Elasticsearch
from config.celery_app import app
from django.utils import timezone
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

CHANGE_LOG_CREATE = "create"
CHANGE_LOG_UPDATE = "update"


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
def track_changes(sender, instance, created, **kwargs):

    current_context = get_current_request()
    print(current_context)
    if not current_context:
        return
    
    request_id = current_context.get('request_id', None)
    ip_address = current_context.get('ip_address', 'Unknown')

    change_type = CHANGE_LOG_CREATE if created else CHANGE_LOG_UPDATE

    hostname = 'Unknown'
    api_endpoint = 'Unknown'
    user = 'Anonymous'

    # Safely get the request object from the context
    request = current_context.get('request', None)
    if request:
        hostname = request.headers.get('Origin', 'Unknown')
        api_endpoint = request.path

        if request.user.is_authenticated:
            user = request.user.email

    # Collect data to send to the Celery task
    change_log_data = {
        'request_id': request_id,
        'model_name': sender.__name__,
        'instance_id': instance.pk,
        'change_type': change_type,
        'timestamp': timezone.now().isoformat(),
        'hostname': hostname,
        'api_endpoint': api_endpoint,
        'user': user,
        'ip_address': ip_address,
        'field_changes': []
    }

    field_names = [field.name for field in sender._meta.get_fields()]

    for field_name in field_names:

        old_value = getattr(instance, f"old_{field_name}", None)
        new_value = getattr(instance, field_name, None)
        if old_value != new_value:
            change_log_data['field_changes'].append({
                'field_name': field_name,
                'old_value': str(old_value),
                'new_value': str(new_value)
            })

    # Trigger the Celery task
    if change_log_data['field_changes']:
        app.send_task('common.track_changes', kwargs={'change_log_data': change_log_data}, queue='common')