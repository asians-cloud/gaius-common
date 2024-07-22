from django.db.models.signals import pre_save, post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from gaius_common.utils import update_lastname_keycloak
from elasticsearch.helpers import bulk
from elasticsearch import Elasticsearch
from gaius_common.common.document import ChangeLogDocument
from django.conf import settings
from django.dispatch import receiver
from gaius_common.middleware.changeLog import get_current_request
from django.utils import timezone

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

client = Elasticsearch(
    hosts=[settings.ELASTICSEARCH_API_HOST],
    api_key=settings.ELASTICSEARCH_API_KEY
)

@receiver(post_save)
def track_changes(sender, instance, created, **kwargs):

    current_context = get_current_request()
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
        if not user:
            user = 'Anonymous'

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
    # Initialize the index
        try:
            ChangeLogDocument.init(using=client)
            print("Task called >>>>>>>>>>>>>>>>",change_log_data['change_type'])

            # Create a list of documents to be indexed
            documents = []
            for field_change in change_log_data['field_changes']:
                documents.append(
                    ChangeLogDocument(
                        request_id=change_log_data['request_id'],
                        model_name=change_log_data['model_name'],
                        instance_id=change_log_data['instance_id'],
                        field_name=field_change['field_name'],
                        old_value=field_change['old_value'],
                        new_value=field_change['new_value'],
                        type=change_log_data['change_type'],
                        timestamp=timezone.now(),  # Use current time for indexing timestamp
                        hostname=change_log_data['hostname'],
                        api_endpoint=change_log_data['api_endpoint'],
                        user=change_log_data['user'],
                        ip_address=change_log_data['ip_address']
                    )
                )

            # Convert documents to the format required by the bulk helper
            if documents:
                actions = [
                    {
                        "_index": ChangeLogDocument._index._name,
                        "_source": doc.to_dict()
                    }
                    for doc in documents
                ]
                # Use the bulk helper to index documents
                bulk(client, actions)
        except Exception:
            # Log the error or handle it as necessary
            pass