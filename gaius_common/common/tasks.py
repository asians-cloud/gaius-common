from django.utils import timezone
from django.conf import settings
from elasticsearch.helpers import bulk
from elasticsearch import Elasticsearch
from gaius_common.common.document import ChangeLogDocument
from elasticsearch.helpers import BulkIndexError
from config.celery_app import app
import logging

logger = logging.getLogger(__name__)

client = Elasticsearch(
    hosts=[settings.ELASTICSEARCH_API_HOST],
    api_key=settings.ELASTICSEARCH_API_KEY
)

@app.task(name='common.track_changes')
def track_changes(change_log_data):
    # Initialize the index
    ChangeLogDocument.init(using=client)
    logger.info("Task called>>>>>>>>>>>>>>>>",change_log_data['change_type'])

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
        try:
            bulk(client, actions)
        except BulkIndexError as e:
            # Log the error or handle it as necessary
            pass