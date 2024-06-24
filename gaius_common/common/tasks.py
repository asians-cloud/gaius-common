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

CHANGE_LOG_CREATE = "create"
CHANGE_LOG_UPDATE = "update"

@app.task(name='common.track_changes')
def track_changes(sender, instance_id=None, created=False, field_changes=None, request_meta=None):
    try:
        if not instance_id or not field_changes or not request_meta:
            return
        
        change_type = CHANGE_LOG_CREATE if created else CHANGE_LOG_UPDATE

        # Initialize the index
        ChangeLogDocument.init(using=client)

        # Create a list of documents to be indexed
        documents = []
        for field_name, (old_value, new_value) in field_changes.items():
            if old_value != new_value:
                documents.append(
                    ChangeLogDocument(
                        request_id=request_meta['request_id'],
                        model_name=sender,
                        instance_id=instance_id,
                        field_name=field_name,
                        old_value=str(old_value),
                        new_value=str(new_value),
                        type=change_type,
                        timestamp=timezone.now(),
                        hostname=request_meta['hostname'],
                        api_endpoint=request_meta['api_endpoint'],
                        user=request_meta['user'],
                        ip_address=request_meta['ip_address']
                    )
                )

        # Convert documents to the format required by the bulk helper
        if documents:
            actions = [
                {
                    "_index": ChangeLogDocument._index._name,  # Ensure the index name is included
                    "_source": doc.to_dict()
                }
                for doc in documents
            ]

            # Use the bulk helper to index documents
            try:
                bulk(client, actions)
            except BulkIndexError as e:
                logger.error(f"Bulk indexing error: {e}")
    except Exception as e:
        logger.error(f"Error in track_changes task: {e}")