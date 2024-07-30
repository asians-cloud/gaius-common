from elasticsearch_dsl import Document, Keyword, Text, Date, Ip
from django.conf import settings


class ChangeLogDocument(Document):
    request_id = Keyword()
    model_name = Keyword()
    instance_id = Text()
    field_name = Keyword()
    old_value = Text()
    new_value = Text()
    timestamp = Date()
    type = Keyword()
    hostname = Text()
    api_endpoint = Text()
    user = Text()
    ip_address = Ip()

    class Index:
        name = settings.LOGS_INDEX_V3
