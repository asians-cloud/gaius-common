from elasticsearch_dsl import Document, Keyword, Text, Date, Integer


class ChangeLogDocument(Document):
    request_id = Keyword()
    model_name = Text()
    instance_id = Text()
    field_name = Text()
    old_value = Text()
    new_value = Text()
    timestamp = Date()
    type = Text()
    hostname = Text()
    api_endpoint = Text()
    user = Text()
    ip_address = Text()

    class Index:
        name = 'change-logs'
