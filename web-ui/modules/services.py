import os
from elasticsearch import Elasticsearch

ES_URL = os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')
ES_USERNAME = os.getenv('ES_USERNAME', 'elastic')
ES_PASSWORD = os.getenv('ES_PASSWORD', '')

client = Elasticsearch(
    [ES_URL],
    basic_auth=(ES_USERNAME, ES_PASSWORD),
    request_timeout=300,
    max_retries=10,
    retry_on_timeout=True
)
