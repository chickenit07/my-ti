import os
from elasticsearch import Elasticsearch
from dotenv import load_dotenv

# Load .env file to get environment variables
load_dotenv()

ES_URL = os.getenv('ELASTICSEARCH_URL', 'http://localhost:9200')
ES_USERNAME = os.getenv('ES_USERNAME', 'elastic')
ES_PASSWORD = os.getenv('ES_PASSWORD', '')
ES_INDEX = os.getenv('ES_INDEX', 'urluserpass')

client = Elasticsearch(
    [ES_URL],
    basic_auth=(ES_USERNAME, ES_PASSWORD),
    request_timeout=300,
    max_retries=10,
    retry_on_timeout=True
)
