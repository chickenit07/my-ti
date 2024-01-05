from flask import Flask, request, jsonify
from elasticsearch import Elasticsearch
from dateutil.parser import parse

# Initialize Flask application
app = Flask(__name__)

# Initialize Elasticsearch client
ES_URL = "http://10.10.0.10:9200"
USERNAME = "elastic"
PASSWORD = "xxx"
client = Elasticsearch(
    [ES_URL],
    http_auth=(USERNAME, PASSWORD),
)

# Define API endpoint for Elasticsearch search
@app.route('/search', methods=['GET'])
def search():
    # Get the domain and username parameters from the HTTP GET request
    domain = request.args.get('domain')
    username = request.args.get('username')

    # Index to search within
    INDEX = "linkpass"

    # Initialize the search query with result size set to 100
    query = {
        "size": 100,
        "query": {
            "bool": {
                "should": []
            }
        }
    }

    # Add wildcard or match queries for domain and username to the search query if specified
    if domain:
        query['query']['bool']['should'].append({"wildcard": {"d": f"*{domain}*"}})
    if username:
        query['query']['bool']['should'].append({"wildcard": {"u": f"*{username}*"}})

    # Execute the search query
    response = client.search(index=INDEX, body=query)

    # Extract and format the specified fields from the search results
    hits = [
        {
            "Time": parse(hit['_source']['@timestamp']).strftime('%d/%m/%Y'),
            "Domain": hit['_source']['d'],
            "Username": hit['_source']['u'],
            "Password": hit['_source']['p']
        }
        for hit in response['hits']['hits']
    ]

    return jsonify(hits)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
