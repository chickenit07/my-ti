from flask import Flask, request, render_template, jsonify
from elasticsearch import Elasticsearch
from dateutil.parser import parse

# Initialize Flask application
app = Flask(__name__)

# Initialize Elasticsearch client
ES_URL = "http://192.168.137.20:9200"
USERNAME = "elastic"
PASSWORD = "Dat1999@"
client = Elasticsearch(
    [ES_URL],
    http_auth=(USERNAME, PASSWORD),
    timeout=30,
    max_retries=10,
    retry_on_timeout=True
)

# Define API endpoint for Elasticsearch search
@app.route('/search', methods=['GET', 'POST'])
def search():
    # Get the domain, username, line, and type parameters from the HTTP GET request
    domain = request.args.get('domain')
    username = request.args.get('username')
    line = request.args.get('line', default=5, type=int)
    search_type = request.args.get('type', default='exact', type=str).lower()

    # Index to search within
    INDEX = "urluserpass"

    # Initialize the search query with the result size set by the "line" parameter
    query = {
        "size": line,
        "query": {
            "bool": {
                "should": []
            }
        }
    }

    # Add wildcard or match queries for domain and username to the search query based on the type parameter
    if domain:
        if search_type == 'exact':
            query['query']['bool']['should'].append({"term": {"d.keyword": domain}})
        elif search_type == 'subdomain':
            # Use a wildcard query for subdomain matching
            query['query']['bool']['should'].append({"wildcard": {"d": f"*.{domain}*"}})
        else:
            query['query']['bool']['should'].append({"wildcard": {"d": f"*{domain}*"}})

    if username:
        if search_type == 'exact':
            query['query']['bool']['should'].append({"term": {"u.keyword": username}})
        else:
            query['query']['bool']['should'].append({"wildcard": {"u": f"*{username}*"}})

    # Execute the search query
    response = client.search(index=INDEX, body=query)

    # Extract and format the specified fields from the search results
    hits = [
        {
            "t": parse(hit['_source']['@timestamp']).strftime('%d-%m-%Y'),
            "d": hit['_source']['d'],
            "u": hit['_source']['u'],
            "p": hit['_source']['p']
        }
        for hit in response['hits']['hits']
    ]

    # Return HTML content with clickable fields
    return render_template('search.html', hits=hits)

@app.route('/searchapi', methods=['GET', 'POST'])
def search_api():
    # Get the domain, username, line, and type parameters from the HTTP GET request
    domain = request.args.get('domain')
    username = request.args.get('username')
    line = request.args.get('line', default=5, type=int)
    search_type = request.args.get('type', default='exact', type=str).lower()

    # Index to search within
    INDEX = "urluserpass"

    # Initialize the search query with the result size set by the "line" parameter
    query = {
        "size": line,
        "query": {
            "bool": {
                "should": []
            }
        }
    }

    # Add wildcard or match queries for domain and username to the search query based on the type parameter
    if domain:
        if search_type == 'exact':
            query['query']['bool']['should'].append({"term": {"d.keyword": domain}})
        elif search_type == 'subdomain':
            # Use a wildcard query for subdomain matching
            query['query']['bool']['should'].append({"wildcard": {"d": f"*.{domain}*"}})
        else:
            query['query']['bool']['should'].append({"wildcard": {"d": f"*{domain}*"}})

    if username:
        if search_type == 'exact':
            query['query']['bool']['should'].append({"term": {"u.keyword": username}})
        else:
            query['query']['bool']['should'].append({"wildcard": {"u": f"*{username}*"}})

    # Execute the search query
    response = client.search(index=INDEX, body=query)

    # Extract and format the specified fields from the search results
    hits = [
        {
            "t": parse(hit['_source']['@timestamp']).strftime('%d-%m-%Y'),
            "d": hit['_source']['d'],
            "u": hit['_source']['u'],
            "p": hit['_source']['p']
        }
        for hit in response['hits']['hits']
    ]

    # Return JSON response
    return jsonify(hits=hits)

# Define a new route to list every username and password
@app.route('/userpasslist', methods=['GET'])
def user_pass_list():
    # Get the domain, username, line, and type parameters from the HTTP GET request
    domain = request.args.get('domain')
    username = request.args.get('username')
    line = request.args.get('line', default=5, type=int)
    search_type = request.args.get('type', default='exact', type=str).lower()

    # Index to search within
    INDEX = "urluserpass"

    # Initialize the search query with the result size set by the "line" parameter
    query = {
        "size": line,
        "query": {
            "bool": {
                "should": []
            }
        }
    }

    # Add wildcard or match queries for domain and username to the search query based on the type parameter
    if domain:
        if search_type == 'exact':
            query['query']['bool']['should'].append({"term": {"d.keyword": domain}})
        elif search_type == 'subdomain':
            # Use a wildcard query for subdomain matching
            query['query']['bool']['should'].append({"wildcard": {"d": f"*.{domain}*"}})
        else:
            query['query']['bool']['should'].append({"wildcard": {"d": f"*{domain}*"}})

    if username:
        if search_type == 'exact':
            query['query']['bool']['should'].append({"term": {"u.keyword": username}})
        else:
            query['query']['bool']['should'].append({"wildcard": {"u": f"*{username}*"}})

    # Execute the search query
    response = client.search(index=INDEX, body=query)

    # Extract and format the specified fields from the search results
    hits = [
        {
            "u": hit['_source']['u'],
            "p": hit['_source']['p']
        }
        for hit in response['hits']['hits']
    ]

    # Return HTML content for listing every username and password
    return render_template('userpasslist.html', hits=hits)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8000, debug=True)
