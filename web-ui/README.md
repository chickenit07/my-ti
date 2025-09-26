# Credential Search Application with User Authentication

This is an updated version of the credential search application that now includes user authentication and a token management system for guest users.

## Features

### User Authentication
- **Login System**: Users must login before accessing the search functionality
- **Two User Types**:
  - **Admin**: Full access without restrictions
  - **Guest**: Limited access with token-based searching

  - Requires tokens to search

### Token System (Guest Users Only)
- **Token Earning**: Guest users can earn tokens by answering the security question correctly
  - Question: "Who is the most handsome man in the world?"
  - Answer: `dat` (case insensitive)
  - Each correct answer = 1 token

- **Token Usage**: Each search costs 1 token for guest users
- **Token Tracking**: Tokens are persistent and stored in the SQLite database

## Installation

1. Install required dependencies:
```bash
pip install -r requirements.txt
```

2. Run the application:
```bash
python app.py
```

3. Access the application at `http://localhost:8000`

## Database

The application uses SQLite3 for user management:
- Database file: `users.db` (created automatically)
- Stores user credentials, roles, and token counts
- Default users are created automatically on first run

## Changes from Previous Version

### Removed
- ❌ Direct security password requirement in search form
- ❌ Single-use password system

### Added
- ✅ User authentication system
- ✅ Login/logout functionality
- ✅ Token-based access control for guest users
- ✅ Persistent token storage
- ✅ User role management (admin/guest)
- ✅ Security question system for token earning
- ✅ Session management
- ✅ Flash messages for user feedback

## How It Works

1. **Login**: Users must login with their credentials
2. **Admin Access**: Admin users can search immediately without restrictions
3. **Guest Access**: Guest users need tokens to search:
   - Answer security questions to earn tokens
   - Each search deducts 1 token
   - Must earn more tokens when balance reaches 0

## Security Features

- Password hashing using SHA256
- Session-based authentication
- Role-based access control
- Secure token management
- Input validation and sanitization

## API Endpoints

- `GET /` - Redirects to login or search based on authentication
- `GET /login` - Login page
- `POST /login` - Process login credentials
- `GET /logout` - Logout and clear session
- `GET /search` - Search interface (requires authentication)
- `POST /add_tokens` - Add tokens for guest users (AJAX endpoint)

## Configuration

### Elasticsearch Configuration
Update these variables in `app.py`:
```python
ES_URL = "http://localhost:9200"
ES_USERNAME = "elastic"
ES_PASSWORD = "Dat1999@"
```

### Security Configuration
Update the security question answer:
```python
SECURITY_PASSWORD = "dat"
```

### Flask Configuration
Change the secret key for production:
```python
app.secret_key = 'your-secret-key-change-this'
```

## File Structure

```
web-ui copy/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── users.db              # SQLite database (auto-created)
├── templates/
│   ├── login.html        # Login page template
│   └── search.html       # Search interface template
└── README.md             # This file
```

## Troubleshooting

### Port Already in Use
If port 8001 is in use, the application will show an error. Either:
1. Stop the existing service on port 8001
2. Change the port in `app.py`: `app.run(host='0.0.0.0', port=8002, debug=True)`

### Database Issues
If you encounter database issues, delete `users.db` and restart the application to recreate it with default users.

### Elasticsearch Connection
Ensure Elasticsearch is running and accessible at the configured URL with the correct credentials. 
## Default Users

The application creates two default users on first run:
- **Admin User**: Full access without restrictions
- **Guest User**: Limited access with token-based searching

**Note**: Default credentials are not displayed on the login page for security reasons. Contact your system administrator for login credentials.

## Search Function Fix

### Problem Identified
The search function was not returning consistent results because of issues with the Elasticsearch query structure:

1. **Bool Query Issue**: The original query used `bool` with `should` clauses without proper configuration
2. **Scoring Problems**: When using `should` without `minimum_should_match`, Elasticsearch might not return results if the score is too low
3. **Query Structure**: The query was not optimized for different search scenarios

### Solution Applied
The search query logic has been improved with:

1. **Single Condition Optimization**: When searching for only domain OR username, the query now uses the condition directly instead of wrapping it in a bool query
2. **Multiple Conditions**: When searching for both domain AND username, the query uses `bool` with `should` and `minimum_should_match: 1`
3. **Better Query Structure**: The query is now more efficient and consistent

### Before vs After

**Before (Problematic)**:
```json
{
  "size": 5,
  "query": {
    "bool": {
      "should": [
        {"wildcard": {"d": "*google*"}}
      ]
    }
  }
}
```

**After (Fixed)**:
```json
{
  "size": 5,
  "query": {
    "wildcard": {"d": "*google*"}
  }
}
```

This fix ensures that:
- ✅ Search results are consistent regardless of the number of results requested
- ✅ Single-condition searches are more efficient
- ✅ Multiple-condition searches work properly with OR logic
- ✅ The query structure is optimized for Elasticsearch

## Latest Fixes (v2)

### Search Function Fix (v2)
The search function has been completely rewritten to ensure consistent results:

**Problem**: Searching for 5 results would return fewer results than searching for 500 results.

**Root Cause**: The query structure was not properly handling different search scenarios.

**Solution**: Implemented a more robust query building logic:

1. **Domain Only**: Uses direct wildcard/term query
2. **Username Only**: Uses direct wildcard/term query  
3. **Both Domain & Username**: Uses bool query with should (OR logic)
4. **No Search Criteria**: Returns empty results properly

**New Query Structure**:
```python
if domain and username:
    # OR logic - matches domain OR username
    query = {
        "size": line,
        "query": {
            "bool": {
                "should": [
                    {"wildcard": {"d": f"*{domain}*"}},
                    {"wildcard": {"u": f"*{username}*"}}
                ],
                "minimum_should_match": 1
            }
        }
    }
elif domain:
    # Direct domain search
    query = {
        "size": line,
        "query": {"wildcard": {"d": f"*{domain}*"}}
    }
```

### UI Improvements
- **Column Width Optimization**: 
  - Select column: Reduced from 5% to 2% width
  - Username column: Increased from 12% to 20% width
  - Password column: Increased from 12% to 20% width
  - Note column: Adjusted from 40% to 32% width
  - Domain column: Increased from 12% to 15% width

### Results
- ✅ **Consistent Results**: Searching for 5 results now returns the same top 5 results as searching for 500 results
- ✅ **Better Performance**: More efficient query structure
- ✅ **Improved UI**: Better column proportions for readability
- ✅ **Reliable Search**: No more inconsistent result counts
