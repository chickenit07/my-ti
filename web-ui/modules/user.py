from flask import Blueprint, request, render_template, session, redirect, url_for, flash, jsonify
from datetime import datetime
from collections import defaultdict, deque
from dateutil.parser import parse

from .db import (
    get_db_connection,
    update_user_tokens,
    log_search,
    create_saved_search,
    save_results,
    get_saved_searches_for_user,
    get_saved_results_for_search,
    delete_saved_result,
    get_user,
)
from .services import client as es_client, ES_INDEX

user_bp = Blueprint('user', __name__)

# In-memory rate limiting shared across user routes
RATE_LIMIT_WINDOW_SECONDS = 10
RATE_LIMIT_MAX_REQUESTS = 5
EARN_TOKENS_WINDOW_SECONDS = 60
EARN_TOKENS_MAX_REQUESTS = 3
recent_requests_by_key = defaultdict(lambda: deque(maxlen=RATE_LIMIT_MAX_REQUESTS))


def _sync_session_from_db():
    try:
        if 'user_id' not in session or 'username' not in session:
            return
        row = get_user(session['username'])
        if not row:
            return
        # Keep session tokens/role in sync with DB in case admin changed them
        session['tokens'] = row['tokens']
        session['role'] = row['role']
    except Exception:
        pass

@user_bp.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('user.search'))
    return redirect(url_for('user.login'))


@user_bp.route('/login', methods=['GET', 'POST'])
def login():
    from .db import get_user, verify_password, update_last_login
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        user = get_user(username)
        if user and verify_password(password, user['password_hash']):
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            session['tokens'] = user['tokens']

            update_last_login(username)
            flash(f'Welcome, {username}!', 'success')
            return redirect(url_for('user.search'))
        else:
            flash('Invalid username or password', 'error')

    return render_template('user/login.html')


@user_bp.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('user.login'))


@user_bp.route('/add_tokens', methods=['POST'])
def add_tokens():
    import os
    security_password = os.getenv('SECURITY_PASSPHRASE', 'changeme')
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    if session['role'] != 'guest':
        return jsonify({'success': False, 'message': 'Only guest users can earn tokens'})

    try:
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        rate_key = f"earn|{session.get('username','anon')}|{ip_address}"
        now_ts = datetime.utcnow().timestamp()
        dq = recent_requests_by_key.setdefault(rate_key, deque(maxlen=EARN_TOKENS_MAX_REQUESTS))
        recent = [t for t in dq if now_ts - t <= EARN_TOKENS_WINDOW_SECONDS]
        dq.clear(); dq.extend(recent)
        if len(dq) >= EARN_TOKENS_MAX_REQUESTS:
            return jsonify({'success': False, 'message': 'Too many attempts. Try again later.'}), 429
        dq.append(now_ts)
    except Exception:
        pass

    security_answer = request.form.get('security_answer', '').strip().lower()
    if security_answer == security_password.lower():
        new_token_count = session['tokens'] + 1
        update_user_tokens(session['username'], new_token_count)
        session['tokens'] = new_token_count
        return jsonify({'success': True, 'message': 'Correct! 1 token added', 'tokens': new_token_count})
    else:
        return jsonify({'success': False, 'message': 'Incorrect answer'})


@user_bp.route('/search', methods=['GET', 'POST'])
def search():
    if 'user_id' not in session:
        return redirect(url_for('user.login'))

    # Ensure session reflects latest DB values (e.g., admin token/role changes)
    _sync_session_from_db()

    if request.method == 'GET':
        return render_template('user/search.html', hits=[], user_role=session['role'], 
                             username=session['username'], tokens=session['tokens'], 
                             total_results=0, current_page=1, total_pages=0,
                             results_per_page=100)

    try:
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        rate_key = f"{session.get('username','anon')}|{ip_address}"
        now_ts = datetime.utcnow().timestamp()
        dq = recent_requests_by_key[rate_key]
        recent = [t for t in dq if now_ts - t <= RATE_LIMIT_WINDOW_SECONDS]
        dq.clear(); dq.extend(recent)
        if len(dq) >= RATE_LIMIT_MAX_REQUESTS:
            flash('Too many requests. Please slow down and try again shortly.', 'error')
            return render_template('user/search.html', hits=[], user_role=session['role'], 
                                 username=session['username'], tokens=session['tokens'],
                                 total_results=0, current_page=1, total_pages=0,
                                 results_per_page=100)
        dq.append(now_ts)
    except Exception:
        pass

    domain = request.form.get('domain')
    username = request.form.get('username')
    requested_line = request.form.get('line', default=50, type=int)
    search_type = request.form.get('type', default='', type=str).lower()
    page = request.form.get('page', default=1, type=int)
    
    # Security: Allow larger searches but paginate display for resource protection
    # Results per page - only admin can change this
    if session['role'] == 'admin':
        RESULTS_PER_PAGE = request.form.get('results_per_page', default=100, type=int)
        RESULTS_PER_PAGE = min(RESULTS_PER_PAGE, 1000)  # Max 1000 per page
    else:
        RESULTS_PER_PAGE = 100  # Non-admins fixed at 100 per page
    
    # Apply search limits for different user roles
    if session['role'] == 'admin':
        # Admins can request up to 10k
        max_search_limit = max(1, min(requested_line, 10000))
    else:
        # Guests default to 50; can request up to 2000. Warn if exceeded
        if requested_line is None:
            requested_line = 50
        if requested_line > 2000:
            max_search_limit = 2000
            try:
                flash('Guest limit is 2,000. Your request was capped to 2,000.', 'warning')
            except Exception:
                pass
        else:
            max_search_limit = max(1, requested_line)
    
    # Use the maximum search limit for Elasticsearch query
    search_limit = max_search_limit
    
    # Validate page number
    if page < 1:
        page = 1

    performing_search = bool(domain or username)

    if performing_search and session['role'] == 'guest':
        if session['tokens'] <= 0:
            flash('You need tokens to search. Answer the security question to earn tokens.', 'warning')
            return render_template('user/search.html', hits=[], user_role=session['role'], 
                                 username=session['username'], tokens=session['tokens'])
        new_token_count = session['tokens'] - 1
        update_user_tokens(session['username'], new_token_count)
        session['tokens'] = new_token_count
        flash(f'Search performed. {new_token_count} tokens remaining.', 'info')


    if performing_search:
        # First, get total count to determine pagination
        count_query = None
        if domain and username:
            count_query = {"query": {"bool": {"should": [
                {"wildcard": {"d": f"*{domain}*"}} if search_type != 'exact' else {"term": {"d.keyword": domain}},
                {"wildcard": {"u": f"*{username}*"}} if search_type != 'exact' else {"term": {"u.keyword": username}}
            ], "minimum_should_match": 1}}}
        elif domain:
            if search_type == 'exact':
                count_query = {"query": {"term": {"d.keyword": domain}}}
            else:
                count_query = {"query": {"wildcard": {"d": f"*{domain}*"}}}
        elif username:
            if search_type == 'exact':
                count_query = {"query": {"term": {"u.keyword": username}}}
            else:
                count_query = {"query": {"wildcard": {"u": f"*{username}*"}}}
        
        # Get total count for pagination (limited by search_limit)
        total_results = 0
        if count_query:
            try:
                # Get TRUE total count without limiting by search_limit
                count_response = es_client.count(index=ES_INDEX, body=count_query)
                true_total = count_response.get('count', 0)
                
                # Only cap results for display purposes, not for count
                total_results = min(true_total, search_limit)
            except Exception as e:
                if "AuthenticationException" in str(e) or "security_exception" in str(e):
                    flash('Elasticsearch authentication error. Please check your ES_PASSWORD environment variable.', 'error')
                else:
                    flash(f'Elasticsearch connection error: {str(e)}', 'error')
                total_results = 0
        
        # Calculate pagination
        total_pages = max(1, (total_results + RESULTS_PER_PAGE - 1) // RESULTS_PER_PAGE)
        if page > total_pages:
            page = total_pages
        
        offset = (page - 1) * RESULTS_PER_PAGE
        # Ensure we do not fetch more than the remaining allowed results for this page
        page_size = min(RESULTS_PER_PAGE, max(0, total_results - offset))
        
        # Now build the paginated search query (always 100 results per page for display)
        if domain and username:
            query = {
                "size": page_size,
                "from": offset,
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"d": f"*{domain}*"}} if search_type != 'exact' else {"term": {"d.keyword": domain}},
                            {"wildcard": {"u": f"*{username}*"}} if search_type != 'exact' else {"term": {"u.keyword": username}}
                        ],
                        "minimum_should_match": 1
                    }
                }
            }
        elif domain:
            if search_type == 'exact':
                query = {"size": page_size, "from": offset, "query": {"term": {"d.keyword": domain}}}
            else:
                query = {"size": page_size, "from": offset, "query": {"wildcard": {"d": f"*{domain}*"}}}
        elif username:
            if search_type == 'exact':
                query = {"size": page_size, "from": offset, "query": {"term": {"u.keyword": username}}}
            else:
                query = {"size": page_size, "from": offset, "query": {"wildcard": {"u": f"*{username}*"}}}
        else:
            query = {"size": 0, "from": 0, "query": {"match_all": {}}}
            total_results = 0
            total_pages = 0
    else:
        query = {"size": 0, "query": {"match_all": {}}}
        total_results = 0
        total_pages = 0

    if performing_search:
        try:
            response = es_client.search(index=ES_INDEX, body=query)
        except Exception as e:
            if "AuthenticationException" in str(e) or "security_exception" in str(e):
                flash('Elasticsearch authentication error. Please check your ES_PASSWORD environment variable.', 'error')
            else:
                flash(f'Search error: {str(e)}', 'error')
            response = {'hits': {'hits': []}}
            total_results = 0
            total_pages = 0
    else:
        response = {'hits': {'hits': []}}
        total_results = 0
        total_pages = 0

    hits = [
        {
            "t": parse(hit['_source']['@timestamp']).strftime('%d-%m-%Y'),
            "d": hit['_source']['d'],
            "u": hit['_source']['u'],
            "p": hit['_source']['p']
        }
        for hit in response['hits']['hits']
    ]

    seen = set()
    unique_hits = []
    for hit in hits:
        key = (hit['d'], hit['u'], hit['p'])
        if key not in seen:
            seen.add(key)
            unique_hits.append(hit)

    # Hard-cap display to current page_size if performing a search
    try:
        if performing_search:
            # page_size is defined only in the performing_search branch
            unique_hits = unique_hits[:page_size]
    except NameError:
        pass

    if performing_search:
        # Show pagination info for large result sets
        if total_results > RESULTS_PER_PAGE:
            # Reflect dynamic page size instead of a hardcoded number
            try:
                per_page_display = page_size
            except NameError:
                per_page_display = RESULTS_PER_PAGE
            flash(f'Searched for up to {search_limit:,} records and found {total_results:,} results. Showing page {page} of {total_pages} ({per_page_display} results this page).', 'info')
        
        try:
            log_search(
                username=session.get('username'),
                ip=ip_address,
                domain=domain,
                username_query=username,
                search_type=search_type,
                line=search_limit,  # Log the actual search limit requested
                result_count=len(unique_hits)
            )
        except Exception:
            pass

    return render_template('user/search.html', hits=unique_hits, user_role=session['role'], 
                         username=session['username'], tokens=session['tokens'],
                         total_results=total_results, current_page=page, total_pages=total_pages,
                         results_per_page=RESULTS_PER_PAGE)


@user_bp.route('/save_results', methods=['POST'])
def save_results_endpoint():
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    data = request.get_json(silent=True) or {}
    items = data.get('items', [])
    name = (data.get('name') or '').strip()
    if not isinstance(items, list) or not items:
        return jsonify({'success': False, 'message': 'No records provided'}), 400
    if not name:
        return jsonify({'success': False, 'message': 'A name is required'}), 400
    cleaned = []
    for it in items:
        try:
            cleaned.append({
                't': it.get('t'),
                'd': str(it['d'])[:512],
                'u': str(it['u'])[:512],
                'p': str(it['p'])[:2048],
                'note': str(it.get('note',''))[:2000]
            })
        except Exception:
            continue
    if not cleaned:
        return jsonify({'success': False, 'message': 'No valid records'}), 400
    saved_id = create_saved_search(session['username'], name)
    save_results(session['username'], cleaned, saved_search_id=saved_id)
    return jsonify({'success': True, 'count': len(cleaned), 'saved_search_id': saved_id})


@user_bp.route('/saved', methods=['GET', 'POST'])
def saved_page():
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    _sync_session_from_db()
    if request.method == 'POST':
        search_id = request.form.get('search_id')
        if search_id:
            try:
                conn = get_db_connection()
                conn.execute('DELETE FROM saved_results WHERE saved_search_id = ? AND owner_username = ?', (search_id, session['username']))
                conn.execute('DELETE FROM saved_searches WHERE id = ? AND owner_username = ?', (search_id, session['username']))
                conn.commit()
                conn.close()
            except Exception:
                pass
        return redirect(url_for('user.saved_page'))
    searches = get_saved_searches_for_user(session['username'])
    return render_template('user/saved.html', searches=searches, username=session['username'], user_role=session['role'])


@user_bp.route('/saved/<int:saved_search_id>', methods=['GET', 'POST'])
def saved_detail_page(saved_search_id: int):
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    _sync_session_from_db()
    if request.method == 'POST':
        action = request.form.get('action')
        item_id = request.form.get('item_id')

        if action == 'delete' and item_id:
            try:
                conn = get_db_connection()
                owner = conn.execute('SELECT owner_username FROM saved_searches WHERE id = ?', (saved_search_id,)).fetchone()
                if not owner:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Saved search not found'})
                is_admin = session.get('role') == 'admin'
                if owner['owner_username'] != session['username'] and not is_admin:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Access denied'})
                row = conn.execute('SELECT id FROM saved_results WHERE id = ? AND saved_search_id = ?', (item_id, saved_search_id)).fetchone()
                conn.close()
                if row:
                    delete_saved_result(session['username'], item_id, is_admin=is_admin)
                    return jsonify({'success': True})
                else:
                    return jsonify({'success': False, 'error': 'Record not found'})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})

        elif action == 'edit' and item_id:
            note = request.form.get('note', '')
            try:
                conn = get_db_connection()
                owner = conn.execute('SELECT owner_username FROM saved_searches WHERE id = ?', (saved_search_id,)).fetchone()
                if not owner:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Saved search not found'})
                is_admin = session.get('role') == 'admin'
                if owner['owner_username'] != session['username'] and not is_admin:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Access denied'})
                conn.execute('UPDATE saved_results SET note = ? WHERE id = ? AND saved_search_id = ?', (note, item_id, saved_search_id))
                conn.commit()
                conn.close()
                return jsonify({'success': True})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})

        elif action == 'bulk_edit':
            updates_json = request.form.get('updates', '[]')
            import json
            try:
                updates = json.loads(updates_json)
                conn = get_db_connection()
                owner = conn.execute('SELECT owner_username FROM saved_searches WHERE id = ?', (saved_search_id,)).fetchone()
                if not owner:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Saved search not found'})
                is_admin = session.get('role') == 'admin'
                if owner['owner_username'] != session['username'] and not is_admin:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Access denied'})
                saved_count = 0
                for update in updates:
                    item_id = update.get('item_id')
                    note = update.get('note', '')
                    if item_id:
                        conn.execute('UPDATE saved_results SET note = ? WHERE id = ? AND saved_search_id = ?', (note, item_id, saved_search_id))
                        saved_count += 1
                conn.commit()
                conn.close()
                return jsonify({'success': True, 'saved_count': saved_count})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})

        elif action == 'bulk_delete':
            item_ids_json = request.form.get('item_ids', '[]')
            import json
            try:
                item_ids = json.loads(item_ids_json)
                conn = get_db_connection()
                owner = conn.execute('SELECT owner_username FROM saved_searches WHERE id = ?', (saved_search_id,)).fetchone()
                if not owner:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Saved search not found'})
                is_admin = session.get('role') == 'admin'
                if owner['owner_username'] != session['username'] and not is_admin:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Access denied'})
                removed_count = 0
                for item_id in item_ids:
                    if item_id:
                        conn.execute('DELETE FROM saved_results WHERE id = ? AND saved_search_id = ?', (item_id, saved_search_id))
                        removed_count += 1
                conn.commit()
                conn.close()
                return jsonify({'success': True, 'removed_count': removed_count})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})

        item_id = request.form.get('id')
        if item_id:
            try:
                conn = get_db_connection()
                row = conn.execute('SELECT id FROM saved_results WHERE id = ? AND saved_search_id = ? AND owner_username = ?', (item_id, saved_search_id, session['username'])).fetchone()
                conn.close()
                if row:
                    delete_saved_result(session['username'], item_id, is_admin=False)
            except Exception:
                pass
        return redirect(url_for('user.saved_detail_page', saved_search_id=saved_search_id))

    conn = get_db_connection()
    owner = conn.execute('SELECT owner_username, name FROM saved_searches WHERE id = ?', (saved_search_id,)).fetchone()
    conn.close()

    if not owner:
        flash('Saved record not found', 'error')
        return redirect(url_for('user.saved_page'))

    is_admin = session.get('role') == 'admin'
    if owner['owner_username'] != session['username'] and not is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('user.saved_page'))

    items = get_saved_results_for_search(saved_search_id)
    return render_template('user/saved_detail.html', search_name=owner['name'], items=items, username=session['username'], is_admin=is_admin, saved_search_id=saved_search_id)


@user_bp.route('/saved/<int:saved_search_id>/add', methods=['POST'])
def add_saved_record(saved_search_id: int):
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    _sync_session_from_db()
    
    try:
        conn = get_db_connection()
        owner = conn.execute('SELECT owner_username FROM saved_searches WHERE id = ?', (saved_search_id,)).fetchone()
        if not owner:
            conn.close()
            return jsonify({'success': False, 'error': 'Saved search not found'})
        
        is_admin = session.get('role') == 'admin'
        if owner['owner_username'] != session['username'] and not is_admin:
            conn.close()
            return jsonify({'success': False, 'error': 'Access denied'})
        
        data = request.get_json()
        domain = data.get('domain', '').strip()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        note = data.get('note', '').strip()
        
        if not domain or not username or not password:
            conn.close()
            return jsonify({'success': False, 'error': 'Domain, username, and password are required'})
        
        # Insert new record with current timestamp
        conn.execute('''
            INSERT INTO saved_results (owner_username, saved_search_id, d, u, p, note, t, created_at)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
        ''', (session['username'], saved_search_id, domain, username, password, note))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Record added successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@user_bp.route('/saved/<int:saved_search_id>/import', methods=['POST'])
def import_saved_records(saved_search_id: int):
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    _sync_session_from_db()
    
    try:
        conn = get_db_connection()
        owner = conn.execute('SELECT owner_username FROM saved_searches WHERE id = ?', (saved_search_id,)).fetchone()
        if not owner:
            conn.close()
            return jsonify({'success': False, 'error': 'Saved search not found'})
        
        is_admin = session.get('role') == 'admin'
        if owner['owner_username'] != session['username'] and not is_admin:
            conn.close()
            return jsonify({'success': False, 'error': 'Access denied'})
        
        if 'file' not in request.files:
            conn.close()
            return jsonify({'success': False, 'error': 'No file provided'})
        
        file = request.files['file']
        if file.filename == '':
            conn.close()
            return jsonify({'success': False, 'error': 'No file selected'})
        
        if not file.filename.endswith('.csv'):
            conn.close()
            return jsonify({'success': False, 'error': 'File must be a CSV'})
        
        # Read and parse CSV
        import csv
        import io
        import chardet
        
        # Read file content as bytes for encoding detection
        file_content = file.read()
        
        # Detect encoding
        detected = chardet.detect(file_content)
        encoding = detected['encoding'] if detected['encoding'] else 'utf-8'
        
        # Decode with detected encoding, fallback to utf-8 with error handling
        try:
            content = file_content.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            # Fallback to utf-8 with error handling for problematic characters
            content = file_content.decode('utf-8', errors='replace')
        
        csv_reader = csv.DictReader(io.StringIO(content))
        
        added_count = 0
        errors = []
        
        for row_num, row in enumerate(csv_reader, start=2):  # Start at 2 because header is row 1
            try:
                domain = row.get('domain', '').strip()
                username = row.get('username', '').strip()
                password = row.get('password', '').strip()
                note = row.get('note', '').strip()
                
                if not domain or not username or not password:
                    errors.append(f'Row {row_num}: Domain, username, and password are required')
                    continue
                
                conn.execute('''
                    INSERT INTO saved_results (owner_username, saved_search_id, d, u, p, note, t, created_at)
                    VALUES (?, ?, ?, ?, ?, ?, datetime('now'), datetime('now'))
                ''', (session['username'], saved_search_id, domain, username, password, note))
                added_count += 1
            except Exception as e:
                errors.append(f'Row {row_num}: {str(e)}')
        
        conn.commit()
        conn.close()
        
        message = f'Successfully imported {added_count} records'
        if errors:
            message += f'. Errors: {len(errors)} rows failed'
        
        return jsonify({'success': True, 'message': message, 'added_count': added_count, 'errors': errors})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@user_bp.route('/get_all_domains', methods=['POST'])
def get_all_domains():
    """Get all domains from current search results (not just current page)"""
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    _sync_session_from_db()
    
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        username = data.get('username', '').strip()
        search_type = data.get('type', '').lower()
        
        # Apply search limits for different user roles
        if session['role'] == 'guest':
            search_limit = 50
        elif session['role'] == 'user':
            search_limit = 200
        else:  # admin
            search_limit = 1000
        
        # Build the search query to get ALL results (not paginated)
        if domain and username:
            query = {
                "size": search_limit,  # Get all results up to limit
                "from": 0,
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"d": f"*{domain}*"}} if search_type != 'exact' else {"term": {"d.keyword": domain}},
                            {"wildcard": {"u": f"*{username}*"}} if search_type != 'exact' else {"term": {"u.keyword": username}}
                        ],
                        "minimum_should_match": 1
                    }
                }
            }
        elif domain:
            if search_type == 'exact':
                query = {"size": search_limit, "from": 0, "query": {"term": {"d.keyword": domain}}}
            else:
                query = {"size": search_limit, "from": 0, "query": {"wildcard": {"d": f"*{domain}*"}}}
        elif username:
            if search_type == 'exact':
                query = {"size": search_limit, "from": 0, "query": {"term": {"u.keyword": username}}}
            else:
                query = {"size": search_limit, "from": 0, "query": {"wildcard": {"u": f"*{username}*"}}}
        else:
            return jsonify({'success': False, 'error': 'No search parameters provided'})
        
        # Execute search
        try:
            response = es_client.search(index=ES_INDEX, body=query)
            hits = response['hits']['hits']
            
            # Extract unique domains
            domains = []
            seen = set()
            for hit in hits:
                source = hit['_source']
                domain_val = source.get('d', '')
                if domain_val and domain_val not in seen:
                    domains.append(domain_val)
                    seen.add(domain_val)
            
            return jsonify({'success': True, 'domains': domains})
        except Exception as es_error:
            return jsonify({'success': False, 'error': f'Elasticsearch error: {str(es_error)}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@user_bp.route('/get_all_usernames', methods=['POST'])
def get_all_usernames():
    """Get all usernames from current search results (not just current page)"""
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    _sync_session_from_db()
    
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        username = data.get('username', '').strip()
        search_type = data.get('type', '').lower()
        
        # Apply search limits for different user roles
        if session['role'] == 'guest':
            search_limit = 50
        elif session['role'] == 'user':
            search_limit = 200
        else:  # admin
            search_limit = 1000
        
        # Build the search query to get ALL results (not paginated)
        if domain and username:
            query = {
                "size": search_limit,
                "from": 0,
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"d": f"*{domain}*"}} if search_type != 'exact' else {"term": {"d.keyword": domain}},
                            {"wildcard": {"u": f"*{username}*"}} if search_type != 'exact' else {"term": {"u.keyword": username}}
                        ],
                        "minimum_should_match": 1
                    }
                }
            }
        elif domain:
            if search_type == 'exact':
                query = {"size": search_limit, "from": 0, "query": {"term": {"d.keyword": domain}}}
            else:
                query = {"size": search_limit, "from": 0, "query": {"wildcard": {"d": f"*{domain}*"}}}
        elif username:
            if search_type == 'exact':
                query = {"size": search_limit, "from": 0, "query": {"term": {"u.keyword": username}}}
            else:
                query = {"size": search_limit, "from": 0, "query": {"wildcard": {"u": f"*{username}*"}}}
        else:
            return jsonify({'success': False, 'error': 'No search parameters provided'})
        
        # Execute search
        try:
            response = es_client.search(index=ES_INDEX, body=query)
            hits = response['hits']['hits']
            
            # Extract unique usernames
            usernames = []
            seen = set()
            for hit in hits:
                source = hit['_source']
                username_val = source.get('u', '')
                if username_val and username_val not in seen:
                    usernames.append(username_val)
                    seen.add(username_val)
            
            return jsonify({'success': True, 'usernames': usernames})
        except Exception as es_error:
            return jsonify({'success': False, 'error': f'Elasticsearch error: {str(es_error)}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@user_bp.route('/get_all_passwords', methods=['POST'])
def get_all_passwords():
    """Get all passwords from current search results (not just current page)"""
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    _sync_session_from_db()
    
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        username = data.get('username', '').strip()
        search_type = data.get('type', '').lower()
        
        # Apply search limits for different user roles
        if session['role'] == 'guest':
            search_limit = 50
        elif session['role'] == 'user':
            search_limit = 200
        else:  # admin
            search_limit = 1000
        
        # Build the search query to get ALL results (not paginated)
        if domain and username:
            query = {
                "size": search_limit,
                "from": 0,
                "query": {
                    "bool": {
                        "should": [
                            {"wildcard": {"d": f"*{domain}*"}} if search_type != 'exact' else {"term": {"d.keyword": domain}},
                            {"wildcard": {"u": f"*{username}*"}} if search_type != 'exact' else {"term": {"u.keyword": username}}
                        ],
                        "minimum_should_match": 1
                    }
                }
            }
        elif domain:
            if search_type == 'exact':
                query = {"size": search_limit, "from": 0, "query": {"term": {"d.keyword": domain}}}
            else:
                query = {"size": search_limit, "from": 0, "query": {"wildcard": {"d": f"*{domain}*"}}}
        elif username:
            if search_type == 'exact':
                query = {"size": search_limit, "from": 0, "query": {"term": {"u.keyword": username}}}
            else:
                query = {"size": search_limit, "from": 0, "query": {"wildcard": {"u": f"*{username}*"}}}
        else:
            return jsonify({'success': False, 'error': 'No search parameters provided'})
        
        # Execute search
        try:
            response = es_client.search(index=ES_INDEX, body=query)
            hits = response['hits']['hits']
            
            # Extract unique passwords
            passwords = []
            seen = set()
            for hit in hits:
                source = hit['_source']
                password_val = source.get('p', '')
                if password_val and password_val not in seen:
                    passwords.append(password_val)
                    seen.add(password_val)
            
            return jsonify({'success': True, 'passwords': passwords})
        except Exception as es_error:
            return jsonify({'success': False, 'error': f'Elasticsearch error: {str(es_error)}'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@user_bp.route('/create_saved_record', methods=['POST'])
def create_saved_record():
    """Create a new empty saved record"""
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    _sync_session_from_db()
    
    try:
        data = request.get_json()
        name = data.get('name', '').strip()
        
        if not name:
            return jsonify({'success': False, 'error': 'Name is required'})
        
        # Create new saved search
        saved_id = create_saved_search(session['username'], name)
        
        return jsonify({'success': True, 'saved_search_id': saved_id, 'message': 'Saved record created successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@user_bp.route('/saved/<int:saved_search_id>/export')
def export_saved_records(saved_search_id: int):
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    _sync_session_from_db()
    
    try:
        conn = get_db_connection()
        owner = conn.execute('SELECT owner_username FROM saved_searches WHERE id = ?', (saved_search_id,)).fetchone()
        if not owner:
            conn.close()
            return jsonify({'success': False, 'error': 'Saved search not found'})
        
        is_admin = session.get('role') == 'admin'
        if owner['owner_username'] != session['username'] and not is_admin:
            conn.close()
            return jsonify({'success': False, 'error': 'Access denied'})
        
        # Get saved search name
        search_info = conn.execute('SELECT name FROM saved_searches WHERE id = ?', (saved_search_id,)).fetchone()
        search_name = search_info['name'] if search_info else f'saved_records_{saved_search_id}'
        
        items = conn.execute('''
            SELECT d, u, p, note, t, created_at
            FROM saved_results 
            WHERE saved_search_id = ?
            ORDER BY created_at DESC
        ''', (saved_search_id,)).fetchall()
        conn.close()
        
        # Create CSV response with proper UTF-8 encoding
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['timestamp', 'domain', 'username', 'password', 'note'])
        
        # Write data
        for item in items:
            writer.writerow([
                item['t'] or item['created_at'],
                item['d'],
                item['u'], 
                item['p'],
                item['note'] or ''
            ])
        
        output.seek(0)
        
        from flask import Response
        from datetime import datetime
        
        # Create UTF-8 encoded response with BOM for Excel compatibility
        csv_content = output.getvalue()
        utf8_bom = '\ufeff'  # UTF-8 BOM
        encoded_content = (utf8_bom + csv_content).encode('utf-8')
        
        # Generate filename with saved record name and current date
        current_date = datetime.now().strftime('%Y-%m-%d')
        # Clean the search name for filename (remove special characters)
        clean_name = "".join(c for c in search_name if c.isalnum() or c in (' ', '-', '_')).rstrip()
        clean_name = clean_name.replace(' ', '_')
        filename = f"{clean_name}_{current_date}.csv"
        
        return Response(
            encoded_content,
            mimetype='text/csv; charset=utf-8',
            headers={
                'Content-Disposition': f'attachment; filename={filename}',
                'Content-Type': 'text/csv; charset=utf-8'
            }
        )
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@user_bp.route('/tokens')
def tokens_page():
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    _sync_session_from_db()
    if session.get('role') != 'guest':
        flash('Only guest users can access the token page.', 'warning')
        return redirect(url_for('user.search'))
    return render_template('user/earn_tokens.html', username=session['username'], tokens=session['tokens'])


