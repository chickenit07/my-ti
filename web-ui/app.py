from flask import Flask, request, render_template, session, redirect, url_for, flash, jsonify
import json
from elasticsearch import Elasticsearch
from dateutil.parser import parse
import sqlite3
import hashlib
import os
from datetime import datetime
from collections import defaultdict, deque

# Initialize Flask application
app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this'  # Change this in production

# Initialize Elasticsearch client
ES_URL = "http://localhost:9200"
ES_USERNAME = "elastic"
ES_PASSWORD = "Dat1999@"
client = Elasticsearch(
    [ES_URL],
    basic_auth=(ES_USERNAME, ES_PASSWORD),
    request_timeout=300,
    max_retries=10,
    retry_on_timeout=True
)

# Security password requirement for guest users to earn tokens
SECURITY_PASSWORD = "dat"

# Database configuration
DATABASE = 'users.db'

def get_db_connection():
    """Get database connection."""
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize the database with default users."""
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            tokens INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS search_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            ip TEXT,
            domain TEXT,
            username_query TEXT,
            search_type TEXT,
            line INTEGER,
            result_count INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS saved_searches (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_username TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS saved_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_username TEXT NOT NULL,
            saved_search_id INTEGER,
            t TEXT,
            d TEXT NOT NULL,
            u TEXT NOT NULL,
            p TEXT NOT NULL,
            note TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    # Attempt to add missing columns if migrating from older versions
    try:
        conn.execute('ALTER TABLE saved_results ADD COLUMN saved_search_id INTEGER')
    except Exception:
        pass
    
    # Create default users if they don't exist. 
    # Con lon nao tim dc password nay tren github thi dung admin cho nhanh =)) khong thi thoi!!!
    admin_hash = hashlib.sha256('AdminPasswordHere'.encode()).hexdigest()
    guest_hash = hashlib.sha256('GuestPasswordHere'.encode()).hexdigest()
    
    try:
        conn.execute('INSERT INTO users (username, password_hash, role, tokens) VALUES (?, ?, ?, ?)',
                    ('admin', admin_hash, 'admin', 0))
    except sqlite3.IntegrityError:
        pass  # User already exists
    
    try:
        conn.execute('INSERT INTO users (username, password_hash, role, tokens) VALUES (?, ?, ?, ?)',
                    ('guest', guest_hash, 'guest', 0))
    except sqlite3.IntegrityError:
        pass  # User already exists
    
    conn.commit()
    conn.close()

def hash_password(password):
    """Hash a password using SHA256."""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hash_value):
    """Verify a password against its hash."""
    return hashlib.sha256(password.encode()).hexdigest() == hash_value

def get_user(username):
    """Get user from database."""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def get_all_users():
    """Get all users."""
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, role, tokens, created_at, last_login FROM users ORDER BY id ASC').fetchall()
    conn.close()
    return users

def update_user_tokens(username, tokens):
    """Update user's token count."""
    conn = get_db_connection()
    conn.execute('UPDATE users SET tokens = ? WHERE username = ?', (tokens, username))
    conn.commit()
    conn.close()

def update_last_login(username):
    """Update user's last login timestamp."""
    conn = get_db_connection()
    conn.execute('UPDATE users SET last_login = ? WHERE username = ?', (datetime.now(), username))
    conn.commit()
    conn.close()

def set_user_password(username, password):
    """Set a new password for a user."""
    conn = get_db_connection()
    conn.execute('UPDATE users SET password_hash = ? WHERE username = ?', (hash_password(password), username))
    conn.commit()
    conn.close()

def upsert_user(username, password, role, tokens=0):
    """Create user if not exists, otherwise update role/tokens/password if provided."""
    existing = get_user(username)
    conn = get_db_connection()
    if existing is None:
        conn.execute('INSERT INTO users (username, password_hash, role, tokens) VALUES (?, ?, ?, ?)',
                     (username, hash_password(password), role, tokens))
    else:
        if password:
            conn.execute('UPDATE users SET password_hash = ? WHERE username = ?', (hash_password(password), username))
        if role:
            conn.execute('UPDATE users SET role = ? WHERE username = ?', (role, username))
        if tokens is not None:
            conn.execute('UPDATE users SET tokens = ? WHERE username = ?', (tokens, username))
    conn.commit()
    conn.close()

def delete_user(username):
    """Delete a user."""
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()

def log_search(username, ip, domain, username_query, search_type, line, result_count):
    """Insert a search log entry."""
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO search_logs (username, ip, domain, username_query, search_type, line, result_count)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (username, ip, domain or '', username_query or '', search_type or '', int(line) if line else None, int(result_count)))
    conn.commit()
    conn.close()

def get_search_logs(limit=200):
    """Fetch recent search logs."""
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT id, username, ip, domain, username_query, search_type, line, result_count, created_at
        FROM search_logs
        ORDER BY id DESC
        LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    return rows

def get_saved_searches_for_user(username, limit=500):
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT s.id, s.name, s.created_at, COUNT(r.id) AS item_count
        FROM saved_searches s
        LEFT JOIN saved_results r ON r.saved_search_id = s.id
        WHERE s.owner_username = ?
        GROUP BY s.id
        ORDER BY s.id DESC
        LIMIT ?
    ''', (username, limit)).fetchall()
    conn.close()
    return rows

def get_saved_searches_all(limit=1000):
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT s.id, s.owner_username, s.name, s.created_at, COUNT(r.id) AS item_count
        FROM saved_searches s
        LEFT JOIN saved_results r ON r.saved_search_id = s.id
        GROUP BY s.id
        ORDER BY s.id DESC
        LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    return rows

def get_saved_results_for_search(saved_search_id):
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT id, t, d, u, p, note, created_at
        FROM saved_results
        WHERE saved_search_id = ?
        ORDER BY id DESC
    ''', (saved_search_id,)).fetchall()
    conn.close()
    return rows

def get_saved_results_for_user(username, limit=500):
    """Fetch recent saved result items for a user (ungrouped)."""
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT id, t, d, u, p, note, created_at
        FROM saved_results
        WHERE owner_username = ?
        ORDER BY id DESC
        LIMIT ?
    ''', (username, limit)).fetchall()
    conn.close()
    return rows

def get_saved_results_all(limit=1000):
    """Fetch recent saved result items across all users (ungrouped)."""
    conn = get_db_connection()
    rows = conn.execute('''
        SELECT id, owner_username, t, d, u, p, note, created_at
        FROM saved_results
        ORDER BY id DESC
        LIMIT ?
    ''', (limit,)).fetchall()
    conn.close()
    return rows

def create_saved_search(owner_username, name):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('INSERT INTO saved_searches (owner_username, name) VALUES (?, ?)', (owner_username, name))
    conn.commit()
    saved_id = cur.lastrowid
    conn.close()
    return saved_id

def save_results(owner_username, items, saved_search_id=None):
    conn = get_db_connection()
    try:
        conn.executemany('''
            INSERT INTO saved_results (owner_username, saved_search_id, t, d, u, p, note)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', [(owner_username, saved_search_id, it.get('t'), it['d'], it['u'], it['p'], it.get('note', '')) for it in items])
        conn.commit()
    finally:
        conn.close()

def delete_saved_result(owner_username, item_id, is_admin=False):
    conn = get_db_connection()
    if is_admin:
        conn.execute('DELETE FROM saved_results WHERE id = ?', (item_id,))
    else:
        conn.execute('DELETE FROM saved_results WHERE id = ? AND owner_username = ?', (item_id, owner_username))
    conn.commit()
    conn.close()

# Initialize database at import time for WSGI and dev
init_db()

# In-memory rate limiting (simple best-effort). Consider Redis for multi-process setups.
RATE_LIMIT_WINDOW_SECONDS = 10
RATE_LIMIT_MAX_REQUESTS = 5
# Separate limits for earning tokens to prevent abuse
EARN_TOKENS_WINDOW_SECONDS = 60
EARN_TOKENS_MAX_REQUESTS = 3
recent_requests_by_key = defaultdict(lambda: deque(maxlen=RATE_LIMIT_MAX_REQUESTS))

@app.route('/')
def index():
    """Redirect to login if not authenticated, otherwise to search."""
    if 'user_id' in session:
        return redirect(url_for('search'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
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
            return redirect(url_for('search'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('user/login.html')

@app.route('/logout')
def logout():
    """Handle user logout."""
    session.clear()
    flash('You have been logged out successfully', 'info')
    return redirect(url_for('login'))

@app.route('/add_tokens', methods=['POST'])
def add_tokens():
    """Add tokens for guest users by answering security question."""
    if 'user_id' not in session:
        return jsonify({'success': False, 'message': 'Not logged in'})
    
    if session['role'] != 'guest':
        return jsonify({'success': False, 'message': 'Only guest users can earn tokens'})
    
    # Rate limit earning tokens per user+IP
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
    if security_answer == SECURITY_PASSWORD.lower():
        # Add 1 token
        new_token_count = session['tokens'] + 1
        update_user_tokens(session['username'], new_token_count)
        session['tokens'] = new_token_count
        
        return jsonify({'success': True, 'message': 'Correct! 1 token added', 'tokens': new_token_count})
    else:
        return jsonify({'success': False, 'message': 'Incorrect answer'})

@app.route('/search', methods=['GET', 'POST'])
def search():
    """Handle search functionality."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Handle GET request (initial page load)
    if request.method == 'GET':
        return render_template('user/search.html', hits=[], user_role=session['role'], 
                             username=session['username'], tokens=session['tokens'])
    
    # Handle POST request (search submission)
    # Basic per-IP+user rate limit
    try:
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        rate_key = f"{session.get('username','anon')}|{ip_address}"
        now_ts = datetime.utcnow().timestamp()
        dq = recent_requests_by_key[rate_key]
        # prune entries older than window (deque limited by maxlen, but window check too)
        recent = [t for t in dq if now_ts - t <= RATE_LIMIT_WINDOW_SECONDS]
        dq.clear(); dq.extend(recent)
        if len(dq) >= RATE_LIMIT_MAX_REQUESTS:
            flash('Too many requests. Please slow down and try again shortly.', 'error')
            return render_template('user/search.html', hits=[], user_role=session['role'], 
                                 username=session['username'], tokens=session['tokens'])
        dq.append(now_ts)
    except Exception:
        pass
    
    domain = request.form.get('domain')
    username = request.form.get('username')
    line = request.form.get('line', default=50, type=int)
    search_type = request.form.get('type', default='', type=str).lower()
    
    # Check if user is performing a search
    performing_search = bool(domain or username)
    
    # For guest users, check if they have tokens for searching
    if performing_search and session['role'] == 'guest':
        if session['tokens'] <= 0:
            flash('You need tokens to search. Answer the security question to earn tokens.', 'warning')
            return render_template('user/search.html', hits=[], user_role=session['role'], 
                                 username=session['username'], tokens=session['tokens'])
        
        # Deduct 1 token for the search
        new_token_count = session['tokens'] - 1
        update_user_tokens(session['username'], new_token_count)
        session['tokens'] = new_token_count
        flash(f'Search performed. {new_token_count} tokens remaining.', 'info')
    
    INDEX = "urluserpass"

    # Build the query based on search criteria
    if performing_search:
        if domain and username:
            # Both domain and username - use bool with should (OR logic)
            query = {
                "size": line,
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
            # Domain only
            if search_type == 'exact':
                query = {
                    "size": line,
                    "query": {"term": {"d.keyword": domain}}
                }
            else:
                query = {
                    "size": line,
                    "query": {"wildcard": {"d": f"*{domain}*"}}
                }
        elif username:
            # Username only
            if search_type == 'exact':
                query = {
                    "size": line,
                    "query": {"term": {"u.keyword": username}}
                }
            else:
                query = {
                    "size": line,
                    "query": {"wildcard": {"u": f"*{username}*"}}
                }
        else:
            # No search criteria - return empty results
            query = {
                "size": 0,
                "query": {"match_all": {}}
            }
    else:
        # No search - return empty results
        query = {
            "size": 0,
            "query": {"match_all": {}}
        }
    
    # Execute the search
    if performing_search:
        try:
            response = client.search(index=INDEX, body=query)
        except Exception as e:
            flash(f'Search error: {str(e)}', 'error')
            response = {'hits': {'hits': []}}
    else:
        # No search, show nothing
        response = {'hits': {'hits': []}}
    
    hits = [
        {
            "t": parse(hit['_source']['@timestamp']).strftime('%d-%m-%Y'),
            "d": hit['_source']['d'],
            "u": hit['_source']['u'],
            "p": hit['_source']['p']
        }
        for hit in response['hits']['hits']
    ]
    
    # Remove duplicates based on (d, u, p)
    seen = set()
    unique_hits = []
    for hit in hits:
        key = (hit['d'], hit['u'], hit['p'])
        if key not in seen:
            seen.add(key)
            unique_hits.append(hit)
    
    # Log search if performed
    if performing_search:
        try:
            log_search(
                username=session.get('username'),
                ip=ip_address,
                domain=domain,
                username_query=username,
                search_type=search_type,
                line=line,
                result_count=len(unique_hits)
            )
        except Exception:
            pass

    return render_template('user/search.html', hits=unique_hits, user_role=session['role'], 
                         username=session['username'], tokens=session['tokens'])

@app.route('/save_results', methods=['POST'])
def save_results_endpoint():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    data = request.get_json(silent=True) or {}
    items = data.get('items', [])
    name = (data.get('name') or '').strip()
    if not isinstance(items, list) or not items:
        return jsonify({'success': False, 'message': 'No items provided'}), 400
    if not name:
        return jsonify({'success': False, 'message': 'A name is required'}), 400
    # Sanitize and only accept needed fields
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
        return jsonify({'success': False, 'message': 'No valid items'}), 400
    saved_id = create_saved_search(session['username'], name)
    save_results(session['username'], cleaned, saved_search_id=saved_id)
    return jsonify({'success': True, 'count': len(cleaned), 'saved_search_id': saved_id})

@app.route('/saved', methods=['GET', 'POST'])
def saved_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        # delete whole saved search
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
        return redirect(url_for('saved_page'))
    searches = get_saved_searches_for_user(session['username'])
    return render_template('user/saved.html', searches=searches, username=session['username'], user_role=session['role'])

@app.route('/saved/<int:saved_search_id>', methods=['GET', 'POST'])
def saved_detail_page(saved_search_id: int):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        action = request.form.get('action')
        item_id = request.form.get('item_id')
        
        if action == 'delete' and item_id:
            # Delete single item in this saved search
            try:
                conn = get_db_connection()
                # Check if user owns this saved search or is admin
                owner = conn.execute('SELECT owner_username FROM saved_searches WHERE id = ?', (saved_search_id,)).fetchone()
                if not owner:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Saved search not found'})
                
                is_admin = session.get('role') == 'admin'
                if owner['owner_username'] != session['username'] and not is_admin:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Access denied'})
                
                # Ensure the item belongs to this saved search
                row = conn.execute('SELECT id FROM saved_results WHERE id = ? AND saved_search_id = ?', (item_id, saved_search_id)).fetchone()
                conn.close()
                if row:
                    delete_saved_result(session['username'], item_id, is_admin=is_admin)
                    return jsonify({'success': True})
                else:
                    return jsonify({'success': False, 'error': 'Item not found'})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        elif action == 'edit' and item_id:
            # Edit note for single item
            note = request.form.get('note', '')
            try:
                conn = get_db_connection()
                # Check if user owns this saved search or is admin
                owner = conn.execute('SELECT owner_username FROM saved_searches WHERE id = ?', (saved_search_id,)).fetchone()
                if not owner:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Saved search not found'})
                
                is_admin = session.get('role') == 'admin'
                if owner['owner_username'] != session['username'] and not is_admin:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Access denied'})
                
                # Update the note
                conn.execute('UPDATE saved_results SET note = ? WHERE id = ? AND saved_search_id = ?', (note, item_id, saved_search_id))
                conn.commit()
                conn.close()
                return jsonify({'success': True})
            except Exception as e:
                return jsonify({'success': False, 'error': str(e)})
        
        elif action == 'bulk_edit':
            # Bulk edit notes for multiple items
            updates_json = request.form.get('updates', '[]')
            try:
                updates = json.loads(updates_json)
                conn = get_db_connection()
                # Check if user owns this saved search or is admin
                owner = conn.execute('SELECT owner_username FROM saved_searches WHERE id = ?', (saved_search_id,)).fetchone()
                if not owner:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Saved search not found'})
                
                is_admin = session.get('role') == 'admin'
                if owner['owner_username'] != session['username'] and not is_admin:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Access denied'})
                
                # Update notes for each item
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
            # Bulk delete multiple items
            item_ids_json = request.form.get('item_ids', '[]')
            try:
                item_ids = json.loads(item_ids_json)
                conn = get_db_connection()
                # Check if user owns this saved search or is admin
                owner = conn.execute('SELECT owner_username FROM saved_searches WHERE id = ?', (saved_search_id,)).fetchone()
                if not owner:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Saved search not found'})
                
                is_admin = session.get('role') == 'admin'
                if owner['owner_username'] != session['username'] and not is_admin:
                    conn.close()
                    return jsonify({'success': False, 'error': 'Access denied'})
                
                # Delete each item
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
        
        # Legacy delete support (for existing delete functionality)
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
        return redirect(url_for('saved_detail_page', saved_search_id=saved_search_id))
    # Check if user owns this saved search or is admin
    conn = get_db_connection()
    owner = conn.execute('SELECT owner_username, name FROM saved_searches WHERE id = ?', (saved_search_id,)).fetchone()
    conn.close()
    
    if not owner:
        flash('Saved item not found', 'error')
        return redirect(url_for('saved_page'))
    
    # Allow access if user owns it or is admin
    is_admin = session.get('role') == 'admin'
    if owner['owner_username'] != session['username'] and not is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('saved_page'))
    
    items = get_saved_results_for_search(saved_search_id)
    return render_template('user/saved_detail.html', search_name=owner['name'], items=items, username=session['username'], is_admin=is_admin, saved_search_id=saved_search_id)

@app.route('/admin/saved', methods=['GET', 'POST'])
def admin_saved_page():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('role') != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('search'))
    if request.method == 'POST':
        item_id = request.form.get('id')
        if item_id:
            # here id represents saved_search id for admin delete
            try:
                conn = get_db_connection()
                conn.execute('DELETE FROM saved_results WHERE saved_search_id = ?', (item_id,))
                conn.execute('DELETE FROM saved_searches WHERE id = ?', (item_id,))
                conn.commit()
                conn.close()
            except Exception:
                pass
        return redirect(url_for('admin_saved_page'))
    rows = get_saved_results_all()
    return render_template('admin/admin_saved.html', rows=rows, username=session['username'])


@app.route('/admin', methods=['GET', 'POST'])
def admin_dashboard():
    """Admin dashboard for managing search logs and users."""
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if session.get('role') != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('search'))

    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_user':
            username = request.form.get('new_username', '').strip()
            password = request.form.get('new_password', '').strip()
            role = request.form.get('new_role', 'guest')
            tokens = request.form.get('new_tokens', '0')
            if username and password:
                try:
                    upsert_user(username, password, role, int(tokens or 0))
                    flash('User created', 'success')
                except Exception as e:
                    flash(f'Failed to create user: {e}', 'error')
            else:
                flash('Username and password are required', 'error')
        elif action == 'update_user':
            username = request.form.get('username', '').strip()
            role = request.form.get('role')
            tokens = request.form.get('tokens')
            try:
                if tokens is not None and tokens != '':
                    update_user_tokens(username, int(tokens))
                if role:
                    conn = get_db_connection()
                    conn.execute('UPDATE users SET role = ? WHERE username = ?', (role, username))
                    conn.commit()
                    conn.close()
                flash('User updated', 'success')
            except Exception as e:
                flash(f'Failed to update user: {e}', 'error')
        elif action == 'reset_password':
            username = request.form.get('username', '').strip()
            password = request.form.get('password', '').strip()
            if username and password:
                try:
                    set_user_password(username, password)
                    flash('Password reset', 'success')
                except Exception as e:
                    flash(f'Failed to reset password: {e}', 'error')
            else:
                flash('Username and password are required', 'error')
        elif action == 'delete_user':
            username = request.form.get('username', '').strip()
            if username:
                try:
                    delete_user(username)
                    flash('User deleted', 'success')
                except Exception as e:
                    flash(f'Failed to delete user: {e}', 'error')
        elif action == 'clear_logs':
            try:
                conn = get_db_connection()
                conn.execute('DELETE FROM search_logs')
                conn.commit()
                conn.close()
                flash('Logs cleared', 'success')
            except Exception as e:
                flash(f'Failed to clear logs: {e}', 'error')
        elif action == 'delete_saved':
            # Delete an entire saved search (and its items)
            try:
                saved_search_id = request.form.get('id')
                if saved_search_id:
                    conn = get_db_connection()
                    conn.execute('DELETE FROM saved_results WHERE saved_search_id = ?', (saved_search_id,))
                    conn.execute('DELETE FROM saved_searches WHERE id = ?', (saved_search_id,))
                    conn.commit()
                    conn.close()
                    flash('Saved search deleted', 'success')
            except Exception as e:
                flash(f'Failed to delete saved search: {e}', 'error')
        elif action == 'clear_saved':
            try:
                conn = get_db_connection()
                conn.execute('DELETE FROM saved_results')
                conn.execute('DELETE FROM saved_searches')
                conn.commit()
                conn.close()
                flash('All saved results cleared', 'success')
            except Exception as e:
                flash(f'Failed to clear saved results: {e}', 'error')

        return redirect(url_for('admin_dashboard'))

    users = get_all_users()
    logs = get_search_logs(limit=int(request.args.get('limit', 200)))
    saved_rows = get_saved_searches_all()
    return render_template('admin/admin.html', users=users, logs=logs, saved_rows=saved_rows, username=session['username'])

@app.route('/tokens')
def tokens_page():
    """Dedicated page for guests to earn tokens."""
    if 'user_id' not in session:
        return redirect(url_for('login'))   
    if session.get('role') != 'guest':
        flash('Only guest users can access the token page.', 'warning')
        return redirect(url_for('search'))
    return render_template('user/earn_tokens.html', username=session['username'], tokens=session['tokens'])

if __name__ == '__main__':
    # Initialize database on startup
    init_db()
    app.run(host='0.0.0.0', port=8001, debug=True)
