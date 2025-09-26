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
)
from .services import client

user_bp = Blueprint('user', __name__)

# In-memory rate limiting shared across user routes
RATE_LIMIT_WINDOW_SECONDS = 10
RATE_LIMIT_MAX_REQUESTS = 5
EARN_TOKENS_WINDOW_SECONDS = 60
EARN_TOKENS_MAX_REQUESTS = 3
recent_requests_by_key = defaultdict(lambda: deque(maxlen=RATE_LIMIT_MAX_REQUESTS))


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

    if request.method == 'GET':
        return render_template('user/search.html', hits=[], user_role=session['role'], 
                             username=session['username'], tokens=session['tokens'])

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
                                 username=session['username'], tokens=session['tokens'])
        dq.append(now_ts)
    except Exception:
        pass

    domain = request.form.get('domain')
    username = request.form.get('username')
    line = request.form.get('line', default=50, type=int)
    search_type = request.form.get('type', default='', type=str).lower()

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

    INDEX = "urluserpass"

    if performing_search:
        if domain and username:
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
            if search_type == 'exact':
                query = {"size": line, "query": {"term": {"d.keyword": domain}}}
            else:
                query = {"size": line, "query": {"wildcard": {"d": f"*{domain}*"}}}
        elif username:
            if search_type == 'exact':
                query = {"size": line, "query": {"term": {"u.keyword": username}}}
            else:
                query = {"size": line, "query": {"wildcard": {"u": f"*{username}*"}}}
        else:
            query = {"size": 0, "query": {"match_all": {}}}
    else:
        query = {"size": 0, "query": {"match_all": {}}}

    if performing_search:
        try:
            response = client.search(index=INDEX, body=query)
        except Exception as e:
            flash(f'Search error: {str(e)}', 'error')
            response = {'hits': {'hits': []}}
    else:
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

    seen = set()
    unique_hits = []
    for hit in hits:
        key = (hit['d'], hit['u'], hit['p'])
        if key not in seen:
            seen.add(key)
            unique_hits.append(hit)

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


@user_bp.route('/save_results', methods=['POST'])
def save_results_endpoint():
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    data = request.get_json(silent=True) or {}
    items = data.get('items', [])
    name = (data.get('name') or '').strip()
    if not isinstance(items, list) or not items:
        return jsonify({'success': False, 'message': 'No items provided'}), 400
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
        return jsonify({'success': False, 'message': 'No valid items'}), 400
    saved_id = create_saved_search(session['username'], name)
    save_results(session['username'], cleaned, saved_search_id=saved_id)
    return jsonify({'success': True, 'count': len(cleaned), 'saved_search_id': saved_id})


@user_bp.route('/saved', methods=['GET', 'POST'])
def saved_page():
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
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
                    return jsonify({'success': False, 'error': 'Item not found'})
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
        flash('Saved item not found', 'error')
        return redirect(url_for('user.saved_page'))

    is_admin = session.get('role') == 'admin'
    if owner['owner_username'] != session['username'] and not is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('user.saved_page'))

    items = get_saved_results_for_search(saved_search_id)
    return render_template('user/saved_detail.html', search_name=owner['name'], items=items, username=session['username'], is_admin=is_admin, saved_search_id=saved_search_id)


@user_bp.route('/tokens')
def tokens_page():
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    if session.get('role') != 'guest':
        flash('Only guest users can access the token page.', 'warning')
        return redirect(url_for('user.search'))
    return render_template('user/earn_tokens.html', username=session['username'], tokens=session['tokens'])


