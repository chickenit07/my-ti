import sqlite3
import hashlib
import os
from datetime import datetime

DATABASE = 'users.db'

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password, hash_value):
    return hashlib.sha256(password.encode()).hexdigest() == hash_value

def init_db():
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

    # Create default users if they don't exist (passwords from env)
    admin_plain = os.getenv('ADMIN_PASSWORD', 'admin123')
    guest_plain = os.getenv('GUEST_PASSWORD', 'guest123')
    admin_hash = hashlib.sha256(admin_plain.encode()).hexdigest()
    guest_hash = hashlib.sha256(guest_plain.encode()).hexdigest()

    try:
        conn.execute('INSERT INTO users (username, password_hash, role, tokens) VALUES (?, ?, ?, ?)',
                    ('admin', admin_hash, 'admin', 0))
    except sqlite3.IntegrityError:
        pass

    try:
        conn.execute('INSERT INTO users (username, password_hash, role, tokens) VALUES (?, ?, ?, ?)',
                    ('guest', guest_hash, 'guest', 0))
    except sqlite3.IntegrityError:
        pass

    conn.commit()
    conn.close()

def get_user(username):
    conn = get_db_connection()
    row = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return row

def get_all_users():
    conn = get_db_connection()
    rows = conn.execute('SELECT id, username, role, tokens, created_at, last_login FROM users ORDER BY id ASC').fetchall()
    conn.close()
    return rows

def update_user_tokens(username, tokens):
    conn = get_db_connection()
    conn.execute('UPDATE users SET tokens = ? WHERE username = ?', (tokens, username))
    conn.commit()
    conn.close()

def update_last_login(username):
    conn = get_db_connection()
    conn.execute('UPDATE users SET last_login = ? WHERE username = ?', (datetime.now(), username))
    conn.commit()
    conn.close()

def set_user_password(username, password):
    conn = get_db_connection()
    conn.execute('UPDATE users SET password_hash = ? WHERE username = ?', (hash_password(password), username))
    conn.commit()
    conn.close()

def upsert_user(username, password, role, tokens=0):
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

def log_search(username, ip, domain, username_query, search_type, line, result_count):
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO search_logs (username, ip, domain, username_query, search_type, line, result_count)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (username, ip, domain or '', username_query or '', search_type or '', int(line) if line else None, int(result_count)))
    conn.commit()
    conn.close()

def get_search_logs(limit=200):
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
        SELECT s.id, s.name, s.created_at, COUNT(r.id) AS record_count
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
        SELECT s.id, s.owner_username, s.name, s.created_at, COUNT(r.id) AS record_count
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

def save_results(owner_username, records, saved_search_id=None):
    conn = get_db_connection()
    try:
        conn.executemany('''
            INSERT INTO saved_results (owner_username, saved_search_id, t, d, u, p, note)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', [(owner_username, saved_search_id, rec.get('t'), rec['d'], rec['u'], rec['p'], rec.get('note', '')) for rec in records])
        conn.commit()
    finally:
        conn.close()

def delete_saved_result(owner_username, record_id, is_admin=False):
    conn = get_db_connection()
    if is_admin:
        conn.execute('DELETE FROM saved_results WHERE id = ?', (record_id,))
    else:
        conn.execute('DELETE FROM saved_results WHERE id = ? AND owner_username = ?', (record_id, owner_username))
    conn.commit()
    conn.close()

def delete_user(username):
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE username = ?', (username,))
    conn.commit()
    conn.close()
