from flask import Blueprint, request, render_template, session, redirect, url_for, flash

from .db import (
    get_db_connection,
    get_all_users,
    get_search_logs,
    get_saved_results_all,
    upsert_user,
    update_user_tokens,
    set_user_password,
    delete_user,
    get_saved_searches_all,
)

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.route('', methods=['GET', 'POST'])
def admin_dashboard():
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    if session.get('role') != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('user.search'))

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

        return redirect(url_for('admin.admin_dashboard'))

    users = get_all_users()
    logs = get_search_logs(limit=int(request.args.get('limit', 200)))
    saved_rows = get_saved_searches_all()
    return render_template('admin/admin.html', users=users, logs=logs, saved_rows=saved_rows, username=session['username'])


@admin_bp.route('/saved', methods=['GET', 'POST'])
def admin_saved_page():
    if 'user_id' not in session:
        return redirect(url_for('user.login'))
    if session.get('role') != 'admin':
        flash('Admin access required', 'error')
        return redirect(url_for('user.search'))
    if request.method == 'POST':
        item_id = request.form.get('id')
        if item_id:
            try:
                conn = get_db_connection()
                conn.execute('DELETE FROM saved_results WHERE saved_search_id = ?', (item_id,))
                conn.execute('DELETE FROM saved_searches WHERE id = ?', (item_id,))
                conn.commit()
                conn.close()
            except Exception:
                pass
        return redirect(url_for('admin.admin_saved_page'))
    rows = get_saved_results_all()
    return render_template('admin/admin_saved.html', rows=rows, username=session['username'])


