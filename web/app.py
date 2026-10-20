"""Single-process web service with a server-configured indexer connection."""
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

import click
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHashError
from flask import Flask, abort, g, redirect, render_template, request, send_file, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

from wazuh_report import fetch_summary, indexer_url, render_report, render_template as render_pdf_template, validate_customer
from vulnerability_report import fetch_vulnerabilities, render_vulnerability_report, render_vulnerability_template

HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)
DUMMY_HASH = HASHER.hash(secrets.token_urlsafe(32))
PDF_LOCK = threading.Lock()
SESSION_SECONDS = 10 * 60
IDLE_SECONDS = SESSION_SECONDS
ABSOLUTE_SECONDS = SESSION_SECONDS


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        DATA_DIR=os.environ.get('REPORT_DATA_DIR', '/data'),
        PUBLIC_ORIGIN=os.environ.get('PUBLIC_ORIGIN', ''),
        INDEXER_IP=os.environ.get('INDEXER_IP', ''),
        INDEXER_PORT=os.environ.get('INDEXER_PORT', '9200'),
        INDEXER_USER=os.environ.get('INDEXER_USER', ''),
        INDEXER_PASSWORD=os.environ.get('INDEXER_PASSWORD', ''),
        ALLOW_HTTP=os.environ.get('ALLOW_LOCAL_HTTP') == '1',
        TRUST_PROXY=os.environ.get('TRUST_PROXY') == '1',
        RETENTION_HOURS=int(os.environ.get('RETENTION_HOURS', '24')),
        MAX_CONTENT_LENGTH=16 * 1024,
        MAX_FORM_MEMORY_SIZE=16 * 1024,
        MAX_FORM_PARTS=20,
    )
    if config:
        app.config.update(config)
    origin = urlsplit(app.config['PUBLIC_ORIGIN'])
    if (origin.scheme not in ('https', 'http') or not origin.hostname or origin.username
            or origin.password or origin.path or origin.query or origin.fragment):
        raise ValueError('PUBLIC_ORIGIN deve ser uma origem HTTPS, sem caminho ou credenciais.')
    local_http = origin.scheme == 'http' and app.config['ALLOW_HTTP'] and origin.hostname in ('localhost', '127.0.0.1', '::1')
    if origin.scheme != 'https' and not local_http:
        raise ValueError('HTTP só é permitido explicitamente em localhost para desenvolvimento.')
    if not 1 <= app.config['RETENTION_HOURS'] <= 720:
        raise ValueError('RETENTION_HOURS deve estar entre 1 e 720.')
    endpoint = indexer_url(app.config['INDEXER_IP'], app.config['INDEXER_PORT'])
    indexer_username = app.config['INDEXER_USER'].strip()
    indexer_password = app.config['INDEXER_PASSWORD']
    if (not indexer_username or len(indexer_username) > 128 or ':' in indexer_username
            or any(ord(char) < 32 for char in indexer_username)
            or not indexer_password or len(indexer_password) > 1024):
        raise ValueError('Configure INDEXER_USER e INDEXER_PASSWORD válidos no servidor.')
    cookie_name = 'reports-dev' if local_http else '__Host-reports'
    data_dir = Path(app.config['DATA_DIR'])
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    reports = data_dir / 'reports'
    reports.mkdir(exist_ok=True, mode=0o700)
    db_path = data_dir / 'reports.sqlite3'
    if app.config['TRUST_PROXY']:
        # Only deploy behind the single Caddy proxy; the app port must not be published.
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=0)

    @contextmanager
    def database():
        with sqlite3.connect(db_path, timeout=15) as db:
            db.row_factory = sqlite3.Row
            yield db

    with database() as db:
        db.executescript('''
            PRAGMA journal_mode=WAL;
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
                customers TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1);
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY, user_id INTEGER, csrf TEXT NOT NULL,
                created REAL NOT NULL, touched REAL NOT NULL);
            CREATE TABLE IF NOT EXISTS attempts (key TEXT NOT NULL, at REAL NOT NULL);
            CREATE INDEX IF NOT EXISTS attempts_key ON attempts(key, at);
            CREATE TABLE IF NOT EXISTS reports (
                id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, customer TEXT NOT NULL,
                hours INTEGER NOT NULL, created REAL NOT NULL);
        ''')
        db.execute('BEGIN IMMEDIATE')
        # Existing accounts remain regular; bootstrap the first administrator on the host.
        columns = {row['name'] for row in db.execute('PRAGMA table_info(users)')}
        if 'is_admin' not in columns:
            db.execute('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0')
        if 'must_change_password' not in columns:
            db.execute('ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0')
        report_columns = {row['name'] for row in db.execute('PRAGMA table_info(reports)')}
        if 'report_type' not in report_columns:
            db.execute("ALTER TABLE reports ADD COLUMN report_type TEXT NOT NULL DEFAULT 'security'")
    os.chmod(db_path, 0o600)
    app.extensions['report_database'] = database

    def prune():
        now = time.time()
        with database() as db:
            db.execute('DELETE FROM sessions WHERE touched <= ? OR created <= ?', (now-IDLE_SECONDS, now-ABSOLUTE_SECONDS))
            db.execute('DELETE FROM attempts WHERE at < ?', (now-900,))
            expired = db.execute('SELECT id FROM reports WHERE created < ?', (now-app.config['RETENTION_HOURS']*3600,)).fetchall()
            for row in expired:
                (reports / f'{row["id"]}.pdf').unlink(missing_ok=True)
            db.execute('DELETE FROM reports WHERE created < ?', (now-app.config['RETENTION_HOURS']*3600,))
        # Remove orphan PDFs left by a crash before their metadata transaction.
        with database() as db:
            known = {r['id'] for r in db.execute('SELECT id FROM reports')}
        for path in reports.glob('*.pdf'):
            if path.stem not in known and path.stat().st_mtime < now-3600:
                path.unlink(missing_ok=True)

    def rate_attempt(keys_limits):
        now = time.time()
        with database() as db:
            db.execute('BEGIN IMMEDIATE')
            db.execute('DELETE FROM attempts WHERE at < ?', (now-900,))
            if any(db.execute('SELECT count(*) FROM attempts WHERE key=?', (key,)).fetchone()[0] >= limit
                   for key, limit in keys_limits):
                return False
            db.executemany('INSERT INTO attempts VALUES (?, ?)', [(key, now) for key, _ in keys_limits])
        return True

    def logged_in(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if not g.user:
                return redirect(url_for('login'))
            return view(*args, **kwargs)
        return wrapped

    def allowed_customer(customer):
        allowed = json.loads(g.user['customers'])
        return bool(g.user['is_admin']) or allowed == ['*'] or customer in allowed

    def admin_required(view):
        @wraps(view)
        @logged_in
        def wrapped(*args, **kwargs):
            if not g.user['is_admin']:
                abort(403)
            return view(*args, **kwargs)
        return wrapped

    def protect_last_admin(db, user_id, active, is_admin):
        row = db.execute('SELECT active,is_admin FROM users WHERE id=?', (user_id,)).fetchone()
        if row and row['active'] and row['is_admin'] and not (active and is_admin):
            if not db.execute('SELECT 1 FROM users WHERE active=1 AND is_admin=1 AND id!=?', (user_id,)).fetchone():
                raise ValueError('Mantenha pelo menos um administrador ativo.')

    @app.before_request
    def guard():
        if request.host != origin.netloc or request.scheme != origin.scheme:
            abort(400)
        if request.path == '/healthz':
            return None
        g.user = None
        g.session = None
        token = request.cookies.get(cookie_name, '')
        if token and len(token) <= 128:
            now = time.time()
            with database() as db:
                row = db.execute('SELECT * FROM sessions WHERE token=? AND touched>? AND created>?',
                                 (digest(token), now-IDLE_SECONDS, now-ABSOLUTE_SECONDS)).fetchone()
                if row:
                    g.session = dict(row)
                    if row['user_id']:
                        g.user = db.execute('SELECT * FROM users WHERE id=? AND active=1', (row['user_id'],)).fetchone()
                        if not g.user:
                            g.session = None
                    if g.session:
                        db.execute('UPDATE sessions SET touched=? WHERE token=?', (now, row['token']))
                        # Activity never extends the original login deadline.
                        g.session_seconds_left = max(1, math.ceil(row['created'] + ABSOLUTE_SECONDS - now))
        if request.method == 'POST':
            supplied_origin = request.headers.get('Origin')
            if not supplied_origin:
                referer = urlsplit(request.headers.get('Referer', ''))
                supplied_origin = f'{referer.scheme}://{referer.netloc}'
            if supplied_origin != app.config['PUBLIC_ORIGIN']:
                abort(403)
            csrf = request.form.get('csrf', '')
            if not g.session or not hmac.compare_digest(g.session['csrf'].encode(), csrf.encode()):
                abort(403)
        if (g.user and g.user['must_change_password']
                and request.endpoint not in ('password_change', 'logout', 'static')):
            return redirect(url_for('password_change'), code=303)

    @app.after_request
    def headers(response):
        response.headers.update({
            'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY', 'Referrer-Policy': 'same-origin',
            'Content-Security-Policy': "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
        })
        if not local_http:
            response.headers['Strict-Transport-Security'] = 'max-age=31536000'
        if hasattr(g, 'new_token'):
            response.set_cookie(cookie_name, g.new_token, secure=not local_http, httponly=True,
                                samesite='Lax', path='/', max_age=ABSOLUTE_SECONDS)
        return response

    def new_session(user_id=None):
        token = secrets.token_urlsafe(32)
        now = time.time()
        with database() as db:
            if g.session:
                db.execute('DELETE FROM sessions WHERE token=?', (g.session['token'],))
            csrf = secrets.token_urlsafe(32)
            db.execute('INSERT INTO sessions VALUES (?, ?, ?, ?, ?)', (digest(token), user_id, csrf, now, now))
        g.new_token = token
        g.session = {'csrf': csrf, 'token': digest(token)}

    @app.get('/healthz')
    def health():
        return {'status': 'ok'}

    @app.route('/login', methods=['GET', 'POST'])
    def login():
        error = None
        if request.method == 'POST':
            username = request.form.get('username', '').strip().casefold()[:128]
            password = request.form.get('password', '')
            keys = [('login-user:'+digest(username), 5), ('login-ip:'+digest(request.remote_addr or ''), 20)]
            if not rate_attempt(keys):
                return render_template('login.html', error='Muitas tentativas. Aguarde 15 minutos.'), 429
            with database() as db:
                user = db.execute('SELECT * FROM users WHERE username=? AND active=1', (username,)).fetchone()
            valid = False
            try:
                valid = HASHER.verify(user['password_hash'] if user else DUMMY_HASH, password) and user is not None
            except (VerificationError, InvalidHashError):
                pass
            if valid:
                with database() as db:
                    if HASHER.check_needs_rehash(user['password_hash']):
                        db.execute('UPDATE users SET password_hash=? WHERE id=?', (HASHER.hash(password), user['id']))
                    db.execute('DELETE FROM attempts WHERE key=?', (keys[0][0],))
                new_session(user['id'])
                return redirect(url_for('password_change' if user['must_change_password'] else 'dashboard'), code=303)
            error = 'Usuário ou senha inválidos.'
        if not g.session:
            if not rate_attempt([('session-ip:'+digest(request.remote_addr or ''), 60)]):
                abort(429)
            prune()
            new_session()
        return render_template('login.html', error=error), 401 if error else 200

    @app.post('/logout')
    @logged_in
    def logout():
        with database() as db:
            db.execute('DELETE FROM sessions WHERE token=?', (g.session['token'],))
        response = redirect(url_for('login'), code=303)
        response.delete_cookie(cookie_name, path='/', secure=not local_http, httponly=True, samesite='Lax')
        return response

    @app.route('/account/password', methods=['GET', 'POST'])
    @logged_in
    def password_change():
        error = None
        if request.method == 'POST':
            if not rate_attempt([('password:'+str(g.user['id']), 5)]):
                return render_template('password_change.html', error='Muitas tentativas. Aguarde 15 minutos.'), 429
            current = request.form.get('current_password', '')
            password = request.form.get('password', '')
            try:
                HASHER.verify(g.user['password_hash'], current)
                if not 15 <= len(password) <= 128:
                    raise ValueError('A nova senha deve ter entre 15 e 128 caracteres.')
                if password != request.form.get('confirmation', ''):
                    raise ValueError('A confirmação não corresponde à nova senha.')
                if hmac.compare_digest(current.encode(), password.encode()):
                    raise ValueError('Escolha uma senha diferente da senha atual.')
                password_hash = HASHER.hash(password)
                with database() as db:
                    db.execute('BEGIN IMMEDIATE')
                    updated = db.execute('UPDATE users SET password_hash=?,must_change_password=0 WHERE id=? AND active=1 AND password_hash=?',
                                         (password_hash, g.user['id'], g.user['password_hash']))
                    if not updated.rowcount:
                        abort(403)
                    db.execute('DELETE FROM sessions WHERE user_id=?', (g.user['id'],))
                # Require login with the new password; every previous session is revoked.
                return redirect(url_for('login'), code=303)
            except (VerificationError, InvalidHashError):
                error = 'Senha atual inválida.'
            except ValueError as exc:
                error = str(exc)
        return render_template('password_change.html', error=error), 400 if error else 200

    def dashboard_page(error=None, status=200, report_type='security'):
        prune()
        with database() as db:
            items = db.execute('SELECT * FROM reports WHERE user_id=? AND report_type=? ORDER BY created DESC', (g.user['id'], report_type)).fetchall()
        return render_template('dashboard.html', reports=items, error=error,
                               report_type=report_type,
                               customers=['*'] if g.user['is_admin'] else json.loads(g.user['customers'])), status

    @app.get('/')
    @logged_in
    def dashboard():
        return dashboard_page()

    @app.get('/vulnerabilities')
    @logged_in
    def vulnerability_dashboard():
        return dashboard_page(report_type='vulnerabilities')

    @app.get('/admin/users')
    @admin_required
    def admin_users():
        with database() as db:
            accounts = [dict(row) for row in db.execute(
                'SELECT id,username,active,is_admin,must_change_password,customers FROM users ORDER BY username')]
        for account in accounts:
            account['customers'] = json.loads(account['customers'])
        return render_template('admin_users.html', accounts=accounts, saved=request.args.get('saved') == '1')

    @app.route('/admin/users/new', methods=['GET', 'POST'])
    @app.route('/admin/users/<int:user_id>', methods=['GET', 'POST'])
    @admin_required
    def admin_user_edit(user_id=None):
        with database() as db:
            account = db.execute('SELECT id,username,active,is_admin,must_change_password,customers FROM users WHERE id=?', (user_id,)).fetchone() if user_id is not None else None
        if user_id is not None and not account:
            abort(404)
        form = dict(account) if account else {'username': '', 'active': 1, 'is_admin': 0, 'customers': '[]'}
        customers = json.loads(form['customers'])
        form['scope'] = 'all' if customers == ['*'] else 'restricted'
        form['customers_text'] = '' if customers == ['*'] else '\n'.join(customers)
        error = None
        if request.method == 'POST':
            if not rate_attempt([('admin-write:'+str(g.user['id']), 60)]):
                abort(429)
            form.update(username=request.form.get('username', '').strip().casefold(),
                        is_admin=request.form.get('role') == 'admin',
                        active=request.form.get('active') == '1',
                        scope=request.form.get('scope', ''),
                        customers_text=request.form.get('customers', ''))
            try:
                if request.form.get('role') not in ('admin', 'regular'):
                    raise ValueError('Escolha um perfil válido.')
                if not re.fullmatch(r'[a-z0-9_.@-]{3,128}', form['username']):
                    raise ValueError('Usuário: 3 a 128 caracteres, letras, números, _, ., @ ou -.')
                if account and form['username'] != account['username']:
                    raise ValueError('O nome de uma conta existente não pode ser alterado.')
                if form['is_admin'] or form['scope'] == 'all':
                    customers = ['*']
                else:
                    if form['scope'] != 'restricted':
                        raise ValueError('Escolha o acesso aos clientes.')
                    customers = list(dict.fromkeys(validate_customer(item) for item in re.split(r'[,\n]', form['customers_text']) if item.strip()))
                    if not customers or '*' in customers:
                        raise ValueError('Informe clientes específicos ou selecione todos os clientes.')
                password = request.form.get('password', '')
                if not account or password:
                    if not 15 <= len(password) <= 128:
                        raise ValueError('A senha temporária deve ter entre 15 e 128 caracteres.')
                    if password != request.form.get('confirmation', ''):
                        raise ValueError('A confirmação não corresponde à senha temporária.')
                elif request.form.get('confirmation'):
                    raise ValueError('Informe também a senha temporária.')
                password_hash = HASHER.hash(password) if password else None
                with database() as db:
                    db.execute('BEGIN IMMEDIATE')
                    # Recheck the actor while holding the write lock against concurrent revocation.
                    actor = db.execute('SELECT active,is_admin,must_change_password FROM users WHERE id=?', (g.user['id'],)).fetchone()
                    session = db.execute('SELECT 1 FROM sessions WHERE token=? AND user_id=?', (g.session['token'], g.user['id'])).fetchone()
                    if not actor or not actor['active'] or not actor['is_admin'] or actor['must_change_password'] or not session:
                        abort(403)
                    if account:
                        current = db.execute('SELECT * FROM users WHERE id=?', (user_id,)).fetchone()
                        if not current:
                            abort(404)
                        protect_last_admin(db, user_id, form['active'], form['is_admin'])
                        must_change = bool(current['must_change_password'] or password_hash or (form['is_admin'] and not current['is_admin']))
                        db.execute('UPDATE users SET customers=?,is_admin=?,active=?,password_hash=?,must_change_password=? WHERE id=?',
                                   (json.dumps(customers), int(form['is_admin']), int(form['active']),
                                    password_hash or current['password_hash'], int(must_change), user_id))
                        db.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
                    else:
                        db.execute('INSERT INTO users(username,password_hash,customers,active,is_admin,must_change_password) VALUES (?,?,?,?,?,1)',
                                   (form['username'], password_hash, json.dumps(customers), int(form['active']), int(form['is_admin'])))
                return redirect(url_for('login') if user_id == g.user['id'] else url_for('admin_users', saved=1), code=303)
            except sqlite3.IntegrityError:
                error = 'Já existe uma conta com esse nome.'
            except ValueError as exc:
                error = str(exc)
        return render_template('admin_user_edit.html', account=account, form=form, error=error), 400 if error else 200

    @app.post('/reports', defaults={'report_type': 'security'})
    @app.post('/vulnerabilities/reports', defaults={'report_type': 'vulnerabilities'})
    @logged_in
    def generate(report_type):
        try:
            customer = validate_customer(request.form.get('customer', ''))
            if not allowed_customer(customer):
                abort(403)
            hours = int(request.form.get('hours', '0'))
            if hours not in (24, 168, 720):
                raise ValueError('Escolha 24 horas, 7 dias ou 30 dias.')
        except (ValueError, TypeError) as exc:
            return dashboard_page(str(exc), 400, report_type)
        if not rate_attempt([('generate:'+str(g.user['id']), 10)]):
            return dashboard_page('Limite de gerações atingido. Aguarde 15 minutos.', 429, report_type)
        if not PDF_LOCK.acquire(blocking=False):
            return dashboard_page('Há uma geração em andamento. Tente novamente em alguns instantes.', 409, report_type)
        report_id = uuid.uuid4().hex
        path = reports / f'{report_id}.pdf'
        try:
            fetch = fetch_vulnerabilities if report_type == 'vulnerabilities' else fetch_summary
            render = render_vulnerability_report if report_type == 'vulnerabilities' else render_report
            snapshot = fetch(customer, endpoint, indexer_username, indexer_password, hours=hours, verify_tls=True, reject_redirects=True)
            render(snapshot, path)
            os.chmod(path, 0o600)
            with database() as db:
                db.execute('INSERT INTO reports(id,user_id,customer,hours,created,report_type) VALUES (?, ?, ?, ?, ?, ?)',
                           (report_id, g.user['id'], customer, hours, time.time(), report_type))
        except Exception:
            # Never expose an upstream exception, URL, credentials, snapshot or traceback to the browser/log.
            path.unlink(missing_ok=True)
            app.logger.warning('Geração de relatório falhou; nenhuma credencial foi registrada.')
            return dashboard_page('Não foi possível gerar o relatório. Solicite ao administrador que verifique a conexão com o indexador.', 502, report_type)
        finally:
            PDF_LOCK.release()
        return redirect(url_for('vulnerability_dashboard' if report_type == 'vulnerabilities' else 'dashboard'), code=303)

    @app.get('/reports/<report_id>')
    @logged_in
    def download(report_id):
        if not re.fullmatch(r'[0-9a-f]{32}', report_id):
            abort(404)
        with database() as db:
            row = db.execute('SELECT * FROM reports WHERE id=? AND user_id=? AND created>?',
                             (report_id, g.user['id'], time.time()-app.config['RETENTION_HOURS']*3600)).fetchone()
        if not row or not allowed_customer(row['customer']):
            abort(404)
        path = reports / f'{report_id}.pdf'
        if not path.is_file():
            abort(404)
        # Customer labels may contain path/control characters; use a safe fixed download name.
        kind = 'Vulnerabilidades' if row['report_type'] == 'vulnerabilities' else 'Seguranca'
        return send_file(path, as_attachment=True, download_name=f'Relatorio_de_{kind}_{report_id[:8]}.pdf', mimetype='application/pdf')

    @app.get('/template', defaults={'report_type': 'security'})
    @app.get('/vulnerabilities/template', defaults={'report_type': 'vulnerabilities'})
    @logged_in
    def template_download(report_type):
        import io
        import tempfile
        if not PDF_LOCK.acquire(blocking=False):
            return dashboard_page('Há uma geração em andamento. Tente novamente.', 409, report_type)
        try:
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'modelo.pdf'
                render = render_vulnerability_template if report_type == 'vulnerabilities' else render_pdf_template
                render(path)
                payload = io.BytesIO(path.read_bytes())
            kind = 'Vulnerabilidades' if report_type == 'vulnerabilities' else 'Seguranca'
            return send_file(payload, as_attachment=True, download_name=f'Modelo_de_Relatorio_de_{kind}.pdf', mimetype='application/pdf')
        finally:
            PDF_LOCK.release()

    @app.cli.command('user-set')
    @click.argument('username')
    @click.option('--customer', multiple=True, help='Cliente autorizado; repita para mais clientes.')
    @click.option('--all-customers', is_flag=True, help='Autoriza explicitamente todos os clientes.')
    @click.option('--create-only', is_flag=True, help='Falha se a conta já existir.')
    @click.option('--admin', is_flag=True, help='Administrador; acesso automático a todos os clientes.')
    def user_set(username, customer, all_customers, create_only, admin):
        """Create/reset an account; revoke its existing sessions."""
        username = username.strip().casefold()
        if not re.fullmatch(r'[a-z0-9_.@-]{3,128}', username):
            raise click.ClickException('Usuário: 3 a 128 caracteres, letras, números, _, ., @ ou -.')
        if admin and customer:
            raise click.ClickException('Administradores têm acesso a todos os clientes.')
        if not admin and bool(customer) == bool(all_customers):
            raise click.ClickException('Informe --customer ou --all-customers.')
        customers = ['*'] if all_customers or admin else [validate_customer(c) for c in customer]
        if not all_customers and not admin and '*' in customers:
            raise click.ClickException('Use --all-customers para autorizar todos os clientes.')
        if create_only:
            with database() as db:
                if db.execute('SELECT 1 FROM users WHERE username=?', (username,)).fetchone():
                    raise click.ClickException('Conta já existe; use os comandos de edição.')
        password = click.prompt('Senha (mínimo 15 caracteres)', hide_input=True, confirmation_prompt=True)
        if not 15 <= len(password) <= 128:
            raise click.ClickException('A senha deve ter entre 15 e 128 caracteres.')
        with database() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = db.execute('SELECT is_admin FROM users WHERE username=?', (username,)).fetchone()
            is_admin = int(bool(admin or (existing and existing['is_admin'])))
            if is_admin:
                customers = ['*']
            query = 'INSERT INTO users(username,password_hash,customers,is_admin,must_change_password) VALUES (?,?,?,?,1)'
            if not create_only:
                query += ' ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,customers=excluded.customers,is_admin=excluded.is_admin,must_change_password=1,active=1'
            try:
                db.execute(query, (username, HASHER.hash(password), json.dumps(customers), is_admin))
            except sqlite3.IntegrityError as exc:
                raise click.ClickException('Conta já existe; use os comandos de edição.') from exc
            user_id = db.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()[0]
            db.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
        click.echo('Conta salva; sessões anteriores revogadas.')

    @app.cli.command('user-list')
    def user_list():
        """List account status and customer access without credential data."""
        with database() as db:
            accounts = [{'username': row['username'], 'active': bool(row['active']),
                         'role': 'admin' if row['is_admin'] else 'regular',
                         'must_change_password': bool(row['must_change_password']),
                         'customers': json.loads(row['customers'])}
                        for row in db.execute('SELECT username,active,is_admin,must_change_password,customers FROM users ORDER BY username')]
        click.echo(json.dumps(accounts, ensure_ascii=False, indent=2))

    @app.cli.command('user-permissions')
    @click.argument('username')
    @click.option('--customer', multiple=True)
    @click.option('--all-customers', is_flag=True)
    def user_permissions(username, customer, all_customers):
        """Replace customer access; preserve password and active/disabled status."""
        if bool(customer) == bool(all_customers):
            raise click.ClickException('Informe --customer ou --all-customers.')
        try:
            customers = ['*'] if all_customers else list(dict.fromkeys(validate_customer(c) for c in customer))
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        if not all_customers and '*' in customers:
            raise click.ClickException('Use --all-customers para autorizar todos os clientes.')
        with database() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT id,is_admin FROM users WHERE username=?', (username.strip().casefold(),)).fetchone()
            if not row:
                raise click.ClickException('Conta não encontrada.')
            if row['is_admin'] and customers != ['*']:
                raise click.ClickException('Administradores têm acesso a todos os clientes. Altere o perfil antes de restringir.')
            db.execute('UPDATE users SET customers=? WHERE id=?', (json.dumps(customers), row['id']))
            db.execute('DELETE FROM sessions WHERE user_id=?', (row['id'],))
        click.echo('Permissões substituídas; sessões anteriores revogadas.')

    @app.cli.command('user-password')
    @click.argument('username')
    def user_password(username):
        """Reset password without changing permissions or active status."""
        username = username.strip().casefold()
        with database() as db:
            if not db.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone():
                raise click.ClickException('Conta não encontrada.')
        password = click.prompt('Senha (mínimo 15 caracteres)', hide_input=True, confirmation_prompt=True)
        if not 15 <= len(password) <= 128:
            raise click.ClickException('A senha deve ter entre 15 e 128 caracteres.')
        password_hash = HASHER.hash(password)
        with database() as db:
            db.execute('UPDATE users SET password_hash=?,must_change_password=1 WHERE username=?', (password_hash, username))
            db.execute('DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE username=?)', (username,))
        click.echo('Senha alterada; sessões anteriores revogadas.')

    @app.cli.command('user-enable')
    @click.argument('username')
    def user_enable(username):
        """Enable an existing account and revoke old sessions."""
        with database() as db:
            row = db.execute('SELECT id FROM users WHERE username=?', (username.strip().casefold(),)).fetchone()
            if not row:
                raise click.ClickException('Conta não encontrada.')
            db.execute('UPDATE users SET active=1 WHERE id=?', (row['id'],))
            db.execute('DELETE FROM sessions WHERE user_id=?', (row['id'],))
        click.echo('Conta ativada; sessões anteriores revogadas.')

    @app.cli.command('user-disable')
    @click.argument('username')
    def user_disable(username):
        with database() as db:
            db.execute('BEGIN IMMEDIATE')
            row = db.execute('SELECT id FROM users WHERE username=?', (username.strip().casefold(),)).fetchone()
            if not row:
                raise click.ClickException('Conta não encontrada.')
            try:
                protect_last_admin(db, row['id'], False, False)
            except ValueError as exc:
                raise click.ClickException(str(exc)) from exc
            db.execute('UPDATE users SET active=0 WHERE id=?', (row['id'],))
            db.execute('DELETE FROM sessions WHERE user_id=?', (row['id'],))
        click.echo('Conta desativada e sessões revogadas.')

    @app.cli.command('user-role')
    @click.argument('username')
    @click.option('--admin', is_flag=True)
    @click.option('--regular', is_flag=True)
    @click.option('--customer', multiple=True)
    @click.option('--all-customers', is_flag=True)
    def user_role(username, admin, regular, customer, all_customers):
        """Bootstrap/promote administrators, or explicitly demote to regular access."""
        if admin == regular:
            raise click.ClickException('Escolha --admin ou --regular.')
        if admin and (customer or all_customers):
            raise click.ClickException('Administradores têm acesso automático a todos os clientes.')
        if regular and bool(customer) == bool(all_customers):
            raise click.ClickException('Informe --customer ou --all-customers para o perfil comum.')
        try:
            customers = ['*'] if admin or all_customers else list(dict.fromkeys(validate_customer(c) for c in customer))
            if regular and not all_customers and '*' in customers:
                raise ValueError('Use --all-customers para autorizar todos os clientes.')
            with database() as db:
                db.execute('BEGIN IMMEDIATE')
                row = db.execute('SELECT id,active,is_admin FROM users WHERE username=?', (username.strip().casefold(),)).fetchone()
                if not row:
                    raise ValueError('Conta não encontrada.')
                protect_last_admin(db, row['id'], row['active'], admin)
                db.execute('UPDATE users SET is_admin=?,customers=?,must_change_password=CASE WHEN ? THEN 1 ELSE must_change_password END WHERE id=?',
                           (int(admin), json.dumps(customers), int(admin and not row['is_admin']), row['id']))
                db.execute('DELETE FROM sessions WHERE user_id=?', (row['id'],))
        except ValueError as exc:
            raise click.ClickException(str(exc)) from exc
        click.echo('Perfil atualizado; sessões anteriores revogadas.')

    @app.cli.command('prune')
    def prune_command():
        """Remove expired sessions/reports, also suitable for periodic operations."""
        prune()
        click.echo('Arquivos e sessões expirados removidos.')

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    @app.errorhandler(429)
    def error_page(error):
        return render_template('error.html', code=error.code), error.code

    return app
