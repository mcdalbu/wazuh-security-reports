"""Single-process web service; credentials and snapshots never enter persistent storage."""
import hashlib
import hmac
import json
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

HASHER = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=1)
DUMMY_HASH = HASHER.hash(secrets.token_urlsafe(32))
PDF_LOCK = threading.Lock()
IDLE_SECONDS = 1800
ABSOLUTE_SECONDS = 8 * 3600


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def create_app(config=None):
    app = Flask(__name__)
    app.config.update(
        DATA_DIR=os.environ.get('REPORT_DATA_DIR', '/data'),
        PUBLIC_ORIGIN=os.environ.get('PUBLIC_ORIGIN', ''),
        INDEXER_ENDPOINTS=os.environ.get('INDEXER_ENDPOINTS', ''),
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
    endpoints = set()
    for item in app.config['INDEXER_ENDPOINTS'].split(','):
        if item.strip():
            parsed = urlsplit(item.strip())
            if parsed.scheme != 'https' or parsed.path or parsed.query or parsed.fragment or parsed.username:
                raise ValueError('INDEXER_ENDPOINTS aceita URLs HTTPS com IP e porta, sem caminho.')
            endpoints.add(indexer_url(parsed.hostname, parsed.port or 9200))
    app.config['ENDPOINTS'] = endpoints
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
    os.chmod(db_path, 0o600)
    app.extensions['report_database'] = database

    def prune():
        now = time.time()
        with database() as db:
            db.execute('DELETE FROM sessions WHERE touched < ? OR created < ?', (now-IDLE_SECONDS, now-ABSOLUTE_SECONDS))
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
        return allowed == ['*'] or customer in allowed

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
                return redirect(url_for('dashboard'), code=303)
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

    def dashboard_page(error=None, status=200):
        prune()
        with database() as db:
            items = db.execute('SELECT * FROM reports WHERE user_id=? ORDER BY created DESC', (g.user['id'],)).fetchall()
        return render_template('dashboard.html', reports=items, error=error,
                               customers=json.loads(g.user['customers'])), status

    @app.get('/')
    @logged_in
    def dashboard():
        return dashboard_page()

    @app.post('/reports')
    @logged_in
    def generate():
        try:
            customer = validate_customer(request.form.get('customer', ''))
            if not allowed_customer(customer):
                abort(403)
            hours = int(request.form.get('hours', '0'))
            if hours not in (24, 168, 720):
                raise ValueError('Escolha 24 horas, 7 dias ou 30 dias.')
            endpoint = indexer_url(request.form.get('ip', ''), request.form.get('port', ''))
            if endpoint not in endpoints:
                raise ValueError('Este IP e porta não estão autorizados na configuração do servidor.')
            username = request.form.get('indexer_user', '').strip()
            password = request.form.get('indexer_password', '')
            if not username or ':' in username or not password:
                raise ValueError('Informe credenciais válidas do indexador.')
        except (ValueError, TypeError) as exc:
            return dashboard_page(str(exc), 400)
        if not rate_attempt([('generate:'+str(g.user['id']), 10)]):
            return dashboard_page('Limite de gerações atingido. Aguarde 15 minutos.', 429)
        if not PDF_LOCK.acquire(blocking=False):
            return dashboard_page('Há uma geração em andamento. Tente novamente em alguns instantes.', 409)
        report_id = uuid.uuid4().hex
        path = reports / f'{report_id}.pdf'
        try:
            snapshot = fetch_summary(customer, endpoint, username, password, hours=hours, verify_tls=True, reject_redirects=True)
            render_report(snapshot, path)
            os.chmod(path, 0o600)
            with database() as db:
                db.execute('INSERT INTO reports VALUES (?, ?, ?, ?, ?)', (report_id, g.user['id'], customer, hours, time.time()))
        except Exception:
            # Never expose an upstream exception, URL, credentials, snapshot or traceback to the browser/log.
            path.unlink(missing_ok=True)
            app.logger.warning('Geração de relatório falhou; nenhuma credencial foi registrada.')
            return dashboard_page('Não foi possível gerar o relatório. Verifique conexão, certificado e credenciais do indexador.', 502)
        finally:
            password = None
            PDF_LOCK.release()
        return redirect(url_for('dashboard'), code=303)

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
        return send_file(path, as_attachment=True, download_name=f'Relatorio_de_Seguranca_{report_id[:8]}.pdf', mimetype='application/pdf')

    @app.get('/template')
    @logged_in
    def template_download():
        import io
        import tempfile
        if not PDF_LOCK.acquire(blocking=False):
            return dashboard_page('Há uma geração em andamento. Tente novamente.', 409)
        try:
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / 'modelo.pdf'
                render_pdf_template(path)
                payload = io.BytesIO(path.read_bytes())
            return send_file(payload, as_attachment=True, download_name='Modelo_de_Relatorio_de_Seguranca.pdf', mimetype='application/pdf')
        finally:
            PDF_LOCK.release()

    @app.cli.command('user-set')
    @click.argument('username')
    @click.option('--customer', multiple=True, help='Cliente autorizado; repita para mais clientes.')
    @click.option('--all-customers', is_flag=True, help='Autoriza explicitamente todos os clientes.')
    def user_set(username, customer, all_customers):
        """Create/reset an account; revoke its existing sessions."""
        username = username.strip().casefold()
        if not re.fullmatch(r'[a-z0-9_.@-]{3,128}', username):
            raise click.ClickException('Usuário: 3 a 128 caracteres, letras, números, _, ., @ ou -.')
        if bool(customer) == bool(all_customers):
            raise click.ClickException('Informe --customer ou --all-customers.')
        customers = ['*'] if all_customers else [validate_customer(c) for c in customer]
        if not all_customers and '*' in customers:
            raise click.ClickException('Use --all-customers para autorizar todos os clientes.')
        password = click.prompt('Senha (mínimo 15 caracteres)', hide_input=True, confirmation_prompt=True)
        if not 15 <= len(password) <= 128:
            raise click.ClickException('A senha deve ter entre 15 e 128 caracteres.')
        with database() as db:
            db.execute('INSERT INTO users(username,password_hash,customers) VALUES (?,?,?) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash,customers=excluded.customers,active=1',
                       (username, HASHER.hash(password), json.dumps(customers)))
            user_id = db.execute('SELECT id FROM users WHERE username=?', (username,)).fetchone()[0]
            db.execute('DELETE FROM sessions WHERE user_id=?', (user_id,))
        click.echo('Conta salva; sessões anteriores revogadas.')

    @app.cli.command('user-disable')
    @click.argument('username')
    def user_disable(username):
        with database() as db:
            row = db.execute('SELECT id FROM users WHERE username=?', (username.strip().casefold(),)).fetchone()
            if not row:
                raise click.ClickException('Conta não encontrada.')
            db.execute('UPDATE users SET active=0 WHERE id=?', (row['id'],))
            db.execute('DELETE FROM sessions WHERE user_id=?', (row['id'],))
        click.echo('Conta desativada e sessões revogadas.')

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
