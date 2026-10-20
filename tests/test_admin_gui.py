"""Admin GUI authorization, role changes, forced passwords and DB migration."""
import json
import re
import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from web.app import HASHER, create_app

ORIGIN = 'https://reports.example.test'
TEMPORARY = 'temporary-test-password-2026'
PERSONAL = 'personal-test-password-2026'


class AdminGuiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password_hash = HASHER.hash(TEMPORARY)

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.app = create_app({'TESTING': True, 'DATA_DIR': folder.name, 'INDEXER_IP': '192.0.2.10', 'INDEXER_USER': 'reader', 'INDEXER_PASSWORD': 'test-only-secret', 'PUBLIC_ORIGIN': ORIGIN})
        self.db = self.app.extensions['report_database']
        self.client = self.app.test_client()
        with self.db() as db:
            db.executemany('INSERT INTO users(username,password_hash,customers,is_admin) VALUES (?,?,?,?)',
                           [('admin', self.password_hash, '["*"]', 1),
                            ('alice', self.password_hash, '["HDBR"]', 0)])

    def get(self, path):
        return self.client.get(path, base_url=ORIGIN)

    def csrf(self, path):
        return re.search(rb'name="csrf" value="([^"]+)"', self.get(path).data)[1].decode()

    def post(self, path, data, origin=ORIGIN):
        return self.client.post(path, data=data, base_url=ORIGIN, headers={'Origin': origin})

    def login(self, username='admin', password=TEMPORARY):
        return self.post('/login', {'username': username, 'password': password, 'csrf': self.csrf('/login')})

    def form(self, username='alice', **overrides):
        return {'username': username, 'role': 'regular', 'active': '1', 'scope': 'restricted',
                'customers': 'HDBR', 'password': '', 'confirmation': '', **overrides}

    def account(self, username):
        with self.db() as db:
            return dict(db.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone())

    def edit(self, user_id, data):
        path = f'/admin/users/{user_id}'
        return self.post(path, {'csrf': self.csrf(path), **data})

    def test_admin_pages_forbidden_to_regular_and_anonymous(self):
        self.assertEqual(self.get('/admin/users').status_code, 302)
        self.login('alice')
        for path in ('/admin/users', '/admin/users/new', '/admin/users/1'):
            self.assertEqual(self.get(path).status_code, 403)
        token = self.csrf('/')
        self.assertEqual(self.post('/admin/users/2', {'csrf': token, **self.form(role='admin')}).status_code, 403)
        self.assertEqual(self.account('alice')['is_admin'], 0)
        self.assertNotIn(b'href="/admin/users"', self.get('/').data)

    def test_create_all_roles_require_password_change(self):
        self.login()
        for role in ('regular', 'admin'):
            path = '/admin/users/new'
            data = self.form('new'+role, role=role, password=TEMPORARY, confirmation=TEMPORARY)
            response = self.post(path, {'csrf': self.csrf(path), **data})
            self.assertEqual(response.status_code, 303)
            account = self.account('new'+role)
            self.assertEqual(account['must_change_password'], 1)
            self.assertTrue(HASHER.verify(account['password_hash'], TEMPORARY))
            self.assertEqual(json.loads(account['customers']), ['*'] if role == 'admin' else ['HDBR'])

    def test_permission_edit_and_promotion_revoke_sessions(self):
        self.login()
        with self.db() as db:
            db.execute('INSERT INTO sessions VALUES (?,?,?,?,?)', ('other-session', 2, 'csrf', time.time(), time.time()))
        response = self.edit(2, self.form(customers='SOC, ARMAZEM_PB\nHDBR'))
        self.assertEqual(response.status_code, 303)
        account = self.account('alice')
        self.assertEqual(json.loads(account['customers']), ['SOC', 'ARMAZEM_PB', 'HDBR'])
        self.assertEqual(account['password_hash'], self.password_hash)
        with self.db() as db:
            self.assertIsNone(db.execute('SELECT * FROM sessions WHERE user_id=2').fetchone())
        self.assertEqual(self.edit(2, self.form(role='admin')).status_code, 303)
        account = self.account('alice')
        self.assertEqual((account['is_admin'], account['must_change_password']), (1, 1))
        self.assertEqual(json.loads(account['customers']), ['*'])

    def test_cannot_remove_last_active_admin_gui_or_cli(self):
        self.login()
        for data in [self.form('admin', role='admin', active='0'), self.form('admin')]:
            response = self.edit(1, data)
            self.assertEqual(response.status_code, 400)
            self.assertIn('pelo menos um administrador', response.text)
            self.assertEqual(self.account('admin')['active'], 1)
            self.assertEqual(self.account('admin')['is_admin'], 1)
        runner = self.app.test_cli_runner()
        for args in [('user-disable', 'admin'), ('user-role', 'admin', '--regular', '--customer', 'HDBR')]:
            self.assertNotEqual(runner.invoke(args=args).exit_code, 0)

    def test_admin_can_demote_disable_and_reset_another_admin(self):
        self.login()
        with self.db() as db:
            db.execute('UPDATE users SET is_admin=1,customers=? WHERE id=2', ('["*"]',))
        self.assertEqual(self.edit(2, self.form(active='0', password=PERSONAL, confirmation=PERSONAL)).status_code, 303)
        account = self.account('alice')
        self.assertEqual((account['active'], account['is_admin'], account['must_change_password']), (0, 0, 1))
        self.assertEqual(json.loads(account['customers']), ['HDBR'])
        self.assertTrue(HASHER.verify(account['password_hash'], PERSONAL))

    def test_forced_password_blocks_every_protected_route_until_changed(self):
        with self.db() as db:
            db.execute('UPDATE users SET must_change_password=1 WHERE id=1')
        self.assertTrue(self.login().location.endswith('/account/password'))
        for path in ('/', '/admin/users', '/admin/users/new', '/admin/users/2', '/template', '/reports/'+'a'*32):
            response = self.get(path)
            self.assertEqual(response.status_code, 303, path)
            self.assertTrue(response.location.endswith('/account/password'))
        path = '/account/password'
        token = self.csrf(path)
        self.assertEqual(self.post('/admin/users/2', {'csrf': token, **self.form(role='admin')}).status_code, 303)
        self.assertEqual(self.account('alice')['is_admin'], 0)
        for current, new, confirmation in [('wrong', PERSONAL, PERSONAL), (TEMPORARY, TEMPORARY, TEMPORARY), (TEMPORARY, PERSONAL, 'mismatch')]:
            response = self.post(path, {'csrf': token, 'current_password': current, 'password': new, 'confirmation': confirmation})
            self.assertEqual(response.status_code, 400)
            self.assertEqual(self.account('admin')['must_change_password'], 1)
        response = self.post(path, {'csrf': token, 'current_password': TEMPORARY, 'password': PERSONAL, 'confirmation': PERSONAL})
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.account('admin')['must_change_password'], 0)
        with self.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM sessions WHERE user_id=1').fetchone()[0], 0)
        self.assertEqual(self.get('/admin/users').status_code, 302)
        self.login(password=PERSONAL)
        self.assertEqual(self.get('/admin/users').status_code, 200)

    def test_admin_csrf_duplicate_and_invalid_input_are_rejected(self):
        self.login()
        path = '/admin/users/new'
        token = self.csrf(path)
        data = self.form('newuser', password=TEMPORARY, confirmation=TEMPORARY)
        for origin, csrf in [('https://evil.test', token), (ORIGIN, 'invalid')]:
            self.assertEqual(self.post(path, {'csrf': csrf, **data}, origin=origin).status_code, 403)
        for overrides in ({'username': 'alice'}, {'role': 'invalid'}, {'customers': ''}, {'confirmation': 'wrong'}):
            self.assertEqual(self.post(path, {'csrf': token, **data, **overrides}).status_code, 400)
        with self.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM users').fetchone()[0], 2)

    def test_bootstrap_admin_preserves_password_and_forces_change(self):
        result = self.app.test_cli_runner().invoke(args=['user-role', 'alice', '--admin'])
        self.assertEqual(result.exit_code, 0, result.output)
        account = self.account('alice')
        self.assertEqual((account['is_admin'], account['must_change_password']), (1, 1))
        self.assertEqual(account['password_hash'], self.password_hash)
        self.assertEqual(json.loads(account['customers']), ['*'])

    def test_legacy_database_migration_preserves_accounts(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'reports.sqlite3'
            with sqlite3.connect(path) as db:
                db.execute('CREATE TABLE users (id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,customers TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1)')
                db.execute('INSERT INTO users VALUES (1,?,?,?,1)', ('legacy', self.password_hash, '["HDBR"]'))
            for _ in range(2):
                app = create_app({'TESTING': True, 'DATA_DIR': folder, 'INDEXER_IP': '192.0.2.10', 'INDEXER_USER': 'reader', 'INDEXER_PASSWORD': 'test-only-secret', 'PUBLIC_ORIGIN': ORIGIN})
                with app.extensions['report_database']() as db:
                    row = db.execute('SELECT * FROM users').fetchone()
                    self.assertEqual((row['username'], row['password_hash'], row['is_admin'], row['must_change_password']), ('legacy', self.password_hash, 0, 0))


if __name__ == '__main__':
    unittest.main()
