"""Authentication, customer isolation, CSRF and confidential artifact access."""
import json
import re
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from web.app import HASHER, create_app

ORIGIN = 'https://reports.example.test'
PASSWORD = 'passphrase-for-test-only-2026'


class WebTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password_hash = HASHER.hash(PASSWORD)

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.app = create_app({'TESTING': True, 'DATA_DIR': self.folder.name,
                               'PUBLIC_ORIGIN': ORIGIN, 'INDEXER_ENDPOINTS': 'https://192.0.2.10:9200'})
        self.client = self.app.test_client()
        self.db = self.app.extensions['report_database']
        with self.db() as db:
            db.executemany('INSERT INTO users(username,password_hash,customers) VALUES (?,?,?)',
                           [('alice', self.password_hash, json.dumps(['HDBR'])),
                            ('bob', self.password_hash, json.dumps(['ARMAZEM_PB']))])

    def get(self, path='/', client=None, **kwargs):
        return (client or self.client).get(path, base_url=ORIGIN, **kwargs)

    def token(self, client=None):
        page = self.get('/login', client)
        return re.search(rb'name="csrf" value="([^"]+)"', page.data)[1].decode()

    def post(self, path, data, client=None, origin=ORIGIN):
        return (client or self.client).post(path, data=data, base_url=ORIGIN, headers={'Origin': origin})

    def login(self, username='alice', client=None):
        token = self.token(client)
        response = self.post('/login', {'csrf': token, 'username': username, 'password': PASSWORD}, client)
        self.assertEqual(response.status_code, 303)
        return response

    def csrf(self, client=None):
        page = self.get('/', client)
        return re.search(rb'name="csrf" value="([^"]+)"', page.data)[1].decode()

    def form(self):
        return {'csrf': self.csrf(), 'customer': 'HDBR', 'hours': '24', 'ip': '192.0.2.10', 'port': '9200',
                'indexer_user': 'reader', 'indexer_password': 'do-not-persist-this-secret'}

    def test_cookie_rotation_logout_headers_and_hashed_storage(self):
        self.token()
        old = self.client.get_cookie('__Host-reports', domain='reports.example.test').value
        response = self.login()
        new = self.client.get_cookie('__Host-reports', domain='reports.example.test').value
        self.assertNotEqual(old, new)
        cookie = response.headers['Set-Cookie']
        for flag in ('Secure', 'HttpOnly', 'SameSite=Lax', 'Path=/'):
            self.assertIn(flag, cookie)
        with self.db() as db:
            tokens = [r['token'] for r in db.execute('SELECT token FROM sessions')]
        self.assertNotIn(new, tokens)
        self.assertEqual(len(tokens), 1)
        page = self.get()
        self.assertIn('frame-ancestors', page.headers['Content-Security-Policy'])
        self.assertEqual(page.headers['Cache-Control'], 'no-store')
        self.assertEqual(self.post('/logout', {'csrf': self.csrf()}).status_code, 303)
        self.assertEqual(self.get().status_code, 302)
        self.client.set_cookie('__Host-reports', new, domain='reports.example.test')
        self.assertEqual(self.get().status_code, 302)

    def test_csrf_origin_host_and_no_anonymous_documents(self):
        self.assertEqual(self.get('/template').status_code, 302)
        self.assertEqual(self.get('/reports/'+'a'*32).status_code, 302)
        csrf = self.token()
        self.assertEqual(self.post('/login', {'username': 'alice', 'password': PASSWORD}).status_code, 403)
        self.assertEqual(self.post('/login', {'csrf': csrf}, origin='https://evil.example').status_code, 403)
        self.assertEqual(self.client.get('/login', base_url='https://evil.example').status_code, 400)
        self.assertEqual(self.client.get('/login', base_url='http://reports.example.test').status_code, 400)
        self.assertEqual(self.post('/login', {'csrf': 'á'}).status_code, 403)

    def test_persistent_throttling_and_generic_errors(self):
        csrf = self.token()
        for _ in range(5):
            response = self.post('/login', {'csrf': csrf, 'username': 'alice', 'password': 'invalid'})
            self.assertEqual(response.status_code, 401)
            self.assertIn('Usuário ou senha inválidos.'.encode(), response.data)
        self.assertEqual(self.post('/login', {'csrf': csrf, 'username': 'alice', 'password': PASSWORD}).status_code, 429)
        response = self.post('/login', {'csrf': csrf, 'username': 'nobody', 'password': 'invalid'})
        self.assertEqual(response.status_code, 401)
        self.assertIn('Usuário ou senha inválidos.'.encode(), response.data)
        self.assertEqual(self.post('/login', {'csrf': csrf, 'username': 'alice', 'password': PASSWORD}).status_code, 429)

    def test_customer_endpoint_period_tls_and_private_download(self):
        self.login()
        form = self.form()
        with patch('web.app.fetch_summary') as fetch, patch('web.app.render_report') as render:
            form['customer'] = 'ARMAZEM_PB'
            self.assertEqual(self.post('/reports', form).status_code, 403)
            form['customer'] = 'HDBR'
            form['ip'] = '169.254.169.254'
            self.assertEqual(self.post('/reports', form).status_code, 400)
            form['ip'] = '192.0.2.10'
            form['hours'] = '12'
            self.assertEqual(self.post('/reports', form).status_code, 400)
            fetch.assert_not_called()
            fetch.return_value = {'synthetic': True}
            render.side_effect = lambda snapshot, path: path.write_bytes(b'%PDF-1.4\nTEST')
            for hours in (24, 168, 720):
                form['hours'] = str(hours)
                response = self.post('/reports', form)
                self.assertEqual(response.status_code, 303)
                fetch.assert_called_with('HDBR', 'https://192.0.2.10:9200', 'reader',
                                         'do-not-persist-this-secret', hours=hours, verify_tls=True, reject_redirects=True)
        with self.db() as db:
            report_id = db.execute('SELECT id FROM reports LIMIT 1').fetchone()[0]
            dump = '\n'.join(db.iterdump())
        self.assertNotIn('do-not-persist-this-secret', dump)
        download = self.get('/reports/'+report_id)
        self.assertEqual(download.status_code, 200)
        download.close()
        other = self.app.test_client()
        self.login('bob', other)
        self.assertEqual(self.get('/reports/'+report_id, other).status_code, 404)
        self.assertNotIn(report_id.encode(), self.get('/', other).data)
        self.assertEqual(self.get('/reports/../../etc/passwd').status_code, 404)

    def test_expiry_retention_and_disabled_account(self):
        self.login()
        with self.db() as db:
            db.execute('UPDATE sessions SET touched=?', (time.time()-1801,))
        self.assertEqual(self.get().status_code, 302)
        self.login()
        with self.db() as db:
            db.execute('UPDATE sessions SET created=?', (time.time()-8*3600-1,))
        self.assertEqual(self.get().status_code, 302)
        self.login()
        with self.db() as db:
            db.execute('UPDATE users SET active=0 WHERE username="alice"')
        self.assertEqual(self.get().status_code, 302)
        report_id = 'a'*32
        path = Path(self.folder.name)/'reports'/f'{report_id}.pdf'
        path.write_bytes(b'old')
        with self.db() as db:
            db.execute('INSERT INTO reports VALUES (?,1,?,24,?)', (report_id, 'HDBR', time.time()-86401))
        result = self.app.test_cli_runner().invoke(args=['prune'])
        self.assertEqual(result.exit_code, 0)
        self.assertFalse(path.exists())

    def test_cli_reset_and_disable_revoke_sessions(self):
        self.login()
        runner = self.app.test_cli_runner()
        result = runner.invoke(args=['user-set', 'alice', '--customer', 'HDBR'], input=f'{PASSWORD}\n{PASSWORD}\n')
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(self.get().status_code, 302)
        self.login()
        self.assertEqual(runner.invoke(args=['user-disable', 'alice']).exit_code, 0)
        self.assertEqual(self.get().status_code, 302)
        self.assertNotEqual(runner.invoke(args=['user-set', 'bob', '--customer', '*']).exit_code, 0)

    def test_safe_error_does_not_echo_upstream_credentials(self):
        self.login()
        with patch('web.app.fetch_summary', side_effect=RuntimeError('do-not-persist-this-secret')):
            response = self.post('/reports', self.form())
        self.assertEqual(response.status_code, 502)
        self.assertNotIn(b'do-not-persist-this-secret', response.data)
        self.assertEqual(list((Path(self.folder.name)/'reports').glob('*.pdf')), [])

    def test_real_report_and_template_download(self):
        import io
        from pypdf import PdfReader
        from test_report import sample_snapshot
        self.login()
        with patch('web.app.fetch_summary', return_value=sample_snapshot()):
            self.assertEqual(self.post('/reports', self.form()).status_code, 303)
        with self.db() as db:
            report_id = db.execute('SELECT id FROM reports').fetchone()[0]
        for route in ('/reports/'+report_id, '/template'):
            response = self.get(route)
            self.assertEqual(response.status_code, 200)
            self.assertIn('attachment', response.headers['Content-Disposition'])
            pdf = PdfReader(io.BytesIO(response.data))
            self.assertEqual(len(pdf.pages), 6)
            self.assertNotIn('wazuh', ''.join(page.extract_text() for page in pdf.pages).lower())
            response.close()

    def test_same_origin_referer_fallback(self):
        csrf = self.token()
        page = self.get('/login')
        self.assertEqual(page.headers['Referrer-Policy'], 'same-origin')
        result = self.client.post('/login', base_url=ORIGIN, headers={'Referer': ORIGIN+'/login'},
                                  data={'csrf': csrf, 'username': 'alice', 'password': PASSWORD})
        self.assertEqual(result.status_code, 303)

    def test_insecure_production_origin_rejected(self):
        with self.assertRaises(ValueError):
            create_app({'DATA_DIR': self.folder.name, 'PUBLIC_ORIGIN': 'http://public.example'})


if __name__ == '__main__':
    unittest.main()
