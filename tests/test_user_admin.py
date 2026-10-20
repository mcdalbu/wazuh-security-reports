"""Account administration must preserve unrelated state and revoke sessions."""
import json
import tempfile
import unittest

from web.app import HASHER, create_app


class UserAdminTests(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.app = create_app({'TESTING': True, 'DATA_DIR': folder.name,
                               'INDEXER_IP': '192.0.2.10', 'INDEXER_USER': 'reader', 'INDEXER_PASSWORD': 'test-only-secret', 'PUBLIC_ORIGIN': 'https://reports.example.test'})
        self.runner = self.app.test_cli_runner()
        self.db = self.app.extensions['report_database']
        with self.db() as db:
            db.execute('INSERT INTO users(username,password_hash,customers,active) VALUES (?,?,?,0)',
                       ('alice', 'unchanged-hash', json.dumps(['HDBR'])))
            db.execute("INSERT INTO sessions VALUES ('token',1,'csrf',0,0)")

    def account(self):
        with self.db() as db:
            return dict(db.execute('SELECT * FROM users WHERE username="alice"').fetchone())

    def assert_revoked(self):
        with self.db() as db:
            self.assertEqual(db.execute('SELECT count(*) FROM sessions').fetchone()[0], 0)

    def test_permissions_preserve_password_and_disabled_status(self):
        result = self.runner.invoke(args=['user-permissions', 'ALICE', '--customer', 'SOC', '--customer', 'ARMAZEM_PB'])
        self.assertEqual(result.exit_code, 0, result.output)
        account = self.account()
        self.assertEqual(json.loads(account['customers']), ['SOC', 'ARMAZEM_PB'])
        self.assertEqual(account['password_hash'], 'unchanged-hash')
        self.assertEqual(account['active'], 0)
        self.assert_revoked()

    def test_all_permissions_and_invalid_choices(self):
        for args in [[], ['--customer', '*'], ['--customer', ''], ['--customer', 'HDBR', '--all-customers']]:
            before = self.account()
            self.assertNotEqual(self.runner.invoke(args=['user-permissions', 'alice', *args]).exit_code, 0)
            self.assertEqual(self.account(), before)
        result = self.runner.invoke(args=['user-permissions', 'alice', '--all-customers'])
        self.assertEqual(result.exit_code, 0, result.output)
        self.assertEqual(json.loads(self.account()['customers']), ['*'])

    def test_add_cannot_overwrite_existing_account(self):
        before = self.account()
        result = self.runner.invoke(args=['user-set', 'alice', '--create-only', '--all-customers'])
        self.assertNotEqual(result.exit_code, 0)
        self.assertEqual(self.account(), before)
        password = 'new-account-test-passphrase'
        result = self.runner.invoke(args=['user-set', 'newuser', '--create-only', '--customer', 'HDBR'], input=f'{password}\n{password}\n')
        self.assertEqual(result.exit_code, 0, result.output)
        with self.db() as db:
            account = db.execute('SELECT * FROM users WHERE username="newuser"').fetchone()
            self.assertTrue(HASHER.verify(account['password_hash'], password))
            self.assertEqual(account['active'], 1)

    def test_password_preserves_permissions_and_disabled_status(self):
        password = 'changed-password-test-passphrase'
        result = self.runner.invoke(args=['user-password', 'alice'], input=f'{password}\n{password}\n')
        self.assertEqual(result.exit_code, 0, result.output)
        account = self.account()
        self.assertTrue(HASHER.verify(account['password_hash'], password))
        self.assertEqual(json.loads(account['customers']), ['HDBR'])
        self.assertEqual(account['active'], 0)
        self.assert_revoked()

    def test_enable_disable_list_and_unknown_users(self):
        for command in ('user-enable', 'user-disable'):
            result = self.runner.invoke(args=[command, 'alice'])
            self.assertEqual(result.exit_code, 0, result.output)
            self.assertEqual(self.account()['active'], int(command == 'user-enable'))
            self.assert_revoked()
        result = self.runner.invoke(args=['user-list'])
        self.assertEqual(json.loads(result.output), [{'username': 'alice', 'active': False, 'role': 'regular', 'must_change_password': False, 'customers': ['HDBR']}])
        for args in [['user-permissions', 'missing', '--all-customers'], ['user-password', 'missing'], ['user-enable', 'missing']]:
            self.assertNotEqual(self.runner.invoke(args=args).exit_code, 0)


if __name__ == '__main__':
    unittest.main()
