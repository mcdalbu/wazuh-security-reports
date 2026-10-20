"""Diagnostics must identify stages without exposing secrets or upstream bodies."""
from contextlib import redirect_stdout
import importlib.util
import io
from pathlib import Path
import ssl
import unittest
import urllib.error
from unittest.mock import MagicMock, patch

spec = importlib.util.spec_from_file_location('indexer_diagnostic', Path(__file__).resolve().parents[1]/'deploy/check_indexer.py')
diagnostic = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostic)


class DiagnosticTests(unittest.TestCase):
    def test_certificate_mismatch_and_expiry_are_distinct(self):
        for reason, expected in [('IP address mismatch: secret-host', 'SAN'),
                                 ('certificate has expired', 'validade')]:
            error = ssl.SSLCertVerificationError('raw-secret')
            error.verify_message = reason
            output = diagnostic.explain(error)
            self.assertIn(expected, output)
            self.assertNotIn('secret', output)

    def test_errors_do_not_echo_raw_exception_or_secret(self):
        secret = 'must-not-appear-in-diagnostic'
        for error, expected in [
            (urllib.error.HTTPError('https://'+secret, 401, secret, {}, None), 'HTTP 401'),
            (urllib.error.HTTPError('https://'+secret, 403, secret, {}, None), 'HTTP 403'),
            (urllib.error.HTTPError('https://'+secret, 302, secret, {}, None), 'redirecionamento'),
            (ssl.SSLCertVerificationError(secret), 'TLS'),
            (ConnectionRefusedError(secret), 'recusada'),
            (TimeoutError(secret), 'tempo limite'),
            (RuntimeError(secret), 'não classificada'),
        ]:
            wrapped = RuntimeError(secret)
            wrapped.__cause__ = urllib.error.URLError(error)
            output = diagnostic.explain(wrapped)
            self.assertIn(expected, output)
            self.assertNotIn(secret, output)

    def invoke(self, fetch_error=None, render_error=None):
        output = io.StringIO()
        with patch.dict('os.environ', {'INDEXER_IP': '192.0.2.10', 'INDEXER_PORT': '9200',
                                       'INDEXER_USER': 'test-reader', 'INDEXER_PASSWORD': 'secret-never-printed'}), \
                patch.object(diagnostic.socket, 'create_connection', return_value=MagicMock()), \
                patch.object(diagnostic.ssl, 'create_default_context', return_value=MagicMock()), \
                patch('wazuh_report.fetch_summary', return_value={}, side_effect=fetch_error) as fetch, \
                patch('wazuh_report.render_report', side_effect=render_error), redirect_stdout(output):
            status = diagnostic.main(['HDBR', '24'])
        self.assertNotIn('secret-never-printed', output.getvalue())
        return status, output.getvalue(), fetch

    def test_full_path_uses_verified_tls_and_exact_customer(self):
        status, output, fetch = self.invoke()
        self.assertEqual(status, 0, output)
        self.assertIn('Geração PDF: OK', output)
        fetch.assert_called_once_with('HDBR', 'https://192.0.2.10:9200', 'test-reader', 'secret-never-printed',
                                      hours=24, verify_tls=True, reject_redirects=True)

    def test_query_and_render_failures_are_distinct_and_safe(self):
        error = RuntimeError('secret-never-printed')
        error.__cause__ = urllib.error.HTTPError('https://example.test', 401, 'secret-never-printed', {}, None)
        status, output, _ = self.invoke(fetch_error=error)
        self.assertEqual(status, 1)
        self.assertIn('CONSULTA: HTTP 401', output)
        status, output, _ = self.invoke(render_error=RuntimeError('secret-never-printed'))
        self.assertEqual(status, 1)
        self.assertIn('PDF: falha', output)


if __name__ == '__main__':
    unittest.main()
