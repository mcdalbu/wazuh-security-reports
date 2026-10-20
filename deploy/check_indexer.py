#!/usr/bin/env python3
"""Run inside app via stdin. Never print credentials, events or raw exceptions."""
import os
from pathlib import Path
import socket
import ssl
import sys
import tempfile
import urllib.error


def explain(error):
    seen = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        if isinstance(error, ssl.SSLCertVerificationError):
            reason = getattr(error, 'verify_message', '').lower()
            code = getattr(error, 'verify_code', None)
            code_label = f' (código {code})' if isinstance(code, int) else ''
            if 'ip address mismatch' in reason or 'hostname mismatch' in reason:
                return f'TLS{code_label}: o certificado não é válido para o IP configurado. Reemita o certificado com esse IP no SAN.'
            if 'expired' in reason or 'not yet valid' in reason:
                return f'TLS{code_label}: certificado fora da validade. Confira a validade do certificado e o relógio dos servidores.'
            if 'unable to get' in reason or 'unable to verify' in reason:
                return f'TLS{code_label}: cadeia incompleta ou CA incompatível. Confira a CA montada e os certificados intermediários do indexador.'
            if 'self-signed' in reason:
                return f'TLS{code_label}: a cadeia apresentada pelo indexador contém um certificado autoassinado que não é confiável nesta configuração.'
            if 'signature failure' in reason:
                return f'TLS{code_label}: assinatura do certificado inválida para a cadeia/CA utilizada.'
            return (f'TLS{code_label}: certificado não confiável ou incompatível com o IP. '
                    'Configure a CA do indexador em SSL_CERT_FILE e confirme o IP no SAN do certificado.')
        if isinstance(error, ssl.SSLError):
            return 'TLS: negociação falhou. Confira se a porta oferece HTTPS e a configuração TLS do indexador.'
        if isinstance(error, urllib.error.HTTPError):
            messages = {401: 'HTTP 401: usuário ou senha do indexador recusados.',
                        403: 'HTTP 403: a conta não tem permissão para consultar os índices de alertas.',
                        404: 'HTTP 404: rota ou índices de alertas não encontrados.'}
            if 300 <= error.code < 400:
                return 'HTTP: redirecionamento recusado para proteger as credenciais.'
            return messages.get(error.code, 'HTTP: consulta recusada pelo indexador.')
        if isinstance(error, (TimeoutError, socket.timeout)):
            return 'Rede/consulta: tempo limite excedido.'
        if isinstance(error, ConnectionRefusedError):
            return 'Rede: conexão recusada. Confira o serviço, IP, porta e firewall.'
        if isinstance(error, FileNotFoundError):
            return 'TLS: arquivo de CA não encontrado. Confira SSL_CERT_FILE e a montagem do certificado no contêiner.'
        if isinstance(error, OSError) and error.errno in (101, 113):
            return 'Rede: destino inacessível. Confira rota, VPN e firewall do host Docker.'
        error = (error.reason if isinstance(error, urllib.error.URLError) and isinstance(error.reason, BaseException)
                 else error.__cause__ or error.__context__)
    return 'Falha não classificada. Nenhuma credencial ou evento foi exibido.'


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) not in (1, 2):
        print('Uso: python - CLIENTE [24|168|720] < deploy/check_indexer.py')
        return 2
    try:
        from wazuh_report import fetch_summary, indexer_url, render_report, validate_customer
        customer = validate_customer(args[0])
        hours = int(args[1]) if len(args) == 2 else 24
        if hours not in (24, 168, 720):
            raise ValueError
        ip = os.environ.get('INDEXER_IP', '')
        port = int(os.environ.get('INDEXER_PORT', '9200'))
        endpoint = indexer_url(ip, port)
        username = os.environ.get('INDEXER_USER', '').strip()
        password = os.environ.get('INDEXER_PASSWORD', '')
        if not username or ':' in username or not password:
            raise ValueError
    except (ValueError, TypeError):
        print('Configuração incompleta/inválida: confira cliente, período e INDEXER_IP/PORT/USER/PASSWORD no Compose.')
        return 2
    except Exception:
        print('Falha ao carregar o gerador PDF. Confira a imagem e as dependências do backend.')
        return 1
    print('Configuração no contêiner: OK (valores e senha ocultos).', flush=True)
    stage = 'TCP'
    try:
        with socket.create_connection((ip, port), timeout=10) as connection:
            print('Conexão TCP: OK.', flush=True)
            stage = 'TLS'
            ca_file = os.environ.get('SSL_CERT_FILE', '')
            print(f'CA personalizada: {"configurada" if ca_file else "SSL_CERT_FILE não definido"}.', flush=True)
            if ca_file:
                if not Path(ca_file).is_file() or not os.access(ca_file, os.R_OK):
                    print('TLS: arquivo de CA configurado não está montado ou não pode ser lido pelo contêiner.')
                    return 1
                print('Arquivo de CA legível no contêiner: OK.', flush=True)
            context = ssl.create_default_context()
            with context.wrap_socket(connection, server_hostname=ip):
                print('Certificado e conexão TLS: OK.', flush=True)
        stage = 'CONSULTA'
        snapshot = fetch_summary(customer, endpoint, username, password, hours=hours,
                                 verify_tls=True, reject_redirects=True)
        print('Autenticação e consulta exata do cliente: OK (eventos ocultos).', flush=True)
        stage = 'PDF'
        with tempfile.TemporaryDirectory(prefix='reports-diagnostic-') as folder:
            render_report(snapshot, Path(folder)/'check.pdf')
        print('Geração PDF: OK. O documento temporário foi removido.', flush=True)
        return 0
    except Exception as error:
        if stage == 'PDF':
            print('PDF: falha na renderização. Confira papel timbrado, fontes, bibliotecas e espaço temporário.')
        else:
            print(f'Falha na etapa {stage}: {explain(error)}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
