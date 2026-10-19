# Portal web em Docker

A versão web reutiliza o gerador de PDFs e o papel timbrado do aplicativo desktop. Permite escolher o cliente, 24h/7d/30d, IP, porta e credenciais do indexador. Mantém gráficos, EPS médio de alertas e severidades por categoria. Os dados consultados e as credenciais ficam somente na memória durante a geração. O PDF e seus metadados ficam em um volume privado.

## Implantar

Requer Docker Engine com Compose v2, um domínio com DNS apontando para o servidor, portas TCP 80/443 disponíveis e acesso de rede ao indexador. Use um servidor administrado e restrinja o acesso à rede de operação quando possível.

```bash
cp deploy/env.example .env
# Edite .env: REPORT_DOMAIN e INDEXER_ENDPOINTS
chmod 600 .env
docker compose build
docker compose run --rm app flask --app web.app:create_app user-set operador --customer HDBR --customer ARMAZEM_PB
docker compose up -d
```

A senha é solicitada interativamente, com confirmação, e deve conter entre 15 e 128 caracteres. Não há conta nem senha padrão. Não passe senhas em argumentos de linha de comando ou no `.env`.

Acesse `https://<REPORT_DOMAIN>`. Caddy emite e renova o certificado HTTPS automaticamente quando DNS e acesso às portas estão corretos. Para ambiente interno sem domínio público, configure um certificado corporativo no Caddy ou `tls internal` e distribua a CA aos navegadores; não ignore avisos de certificado. O domínio também precisa coincidir com `PUBLIC_ORIGIN`.

`INDEXER_ENDPOINTS` contém a lista de URLs permitidas, por exemplo `https://192.0.2.10:9200`; aceita múltiplas separadas por vírgula. Use o IP real e a porta da sua instalação. A interface só consulta os destinos dessa lista, sem resolver nomes externos e sem seguir redirecionamentos. A porta da aplicação não é publicada: o único acesso externo passa pelo proxy HTTPS.

### Portainer — Docker Standalone

Na área **Stacks → Add stack**, selecione **Repository** e configure:

- **Repository URL:** `https://github.com/mcdalbu/wazuh-security-reports`.
- Habilite a autenticação do repositório privado usando uma credencial GitHub com acesso de leitura a esse repositório. Não inclua o token na URL.
- **Repository reference:** `refs/heads/main`.
- **Compose path:** `compose.yaml`.
- Em **Environment variables**, preencha `REPORT_DOMAIN` (somente o domínio, sem `https://`), `INDEXER_ENDPOINTS` (URL HTTPS com o IP e a porta autorizados) e, opcionalmente, `RETENTION_HOURS` (padrão `24`).
- Implante a stack. Os Dockerfiles da aplicação e do proxy estão no repositório; a construção requer acesso às imagens oficiais e aos repositórios de pacotes.

O arquivo usa `deploy.resources.limits` para memória, CPU e processos, evitando os campos `mem_limit`, `cpus` e `pids_limit` no nível do serviço que alguns validadores do Portainer recusam. Use Docker Compose v2 atualizado no ambiente Standalone. O `depends_on` usa o formato de lista para compatibilidade com validadores antigos. Esse formato determina a ordem de início, sem esperar o healthcheck: o proxy pode responder temporariamente com erro 502 enquanto a aplicação inicia; tente novamente após alguns segundos.

Se a stack já existir, atualize a referência Git e use **Pull and redeploy** para carregar o Compose corrigido. Preserve os volumes existentes.

Depois da implantação, abra **Containers → contêiner do serviço app → Console**, conecte com `/bin/sh` e execute:

```sh
flask --app web.app:create_app user-set operador --customer HDBR --customer ARMAZEM_PB
```

A senha será solicitada no console, sem eco. Acesse então `https://<REPORT_DOMAIN>`.

O editor web da stack recebe somente o YAML; ele não fornece o código usado por `build: .`. Para usar **Web editor**, primeiro construa as duas imagens no mesmo Docker Engine, ou publique-as em um registry privado, e substitua cada `build` por seu `image` correspondente. Em ambientes via Portainer Agent que não suportem build, use também imagens previamente construídas. Não publique as imagens em registry público: elas contêm o papel timbrado confidencial.

Se usar a CA privada descrita abaixo, o arquivo PEM deve existir no host do Docker e ser montado com caminho absoluto; o arquivo local da máquina com o navegador não fica disponível no servidor. Acrescente a variável `SSL_CERT_FILE` e o volume ao Compose usado pela stack.

### CA privada do indexador

O certificado do indexador deve incluir seu IP em Subject Alternative Name e encadear em uma CA confiável. Para uma CA privada, crie `secrets/indexer-ca.pem` contendo a cadeia PEM confiável (apenas certificados públicos, nunca a chave privada), e um arquivo `compose.ca.yaml`:

```yaml
services:
  app:
    environment:
      SSL_CERT_FILE: /run/certs/indexer-ca.pem
    volumes:
      - ./secrets/indexer-ca.pem:/run/certs/indexer-ca.pem:ro
```

```bash
docker compose -f compose.yaml -f compose.ca.yaml up -d --build
```

Mantenha esse override em uso nas operações seguintes. Não há opção web para desligar a validação TLS. Se houver proxy HTTP corporativo nas variáveis de ambiente do container, administre essa configuração como parte da infraestrutura de confiança.

## Contas e permissões

```bash
# Criar ou redefinir senha e clientes permitidos (revoga as sessões antigas)
docker compose exec app flask --app web.app:create_app user-set operador --customer HDBR
# Acesso a todos os clientes somente quando autorizado explicitamente
docker compose exec app flask --app web.app:create_app user-set administrador --all-customers
# Desativar uma conta imediatamente
docker compose exec app flask --app web.app:create_app user-disable operador
```

As contas com `--all-customers` continuam vendo apenas os PDFs que elas próprias geraram. Os demais usuários precisam ter cada valor exato de cliente autorizado. Não existe cadastro público ou recuperação de senha por e-mail. A recuperação é feita pelo administrador pelo comando `user-set`. As credenciais do portal são independentes das credenciais do indexador. Use uma conta de indexador com privilégio somente de leitura nos índices de alertas e, quando aplicável, restrições de documentos por cliente.

## Proteções e operação

- Senhas com Argon2id (64 MiB, 3 iterações); nunca armazenadas em texto puro.
- Token aleatório de sessão com 256 bits; apenas seu hash é persistido. Renovação ao entrar, revogação ao sair ou redefinir/desativar a conta.
- Cookie `__Host-`, Secure, HttpOnly e SameSite=Lax; limite de inatividade de 30 minutos e duração máxima de 8 horas.
- Token CSRF e verificação de origem em todos os POSTs, incluindo login e logout.
- Cinco tentativas por conta e vinte por IP em 15 minutos; respostas de login genéricas. A limitação por IP assume um único proxy Caddy com sobrescrita dos cabeçalhos recebidos.
- Autorização por cliente e propriedade dos documentos em cada download; nomes aleatórios, sem acesso público ao volume.
- Política de conteúdo sem scripts externos, sem cache, proteção contra framing e HSTS.
- Contêineres executam com UID 10001, raiz somente leitura, sem capabilities e sem escalada de privilégios; limites de memória, processos e corpo da requisição.
- O contexto de build usa uma lista de arquivos permitidos: relatórios de clientes, histórico Git, pacotes, bancos e segredos não entram na imagem. A imagem contém o papel timbrado confidencial; mantenha repositórios e registries privados.

Os relatórios expiram para download após `RETENTION_HOURS` (padrão 24). A limpeza física ocorre ao abrir o portal, iniciar um login ou executar `prune`; configure uma execução periódica no host caso precise removê-los mesmo sem uso da aplicação:

```bash
docker compose exec -T app flask --app web.app:create_app prune
```

Faça backup protegido do volume `reports_data` (contas, sessões e PDFs) e dos volumes Caddy (certificados/chaves). Criptografia de disco e proteção dos backups são responsabilidades da implantação. Não remova volumes durante atualizações. `docker compose down -v` apaga os dados.

Uma geração ocorre por vez para evitar concorrência na biblioteca de PDF. Uma segunda solicitação recebe uma mensagem para tentar novamente. Cada conta pode solicitar até dez gerações em 15 minutos. O serviço usa um único worker Gunicorn com quatro threads: não aumente workers nem réplicas sem substituir o controle de concorrência e o armazenamento locais. A geração é síncrona, pode demorar até alguns minutos em 30 dias e não persiste credenciais para retomada em caso de reinício.

O portal usa autenticação por senha; MFA/SSO não estão implementados. Para exposição pública com política corporativa de MFA, coloque um provedor de identidade com MFA na frente do Caddy ou integre OIDC antes de liberar o acesso.

As medidas seguem orientações de [armazenamento de senhas](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [sessões](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html) e [segurança do Flask](https://flask.palletsprojects.com/en/stable/web-security/). Não substituem uma revisão da infraestrutura.

## Desenvolvimento e verificações

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-web.txt
.venv/bin/python -m unittest discover -s tests -v
mkdir -p data
PUBLIC_ORIGIN=http://127.0.0.1:8000 ALLOW_LOCAL_HTTP=1 REPORT_DATA_DIR=./data \
  INDEXER_ENDPOINTS=https://192.0.2.10:9200 \
  .venv/bin/flask --app web.app:create_app run --host 127.0.0.1 --port 8000
```

HTTP é aceito somente no modo explícito de desenvolvimento com origem loopback. Nunca use o servidor Flask de desenvolvimento em produção ou habilite debug com dados reais. Para criar contas localmente, exporte as mesmas variáveis e use `.venv/bin/flask --app web.app:create_app user-set ...`.
