# Portal web — Docker Compose / Docker Standalone

A implantação usa **Docker Compose v2** em um único Docker Engine. O projeto Compose é chamado `reports`, com aplicação, proxy Caddy e volumes persistentes. HTTP é publicado em **8083** e redireciona para HTTPS em **8443**. O endereço da aplicação é configurado na implantação; nenhum IP é fixado no código, no YAML ou nas imagens.

## Executar a partir do código

Requisitos: Docker Engine com Compose v2, acesso à rede do indexador e portas 8083/8443 disponíveis no host da aplicação. O repositório e as imagens devem continuar privados porque incluem o papel timbrado confidencial.

Na pasta do repositório já clonado:

```bash
cp deploy/env.example .env
# Edite .env: REPORT_DOMAIN e INDEXER_ENDPOINTS
chmod 600 .env
docker compose -p reports config --quiet
docker compose -p reports build
docker compose -p reports run --rm app flask --app web.app:create_app user-set operador --customer HDBR --customer ARMAZEM_PB
docker compose -p reports up -d
docker compose -p reports ps
```

A conta é criada com senha interativa de 15 a 128 caracteres. Não há usuário ou senha padrão. As contas do portal são independentes das credenciais do indexador.

| Variável | Configuração |
| --- | --- |
| `REPORT_DOMAIN` | DNS ou IP pelo qual o navegador alcança o **host da aplicação**, sem protocolo nem porta. Não é necessariamente o IP do painel Portainer. |
| `INDEXER_ENDPOINTS` | URL HTTPS com IP literal e porta autorizados; múltiplas URLs separadas por vírgula. Exemplo: `https://192.0.2.10:9200`. |
| `RETENTION_HOURS` | Retenção dos PDFs, padrão `24`, entre 1 e 720 horas. |
| `APP_IMAGE` / `PROXY_IMAGE` | Opcionais; as imagens locais padrão são `localhost/wazuh-security-reports-app:0.4.3` e `localhost/wazuh-security-reports-proxy:0.4.3`. |

Acesse **`https://<REPORT_DOMAIN>:8443`**. `http://<REPORT_DOMAIN>:8083` redireciona para esse endereço, preservando caminho e parâmetros. O login é servido por HTTPS. A origem exata usada pela aplicação é `https://<REPORT_DOMAIN>:8443`, para validar o Host e a origem dos formulários.

Os arquivos usam `mem_limit`, `cpus`, `pids_limit`, `restart` e `depends_on.condition: service_healthy` do Docker Compose. O proxy inicia após o backend ficar saudável. A porta 8000 do backend não é publicada. A raiz dos contêineres permanece somente leitura; `/tmp` é um volume tmpfs gravável e o Gunicorn usa `/dev/shm` para o heartbeat. Ambos os serviços usam UID 10001, sem capabilities e com `no-new-privileges`.

## Portainer com Docker Standalone

Selecione um ambiente **Docker Standalone** no Portainer antes de criar/atualizar a stack. O tipo do ambiente define o mecanismo de implantação; trocar apenas o conteúdo de um YAML não muda um ambiente Swarm para Standalone. O arquivo atual deve ser executado pelo Docker Compose. Não é necessário desativar o Swarm de um host para executar contêineres independentes com o comando `docker compose`.

Use **`compose.portainer.yaml`**, que já possui `image:` e não exige build dentro do Portainer. `compose.portainer.ip.yaml` é mantido como alias de compatibilidade com a mesma configuração Standalone e portas 8083/8443.

### Disponibilizar as imagens

Se as imagens 0.4.3 já estiverem importadas no mesmo Docker Engine, reutilize-as. Esta conversão de implantação não exige novas imagens.

Para prepará-las em uma máquina com Docker:

```bash
./deploy/build_portainer_images.sh
```

O script constrói aplicação e proxy e gera `output/containers/wazuh-security-reports-0.4.3-<arquitetura>.tar.gz` e seu checksum. Não envia nada a um registry. Se a construção for feita no próprio host da aplicação, as imagens já estarão no Docker local. Caso contrário, importe o pacote em **Images → Import** no ambiente Standalone selecionado, ou use:

```bash
docker load -i arquivo.tar.gz
```

O pacote `amd64` é para Linux x86-64. Após importar, confirme as duas imagens na lista. Desative **Re-pull image / Always pull images** para imagens locais. Para um registry privado, configure suas credenciais em **Registries** e ajuste `APP_IMAGE`/`PROXY_IMAGE`; a autenticação Git é independente da autenticação de registry.

### Criar a stack

Em **Stacks → Add stack**, escolha:

- **Web editor:** cole todo o conteúdo de `compose.portainer.yaml`; ou
- **Repository:** use `https://github.com/mcdalbu/wazuh-security-reports`, autenticação de leitura para o repositório privado, referência `refs/heads/main` e **Compose path: `compose.portainer.yaml`**. Não inclua tokens na URL.

Preencha `REPORT_DOMAIN`, `INDEXER_ENDPOINTS` e, opcionalmente, `RETENTION_HOURS` em **Environment variables**. Use o nome `reports` para a stack e implante após confirmar que as imagens existem no ambiente correto.

Para criar/redefinir uma conta, abra o Console do serviço `app` com `/bin/sh`:

```sh
flask --app web.app:create_app user-set operador --customer HDBR --customer ARMAZEM_PB
```

### Migrar uma implantação existente

Antes da troca, identifique o host que contém os volumes e faça backup dos dados. Compose e uma implantação antiga não podem publicar as mesmas portas simultaneamente; pare a implantação antiga de `reports` na janela de migração e inicie o projeto Compose no host correto. Preserve os volumes e confira seus nomes antes de montar os dados no novo projeto.

O projeto `reports` usa, por padrão, `reports_reports_data`, `reports_caddy_data` e `reports_caddy_config`. Nomes iguais em hosts diferentes não significam os mesmos dados. Se os volumes existentes tiverem nomes diferentes, declare-os como externos com seus nomes reais antes de iniciar. Não use `down -v` em uma atualização: isso remove volumes, incluindo contas, PDFs e a CA.

## HTTPS interno e confiança na CA

Para um IP privado, Caddy gera automaticamente o certificado com sua CA interna. Não precisa de validação pública do Let's Encrypt. O `default_sni` permite selecionar o certificado quando o navegador acessa por IP sem SNI atrás do NAT do Docker.

Após iniciar, exporte **somente o certificado público** da CA do seu servidor:

```bash
docker compose -p reports exec -T proxy cat /data/caddy/pki/authorities/local/root.crt > reports-root-ca.crt
```

No Portainer, o mesmo `cat` pode ser executado no Console do serviço `proxy`. Salve o bloco completo `BEGIN CERTIFICATE`/`END CERTIFICATE` e importe-o nas autoridades confiáveis do sistema/navegador de cada dispositivo autorizado. Não ignore o aviso de certificado para fazer login. Nunca distribua `root.key`.

Preserve `caddy_data`: a CA continua válida ao trocar as portas ou recriar os contêineres. Recriar esse volume gera uma nova CA que precisa ser distribuída novamente. Para um nome DNS público, os desafios de emissão pública exigem DNS e roteamento externo apropriados para as portas de validação; a simples publicação de 8083/8443 não atende sozinha a esses desafios.

## CA privada do indexador

O certificado do indexador deve incluir seu IP em Subject Alternative Name e encadear em uma CA confiável. Para uma CA privada, salve os certificados públicos PEM em `secrets/indexer-ca.pem` (sem chave privada) e crie `compose.ca.yaml`:

```yaml
services:
  app:
    environment:
      SSL_CERT_FILE: /run/certs/indexer-ca.pem
    volumes:
      - ./secrets/indexer-ca.pem:/run/certs/indexer-ca.pem:ro
```

```bash
docker compose -p reports -f compose.yaml -f compose.ca.yaml up -d --build
```

Use os mesmos arquivos nas operações seguintes. No Portainer, monte o PEM usando um caminho absoluto existente no host Docker. Não há opção web para desligar a validação TLS.

## Contas, operação e dados

```bash
# Redefinir senha/clientes autorizados e revogar sessões existentes
docker compose -p reports exec app flask --app web.app:create_app user-set operador --customer HDBR
# Autorizar todos os clientes explicitamente
docker compose -p reports exec app flask --app web.app:create_app user-set administrador --all-customers
# Desativar uma conta e revogar suas sessões
docker compose -p reports exec app flask --app web.app:create_app user-disable operador
# Logs e estado dos serviços
docker compose -p reports logs --tail=100 app proxy
docker compose -p reports ps
# Limpeza de sessões e documentos expirados
docker compose -p reports exec -T app flask --app web.app:create_app prune
```

Cada conta vê somente seus próprios PDFs, e os clientes autorizados são verificados na geração e no download. O filtro do indexador usa o valor exato de `agent.labels.customer`. As credenciais e o snapshot não são persistidos; PDFs e metadados ficam no volume privado. Use uma conta do indexador somente de leitura e, quando aplicável, restrições de documentos por cliente.

Senhas usam Argon2id. As sessões são armazenadas pelo hash do token, expiram após 30 minutos de inatividade ou oito horas totais, e usam cookies Secure/HttpOnly/SameSite. Todos os POSTs exigem CSRF e origem correta. Há limites de tentativas de login e de geração. MFA/SSO não estão implementados.

Os PDFs deixam de estar disponíveis após a retenção. A remoção física ocorre durante o uso do portal ou via `prune`; agende esse comando no host se precisar de limpeza mesmo sem acessos. Proteja os backups dos três volumes. A imagem contém o papel timbrado, mas exclui credenciais, relatórios de clientes, Git e dados locais pelo `.dockerignore`.

Uma geração é executada por vez. Mantenha um worker Gunicorn e uma instância do backend para respeitar a serialização de PDF e o armazenamento SQLite local. Uma segunda geração simultânea recebe mensagem para tentar novamente.

## Verificar o código sem consultar o indexador

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-web.txt
.venv/bin/python -m unittest discover -s tests -v
```

Referências: [Docker Compose](https://docs.docker.com/compose/intro/compose-application-model/), [recursos dos serviços](https://docs.docker.com/reference/compose-file/services/), [importar imagens no Portainer](https://docs.portainer.io/user/docker/images/import) e [HTTPS automático do Caddy](https://caddyserver.com/docs/automatic-https).
