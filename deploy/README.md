# Portal web — Docker Compose / Docker Standalone

A implantação usa **Docker Compose v2** em um único Docker Engine. O projeto Compose é chamado `reports`, com aplicação, proxy Caddy e volumes persistentes. HTTP é publicado em **8083** e redireciona para HTTPS em **8443**. O endereço da aplicação é configurado na implantação; nenhum IP é fixado no código, no YAML ou nas imagens.

## Executar a partir do código

Requisitos: Docker Engine com Compose v2, acesso à rede do indexador e portas 8083/8443 disponíveis no host da aplicação. O repositório e as imagens devem continuar privados porque incluem o papel timbrado confidencial.

### Script para Ubuntu

Clone o repositório privado na máquina Ubuntu que executará a aplicação. Na raiz do clone:

```bash
cp deploy/env.example .env
# Preencha REPORT_DOMAIN, INDEXER_IP, INDEXER_PORT, INDEXER_USER e INDEXER_PASSWORD
chmod 600 .env
./deploy/deploy_ubuntu.sh --install-docker
```

O script solicita o IP/DNS do **host da aplicação**, a URL HTTPS do indexador, o usuário do portal e um cliente autorizado. A senha é solicitada pelo comando de criação da conta, com entrada oculta e confirmação. Não há senha padrão. `--install-docker` instala o Engine e o plugin Compose pelo [repositório APT oficial do Docker](https://docs.docker.com/engine/install/ubuntu/); omita a opção se já estiverem instalados. O script usa `sudo` quando necessário e interrompe a instalação se encontrar pacotes de runtime conflitantes, sem removê-los automaticamente.

Também é possível fornecer a configuração, mantendo a senha interativa:

```bash
./deploy/deploy_ubuntu.sh --install-docker \
  --host IP_OU_DNS_DA_APLICACAO \
  --indexer https://IP_DO_INDEXADOR:9200 \
  --username operador --customer HDBR --customer ARMAZEM_PB
```

Substitua os marcadores pelos endereços reais. No prompt interativo de clientes, separe valores com vírgulas: `SOC,ARMAZEM_PB,HDBR`. Pelas opções, repita `--customer` para cada valor exato. Para uma conta com acesso a todos os clientes, use `--all-customers` no lugar de `--customer`. O script preserva as demais configurações de `.env`, aplica permissão `600`, constrói as imagens localmente uma de cada vez, aguarda a inicialização e mantém os volumes do projeto `reports`. Reexecutar com uma conta redefine a senha e revoga as sessões dessa conta.

Para criar ou redefinir uma conta autorizada a **todos os clientes**, use `--all` (alias de `--all-customers`):

```bash
./deploy/deploy_ubuntu.sh --username secteam --all
```

Essa opção pula o prompt de clientes; a senha continua interativa. Não combine `--all` com `--customer` ou `--skip-account`.

Para atualizar após obter o novo código, preservando contas e dados:

```bash
./deploy/deploy_ubuntu.sh --skip-account
```

O certificado **público** da CA interna é exportado para `output/deployment/reports-root-ca.crt`, quando disponível. Instale-o nos dispositivos autorizados antes do login. O script não instala a CA nos clientes nem altera regras de firewall. Como Docker publica portas fora das regras usuais do UFW, restrinja o acesso a 8083/8443 na rede/VPN e nas regras apropriadas do host. Veja as [limitações de firewall do Docker](https://docs.docker.com/engine/install/ubuntu/#firewall-limitations).

Execute o script no host de destino com o contexto Docker local. Ele usa apenas `compose.yaml`; se precisar montar uma CA privada do indexador, use os comandos com `compose.ca.yaml` na seção correspondente, ou acrescente essa montagem ao seu arquivo principal antes de executar o script. Para migrar de uma stack antiga, consulte a seção de migração antes de iniciar, para preservar os volumes e liberar as portas.

### Comandos manuais

Na pasta do repositório já clonado:

```bash
cp deploy/env.example .env
# Edite .env: REPORT_DOMAIN, INDEXER_IP, INDEXER_PORT, INDEXER_USER e INDEXER_PASSWORD
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
| `INDEXER_IP` | IP literal do indexador, sem protocolo nem porta. |
| `INDEXER_PORT` | Porta HTTPS do indexador; padrão `9200`. |
| `INDEXER_USER` | Usuário do indexador com permissão de leitura dos alertas. |
| `INDEXER_PASSWORD` | Senha do indexador, configurada no servidor. Não aparece no formulário web. |
| `RETENTION_HOURS` | Retenção dos PDFs, padrão `24`, entre 1 e 720 horas. |
| `APP_IMAGE` / `PROXY_IMAGE` | Opcionais; as imagens locais padrão são `localhost/wazuh-security-reports-app:0.4.3` e `localhost/wazuh-security-reports-proxy:0.4.3`. |

Acesse **`https://<REPORT_DOMAIN>:8443`**. `http://<REPORT_DOMAIN>:8083` redireciona para esse endereço, preservando caminho e parâmetros. O login é servido por HTTPS. A origem exata usada pela aplicação é `https://<REPORT_DOMAIN>:8443`, para validar o Host e a origem dos formulários.

### Conexão do indexador configurada no Docker Compose

O formulário solicita somente **cliente e período**. O backend sempre usa o IP, a porta e as credenciais definidos no serviço `app`; valores de conexão enviados pelo navegador não substituem a configuração do servidor. A validação TLS continua obrigatória.

Os arquivos Compose recebem os valores do `.env` privado do host. Exemplo com dados fictícios:

```dotenv
REPORT_DOMAIN=192.0.2.5
INDEXER_IP=192.0.2.10
INDEXER_PORT=9200
INDEXER_USER=leitor_alertas
INDEXER_PASSWORD='SUBSTITUA_PELA_SENHA_REAL'
RETENTION_HOURS=24
```

Proteja `.env` com `chmod 600 .env` e mantenha-o fora do Git e dos pacotes de atualização. Aspas simples no `.env` preservam caracteres como `$` e `#`; uma aspa simples dentro do valor deve ser escapada como `\'`. Os valores são passados ao ambiente do contêiner pelo Compose e podem ser lidos por administradores do Docker. Para conferir o YAML sem imprimir as credenciais, use `docker compose -p reports config --quiet`.

Na atualização de uma instalação antiga, substitua `INDEXER_ENDPOINTS` pelos quatro campos acima. A variável antiga não é mais utilizada. Depois de atualizar o código e reconstruir a imagem, recrie o serviço para aplicar a configuração:

```bash
docker compose -p reports build app &&
  docker compose -p reports up -d --no-build --wait app
```

Se alterar somente os valores de conexão posteriormente, basta `docker compose -p reports up -d --no-build --wait app`. O aplicativo recusa iniciar se o IP, a porta ou as credenciais estiverem ausentes ou inválidos. Use a seção de CA privada abaixo quando o certificado do indexador não encadear em uma CA pública confiável.

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

Preencha `REPORT_DOMAIN`, `INDEXER_IP`, `INDEXER_PORT`, `INDEXER_USER`, `INDEXER_PASSWORD` e, opcionalmente, `RETENTION_HOURS` em **Environment variables**. Use o nome `reports` para a stack e implante após confirmar que as imagens atualizadas existem no ambiente correto.

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

Se a geração apresentar erro genérico, copie `deploy/check_indexer.py` para o host e execute o diagnóstico dentro do contêiner, substituindo o cliente pelo valor exato desejado:

```bash
docker compose -p reports exec -T app python - HDBR 24 < deploy/check_indexer.py
```

O teste separa configuração, TCP, TLS, consulta e renderização PDF. Não imprime senhas, eventos ou exceções brutas. O PDF temporário é removido ao terminar. O segundo argumento pode ser `24`, `168` ou `720`. Não requer reconstruir a imagem, pois o script é enviado por stdin. Use os mesmos `-f` da sua implantação se houver um arquivo extra de CA.

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

## Relatórios de segurança e vulnerabilidades

Na navegação, **Segurança** mantém o relatório geral; **Vulnerabilidades** abre uma página própria, com cliente, período, modelo e histórico dedicados. A conexão com o indexador continua configurada no Compose, com a mesma CA e sem campos de credenciais no navegador.

O relatório de vulnerabilidades exige `agent.labels.customer` e `rule.groups: vulnerability-detector` por `term` exato, além do período em `timestamp`. Ele consulta eventos nos índices de alertas; **não é um inventário atual de pendências**. A documentação do módulo distingue inventário e eventos de detecção/resolução: [funcionamento da detecção de vulnerabilidades](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/how-it-works.html#alert-generation).

Campos utilizados: `data.vulnerability.cve`, `data.vulnerability.severity`, `data.vulnerability.status`, `data.vulnerability.package.name`, `data.vulnerability.package.version`, `agent.id`, `agent.name` e `timestamp`. Campos ausentes são contabilizados. A severidade vem da vulnerabilidade, sem inferência de `rule.level`; CVEs e agentes distintos são estimativas. Listas limitadas aos maiores volumes não representam todas as ocorrências.

O gerador fica em `vulnerability_report.py`; o modelo editável, em `modelo_relatorio_vulnerabilidades.md`. O modelo PDF pode ser baixado na própria página Vulnerabilidades. A migração adiciona `reports.report_type`, mantendo documentos antigos como `security`; o histórico e o nome dos downloads refletem o tipo. Clientes autorizados, CSRF, retenção, isolamento dos documentos e a sessão de 10 minutos continuam obrigatórios.

Na atualização, copie o novo módulo junto com `wazuh_report.py`, `web/`, `Dockerfile` e `.dockerignore`. Reconstrua e recrie o backend preservando os arquivos Compose, `.env`, CA e volumes. Se usa o arquivo extra da CA:

```bash
docker compose -p reports -f compose.yaml -f compose.indexer-ca.yaml build app &&
  docker compose -p reports -f compose.yaml -f compose.indexer-ca.yaml \
    up -d --no-build --wait app
```

## Contas, operação e dados

### Administração pela interface web

O perfil **Administrador** acessa todos os clientes por padrão e tem a seção **Usuários** na navegação. Nela, pode criar contas, editar clientes, ativar/desativar contas, redefinir senhas temporárias e promover outros usuários para administrador. Usuários comuns não têm acesso a essas telas nem às operações de administração. O portal impede a desativação ou a remoção do perfil do último administrador ativo.

Após copiar o código atualizado e reconstruir a imagem do backend, promova uma conta existente uma única vez no host:

```bash
./deploy/manage_users.sh promote secteam
```

Ou crie o primeiro administrador na instalação com `./deploy/deploy_ubuntu.sh --username secteam --admin`. O comando direto para promover é `docker compose -p reports exec app flask --app web.app:create_app user-role secteam --admin`. A opção antiga `--all` concede acesso a todos os clientes a um usuário comum; para gerenciar contas é necessário o perfil administrador.

**Todas as contas novas** precisam substituir a senha temporária no primeiro acesso. Até a troca, relatórios e administração ficam bloqueados. Redefinir uma senha também exige nova troca; promover um usuário a administrador exige troca no próximo acesso. Na tela, o usuário informa a senha atual, define uma senha diferente (15–128 caracteres) e confirma. Após salvar, todas as sessões são encerradas e ele entra com a nova senha. A opção **Alterar senha** também fica disponível na navegação para trocas voluntárias.

A migração do banco é automática e preserva as contas existentes como usuários comuns, sem promover ninguém por inferência do nome ou do acesso a todos os clientes. Contas existentes não são forçadas a trocar a senha apenas pela migração; novas contas, promoções e redefinições seguem a política acima. Acesso administrativo não dá acesso aos PDFs privados de outras contas.

### Script de administração de usuários

Copie `deploy/manage_users.sh` junto com a versão atualizada de `web/app.py`. Como os comandos de administração ficam na imagem, após atualizar o código reconstrua o backend uma vez:

```bash
docker compose -p reports build app &&
  docker compose -p reports up -d --no-build --wait app
chmod +x deploy/manage_users.sh
```

Execute no host Docker, a partir da raiz do repositório:

```bash
# Listar contas, estado e clientes autorizados (sem hashes ou senhas)
./deploy/manage_users.sh list
# Criar conta nova; senha oculta com confirmação
./deploy/manage_users.sh add analista --customer HDBR --customer ARMAZEM_PB
# Criar administrador ou promover uma conta existente
./deploy/manage_users.sh add-admin administrador
./deploy/manage_users.sh promote secteam
# Substituir toda a lista de permissões sem alterar a senha
./deploy/manage_users.sh permissions analista --customer SOC --customer HDBR
# Autorizar todos os clientes
./deploy/manage_users.sh permissions secteam --all
# Redefinir somente a senha
./deploy/manage_users.sh password analista
# Desativar ou reativar uma conta
./deploy/manage_users.sh disable analista
./deploy/manage_users.sh enable analista
```

`permissions` **substitui a lista completa**: para manter um cliente, inclua-o na nova lista. Repita `--customer` para cada valor exato; `--all`/`--all-customers` autoriza todos, inclusive novos clientes. Todas as edições revogam as sessões anteriores. Alterar permissões ou senha preserva o estado desativado; `enable` reativa explicitamente. `add` falha se a conta já existir. O script usa o contêiner `app` em execução do projeto `reports`, sem instalar pacotes Python no host. O acesso administrativo depende da permissão de executar Docker no host.

### Comandos diretos

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

Cada conta vê somente seus próprios PDFs, e os clientes autorizados são verificados na geração e no download. O filtro do indexador usa o valor exato de `agent.labels.customer`. As credenciais do indexador ficam na configuração privada do servidor e no ambiente do contêiner; não são gravadas no banco, PDFs ou logs nem enviadas ao navegador. O snapshot não é persistido; PDFs e metadados ficam no volume privado. Use uma conta do indexador somente de leitura e, quando aplicável, restrições de documentos por cliente.

Senhas usam Argon2id. As sessões são armazenadas pelo hash do token, expiram obrigatoriamente 10 minutos após o login, mesmo com atividade, e usam cookies Secure/HttpOnly/SameSite. Todos os POSTs exigem CSRF e origem correta. Há limites de tentativas de login e de geração. As páginas autenticadas retornam ao login ao atingir o prazo, e o backend recusa a sessão expirada independentemente do navegador. A regra também vale para administradores. MFA/SSO não estão implementados.

Os PDFs deixam de estar disponíveis após a retenção. A remoção física ocorre durante o uso do portal ou via `prune`; agende esse comando no host se precisar de limpeza mesmo sem acessos. Proteja os backups dos três volumes. A imagem contém o papel timbrado, mas exclui credenciais, relatórios de clientes, Git e dados locais pelo `.dockerignore`.

Uma geração é executada por vez. Mantenha um worker Gunicorn e uma instância do backend para respeitar a serialização de PDF e o armazenamento SQLite local. Uma segunda geração simultânea recebe mensagem para tentar novamente.

## Verificar o código sem consultar o indexador

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements-web.txt
.venv/bin/python -m unittest discover -s tests -v
```

Referências: [Docker Compose](https://docs.docker.com/compose/intro/compose-application-model/), [recursos dos serviços](https://docs.docker.com/reference/compose-file/services/), [importar imagens no Portainer](https://docs.portainer.io/user/docker/images/import) e [HTTPS automático do Caddy](https://caddyserver.com/docs/automatic-https).
