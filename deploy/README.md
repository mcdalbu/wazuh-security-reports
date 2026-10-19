# Portal web em Docker

A versão web reutiliza o gerador de PDFs e o papel timbrado do aplicativo desktop. Permite escolher o cliente, 24h/7d/30d, IP, porta e credenciais do indexador. Mantém gráficos, EPS médio de alertas e severidades por categoria. Os dados consultados e as credenciais ficam somente na memória durante a geração. O PDF e seus metadados ficam em um volume privado.

## Implantar

Requer Docker Engine com Compose v2, portas TCP 80/443 disponíveis no servidor e acesso de rede ao indexador. Para HTTPS público, use um domínio com DNS apontando para o servidor; para rede interna/VPN, use um IP privado e a CA interna conforme a seção de acesso por IP. Use um servidor administrado e restrinja o acesso à rede de operação quando possível.

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

**O repositório deve permanecer privado.** O erro `no image specified` ocorre quando a implantação exige `image:` e não constrói os Dockerfiles. A autenticação Git permite ler o código; ela não constrói nem disponibiliza uma imagem Docker.

Use **`compose.portainer.yaml`** no Portainer. Esse arquivo contém somente referências `image:`, sem `build:`, e preserva autenticação, HTTPS, limites de recursos e volumes. As imagens precisam existir no mesmo Docker Engine do ambiente selecionado antes de implantar.

#### Portas HTTP 8083 e HTTPS 8443 — 0.4.3

Para rede interna/VPN com essas portas, use **`compose.portainer.ip.yaml`**. Preencha `REPORT_DOMAIN` com o IP do portal (sem protocolo nem porta). Esse arquivo publica `8083:8080` e `8443:8443`, configura a origem da aplicação como `https://<IP>:8443` e informa `REPORT_HTTPS_PORT=8443` ao proxy. O HTTP em `http://<IP>:8083` redireciona para `https://<IP>:8443`, preservando o caminho e a consulta. O login é servido por HTTPS.

Importe as imagens **0.4.3** antes da atualização. Se usar `APP_IMAGE`/`PROXY_IMAGE`, atualize as tags ou remova os valores antigos. Preserve os volumes: a CA existente continua válida, pois certificados identificam o IP, não a porta. A instalação da CA nos clientes descrita abaixo continua necessária se ainda não foi feita.

O `compose.portainer.yaml` padrão mantém portas externas 80/443. Para outras combinações, alinhe sempre três itens: portas publicadas, `PUBLIC_ORIGIN` da aplicação e `REPORT_HTTPS_PORT` do proxy. O Caddy usa um redirecionamento explícito para não perder a porta pública quando há mapeamento de portas no Docker.

#### Acesso por IP na rede interna/VPN — 0.4.2

Use as imagens `0.4.2` e configure `REPORT_DOMAIN` com o **IP do servidor Docker do portal**, sem protocolo ou porta (o nome histórico dessa variável também aceita IP). A aplicação usa `https://<IP>` como origem exata; abra o mesmo endereço no navegador. O IP do indexador continua separado em `INDEXER_ENDPOINTS`.

Para IP privado, o Caddy gera automaticamente um certificado com sua CA interna; não precisa alcançar o Let's Encrypt nem abrir portas da rede interna para a Internet. O `default_sni` permite selecionar o certificado correto quando o navegador acessa por IP sem enviar SNI e o tráfego chega por NAT do Docker.

O certificado da CA precisa ser confiável **em cada dispositivo/navegador que acessará o portal**. Após implantar, abra o Console do serviço `proxy` no Portainer com `/bin/sh` e execute:

```sh
cat /data/caddy/pki/authorities/local/root.crt
```

Salve o bloco completo de `-----BEGIN CERTIFICATE-----` até `-----END CERTIFICATE-----` como `reports-root-ca.crt` e importe-o nas autoridades certificadoras confiáveis do sistema/navegador. Confirme que o arquivo veio do seu próprio servidor. Exporte somente `root.crt`; nunca distribua `root.key`. Não ignore o aviso de certificado para fazer login. Reabra o navegador e acesse `https://<IP>` após instalar a CA.

Preserve `caddy_data`: ele contém a CA, sua chave e os certificados. Se esse volume for recriado, será necessário distribuir a nova CA. A opção `skip_install_trust` evita tentar instalar a CA dentro do contêiner de raiz somente leitura; a confiança nos dispositivos clientes continua necessária.

A versão mantém as correções de capabilities e temporários da `0.4.1`. Se usar `APP_IMAGE`/`PROXY_IMAGE`, atualize as tags para `0.4.3` ou remova as variáveis para aceitar os padrões atuais. Para nomes DNS públicos, permanece a emissão automática pública quando o DNS e as portas externas atendem aos requisitos.

#### Atualização corretiva 0.4.1

Esta versão remove a capability `cap_net_bind_service` do executável Caddy durante o build, pois o proxy já escuta internamente em 8080/8443. Isso corrige `exec /usr/bin/caddy: operation not permitted` em runtimes que removem as capabilities e não aplicam `no-new-privileges`.

O `/tmp` agora é declarado como volume `type: tmpfs`, com modo `01777`, preservando a raiz somente leitura e permitindo escrita pelo UID 10001. O Gunicorn usa `/dev/shm` para seu arquivo de heartbeat. Isso evita o erro `Read-only file system: /tmp/wgunicorn-*` observado quando a montagem temporária anterior não foi aplicada pelo ambiente. A montagem `/tmp` é necessária também para a geração do PDF.

Essas correções estão incluídas na versão atual **0.4.3**. Importe o pacote atual e substitua o YAML completo da stack pelo `compose.portainer.yaml` atualizado. Se tiver definido `APP_IMAGE` ou `PROXY_IMAGE`, atualize também as tags dessas variáveis para `0.4.2`, ou remova-as para usar os novos padrões. Preserve o nome da stack, as variáveis de domínio/indexador e os volumes existentes. Não use `privileged`, não adicione capabilities e não desligue `read_only` para contornar os erros.

#### 1. Disponibilizar as imagens

Você pode importar o arquivo Docker de imagens fornecido com a entrega em **Images → Import → Select file → Upload**. O pacote contém aplicação e proxy; após importar, confirme que ambas aparecem na lista:

- `localhost/wazuh-security-reports-app:0.4.3`
- `localhost/wazuh-security-reports-proxy:0.4.3`

Use o pacote compatível com a arquitetura do servidor. O arquivo pré-construído `amd64` é para Linux x86-64. Não habilite **Re-pull image / Always pull images** para imagens importadas localmente: elas não foram publicadas no Docker Hub.

Para reconstruir em uma máquina com Docker, com o repositório privado já clonado:

```bash
./deploy/build_portainer_images.sh
```

O script gera `output/containers/wazuh-security-reports-0.4.3-<arquitetura>.tar.gz` e seu checksum. Não envia nada para um registry. Se executar no próprio host do Portainer, as imagens também ficam prontas no Docker local, sem precisar importar o arquivo. Se executar em outra máquina, importe o arquivo no ambiente correto do Portainer. Pela CLI, use `docker load -i arquivo.tar.gz` (não `docker import`).

Como alternativa, publique as duas imagens em um **registry privado**, configure sua autenticação em **Registries** no Portainer e defina `APP_IMAGE` e `PROXY_IMAGE` com as referências completas. A imagem da aplicação contém o papel timbrado confidencial: não torne o registry público. Credenciais de registry são distintas da autenticação Git.

#### 2. Implantar a stack

Na área **Stacks → Add stack**, você pode:

- Usar **Web editor** e colar todo o conteúdo de `compose.portainer.yaml`; ou
- Selecionar **Repository**, informar `https://github.com/mcdalbu/wazuh-security-reports`, habilitar autenticação com uma credencial de leitura do repositório privado, usar referência `refs/heads/main` e **Compose path: `compose.portainer.yaml`**. Não inclua o token na URL.

Em **Environment variables**, preencha:

| Variável | Valor |
| --- | --- |
| `REPORT_DOMAIN` | Domínio ou IP do portal, sem `https://` nem barra final |
| `INDEXER_ENDPOINTS` | URL HTTPS com o IP e porta autorizados, por exemplo `https://192.0.2.10:9200` |
| `RETENTION_HOURS` | Opcional, padrão `24` |
| `APP_IMAGE` / `PROXY_IMAGE` | Opcionais; mantenha os padrões para as imagens importadas |

Implante a stack após confirmar as imagens. Para atualizar uma stack existente, preserve o mesmo nome e os volumes; altere o Compose path, carregue o arquivo atualizado e desative a opção de baixar novamente as imagens quando elas forem locais.

Os limites usam `deploy.resources.limits`, e `depends_on` usa lista para compatibilidade com o parser observado. A lista determina a ordem de início, sem esperar o healthcheck: o proxy pode responder temporariamente com 502 enquanto a aplicação inicia; tente novamente após alguns segundos.

#### 3. Criar a conta do portal

Abra **Containers → contêiner do serviço app → Console**, conecte com `/bin/sh` e execute:

```sh
flask --app web.app:create_app user-set operador --customer HDBR --customer ARMAZEM_PB
```

A senha será solicitada sem eco. Acesse então `https://<REPORT_DOMAIN>`.

Se usar CA privada do indexador, o arquivo PEM descrito abaixo deve existir no host do Docker e ser montado com caminho absoluto. Acrescente `SSL_CERT_FILE` e o volume ao Compose da stack; arquivos da máquina com o navegador não ficam automaticamente disponíveis no servidor.

Referências: [importar imagens no Portainer](https://docs.portainer.io/user/docker/images/import) e [configurar uma stack](https://docs.portainer.io/sts/user/docker/stacks/add).

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
