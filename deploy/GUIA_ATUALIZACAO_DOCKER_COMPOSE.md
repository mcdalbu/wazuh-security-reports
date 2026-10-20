# Guia de atualização da aplicação no Docker Compose

Este guia aplica a atualização com o relatório dedicado de vulnerabilidades no ambiente já instalado em `~/relatoria`, usando o projeto `reports` e a CA privada do indexador.

**Resultado:** o portal passa a oferecer **Segurança** e **Vulnerabilidades**, com geração, histórico e modelos separados. Contas, permissões, limite de sessão de 10 minutos, configuração do indexador e certificados são preservados.

## 1. Copiar o pacote para o servidor

Copie os dois arquivos entregues para a pasta pessoal do usuário no servidor:

- `reports-web-vulnerabilities-update.tar.gz`
- `reports-web-vulnerabilities-update.tar.gz.sha256`

Verifique a integridade:

```bash
cd ~
sha256sum -c reports-web-vulnerabilities-update.tar.gz.sha256
```

Continue somente se aparecer `OK`.

O pacote contém `vulnerability_report.py`, `wazuh_report.py`, `web/`, `Dockerfile`, `.dockerignore`, o modelo Markdown e documentação. Ele não contém `.env`, arquivos Compose, CA ou dados de clientes. Os Dockerfiles e módulos precisam ser atualizados juntos.

## 2. Conferir a instalação atual

```bash
cd ~/relatoria
docker compose -p reports -f compose.yaml -f compose.indexer-ca.yaml config --quiet &&
docker compose -p reports -f compose.yaml -f compose.indexer-ca.yaml ps
```

Os serviços existentes devem aparecer. Mantenha estes arquivos da sua instalação:

```text
compose.yaml
compose.indexer-ca.yaml
.env
secrets/indexer-ca.pem
```

As portas continuam 8083 para HTTP e 8443 para HTTPS. Não é necessário executar novamente a criação de usuários ou a instalação do Docker.

## 3. Fazer backup antes da migração do banco

Execute os blocos desta seção na mesma sessão do terminal, para manter a variável `backup_dir`.

```bash
cd ~/relatoria
umask 077
backup_dir="$HOME/relatoria-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -m 700 "$backup_dir"
printf 'Backup: %s\n' "$backup_dir"
```

### Código e configuração

```bash
tar --exclude='./output' --exclude='./tmp' --exclude='./.git' \
  --exclude='./.venv' --exclude='__pycache__' \
  -czf "$backup_dir/codigo-e-configuracao.tar.gz" .
```

Esse arquivo inclui configuração privada e papel timbrado. Mantenha o diretório de backup protegido.

### Banco consistente de contas e metadados

O comando abaixo usa a API de backup do SQLite dentro do contêiner. A saída binária é gravada no arquivo, sem imprimir hashes de senha ou outros dados no terminal:

```bash
docker compose -p reports -f compose.yaml -f compose.indexer-ca.yaml \
  exec -T app python - <<'PY' > "$backup_dir/reports.sqlite3"
import pathlib
import sqlite3
import sys
import tempfile

with tempfile.TemporaryDirectory() as folder:
    destination = pathlib.Path(folder) / 'reports.sqlite3'
    source = sqlite3.connect('file:/data/reports.sqlite3?mode=ro', uri=True)
    backup = sqlite3.connect(destination)
    try:
        source.backup(backup)
    finally:
        backup.close()
        source.close()
    sys.stdout.buffer.write(destination.read_bytes())
PY
```

Confirme que os arquivos foram criados e que o comando terminou sem erro:

```bash
ls -lh "$backup_dir"
test -s "$backup_dir/reports.sqlite3"
```

Esse backup cobre o banco, código e configuração. Os PDFs continuam no volume existente; ele não é uma cópia integral dos volumes de documentos e da CA interna do proxy. Mantenha sua rotina de backup dos volumes se precisar de recuperação completa do ambiente.

## 4. Extrair a atualização

```bash
cd ~/relatoria
tar -xzf ~/reports-web-vulnerabilities-update.tar.gz
ls -l vulnerability_report.py wazuh_report.py Dockerfile .dockerignore
```

O arquivo `.dockerignore` é oculto e não aparece em um `ls` simples. Ele é necessário para permitir a inclusão do novo gerador na imagem e excluir arquivos privados do build.

## 5. Construir a nova imagem

Use o builder separado para o host que já apresentou o erro de exportação `ref ... locked`:

```bash
cd ~/relatoria
docker buildx inspect reports-builder >/dev/null 2>&1 ||
  docker buildx create --name reports-builder --driver docker-container
docker buildx inspect reports-builder --bootstrap
```

Obtenha o nome da imagem do próprio Compose e construa:

```bash
app_image=$(docker compose -p reports -f compose.yaml -f compose.indexer-ca.yaml config --images app)
test -n "$app_image" &&
docker buildx build --builder reports-builder --load \
  -t "$app_image" -f Dockerfile . &&
docker compose -p reports -f compose.yaml -f compose.indexer-ca.yaml \
  up -d --no-build --wait --wait-timeout 180 app
```

Execute esse bloco junto, incluindo os `&&`. Assim, o serviço só é atualizado se o build concluir com sucesso. `--load` disponibiliza a imagem construída no Docker local. O serviço `app` é recriado com a nova imagem; os volumes existentes permanecem montados.

O portal pode ficar indisponível por alguns segundos enquanto o backend é recriado. Não é necessário executar `down` antes de atualizar. O proxy e seus certificados permanecem na implantação existente.

## 6. Confirmar a atualização

```bash
docker compose -p reports -f compose.yaml -f compose.indexer-ca.yaml ps
```

O backend deve estar `healthy`. Confirme o novo módulo e a duração da sessão:

```bash
docker compose -p reports -f compose.yaml -f compose.indexer-ca.yaml \
  exec -T app python -c 'from vulnerability_report import GROUP; from web.app import ABSOLUTE_SECONDS; print("Grupo:", GROUP); print("Sessão em segundos:", ABSOLUTE_SECONDS)'
```

Saída esperada:

```text
Grupo: vulnerability-detector
Sessão em segundos: 600
```

No navegador:

1. Entre no endereço HTTPS que já utiliza, na porta 8443.
2. Confira as opções **Segurança** e **Vulnerabilidades** na navegação.
3. Abra **Vulnerabilidades** e baixe o modelo dedicado.
4. Escolha um cliente autorizado e 24 horas, 7 dias ou 30 dias para gerar o relatório.
5. Confira o documento no histórico de vulnerabilidades e valide que os relatórios antigos continuam em Segurança.

O banco adiciona a coluna de tipo automaticamente. Documentos anteriores são preservados com tipo `security`; contas e permissões continuam existentes. Sessões abertas há mais de 10 minutos exigem novo login.

## 7. Se ocorrer uma falha

### O build falhou

Interrompa a atualização antes de recriar o serviço. A implantação anterior pode continuar atendendo. Se o erro `ref ... locked` persistir mesmo com o builder separado, investigue o runtime Docker/containerd; apagar dados da aplicação não corrige necessariamente esse problema.

### O backend não ficou saudável

```bash
docker compose -p reports -f compose.yaml -f compose.indexer-ca.yaml \
  logs --tail=80 app
```

### Erro de conexão ou certificado do indexador

Preserve o uso dos dois arquivos `-f`. Se `deploy/check_indexer.py` já estiver instalado:

```bash
docker compose -p reports -f compose.yaml -f compose.indexer-ca.yaml \
  exec -T app python - HDBR 24 < deploy/check_indexer.py
```

Substitua `HDBR` por um cliente autorizado. O diagnóstico separa rede, TLS, consulta e PDF, sem exibir credenciais ou eventos.

### O novo módulo não foi encontrado

Confira se `vulnerability_report.py` está na raiz, se `Dockerfile` copia os dois geradores e se `.dockerignore` permite o novo módulo. Uma imagem antiga pode continuar `healthy` mesmo quando um build novo falhou; confirme a conclusão do build antes do `up`.

### Necessidade de retornar à versão anterior

Mantenha o backup da seção 3. A migração altera o esquema do banco; retornar somente o código ou a imagem antiga pode ser insuficiente. Uma reversão que restaure o banco deve ocorrer com o backend parado e substitui os dados pelo estado do momento do backup. Planeje a reversão considerando os registros criados depois dele.

## Cuidados durante esta atualização

- Use sempre o projeto `reports` e os dois arquivos Compose da implantação.
- Preserve `.env`, `secrets/indexer-ca.pem` e os volumes de dados e certificados.
- Não execute `docker compose down -v`, `docker volume prune` ou `docker system prune --volumes` para aplicar a atualização.
- Mantenha senhas, relatórios, certificados privados e backups fora do repositório.

Referências: [Docker Compose up](https://docs.docker.com/reference/cli/docker/compose/up/), [Buildx --load](https://docs.docker.com/reference/cli/docker/buildx/build/#load) e [backup do SQLite no Python](https://docs.python.org/3.12/library/sqlite3.html#sqlite3.Connection.backup).
