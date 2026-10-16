# Relatórios de Segurança Wazuh

Aplicação GTK4/libadwaita para gerar um relatório PDF por cliente. A janela recebe o valor exato de `agent.labels.customer`, consulta `wazuh-alerts-*` nas últimas 24 horas, 7 dias ou 30 dias e gera o PDF no papel timbrado confidencial com gráficos de tendência, agentes e regras de maior severidade. O nome do produto de coleta não aparece no conteúdo do PDF.

## Instalar os pacotes

- Debian/Ubuntu: `sudo apt install ./dist/wazuh-security-reports_0.3.0-1_all.deb`
- Fedora/RHEL: `sudo dnf install ./dist/wazuh-security-reports-0.3.0-1.noarch.rpm`

O instalador coloca um lançador chamado **Relatórios de Segurança Wazuh** no menu de aplicativos, com ícone próprio. Os pacotes declaram as bibliotecas GTK4/libadwaita e PDF como dependências. O destino padrão dos relatórios é `~/Relatorios Wazuh`, que pode ser alterado na janela.

## Executar a partir do código-fonte

No Debian 13 ou Ubuntu, instale as dependências:

```bash
sudo apt install python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 python3-reportlab python3-pypdf fonts-dejavu-core
```

As dependências GTK/PyGObject devem ser instaladas no Python do sistema. O projeto não grava credenciais. O PDF do papel timbrado fica em `assets/timbrado_confidencial.pdf`.

```bash
./run.sh
```

Na janela:

1. Informe o valor de `agent.labels.customer` do cliente.
2. Escolha o período: **24 horas**, **7 dias** ou **30 dias**.
3. Informe ou ajuste o IP, a porta, o usuário e a senha do Wazuh Indexer.
4. Escolha a pasta de saída e clique em **Gerar relatório**.

O arquivo será salvo como `Relatorio_de_Seguranca_<cliente>_<data>_<hora>.pdf`, evitando sobrescrever relatórios anteriores. A janela permite abrir o PDF após a geração. A senha também pode ser preenchida pela variável de ambiente `WAZUH_INDEXER_PASSWORD`; `WAZUH_INDEXER_IP`, `WAZUH_INDEXER_PORT` e `WAZUH_INDEXER_USER` ajustam os valores iniciais de conexão.

A opção **Validar certificado TLS** vem desligada para aceitar o certificado privado usado neste ambiente. Ative-a se o certificado do indexador estiver configurado como confiável no computador.

## Consulta e conteúdo

O filtro de cliente é um `term` exato em `agent.labels.customer`; o período usa `timestamp` em intervalo semiaberto. O gráfico agrupa os dados por hora em 24h, por 6 horas em 7d e por dia em 30d. O relatório mostra total de alertas, nível 10 ou superior, falhas de autenticação, principais agentes e regras, tendência temporal e recomendações de triagem. Ele informa quando a contagem representa alertas e não incidentes únicos. Uma falha de consulta, timeout ou erro de shard impede a geração do PDF.

O módulo `wazuh_report.py` contém a consulta e a renderização; `wazuh_security_app.py` contém a interface. O modelo editável está em `modelo_relatorio_seguranca.md`. O PDF gerado é salvo de forma atômica para evitar arquivos parciais.

## Leitura gerencial e técnica

O relatório e o modelo em PDF compartilham as descrições das seções. A apresentação contém seis partes: visão executiva, volume e severidade, ativos e regras, acessos e sinais para investigação, plano de ação e referência técnica. Cada seção explica o que é apresentado, sua utilidade e os cuidados de interpretação.

Os indicadores incluem participação dos alertas de nível 10+, participação das falhas de autenticação, fontes observadas, média de alertas por hora, pico temporal e distribuição por nível. A consulta também solicita estimativa de agentes distintos, campos ausentes e primeiro/último alerta. Extrações antigas continuam aceitas e informam quando esses dados não foram coletados. Fontes observadas não medem cobertura sem inventário; participação de falhas no total de alertas não mede a taxa de falha das tentativas de autenticação.

O plano de ação apresenta responsáveis sugeridos e resultados verificáveis. Prazos, estado, incidentes confirmados, impacto e SLA exigem dados de atendimento e validação humana. O relatório indica como incorporar comparação histórica, inventário/criticidade e indicadores de resposta sem inventar métricas indisponíveis.

Para gerar o modelo PDF com as mesmas orientações da aplicação:

```bash
python3 -c 'from wazuh_report import render_template; render_template("output/pdf/Modelo_de_Relatorio_de_Seguranca_timbrado.pdf")'
```

O modelo em Markdown também é instalado em `/usr/share/doc/wazuh-security-reports/`.

Para executar as verificações sem consultar o indexador:

```bash
python3 -m unittest discover -s tests -v
```

## Recriar os pacotes

```bash
python3 packaging/build_packages.py
```

O `.deb` requer `dpkg-deb`; o `.rpm` requer `rpmbuild`. Ambos são construídos sem instalar a aplicação no sistema. Os arquivos finais ficam em `dist/`.
