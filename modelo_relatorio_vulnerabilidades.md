# Relatório de Vulnerabilidades - {{CLIENTE}}

**Classificação:** Confidencial\
**Período:** {{24H / 7D / 30D}} - {{INÍCIO_LOCAL}} a {{FIM_LOCAL}} (America/Recife)\
**Extraído em UTC:** {{DATA_HORA_EXTRAÇÃO}}\
**Fonte:** indexador de alertas\
**Filtros obrigatórios, combinados por AND:**

- `agent.labels.customer = {{CLIENTE}}` (term exato)
- `rule.groups = vulnerability-detector` (term exato)
- `timestamp >= {{INÍCIO_UTC}} AND timestamp < {{FIM_UTC}}`

> Este relatório analisa eventos no período, não o inventário atual de vulnerabilidades abertas. Repetições, detecções e resoluções podem aparecer no mesmo recorte. Ausência de eventos não comprova ausência de vulnerabilidades.

## 1. Visão executiva e escopo

### Objetivo e leitura gerencial

Resume o volume de eventos e a amplitude dos achados para orientar a priorização e o planejamento de correções. O contexto de negócio, a exposição e o estado atual no ativo precisam ser validados antes de definir urgência.

{{SÍNTESE_DOS_ACHADOS}}. {{SERVIÇOS_E_EXPOSIÇÃO_A_VALIDAR}}. {{RESPONSÁVEIS_E_PRIORIDADES}}.

| Indicador | Resultado | Interpretação |
|---|---|---|
| Eventos do módulo | {{TOTAL_EVENTOS}} | Registros no período; podem repetir uma mesma condição. |
| CVEs distintas (estim.) | {{CVES_ESTIMADAS}} | Identificadores distintos; não são pares CVE/ativo ou CVE/ativo/pacote. |
| Agentes com eventos (estim.) | {{AGENTES_ESTIMADOS}} | Ativos observados neste recorte, não todo o inventário monitorado. |
| Eventos Altos ou Críticos | {{TOTAL_ALTOS_CRÍTICOS}} | Severidade da vulnerabilidade; inclui detecções e resoluções. |
| EPS médio (eventos do módulo) | {{EPS}} | Total de eventos filtrados dividido pela duração total em segundos. |

O EPS inclui os intervalos sem eventos e contabiliza somente o módulo e o cliente filtrados. Não mede o volume total processado pela plataforma nem a quantidade de vulnerabilidades únicas.

**Se não houver eventos:** validar saúde da coleta, comportamento de geração de eventos e inventário antes de afirmar que o cliente não tem vulnerabilidades.

## 2. Evolução, severidade e estados

### Eventos ao longo do período

Mostra quando detecções e mudanças de estado foram registradas. Picos ajudam a correlacionar atualizações, varreduras e mudanças de software. Uma tendência de risco exige uma base comparável e contexto adicional.

{{GRÁFICO_DE_TENDÊNCIA_DE_EVENTOS}}

Usar intervalos de 1 hora para 24h, 6 horas para 7d e dia de calendário para 30d. Exibir no horário de Recife; os intervalos das extremidades podem ser parciais.

### Severidade da vulnerabilidade

Usa `data.vulnerability.severity`, não o nível numérico da regra. As categorias apresentadas são **Baixo, Médio, Alto e Crítico**, com uma categoria separada para dados sem classificação.

{{GRÁFICO_DE_EVENTOS_POR_SEVERIDADE}}

Valores `Low`, `Medium`/`Moderate`, `High` e `Critical` são apresentados em português. Valores ausentes ou desconhecidos ficam como **Sem classificação**. A classificação não é inferida a partir de `rule.level`.

### Estados registrados nos eventos

Agrupa o estado em `data.vulnerability.status` registrado em cada evento. Isso ajuda a entender detecções e registros de resolução, sem transformar um histórico de eventos em saldo de pendências atuais.

| Estado registrado | Eventos |
|---|---:|
| Ativa no evento | {{N}} |
| Resolvida no evento | {{N}} |
| Outros estados informados | {{N}} |

Um evento de resolução não confirma que todas as instalações foram corrigidas. Um evento ativo antigo também não prova que o achado segue aberto. Não subtrair registros de resolução de registros ativos para calcular saldo de vulnerabilidades.

## 3. Ativos e pacotes observados

### Agentes com maior volume de eventos

Localiza os ativos que concentram registros para identificar donos de serviços e planejar validações. O volume não mede sozinho o risco ou a quantidade de falhas únicas.

{{GRÁFICO_DE_ATÉ_OITO_AGENTES_POR_VOLUME}}

**Leitura:** {{AGENTE_E_ID}}, {{EVENTOS}}, {{SERVIÇO_E_DONO_A_CONFIRMAR}}. Cardinalidades e listas de maiores volumes não medem cobertura sem inventário de referência.

### Pacotes com maior volume de eventos

Ajuda a organizar campanhas de atualização. Confirmar versão instalada, fornecedor, compatibilidade e janela de mudança antes da correção.

{{GRÁFICO_DE_ATÉ_OITO_PACOTES_POR_VOLUME}}

**Leitura:** {{PACOTE}}, {{EVENTOS}}, {{ATIVOS_E_VERSÕES_A_VALIDAR}}. As listas são parciais e podem ter erro de distribuição em agregações por termos.

## 4. CVEs e evidências técnicas

### CVEs mais frequentes

Lista até oito CVEs por volume de eventos, com categorias de severidade observadas e estimativa de agentes. Frequência não equivale a prioridade de risco; a mesma CVE pode ocorrer em múltiplos pacotes e ativos, com estados diferentes.

| CVE | Severidade nos eventos | Eventos | Agentes (estim.) |
|---|---|---:|---:|
| {{CVE}} | {{CATEGORIAS}} | {{N}} | {{N}} |

### Amostra técnica dos eventos mais recentes

Mostra o evento mais recente de cada CVE selecionada, limitado às três primeiras da lista. Serve como ponto inicial para investigação; não representa todas as ocorrências nem substitui a evidência de correção.

| CVE / estado | Agente | Pacote / versão |
|---|---|---|
| {{CVE / ESTADO_NO_EVENTO}} | {{AGENTE}} | {{PACOTE / VERSÃO}} |

Campos principais: `data.vulnerability.cve`, `data.vulnerability.severity`, `data.vulnerability.status`, `data.vulnerability.package.name`, `data.vulnerability.package.version`, `agent.id`, `agent.name` e `timestamp`. Dados ausentes devem ser identificados como não informados.

## 5. Plano de tratamento e acompanhamento

Converte os achados em ações verificáveis. A gestão confirma responsáveis, prioridade, prazo e eventuais exceções conforme o serviço afetado. Não há prazo de correção ou SLA presumido.

| Etapa | Ação e evidência esperada | Responsável sugerido |
|---|---|---|
| Validar | Confirmar CVE, versão instalada, exposição e dono; registrar evidência no chamado. | Segurança + dono do ativo |
| Priorizar | Considerar severidade, exposição, criticidade e exploração verificada em fonte confiável. | Segurança + gestão |
| Corrigir | Testar e aplicar versão recomendada pelo fornecedor ou mitigação validada em janela aprovada. | Infraestrutura / aplicação |
| Reavaliar | Executar nova avaliação e confrontar o inventário atual com a evidência de correção. | Operação + segurança |

Para cada ocorrência validada, registrar **CVE, ativo, pacote/versão, chamado, dono, prazo acordado, decisão, exceção aprovada e evidência de reavaliação**.

A presença de CVE não comprova exploração. Datas de publicação não equivalem à descoberta no ambiente. KEV, EPSS, exposição à internet, criticidade do negócio, SLA, tempo de correção e percentual de remediação não são calculados sem fontes adicionais e reconciliação de ocorrências.

## 6. Escopo técnico e qualidade dos dados

Documenta o recorte exato, os campos ausentes e os limites das agregações para permitir reprodução e avaliar a confiança na leitura.

| Parâmetro | Valor |
|---|---|
| Cliente (term exato) | {{CLIENTE}} |
| Grupo (term exato) | `rule.groups: vulnerability-detector` |
| Campo de tempo | `timestamp` |
| Início UTC (inclusive) | {{INÍCIO_UTC}} |
| Fim UTC (exclusive) | {{FIM_UTC}} |
| Extraído em UTC | {{EXTRAÇÃO_UTC}} |

| Verificação | Resultado |
|---|---|
| Timeout / falhas de shard | {{RESULTADO}} |
| Eventos sem agente | {{N}} |
| Eventos sem CVE | {{N}} |
| Eventos sem severidade | {{N}} |
| Eventos sem estado | {{N}} |
| Eventos sem pacote | {{N}} |

Só gerar o relatório quando a consulta confirmar a contagem exata e não houver timeout ou falha de shard. CVEs e agentes distintos são estimativas de cardinalidade. Listas de maiores volumes não são exaustivas e podem ter erro entre shards. Um evento com múltiplos valores pode participar de mais de uma categoria.

O recorte é histórico e não substitui uma consulta reconciliada ao inventário atual por ativo, CVE e pacote. O grupo solicitado é obrigatório: não ampliar automaticamente o filtro para outros grupos se o resultado estiver vazio.
