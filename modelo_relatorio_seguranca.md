# Relatório de Segurança - {{CLIENTE}}

**Período:** {{24H / 7D / 30D}} - {{INICIO_LOCAL}} a {{FIM_LOCAL}} (America/Recife)<br>
**Extraído em UTC:** {{DATA_HORA_EXTRACAO}}<br>
**Classificação:** Confidencial<br>
**Fonte:** indexador de alertas<br>
**Filtro obrigatório:** `agent.labels.customer = {{CLIENTE}}` (termo exato), com intervalo UTC semiaberto em `timestamp`.

Preencher os campos entre chaves com evidências. Preservar as descrições das seções e informar dados indisponíveis e validações pendentes.

## 1. Visão executiva

### Resumo executivo

Resume o que merece atenção e ajuda a gestão a direcionar a equipe. A avaliação de impacto depende dos serviços envolvidos e da validação dos sinais registrados.

Foram registrados **{{TOTAL}} alertas**, incluindo **{{ALTOS_E_CRITICOS}} ({{PERCENTUAL_ALTOS_E_CRITICOS}})** classificados como Alto ou Crítico e **{{FALHAS_AUTENTICACAO}} ({{PERCENTUAL_FALHAS_NO_TOTAL}})** de falha de autenticação. {{SINAIS_RELEVANTES_E_CONTEXTO_DOS_SERVICOS}}. {{O_QUE_FOI_CONFIRMADO_E_O_QUE_AGUARDA_ANALISE}}.

Se não houver alertas, verificar a cobertura e a saúde da coleta antes de interpretar a ausência de registros.

### Principais indicadores

Mostram a carga recebida e os recortes para triagem. Percentuais ajudam a dimensionar o trabalho; uma tendência requer comparação entre períodos equivalentes e com a mesma cobertura.

| Indicador | Resultado | Como interpretar |
|---|---|---|
| Alertas no período | {{TOTAL}} | Volume recebido; pode repetir uma mesma condição. |
| EPS médio (alertas) | {{EPS_MEDIO}} | Total de alertas indexados dividido pela duração analisada em segundos. |
| Alto ou Crítico | {{N}} ({{%_DO_TOTAL}}) | Recorte para validação prioritária neste relatório. |
| Falhas de autenticação | {{N}} ({{%_DO_TOTAL_DE_ALERTAS}}) | Direciona a investigação de contas e acessos. |
| Agentes com alertas | {{QUANTIDADE_E_TIPO_DE_CONTAGEM}} | Fontes observadas; identificar estimativa ou limite inferior. |
| Média de alertas por hora | {{TOTAL_DIVIDIDO_PELAS_HORAS}} | Apoia o dimensionamento da carga operacional. |

Alertas Altos ou Críticos e falhas de autenticação podem se sobrepor. A participação de falhas no total de alertas não é a taxa de falha das tentativas de autenticação. Não somar recortes sobrepostos.

**Cálculo do EPS médio:** `total de alertas indexados / (fim UTC - início UTC em segundos)`. Usar toda a duração do período, incluindo intervalos sem alertas. A fonte não contabiliza os eventos processados que não geraram alerta.

### Encaminhamento para a gestão

Transforma os números em decisões e responsabilidades. Considerar criticidade do serviço, exposição do ativo e evidências confirmadas ao pactuar a urgência.

{{DECISAO_SUGERIDA}}. {{DONO_DO_SERVICO_A_CONFIRMAR}}. {{RECURSO_OU_APOIO_NECESSARIO}}. {{IMPACTO_CONFIRMADO_OU_PENDENTE}}.

## 2. Volume e severidade

### Tendência temporal

Localiza concentrações de alertas e orienta a correlação com mudanças, rotinas e tentativas de acesso. Um pico precisa de investigação para explicar sua causa.

{{GRAFICO_DE_LINHA_COM_CONTAGEM_POR_INTERVALO}}

Usar 1 hora para 24h, 6 horas para 7d e dia de calendário de Recife para 30d. Incluir intervalos sem alertas e indicar o primeiro e o último como potencialmente parciais.

**Leitura:** {{INICIO_DO_MAIOR_INTERVALO}}, {{CONTAGEM_E_PARTICIPACAO_NO_TOTAL}}. {{MUDANCA_OU_ROTINA_A_VERIFICAR}}. Só afirmar aumento ou anomalia com base comparável e critérios definidos.

### Distribuição por severidade

Agrupa as categorias de severidade para organizar a triagem. O impacto no negócio depende do contexto e da evidência, além da severidade registrada.

{{GRAFICO_DE_BARRAS_COM_CONTAGEM_E_PERCENTUAL_POR_SEVERIDADE}}

**Categorias apresentadas:** Baixo, Médio, Alto e Crítico.

Mostrar separadamente alertas sem classificação de severidade. Os alertas Altos e Críticos orientam a triagem prioritária. O impacto no negócio exige validação.

**Vocabulário:** alerta é um registro de condição detectada; regra é o critério que o gerou; agente ou coletor é a fonte que o encaminhou; incidente é uma ocorrência validada que requer tratamento no processo de resposta.

## 3. Ativos e regras com maior volume

### Principais agentes ou coletores

Mostra onde os registros se concentram para direcionar a investigação e a revisão de rotinas. Um coletor pode representar vários sistemas; confirmar a origem real e o dono do serviço.

{{GRAFICO_DOS_CINCO_MAIORES_AGENTES}}

**Leitura:** {{AGENTE_E_ID}}, {{CONTAGEM}}, {{PERCENTUAL_DO_TOTAL}}. {{COLETOR_CENTRAL_OU_ATIVO_FINAL}}. {{SERVICOS_E_DONO_A_VALIDAR}}.

### Regras mais frequentes

Mostra quais condições geraram mais registros. Atividade esperada, falha operacional e comportamento suspeito exigem tratamentos diferentes; o contexto orienta eventual ajuste da detecção.

| Regra | Sinal registrado | Alertas | % do total |
|---|---|---:|---:|
| {{ID}} | {{DESCRICAO}} | {{N}} | {{%}} |

{{EXPLICACAO_DA_CONCENTRACAO_E_VALIDACOES_NECESSARIAS}}. Informar limites das listas, abreviações e erro de agregação relevante. Listas dos maiores volumes não representam todo o inventário.

## 4. Acessos e sinais para investigação

### Falhas de autenticação

Ajuda a investigar contas, origens e serviços com falhas recorrentes. Credenciais desatualizadas, configuração e tentativa indevida são hipóteses a validar com eventos brutos.

{{GRAFICO_DAS_FALHAS_POR_AGENTE}}

**Leitura:** {{N}} alertas de falha, {{%_DO_TOTAL_DE_ALERTAS}} do total. {{CONTA_ORIGEM_E_SERVICO_QUANDO_VALIDADOS}}. {{SUCESSO_POSTERIOR}}. Uma taxa de falha exige o total de tentativas com semântica e cobertura equivalentes.

### Alertas Altos e Críticos

Reúne os sinais classificados como Alto ou Crítico para triagem. Confirmar evidências e avaliar o ativo e o serviço antes de classificar um incidente ou seu impacto.

| Regra | Sinal registrado | Alertas | Agente principal |
|---|---|---:|---|
| {{ID}} | {{DESCRICAO}} | {{N}} | {{AGENTE}} |

**Validação:** {{EVIDENCIA}}; {{HIPOTESE}}; {{ORIGEM_CONTA_PROCESSO_E_ATIVO}}; {{MUDANCA_AUTORIZADA}}; {{DECISAO_OU_PENDENCIA}}. Correlacionar repetições antes de contar incidentes únicos.

## 5. Plano de ação e acompanhamento

### Ações propostas

Define entregas verificáveis para reduzir a incerteza e tratar os achados. Responsáveis são sugeridos por função; a gestão confirma dono, prioridade e prazo com o serviço afetado.

| Seq. | Ação e evidência de conclusão | Responsável sugerido |
|---|---|---|
| 1 | {{ACAO_E_RESULTADO_VERIFICAVEL}} | {{FUNCAO}} |
| 2 | {{ACAO_E_RESULTADO_VERIFICAVEL}} | {{FUNCAO}} |

### Como acompanhar a execução

Mostra se a análise gerou uma ação concluída. Os registros tornam a evolução auditável e ajudam a remover pendências.

Registrar **{{CHAMADO}}**, **{{DONO_CONFIRMADO}}**, **{{PRAZO_ACORDADO}}**, **{{ESTADO}}**, **{{DECISAO}}** e **{{EVIDENCIA_DE_CONCLUSAO}}**. Não presumir atendimento ou cumprimento de SLA sem dados do fluxo de chamados.

### Indicadores úteis para a próxima evolução

As informações abaixo aumentam o valor gerencial e técnico, mas exigem fontes adicionais. Declarar quais ainda não foram apuradas.

| Indicador | Para que serve | Dados necessários |
|---|---|---|
| Variação frente ao período anterior | Identificar crescimento e recorrência. | Outro intervalo de igual duração e mesma cobertura. Se a base anterior for zero, informar "sem base percentual". |
| Cobertura e criticidade dos ativos | Relacionar sinais a serviços essenciais e lacunas de monitoramento. | Inventário, dono, criticidade e estado da coleta. |
| Tempo de resposta e cumprimento de SLA | Avaliar eficiência e pendências. | Chamados com abertura, reconhecimento, resolução, estado e metas acordadas. |
| Incidentes confirmados e impacto | Medir resultado e exposição do negócio. | Validação do analista, deduplicação, serviço afetado e impacto registrado. |
| Origens, contas e técnicas observadas | Identificar recorrência e organizar hipóteses. | Campos normalizados por fonte e validação das origens, contas e técnicas de ataque. |

## 6. Referência técnica e confiança dos dados

### Escopo reproduzível

Documenta o cliente e o intervalo para permitir reprodução e rastreabilidade. Usar UTC na consulta e America/Recife na apresentação dos gráficos.

```json
{
  "size": 0,
  "track_total_hits": true,
  "query": {
    "bool": {
      "filter": [
        { "term": { "agent.labels.customer": "{{CLIENTE}}" } },
        { "range": { "timestamp": { "gte": "{{INICIO_UTC}}", "lt": "{{FIM_UTC}}" } } }
      ]
    }
  }
}
```

**Extração:** {{DATA_HORA_UTC}}. Para reproduzir achados, acrescentar `rule.id` e, quando disponível, `agent.id` ao filtro do cliente e do tempo. Recuperar origem, conta, processo e evento bruto necessários à validação.

### Qualidade observável na extração

Ajuda o leitor a entender a confiança disponível. Campos ausentes, ingestão e lacunas podem limitar a análise; ausência de alertas deve ser confrontada com inventário e saúde da coleta.

| Verificação | Resultado | Consequência |
|---|---|---|
| Total exato, timeout e falhas de shard | {{RESULTADO}} | Consulta incompleta não sustenta um relatório final. |
| Sem identificação de agente | {{CONTAGEM_OU_NAO_COLETADO}} | Limita a atribuição a fontes. |
| Sem classificação de severidade | {{CONTAGEM_OU_NAO_COLETADO}} | Limita a distribuição por severidade. |
| Primeiro e último alerta | {{HORARIOS_OU_NAO_COLETADO}} | Mostra atividade observada; não comprova continuidade da coleta. |

### Limites de interpretação

Explicita restrições para que a gestão use as conclusões com o grau adequado de confiança e a equipe saiba o que ainda precisa validar.

Registrar cobertura, ingestão tardia, diferenças entre consultas, campos ausentes, erro de agregação e validação dos eventos brutos. Agentes com alertas são fontes observadas; cobertura exige inventário. Cardinalidade é uma estimativa; "ao menos" é um limite inferior quando a lista foi truncada. Contagens podem repetir condições e se sobrepor entre recortes. Histórico, incidentes confirmados, impacto e tempos de atendimento exigem evidência adicional.

Referência de processo: [NIST SP 800-61 Rev. 3 (2025)](https://csrc.nist.gov/pubs/sp/800/61/r3/final).
