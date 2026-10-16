# Relatório de eventos Wazuh — {{CLIENTE}}

**Período:** {{INICIO_LOCAL}} a {{FIM_LOCAL}} ({{FUSO}})  
**Fonte:** {{INDEXADOR}}, índice `wazuh-alerts-*`  
**Filtro obrigatório:** `agent.labels.customer = {{CLIENTE}}` e `timestamp` entre {{INICIO_UTC}} (inclusive) e {{FIM_UTC}} (exclusive)  
**Extraído em:** {{DATA_HORA_EXTRACAO}}

## Resumo executivo

Foram encontrados **{{TOTAL}} alertas** com a tag do cliente. **{{NIVEL_10_MAIS}}** tiveram nível Wazuh 10 ou superior e **{{FALHAS_AUTENTICACAO}}** pertenciam ao grupo `authentication_failed`. {{SINTese_DOS_ACHADOS_E_IMPACTO_POTENCIAL}}

## Principais indicadores

| Indicador | Quantidade |
|---|---:|
| Alertas do cliente | {{TOTAL}} |
| Nível 10 ou superior | {{NIVEL_10_MAIS}} |
| Falhas de autenticação | {{FALHAS_AUTENTICACAO}} |
| Agentes com alertas | {{AGENTES_UNICOS}} |

## Agentes e regras com maior volume

| Agente | Alertas | Regra principal | Observação |
|---|---:|---|---|
| {{AGENTE}} | {{QUANTIDADE}} | {{REGRA}} | {{CONTEXTO}} |

## Eventos prioritários

| Prioridade | Regra / descrição | Agente | Alertas | Evidência e interpretação |
|---|---|---|---:|---|
| {{PRIORIDADE}} | {{REGRA_DESCRICAO}} | {{AGENTE}} | {{QUANTIDADE}} | {{EVIDENCIA}} |

## Tendência temporal

{{VOLUME_POR_HORA_PICOS_E_COMPARACAO_COM_LINHA_DE_BASE}}

### Gráfico 1 — Volume por hora

{{INSERIR_GRAFICO_DE_LINHA_COM_CONTAGEM_POR_HORA_NO_FUSO_LOCAL}}  
**Dados:** `timestamp`, quantidade de alertas por hora. Marcar horas parciais.

### Gráfico 2 — Agentes com maior volume

{{INSERIR_GRAFICO_DE_BARRAS_HORIZONTAIS_DOS_PRINCIPAIS_AGENTES}}  
**Dados:** `agent.name`, quantidade de alertas; ordenar do maior para o menor.

### Gráfico 3 — Regras de maior severidade

{{INSERIR_GRAFICO_DE_BARRAS_DAS_REGRAS_COM_NIVEL_10_OU_SUPERIOR}}  
**Dados:** `rule.id`, `rule.description`, `rule.level`, quantidade de alertas. Informar que contagens não representam incidentes únicos.

## Recomendações

1. {{ACAO_RESPONSAVEL_PRAZO}}
2. {{ACAO_RESPONSAVEL_PRAZO}}

## Método e limitações

Consulta OpenSearch/Wazuh Indexer:

```json
{
  "size": 0,
  "track_total_hits": true,
  "query": {
    "bool": {
      "filter": [
        { "term": { "agent.labels.customer": "{{CLIENTE}}" } },
        { "range": { "timestamp": { "gte": "{{INICIO_UTC}}", "lt": "{{FIM_UTC}}" } }
      ]
    }
  }
}
```

Registrar se houve *timeout*, falha de shard, ingestão tardia, diferenças entre consultas ou campos ausentes. Contagens representam alertas; não equivalem automaticamente a incidentes únicos. Documentar separadamente a validação dos eventos brutos e qualquer confirmação de impacto.
