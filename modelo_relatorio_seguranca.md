# Relatório de Segurança — {{CLIENTE}}

**Período selecionado:** {{PERIODO_24H_7D_30D}}<br>
**Período:** {{INICIO_LOCAL}} a {{FIM_LOCAL}} ({{FUSO}})  
**Fonte:** indexador de alertas<br>
**Filtro obrigatório:** `agent.labels.customer = {{CLIENTE}}` e `timestamp` entre {{INICIO_UTC}} (inclusive) e {{FIM_UTC}} (exclusive)  
**Extraído em:** {{DATA_HORA_EXTRACAO}}

## Resumo executivo

Foram encontrados **{{TOTAL}} alertas** com a tag do cliente. **{{NIVEL_10_MAIS}}** tiveram nível 10 ou superior e **{{FALHAS_AUTENTICACAO}}** pertenciam ao grupo `authentication_failed`. {{SINTESE_DOS_ACHADOS_E_IMPACTO_POTENCIAL}}

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

{{VOLUME_POR_INTERVALO_PICOS_E_COMPARACAO_COM_LINHA_DE_BASE}}

### Gráfico 1 — Volume por {{INTERVALO_DO_GRAFICO}}

{{INSERIR_GRAFICO_DE_LINHA_COM_CONTAGEM_POR_INTERVALO_NO_FUSO_LOCAL}}<br>
**Dados:** `timestamp`, quantidade de alertas por intervalo. Usar 1 hora para 24h, 6 horas para 7d e 1 dia para 30d. Marcar intervalos parciais.

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

Consulta ao indexador de alertas:

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
