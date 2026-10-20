"""Query Wazuh Indexer and render a customer security report as a PDF."""

from __future__ import annotations

import base64
import html
import ipaddress
import json
import re
import ssl
import tempfile
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from pypdf import PdfReader, PdfWriter
from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Flowable, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)


ROOT = Path(__file__).resolve().parent
LETTERHEAD = ROOT / "assets" / "timbrado_confidencial.pdf"
DEFAULT_OUTPUT_DIR = Path.home() / "Relatorios Wazuh"
LOCAL_TZ = ZoneInfo("America/Recife")
ORANGE = colors.HexColor("#e85b0b")
DARK = colors.HexColor("#262626")
MID = colors.HexColor("#626262")
LIGHT = colors.HexColor("#f7f2ee")
GRID = colors.HexColor("#dedede")
PERIODS = {
    24: ("24 horas", "1h", "hora"),
    168: ("7 dias", "6h", "6 horas"),
    720: ("30 dias", "1d", "dia"),
}
SEVERITY_BANDS = ((0, 6, "Baixo"), (7, 11, "Médio"), (12, 14, "Alto"), (15, 15, "Crítico"))
SEVERITY_LEGEND = "Severidades: Baixo, Médio, Alto e Crítico."


def validate_customer(customer: str) -> str:
    customer = customer.strip()
    if not customer:
        raise ValueError("Informe o valor de agent.labels.customer.")
    if len(customer) > 128:
        raise ValueError("O valor do cliente é longo demais.")
    return customer


def indexer_url(ip: str, port: str | int) -> str:
    """Build the HTTPS endpoint from a literal IPv4 or IPv6 address and port."""
    try:
        address = ipaddress.ip_address(ip.strip())
    except ValueError as error:
        raise ValueError("Informe um endereço IP válido para o indexador.") from error
    try:
        port_number = int(str(port).strip())
    except ValueError as error:
        raise ValueError("Informe uma porta numérica válida.") from error
    if not 1 <= port_number <= 65535:
        raise ValueError("A porta deve estar entre 1 e 65535.")
    host = f"[{address}]" if address.version == 6 else str(address)
    return f"https://{host}:{port_number}"


def query_body(customer: str, start: datetime, end: datetime, hours: int = 24) -> dict:
    """Use an exact term filter for the customer on every aggregation."""
    customer = validate_customer(customer)
    if hours not in PERIODS:
        raise ValueError("Escolha um período de 24 horas, 7 dias ou 30 dias.")
    scope = [
        {"term": {"agent.labels.customer": customer}},
        {"range": {"timestamp": {"gte": start.isoformat(), "lt": end.isoformat()}}},
    ]
    high_scope = {"bool": {"filter": scope + [{"range": {"rule.level": {"gte": 12, "lte": 15}}}]}}
    failed_scope = {"bool": {"filter": scope + [{"term": {"rule.groups": "authentication_failed"}}]}}
    histogram = {
        "field": "timestamp", "time_zone": LOCAL_TZ.key, "min_doc_count": 0,
        "extended_bounds": {"min": start.isoformat(),
                            "max": (end - timedelta(microseconds=1)).isoformat()},
    }
    histogram["calendar_interval" if hours == 720 else "fixed_interval"] = PERIODS[hours][1]
    return {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": scope}},
        "aggs": {
            "agents_observed": {"cardinality": {"field": "agent.id", "precision_threshold": 40000}},
            "missing_agent": {"missing": {"field": "agent.id"}},
            "missing_level": {"missing": {"field": "rule.level"}},
            "first_event": {"min": {"field": "timestamp"}},
            "last_event": {"max": {"field": "timestamp"}},
            "by_level": {"terms": {"field": "rule.level", "size": 20}},
            "by_hour": {"date_histogram": histogram},
            "by_agent": {"terms": {"field": "agent.id", "size": 30}, "aggs": {
                "name": {"terms": {"field": "agent.name", "size": 1}},
            }},
            "by_rule": {"terms": {"field": "rule.id", "size": 20}, "aggs": {
                "description": {"terms": {"field": "rule.description", "size": 1}},
            }},
            "high": {"filter": high_scope, "aggs": {
                "rules": {"terms": {"field": "rule.id", "size": 30}, "aggs": {
                    "description": {"terms": {"field": "rule.description", "size": 1}},
                    "agents": {"terms": {"field": "agent.name", "size": 3}},
                }},
            }},
            "failed_auth": {"filter": failed_scope, "aggs": {
                "agents": {"terms": {"field": "agent.name", "size": 10}},
            }},
        },
    }


def search_alerts(base_url: str, username: str, password: str, body: dict, *,
                  hours: int, verify_tls: bool, reject_redirects: bool) -> dict:
    """Shared bounded, TLS-aware transport for independently scoped alert reports."""
    base_url = base_url.strip().rstrip("/")
    if not base_url.startswith("https://") or not username.strip() or not password:
        raise ValueError("Configure uma conexão HTTPS e credenciais válidas.")
    if hours not in PERIODS:
        raise ValueError("Escolha um período de 24 horas, 7 dias ou 30 dias.")
    token = base64.b64encode(f"{username.strip()}:{password}".encode()).decode()
    request = urllib.request.Request(
        f"{base_url}/wazuh-alerts-*/_search",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Basic {token}", "Content-Type": "application/json"},
        method="POST",
    )
    context = None if verify_tls else ssl._create_unverified_context()
    class RejectRedirects(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise urllib.error.HTTPError(req.full_url, code, "Redirecionamento recusado", headers, fp)

    def open_request():
        timeout = {24: 60, 168: 180, 720: 300}[hours]
        if reject_redirects:
            opener = urllib.request.build_opener(
                urllib.request.HTTPSHandler(context=context), RejectRedirects())
            return opener.open(request, timeout=timeout)
        return urllib.request.urlopen(request, context=context, timeout=timeout)

    try:
        with open_request() as response:
            result = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code == 401:
            raise RuntimeError("Autenticação recusada pelo indexador (HTTP 401).") from error
        raise RuntimeError(f"Consulta recusada pelo indexador (HTTP {error.code}).") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"Não foi possível conectar ao indexador: {error.reason}") from error
    if result.get("timed_out") or result.get("_shards", {}).get("failed"):
        raise RuntimeError("A consulta não terminou completamente; tente novamente.")
    if result.get("hits", {}).get("total", {}).get("relation") != "eq":
        raise RuntimeError("O indexador não confirmou uma contagem exata.")
    return result


def fetch_summary(
    customer: str,
    base_url: str,
    username: str,
    password: str,
    *,
    hours: int = 24,
    verify_tls: bool = False,
    reject_redirects: bool = False,
    now: datetime | None = None,
) -> dict:
    customer = validate_customer(customer)
    base_url = base_url.strip().rstrip("/")
    if not base_url.startswith("https://"):
        raise ValueError("Use uma URL HTTPS para o indexador.")
    if not username.strip() or not password:
        raise ValueError("Informe o usuário e a senha do indexador.")
    if hours not in PERIODS:
        raise ValueError("Escolha um período de 24 horas, 7 dias ou 30 dias.")
    end = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = end - timedelta(hours=hours)
    body = query_body(customer, start, end, hours)
    result = search_alerts(base_url, username, password, body, hours=hours,
                           verify_tls=verify_tls, reject_redirects=reject_redirects)
    return {"customer": customer, "start_utc": start.isoformat(), "end_utc": end.isoformat(),
            "hours": hours, "priority_scope": "high_critical",
            "extracted_at_utc": datetime.now(timezone.utc).isoformat(),
            "index": "wazuh-alerts-*", "result": result}


def _register_fonts() -> None:
    if "ReportSans" in pdfmetrics.getRegisteredFontNames():
        return
    regular = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf")
    bold = Path("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf")
    if not regular.exists() or not bold.exists():
        raise RuntimeError("Fonte DejaVu Sans não encontrada. Instale fonts-dejavu-core.")
    pdfmetrics.registerFont(TTFont("ReportSans", str(regular)))
    pdfmetrics.registerFont(TTFont("ReportSans-Bold", str(bold)))


def _styles() -> dict:
    return {
        "title": ParagraphStyle("title", fontName="ReportSans-Bold", fontSize=15.8, leading=20,
                                textColor=DARK, spaceAfter=8),
        "subtitle": ParagraphStyle("subtitle", fontName="ReportSans", fontSize=8.4, leading=12,
                                   textColor=MID, spaceAfter=7),
        "h1": ParagraphStyle("h1", fontName="ReportSans-Bold", fontSize=10.6, leading=14,
                             textColor=DARK, spaceBefore=11, spaceAfter=5, keepWithNext=True),
        "body": ParagraphStyle("body", fontName="ReportSans", fontSize=8.4, leading=12.1,
                               textColor=DARK, spaceAfter=6),
        "small": ParagraphStyle("small", fontName="ReportSans", fontSize=7.3, leading=10.3,
                                textColor=DARK, spaceAfter=4),
        "caption": ParagraphStyle("caption", fontName="ReportSans", fontSize=7.1, leading=10,
                                  textColor=MID, spaceAfter=5),
        "guide": ParagraphStyle("guide", fontName="ReportSans", fontSize=7.6, leading=10.7,
                                textColor=MID, spaceAfter=6, keepWithNext=True),
        "cell": ParagraphStyle("cell", fontName="ReportSans", fontSize=7.1, leading=9.7,
                               textColor=DARK),
        "head": ParagraphStyle("head", fontName="ReportSans-Bold", fontSize=7.1, leading=9.7,
                               textColor=colors.white),
    }


def _number(value: int) -> str:
    return f"{value:,}".replace(",", ".")


def _description(bucket: dict) -> str:
    descriptions = bucket.get("description", {}).get("buckets", [])
    return descriptions[0]["key"] if descriptions else "Descrição indisponível"


def _agent_name(bucket: dict) -> str:
    names = bucket.get("name", {}).get("buckets", [])
    return names[0]["key"] if names else bucket["key"]


def _safe(value: object) -> str:
    return html.escape(_public_text(value), quote=False)


def _public_text(value: object) -> str:
    """Keep the collection platform's name out of customer-facing PDFs."""
    neutral = re.sub(r"wazuh[-_ ]+agent\b", "agente de segurança", str(value),
                     flags=re.IGNORECASE)
    neutral = re.sub(r"wazuh", "plataforma de segurança", neutral, flags=re.IGNORECASE)
    def category(match):
        low = int(match.group(1))
        high = int(match.group(2)) if match.group(2) else 15 if match.group(3) else low
        names = [name for start, end, name in SEVERITY_BANDS if start <= high and end >= low]
        return " / ".join(names) if names else "Sem classificação"
    return re.sub(r"\b(?:n[ií]ve(?:l|is)|levels?|lv|severity|severidade)\s*[:=]?\s*(\d{1,2})(?!\d)"
                  r"(?:\s*(?:a|até|to|[-–])\s*(\d{1,2})(?!\d))?(\s*(?:ou superior|\+))?",
                  category, neutral, flags=re.IGNORECASE)


class BarChart(Flowable):
    def __init__(self, items: list[tuple[str, int]], *, width: float = 450, row: float = 23):
        super().__init__()
        self.items = items
        self.width = width
        self.row = row
        self.height = max(48, len(items) * row + 15)

    def draw(self):
        c = self.canv
        if not self.items:
            c.setFont("ReportSans", 8)
            c.setFillColor(MID)
            c.drawString(0, 18, "Nenhum alerta neste recorte.")
            return
        maximum = max(value for _, value in self.items) or 1
        label_width = 170
        plot_width = self.width - label_width - 50
        for index, (label, value) in enumerate(self.items):
            label = _public_text(label)
            y = self.height - 18 - index * self.row
            c.setFont("ReportSans", 7.2)
            c.setFillColor(DARK)
            while pdfmetrics.stringWidth(label, "ReportSans", 7.2) > label_width - 7:
                label = label[:-2]
            c.drawString(0, y, label)
            c.setFillColor(LIGHT)
            c.rect(label_width, y - 2, plot_width, 10, fill=1, stroke=0)
            c.setFillColor(ORANGE)
            c.rect(label_width, y - 2, plot_width * value / maximum, 10, fill=1, stroke=0)
            c.setFillColor(DARK)
            c.drawRightString(self.width, y, _number(value))


class TrendChart(Flowable):
    def __init__(self, buckets: list[dict], *, daily: bool = False,
                 width: float = 450, height: float = 150):
        super().__init__()
        self.buckets = buckets
        self.daily = daily
        self.width = width
        self.height = height

    def draw(self):
        c = self.canv
        if not self.buckets:
            c.setFont("ReportSans", 8)
            c.setFillColor(MID)
            c.drawString(0, self.height / 2, "Nenhum alerta no período.")
            return
        values = [bucket["doc_count"] for bucket in self.buckets]
        left, bottom = 32, 21
        plot_width, plot_height = self.width - left - 8, self.height - bottom - 10
        maximum = max(values) * 1.08 or 1
        c.setStrokeColor(GRID)
        c.setLineWidth(0.5)
        for fraction in (0, 0.5, 1):
            y = bottom + plot_height * fraction
            c.line(left, y, self.width - 8, y)
            c.setFillColor(MID)
            c.setFont("ReportSans", 6.1)
            c.drawRightString(left - 4, y - 2, _number(round(maximum * fraction)))
        denominator = max(1, len(values) - 1)
        points = [(left + plot_width * i / denominator, bottom + plot_height * value / maximum)
                  for i, value in enumerate(values)]
        c.setStrokeColor(ORANGE)
        c.setLineWidth(1.7)
        for a, b in zip(points, points[1:]):
            c.line(*a, *b)
        if len(points) == 1:
            c.setFillColor(ORANGE)
            c.circle(*points[0], 2, fill=1, stroke=0)
        ticks = sorted(set((0, (len(values) - 1) // 4, (len(values) - 1) // 2,
                            3 * (len(values) - 1) // 4, len(values) - 1)))
        for index in ticks:
            stamp = datetime.fromtimestamp(self.buckets[index]["key"] / 1000, timezone.utc).astimezone(LOCAL_TZ)
            c.setFont("ReportSans", 6.1)
            c.setFillColor(MID)
            c.drawCentredString(points[index][0], 7,
                                stamp.strftime("%d/%m" if self.daily else "%d/%m %Hh"))


def _table(rows: list[list[str]], widths: list[int], styles: dict) -> Table:
    data = [[Paragraph(_safe(cell), styles["head" if index == 0 else "cell"]) for cell in row]
            for index, row in enumerate(rows)]
    table = Table(data, colWidths=widths, repeatRows=1, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7), ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("BACKGROUND", (0, 0), (-1, 0), ORANGE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("LINEBELOW", (0, -1), (-1, -1), 0.4, GRID),
    ]))
    return table


def _page_chrome(canvas, doc):
    # The supplied letterhead has a bordered watermark in the reading area.
    # Cover that area while retaining the original header and footer.
    canvas.setFillColor(colors.white)
    canvas.rect(70, 145, 455, 590, fill=1, stroke=0)
    canvas.setFillColor(MID)
    canvas.setFont("ReportSans", 7)
    canvas.drawRightString(520, 122, f"Página {doc.page}")


SECTION_NOTES = {
    "summary": "Resume o que merece atenção no período e orienta a alocação de pessoas para análise. Os achados são sinais registrados pelas regras e precisam de contexto do negócio para definir impacto.",
    "indicators": "Os indicadores mostram a carga de alertas e os recortes para triagem. Use as proporções para dimensionar o trabalho e comparar períodos equivalentes quando houver uma referência histórica.",
    "decisions": "Transforma os números em encaminhamentos para a gestão. A criticidade do serviço, a exposição do ativo e a confirmação das evidências devem orientar a urgência de cada decisão.",
    "trend": "Mostra quando os alertas se concentraram. Picos ajudam a localizar janelas de investigação e a correlacionar mudanças, rotinas e tentativas de acesso; a causa precisa ser verificada nos eventos.",
    "severity": "Agrupa os alertas nas categorias Baixo, Médio, Alto e Crítico. A distribuição ajuda a organizar a triagem e a dimensionar a fila de análise. A severidade, isoladamente, não determina o impacto no negócio.",
    "agents": "Identifica os ativos ou coletores que concentram registros. Isso direciona a investigação e a revisão de rotinas. Um coletor pode representar vários sistemas, por isso a origem real deve ser confirmada.",
    "rules": "Explica quais condições foram mais registradas. Regras frequentes podem indicar atividade esperada, falha operacional ou comportamento suspeito; revisar o contexto evita conclusões baseadas apenas no volume.",
    "auth": "Mostra registros de falha de autenticação. A concentração ajuda a investigar contas, origens e serviços; credenciais desatualizadas, erro de configuração e tentativa indevida são hipóteses a validar.",
    "priority": "Reúne alertas classificados como Alto ou Crítico para orientar a triagem. A equipe deve confirmar as evidências e avaliar o serviço afetado antes de classificar um incidente ou seu impacto.",
    "actions": "Propõe entregas verificáveis para reduzir a incerteza e tratar os achados. O responsável é sugerido por função; a gestão deve confirmar o dono, o prazo e a prioridade no fluxo de atendimento.",
    "followup": "Permite acompanhar se a análise gerou uma ação concluída. Registrar chamado, dono, prazo, estado e evidência de conclusão torna a evolução auditável e ajuda a remover pendências.",
    "evolution": "Indica informações adicionais que aumentariam o valor do relatório. Esses indicadores dependem de outras fontes e ainda não são calculados automaticamente a partir desta consulta.",
    "scope": "Documenta exatamente o cliente e o intervalo consultados para permitir reprodução técnica e rastreabilidade. As datas abaixo estão em UTC; os gráficos e a leitura executiva usam o horário de Recife.",
    "quality": "Mostra quais evidências de qualidade estão disponíveis na extração. Campos ausentes e lacunas de coleta podem limitar a análise; ausência de alertas deve ser confrontada com o inventário e a saúde da coleta.",
    "limits": "Explicita os limites para que a gestão use as conclusões com o grau de confiança adequado e a equipe técnica saiba o que ainda precisa validar.",
}


def _percent(value: int, total: int) -> str:
    ratio = value / total * 100 if total else 0
    if 0 < ratio < 0.001:
        return "menos de 0,001%"
    precision = 3 if 0 < ratio < 0.01 else 2 if 0 < ratio < 0.1 else 1
    return f"{ratio:.{precision}f}".replace(".", ",") + "%"


def _average_eps(snapshot: dict) -> str:
    start = datetime.fromisoformat(snapshot["start_utc"])
    end = datetime.fromisoformat(snapshot["end_utc"])
    seconds = (end - start).total_seconds()
    if seconds <= 0:
        raise ValueError("O período deve ter duração positiva para calcular o EPS médio.")
    rate = snapshot["result"]["hits"]["total"]["value"] / seconds
    if 0 < rate < 0.0001:
        return "menos de 0,0001"
    precision = 4 if 0 < rate < 0.01 else 2
    return f"{rate:,.{precision}f}".replace(",", "_").replace(".", ",").replace("_", ".")


def _observed_agents(aggregations: dict) -> str:
    if "agents_observed" in aggregations:
        return _number(int(aggregations["agents_observed"]["value"])) + " (estim.)"
    terms = aggregations.get("by_agent", {})
    count = len(terms.get("buckets", []))
    if terms.get("sum_other_doc_count") == 0 and terms.get("doc_count_error_upper_bound") == 0:
        return _number(count)
    return f"Ao menos {_number(count)}"


def _severity_items(aggregations: dict, total: int) -> list[tuple[str, int]]:
    counts = [0, 0, 0, 0]
    for bucket in aggregations.get("by_level", {}).get("buckets", []):
        try:
            level = int(bucket["key"])
        except (ValueError, TypeError):
            continue
        for index, (low, high, _) in enumerate(SEVERITY_BANDS):
            if low <= level <= high:
                counts[index] += bucket["doc_count"]
                break
    items = [(f"{name}: {_percent(count, total)}", count)
             for (_, _, name), count in zip(SEVERITY_BANDS, counts)]
    other = max(0, total - sum(counts))
    if other:
        items.append((f"Sem classificação / outros ({_percent(other, total)})", other))
    return items


def _priority_data(snapshot: dict) -> tuple[int, list, bool]:
    aggs = snapshot["result"]["aggregations"]
    if snapshot.get("priority_scope") == "high_critical":
        return aggs["high"]["doc_count"], aggs["high"]["rules"]["buckets"], True
    # Old extracts used a different selection. Their rule details cannot be relabeled safely.
    items = _severity_items(aggs, snapshot["result"]["hits"]["total"]["value"])
    return items[2][1] + items[3][1], [], False


def _section(title: str, key: str, styles: dict) -> list:
    return [Paragraph(title, styles["h1"]), Paragraph(SECTION_NOTES[key], styles["guide"])]


def _quality_rows(snapshot: dict) -> list[list[str]]:
    result = snapshot["result"]
    aggs = result["aggregations"]
    rows = [["Verificação", "Resultado e interpretação"]]
    complete = result.get("timed_out") is False and result.get("_shards", {}).get("failed") == 0
    rows.append(["Execução da consulta", "Sem timeout e sem falhas de shard." if complete
                 else "Consultar o registro da extração original; confirmação indisponível."])
    for key, title in (("missing_agent", "Alertas sem identificação de agente"),
                       ("missing_level", "Alertas sem classificação de severidade")):
        value = aggs.get(key, {}).get("doc_count")
        rows.append([title, _number(value) if value is not None else "Não coletado na extração original."])
    for key, title in (("first_event", "Primeiro alerta no recorte"), ("last_event", "Último alerta no recorte")):
        metric = aggs.get(key)
        value = metric.get("value") if metric else None
        if value is not None:
            stamp = datetime.fromtimestamp(value / 1000, timezone.utc).astimezone(LOCAL_TZ)
            display = stamp.strftime("%d/%m/%Y %H:%M:%S") + " (Recife)"
        else:
            display = "Nenhum alerta no recorte." if metric else "Não coletado na extração original."
        rows.append([title, display])
    return rows


EVOLUTION_ROWS = [
    ["Indicador a incorporar", "Valor para a gestão / fonte necessária"],
    ["Variação frente ao período anterior", "Identificar crescimento e recorrência. Requer consulta a outro intervalo de igual duração e mesma cobertura."],
    ["Cobertura e criticidade dos ativos", "Relacionar sinais aos serviços essenciais e lacunas de monitoramento. Requer inventário, dono, criticidade e estado da coleta."],
    ["Tempo de resposta e cumprimento de SLA", "Avaliar eficiência e pendências da operação. Requer chamados com abertura, reconhecimento, resolução, estado e metas acordadas."],
    ["Incidentes confirmados e impacto", "Medir resultado e exposição do negócio. Requer validação do analista, deduplicação, serviço afetado e impacto registrado."],
]
TERMS_NOTE = ("<b>Vocabulário:</b> alerta é um registro de condição detectada; regra é o critério que o gerou; "
              "agente ou coletor é a fonte que o encaminhou; incidente é uma ocorrência validada que requer "
              "tratamento no processo de resposta.")


def _story(snapshot: dict) -> list:
    styles = _styles()
    P = lambda text, style="body": Paragraph(text, styles[style])
    S = lambda title, key: _section(title, key, styles)
    customer = snapshot["customer"]
    hours = snapshot.get("hours", 24)
    if hours not in PERIODS:
        raise ValueError("Período do relatório inválido.")
    range_label, _, bucket_label = PERIODS[hours]
    result = snapshot["result"]
    aggs = result["aggregations"]
    total = result["hits"]["total"]["value"]
    high, high_rules, priority_details_available = _priority_data(snapshot)
    failures = aggs["failed_auth"]["doc_count"]
    agents = aggs["by_agent"]["buckets"]
    rules = aggs["by_rule"]["buckets"]
    failed_agents = aggs["failed_auth"]["agents"]["buckets"]
    buckets = aggs["by_hour"]["buckets"]
    start = datetime.fromisoformat(snapshot["start_utc"]).astimezone(LOCAL_TZ)
    end = datetime.fromisoformat(snapshot["end_utc"]).astimezone(LOCAL_TZ)
    period = (f"Últimos {range_label} | {start:%d/%m/%Y %H:%M} a {end:%d/%m/%Y %H:%M} "
              "| Horário de Recife | Confidencial")
    top_agent = _agent_name(agents[0]) if agents else "sem agente identificado"
    top_agent_count = agents[0]["doc_count"] if agents else 0
    top_rule = rules[0] if rules else None
    top_rule_count = top_rule["doc_count"] if top_rule else 0
    average = f"{total / hours:,.1f}".replace(",", "_").replace(".", ",").replace("_", ".")

    story = [P(f"Relatório de Segurança {_safe(customer)}", "title"), P(period, "subtitle"),
             P(f"<b>Escopo:</b> alertas com agent.labels.customer = <b>{_safe(customer)}</b>.", "small"),
             P("Guia de leitura: comece pela visão executiva e consulte o diagnóstico, o plano de ação e a referência técnica conforme a necessidade.", "caption")]
    story += S("Resumo executivo", "summary")
    if total:
        story.append(P(f"Foram registrados <b>{_number(total)} alertas</b>. "
                       f"Classificados como Alto ou Crítico: <b>{_number(high)} ({_percent(high, total)})</b>. "
                       f"Falhas de autenticação: <b>{_number(failures)} ({_percent(failures, total)})</b>. "
                       "A avaliação de impacto depende da análise dos eventos e do contexto dos serviços afetados."))
    else:
        story.append(P("Não foram encontrados alertas no recorte. A equipe deve verificar a cobertura e a saúde da coleta antes de interpretar esse resultado como ausência de atividade de segurança."))
    story += S("Principais indicadores", "indicators")
    story.append(_table([
        ["Indicador", "Resultado", "Como usar"],
        ["Alertas no período", _number(total), "Dimensiona o volume recebido."],
        ["EPS médio (alertas)", _average_eps(snapshot), "Média de alertas indexados por segundo no período."],
        ["Alto ou Crítico", f"{_number(high)} ({_percent(high, total)})", "Recorte para validação prioritária."],
        ["Falhas de autenticação", f"{_number(failures)} ({_percent(failures, total)})", "Direciona análise de contas e acessos."],
        ["Agentes com alertas", _observed_agents(aggs), "Mostra fontes observadas; requer inventário para medir cobertura."],
        ["Média de alertas por hora", average, "Ajuda a dimensionar carga operacional."],
    ], [150, 105, 195], styles))
    story.append(P("EPS médio = total de alertas indexados dividido pela duração do período em segundos. Eventos processados que não geraram alerta não são contabilizados nesta fonte.", "caption"))
    story.append(P("Um mesmo alerta pode pertencer aos recortes Alto/Crítico e falha de autenticação. As contagens representam alertas e podem repetir uma mesma condição.", "caption"))
    story += S("Encaminhamento para a gestão", "decisions")
    if high:
        story.append(P(f"Priorizar a validação dos alertas Altos e Críticos ({_number(high)} no período) pela equipe de segurança e confirmar quais serviços e responsáveis estão envolvidos. Não há classificação de impacto confirmada nesta extração.", "small"))
    else:
        story.append(P("O recorte não contém alertas Altos ou Críticos. Manter a revisão dos demais sinais e da coleta, considerando a criticidade dos serviços.", "small"))

    story += [PageBreak(), P("Volume e severidade", "title"),
              P("Leitura da carga de alertas ao longo do tempo e das categorias de severidade.", "subtitle")]
    story += S(f"Tendência: volume por {bucket_label}", "trend")
    story.append(TrendChart(buckets, daily=hours == 720, height=145))
    story.append(P(f"Intervalos de {bucket_label}, exibidos no horário de Recife. O primeiro e o último intervalo podem ser parciais. Valores agregados sem deduplicação.", "caption"))
    if buckets and total:
        peak = max(buckets, key=lambda b: b["doc_count"])
        stamp = datetime.fromtimestamp(peak["key"] / 1000, timezone.utc).astimezone(LOCAL_TZ)
        story.append(P(f"<b>Maior intervalo observado:</b> {_number(peak['doc_count'])} alertas "
                       f"({_percent(peak['doc_count'], total)} do período), com início em {stamp:%d/%m/%Y %H:%M}. "
                       "Comparar com mudanças e rotinas desse horário; o gráfico sozinho não confirma uma anomalia.", "small"))
    story += S("Distribuição por severidade", "severity")
    story.append(BarChart(_severity_items(aggs, total), row=22))
    story.append(P(SEVERITY_LEGEND, "caption"))
    story.append(P("Os alertas Altos e Críticos orientam a triagem prioritária. A prioridade de negócio exige análise do ativo e das evidências.", "caption"))
    story.append(P(TERMS_NOTE, "small"))

    story += [PageBreak(), P("Ativos e regras com maior volume", "title"),
              P("Localização das concentrações que merecem revisão de contexto e qualidade da detecção.", "subtitle")]
    story += S("Principais agentes ou coletores", "agents")
    story.append(BarChart([(f"{b['key']} | {_agent_name(b)}", b["doc_count"]) for b in agents[:5]], row=22))
    if agents and total:
        story.append(P(f"<b>Concentração:</b> {_safe(top_agent)} (agent.id: {_safe(agents[0]['key'])}) respondeu por {_number(top_agent_count)} alertas "
                       f"({_percent(top_agent_count, total)}). Validar se esse agente é um coletor central e quais sistemas originaram os registros.", "small"))
    story += S("Regras mais frequentes", "rules")
    rule_rows = [[str(b["key"]), _public_text(_description(b))[:125], _number(b["doc_count"]),
                  _percent(b["doc_count"], total)] for b in rules[:5]]
    story.append(_table([["Regra", "Descrição do sinal", "Alertas", "% do total"]] +
                        (rule_rows or [["-", "Nenhuma regra no recorte.", "0", "0,0%"]]),
                        [42, 266, 72, 70], styles))
    if top_rule and total:
        story.append(P(f"A regra {_safe(top_rule['key'])} concentrou {_percent(top_rule_count, total)} do volume. "
                       "A equipe deve validar a necessidade de ajuste junto ao dono do serviço, preservando evidências e a capacidade de detecção.", "small"))
    story.append(P("Listas limitadas aos maiores volumes. Descrições podem ser abreviadas; os identificadores permitem recuperar os eventos originais. Agentes e regras omitidos das listas continuam incluídos no total do período.", "caption"))

    story += [PageBreak(), P("Acessos e sinais para investigação", "title"),
              P("Recortes para apoiar a validação técnica e o direcionamento de responsáveis.", "subtitle")]
    story += S("Falhas de autenticação", "auth")
    story.append(BarChart([(str(b["key"]), b["doc_count"]) for b in failed_agents[:4]], row=21))
    story.append(P(f"Foram registrados {_number(failures)} alertas no grupo authentication_failed "
                   f"({_percent(failures, total)} do total). "
                   "Correlacionar conta, origem, serviço e autenticações bem-sucedidas posteriores. Esta consulta não calcula a proporção de tentativas que falharam.", "small"))
    story += S("Alertas Altos e Críticos", "priority")
    priority_rows = [["Regra", "Sinal registrado", "Alertas", "Agente com maior volume"]]
    for b in high_rules[:4]:
        agent_list = b.get("agents", {}).get("buckets", [])
        agent = _public_text(agent_list[0]["key"])[:80] if agent_list else "Não identificado"
        priority_rows.append([str(b["key"]), _public_text(_description(b))[:120], _number(b["doc_count"]), agent])
    if len(priority_rows) == 1:
        message = ("Detalhamento por regra requer nova extração com a classificação atual."
                   if high and not priority_details_available else "Nenhum alerta Alto ou Crítico no intervalo.")
        priority_rows.append(["-", message, "-" if high else "0", "-"])
    story.append(_table(priority_rows, [42, 223, 60, 125], styles))
    story.append(P("Para cada regra, recuperar os eventos brutos pelo identificador e verificar origem, conta, processo, ativo e mudanças autorizadas. Repetições devem ser correlacionadas antes de contar incidentes.", "small"))

    story += [PageBreak(), P("Plano de ação e acompanhamento", "title"),
              P("Encaminhamentos sugeridos para transformar a análise em trabalho rastreável.", "subtitle")]
    story += S("Ações propostas", "actions")
    actions = []
    if high:
        actions.append(["Validar alertas Altos e Críticos e registrar contexto, classificação e evidências. Concluir com decisão de tratamento e chamado vinculado quando aplicável.", "Segurança / SOC"])
    if failures:
        actions.append(["Investigar falhas de autenticação por conta e origem, correlacionando sucesso posterior. Concluir com causa identificada e medida adotada ou justificativa documentada.", "IAM / Infraestrutura"])
    if total:
        actions.append(["Revisar o agente e a regra de maior volume com o dono do serviço. Concluir com explicação da concentração e decisão documentada sobre eventual ajuste da detecção.", "Operações / dono do serviço"])
    actions.append(["Conferir inventário e disponibilidade da coleta. Concluir com lista de fontes esperadas, lacunas identificadas e responsáveis pela regularização.", "Operação da coleta"])
    story.append(_table([["Seq.", "Ação e evidência esperada para conclusão", "Responsável sugerido"]] +
                        [[str(i), action, owner] for i, (action, owner) in enumerate(actions, 1)],
                        [35, 300, 115], styles))
    story += S("Como acompanhar a execução", "followup")
    story.append(P("Pactuar prazo e prioridade com o dono do serviço. Registrar no atendimento: identificador do chamado, responsável, data-alvo, estado, decisão tomada e evidência de conclusão. Os dados de chamados e SLA não foram consultados para este relatório.", "small"))
    story += S("Indicadores úteis para a próxima evolução", "evolution")
    story.append(_table(EVOLUTION_ROWS, [155, 295], styles))

    story += [PageBreak(), P("Referência técnica e confiança dos dados", "title"),
              P("Informações necessárias para reproduzir o recorte e reconhecer seus limites.", "subtitle")]
    story += S("Escopo reproduzível", "scope")
    extracted = snapshot.get("extracted_at_utc", "Não registrado na extração original.")
    story.append(_table([["Parâmetro", "Valor"], ["Cliente (term exato)", str(customer)],
                         ["Campo do cliente", "agent.labels.customer"], ["Campo de tempo", "timestamp"],
                         ["Início UTC (inclusive)", snapshot["start_utc"]],
                         ["Fim UTC (exclusive)", snapshot["end_utc"]], ["Extraído em UTC", extracted]],
                        [145, 305], styles))
    story += S("Qualidade observável na extração", "quality")
    story.append(_table(_quality_rows(snapshot), [180, 270], styles))
    story += S("Limites de interpretação", "limits")
    story.append(P("As contagens representam alertas e podem repetir uma mesma condição. Agentes com alertas representam fontes observadas; cobertura exige comparação com inventário. A contagem por cardinalidade, quando usada, é uma estimativa. A comparação com período anterior, a confirmação de incidentes, o impacto e os tempos de atendimento não foram apurados.", "small"))
    story.append(P("As listas de agentes e regras são recortes dos maiores volumes; agregações por termos podem ter erro de distribuição entre fontes. A expressão 'ao menos' indica um limite inferior quando a lista de agentes é truncada. Os campos ausentes são informados quando disponíveis. O diagnóstico depende da investigação dos eventos brutos.", "small"))
    for note in snapshot.get("data_notes", []):
        story.append(P(_safe(note), "small"))
    story.append(P('Referência de processo para organização das ações: <link href="https://csrc.nist.gov/pubs/sp/800/61/r3/final" color="#626262">NIST SP 800-61 Rev. 3 (2025)</link>.', "caption"))
    return story


class ChartPlaceholder(Flowable):
    def __init__(self, label: str, height: float = 115):
        super().__init__()
        self.width, self.height, self.label = 450, height, label

    def draw(self):
        c = self.canv
        c.setStrokeColor(GRID)
        c.roundRect(0, 0, self.width, self.height, 5, stroke=1, fill=0)
        c.setFont("ReportSans", 8)
        c.setFillColor(MID)
        c.drawCentredString(self.width / 2, self.height / 2, self.label)


def _template_story() -> list:
    styles = _styles()
    P = lambda text, style="body": Paragraph(text, styles[style])
    S = lambda title, key: _section(title, key, styles)
    story = [P("Modelo de Relatório de Segurança", "title"),
             P("Cliente {{CLIENTE}} | Período {{24h / 7d / 30d}} | {{INÍCIO}} a {{FIM}} | Recife | Confidencial", "subtitle"),
             P("Preencher os campos entre chaves com dados da consulta. Preservar as descrições e registrar as validações humanas.", "small")]
    story += S("Resumo executivo", "summary")
    story.append(P("{{TOTAL}} alertas no período; {{ALTOS_E_CRITICOS}} ({{PERCENTUAL}}) classificados como Alto ou Crítico e {{FALHAS}} ({{PERCENTUAL}}) de falha de autenticação. {{SÍNTESE_DOS_SINAIS_E_SERVIÇOS_ENVOLVIDOS}}", "small"))
    story += S("Principais indicadores", "indicators")
    story.append(_table([["Indicador", "Resultado", "Como usar"],
                         ["Alertas no período", "{{TOTAL}}", "Dimensionar a carga recebida."],
                         ["EPS médio (alertas)", "{{EPS_MEDIO}}", "Média de alertas indexados por segundo."],
                         ["Alto ou Crítico", "{{N}} ({{%}})", "Direcionar validação prioritária."],
                         ["Falhas de autenticação", "{{N}} ({{%}})", "Direcionar análise de acessos."],
                         ["Agentes com alertas", "{{N / estimativa}}", "Fontes observadas; cruzar com inventário."],
                         ["Média de alertas por hora", "{{TOTAL / HORAS}}", "Dimensionar a carga operacional."]],
                        [150, 105, 195], styles))
    story.append(P("EPS médio = {{TOTAL_DE_ALERTAS}} / {{DURAÇÃO_EM_SEGUNDOS}}. A fonte inclui alertas indexados; eventos processados sem gerar alerta ficam fora desse cálculo.", "caption"))
    story.append(P("Alertas Altos/Críticos e falhas de autenticação podem se sobrepor. Registrar a base de cada percentual.", "caption"))
    story += S("Encaminhamento para a gestão", "decisions")
    story.append(P("{{DECISÃO_SUGERIDA}} | {{SERVIÇOS_A_VALIDAR}} | {{RESPONSÁVEL_A_CONFIRMAR}}. Informar se o impacto está confirmado ou se a análise permanece pendente.", "small"))

    story += [PageBreak(), P("Volume e severidade", "title")]
    story += S("Tendência temporal", "trend")
    story.append(ChartPlaceholder("Série temporal dos alertas do cliente", 145))
    story.append(P("Usar 1h para 24h, 6h para 7d e dia de calendário de Recife para 30d. Indicar intervalos parciais e lacunas. {{PICO_E_CONTEXTO_A_VALIDAR}}.", "caption"))
    story += S("Distribuição por severidade", "severity")
    story.append(ChartPlaceholder("Contagem e percentual por faixa de severidade", 125))
    story.append(P(SEVERITY_LEGEND, "caption"))
    story.append(P("Mostrar separadamente severidades ausentes ou não classificadas. Não atribuir impacto de negócio automaticamente pela categoria.", "caption"))
    story.append(P(TERMS_NOTE, "small"))

    story += [PageBreak(), P("Ativos e regras com maior volume", "title")]
    story += S("Principais agentes ou coletores", "agents")
    story.append(ChartPlaceholder("Maiores agentes por volume, com percentual do total", 130))
    story.append(P("{{CONCENTRAÇÃO_DO_PRINCIPAL_AGENTE}} | {{TIPO_DE_FONTE}} | {{SERVIÇO_E_DONO_A_CONFIRMAR}}", "small"))
    story += S("Regras mais frequentes", "rules")
    story.append(_table([["Regra", "Sinal registrado", "Alertas", "% do total"],
                         ["{{ID}}", "{{DESCRIÇÃO}}", "{{N}}", "{{%}}"],
                         ["{{ID}}", "{{DESCRIÇÃO}}", "{{N}}", "{{%}}"]], [42, 266, 72, 70], styles))
    story.append(P("{{EXPLICAÇÃO_DA_CONCENTRAÇÃO_E_VALIDAÇÕES_NECESSÁRIAS}}. Informar os limites das listas e qualquer erro de agregação relevante.", "small"))

    story += [PageBreak(), P("Acessos e sinais para investigação", "title")]
    story += S("Falhas de autenticação", "auth")
    story.append(ChartPlaceholder("Falhas de autenticação por agente", 110))
    story.append(P("{{N}} alertas de falha ({{%_DO_TOTAL_DE_ALERTAS}}). Registrar hipóteses, conta/origem quando validadas e eventual sucesso posterior. A base de tentativas totais é necessária para calcular taxa de falha.", "small"))
    story += S("Alertas Altos e Críticos", "priority")
    story.append(_table([["Regra", "Sinal registrado", "Alertas", "Agente principal"],
                         ["{{ID}}", "{{DESCRIÇÃO}}", "{{N}}", "{{AGENTE}}"],
                         ["{{ID}}", "{{DESCRIÇÃO}}", "{{N}}", "{{AGENTE}}"]], [42, 223, 60, 125], styles))
    story.append(P("{{EVIDÊNCIA}} | {{HIPÓTESE}} | {{VALIDAÇÃO_PENDENTE}}. Registrar confirmação, descarte ou necessidade de investigação adicional.", "small"))

    story += [PageBreak(), P("Plano de ação e acompanhamento", "title")]
    story += S("Ações propostas", "actions")
    story.append(_table([["Seq.", "Ação e evidência de conclusão", "Responsável sugerido"],
                         ["1", "{{AÇÃO / RESULTADO_VERIFICÁVEL}}", "{{FUNÇÃO}}"],
                         ["2", "{{AÇÃO / RESULTADO_VERIFICÁVEL}}", "{{FUNÇÃO}}"]], [35, 300, 115], styles))
    story += S("Como acompanhar a execução", "followup")
    story.append(P("Registrar {{CHAMADO}}, {{DONO}}, {{PRAZO_ACORDADO}}, {{ESTADO}}, {{DECISÃO}} e {{EVIDÊNCIA_DE_CONCLUSÃO}}. Não presumir atendimento ou cumprimento de SLA sem dados do fluxo de chamados.", "small"))
    story += S("Indicadores úteis para a próxima evolução", "evolution")
    story.append(_table(EVOLUTION_ROWS, [155, 295], styles))

    story += [PageBreak(), P("Referência técnica e confiança dos dados", "title")]
    story += S("Escopo reproduzível", "scope")
    story.append(_table([["Parâmetro", "Valor"], ["Cliente (term exato)", "{{CLIENTE}}"],
                         ["Campo do cliente", "agent.labels.customer"], ["Campo de tempo", "timestamp"],
                         ["Início UTC (inclusive)", "{{INÍCIO_UTC}}"], ["Fim UTC (exclusive)", "{{FIM_UTC}}"],
                         ["Extraído em UTC", "{{DATA_HORA_EXTRAÇÃO}}"]], [145, 305], styles))
    story += S("Qualidade observável na extração", "quality")
    story.append(_table([["Verificação", "Resultado"], ["Timeout / falhas de shard", "{{RESULTADO}}"],
                         ["Sem agente / sem severidade", "{{CONTAGENS_OU_NÃO_COLETADO}}"],
                         ["Primeiro / último alerta", "{{HORÁRIOS_OU_NÃO_COLETADO}}"]], [180, 270], styles))
    story += S("Limites de interpretação", "limits")
    story.append(P("Registrar limitações de cobertura, ingestão, campos ausentes, agregação e validação dos eventos brutos. Alertas podem repetir condições e se sobrepor em recortes. Listas dos maiores volumes não representam todo o inventário. Informar se não há base histórica, criticidade de ativos ou dados de atendimento.", "small"))
    story.append(P('Referência de processo: <link href="https://csrc.nist.gov/pubs/sp/800/61/r3/final" color="#626262">NIST SP 800-61 Rev. 3 (2025)</link>.', "caption"))
    return story


def _write_pdf(story: list, destination: Path | str, title: str) -> Path:
    _register_fonts()
    destination = Path(destination).expanduser().resolve()
    if not LETTERHEAD.is_file():
        raise RuntimeError(f"Papel timbrado não encontrado: {LETTERHEAD}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="security-report-") as temp_dir:
        overlay_path = Path(temp_dir) / "content.pdf"
        document = SimpleDocTemplate(str(overlay_path), pagesize=(595.28, 841.89),
                                     leftMargin=73, rightMargin=72, topMargin=113,
                                     bottomMargin=145, title=_public_text(title))
        document.build(story, onFirstPage=_page_chrome, onLaterPages=_page_chrome)
        content = PdfReader(str(overlay_path))
        writer = PdfWriter()
        # Keep independent readers alive: template pages must not share mutable content.
        backgrounds = [PdfReader(str(LETTERHEAD)) for _ in content.pages]
        for background, content_page in zip(backgrounds, content.pages):
            page = background.pages[0]
            page.merge_page(content_page)
            writer.add_page(page)
        writer.add_metadata({"/Title": _public_text(title), "/Author": "HostDime Brasil"})
        temporary_destination = destination.with_suffix(".pdf.tmp")
        try:
            with temporary_destination.open("wb") as stream:
                writer.write(stream)
            temporary_destination.replace(destination)
        finally:
            temporary_destination.unlink(missing_ok=True)
    return destination


def render_report(snapshot: dict, destination: Path | str) -> Path:
    """Render a customer report using the same guidance as the reusable template."""
    _register_fonts()
    return _write_pdf(_story(snapshot), destination, f"Relatório de Segurança {snapshot['customer']}")


def render_template(destination: Path | str) -> Path:
    """Render an editable-field model without customer data or invented metrics."""
    _register_fonts()
    return _write_pdf(_template_story(), destination, "Modelo de Relatório de Segurança")


def default_filename(customer: str, *, now: datetime | None = None) -> str:
    customer = validate_customer(customer)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", customer).strip("._") or "cliente"
    local_stamp = (now or datetime.now(timezone.utc)).astimezone(LOCAL_TZ).strftime("%Y-%m-%d_%H%M%S")
    return f"Relatorio_de_Seguranca_{safe_name}_{local_stamp}.pdf"
