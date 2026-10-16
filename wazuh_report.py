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
    high_scope = {"bool": {"filter": scope + [{"range": {"rule.level": {"gte": 10}}}]}}
    failed_scope = {"bool": {"filter": scope + [{"term": {"rule.groups": "authentication_failed"}}]}}
    return {
        "size": 0,
        "track_total_hits": True,
        "query": {"bool": {"filter": scope}},
        "aggs": {
            "by_level": {"terms": {"field": "rule.level", "size": 20}},
            "by_hour": {"date_histogram": {
                "field": "timestamp", "fixed_interval": PERIODS[hours][1], "min_doc_count": 0,
                "extended_bounds": {"min": start.isoformat(),
                                    "max": (end - timedelta(microseconds=1)).isoformat()},
            }},
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


def fetch_summary(
    customer: str,
    base_url: str,
    username: str,
    password: str,
    *,
    hours: int = 24,
    verify_tls: bool = False,
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
    token = base64.b64encode(f"{username.strip()}:{password}".encode()).decode()
    request = urllib.request.Request(
        f"{base_url}/wazuh-alerts-*/_search",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Basic {token}", "Content-Type": "application/json"},
        method="POST",
    )
    context = None if verify_tls else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(request, context=context,
                                    timeout={24: 60, 168: 180, 720: 300}[hours]) as response:
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
    return {"customer": customer, "start_utc": start.isoformat(), "end_utc": end.isoformat(),
            "hours": hours, "index": "wazuh-alerts-*", "result": result}


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
    return re.sub(r"wazuh", "plataforma de segurança", neutral, flags=re.IGNORECASE)


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
        ticks = sorted(set((0, denominator // 4, denominator // 2, 3 * denominator // 4, denominator)))
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


def _story(snapshot: dict) -> list:
    styles = _styles()
    P = lambda text, style="body": Paragraph(text, styles[style])
    customer = snapshot["customer"]
    hours = snapshot.get("hours", 24)
    if hours not in PERIODS:
        raise ValueError("Período do relatório inválido.")
    range_label, _, bucket_label = PERIODS[hours]
    result = snapshot["result"]
    aggregations = result["aggregations"]
    total = result["hits"]["total"]["value"]
    high = aggregations["high"]["doc_count"]
    failures = aggregations["failed_auth"]["doc_count"]
    agents = aggregations["by_agent"]["buckets"]
    rules = aggregations["by_rule"]["buckets"]
    high_rules = aggregations["high"]["rules"]["buckets"]
    failed_agents = aggregations["failed_auth"]["agents"]["buckets"]
    start = datetime.fromisoformat(snapshot["start_utc"]).astimezone(LOCAL_TZ)
    end = datetime.fromisoformat(snapshot["end_utc"]).astimezone(LOCAL_TZ)
    period = (f"Últimos {range_label} | {start:%d/%m/%Y %H:%M} a {end:%d/%m/%Y %H:%M} "
              "| Horário de Recife | Confidencial")
    top_agent = _agent_name(agents[0]) if agents else "—"
    top_agent_count = agents[0]["doc_count"] if agents else 0
    top_rule = rules[0] if rules else None
    top_rule_text = _description(top_rule) if top_rule else "sem regra registrada"
    top_rule_count = top_rule["doc_count"] if top_rule else 0
    share_agent = f"{top_agent_count / total * 100:.1f}".replace(".", ",") if total else "0"
    share_rule = f"{top_rule_count / total * 100:.1f}".replace(".", ",") if total else "0"
    top_priority = high_rules[:3]

    story = [
        P(f"Relatório de Segurança {_safe(customer)}", "title"),
        P(period, "subtitle"),
        P(f"<b>Escopo:</b> somente alertas com <b>agent.labels.customer = {_safe(customer)}</b> "
          "no período selecionado, pelo campo timestamp.", "small"),
        P("Resumo executivo", "h1"),
        P(f"Foram encontrados <b>{_number(total)} alertas</b>. O agente {_safe(top_agent)} concentrou "
          f"{_number(top_agent_count)} ({share_agent}%) e a regra {_safe(top_rule['key']) if top_rule else '—'} "
          f"({_safe(top_rule_text)}) respondeu por {_number(top_rule_count)} ({share_rule}%). "
          f"Houve <b>{_number(high)} alertas de nível 10 ou superior</b> e "
          f"<b>{_number(failures)} falhas de autenticação</b>. As contagens representam alertas, não incidentes únicos."),
        _table([["Indicador", "Quantidade"], [f"Alertas {_safe(customer)}", _number(total)],
                ["Nível 10 ou superior", _number(high)], ["Falhas de autenticação", _number(failures)]],
               [320, 130], styles),
        P(f"Volume de alertas por {bucket_label}", "h1"),
        TrendChart(aggregations["by_hour"]["buckets"], daily=hours == 720),
        P(f"Intervalos de {bucket_label} no fuso de Recife. O primeiro e o último intervalo "
          "podem ser parciais; o gráfico mostra alertas sem deduplicação.", "caption"),
        P("Pontos para triagem", "h1"),
    ]
    if top_priority:
        findings = "; ".join(f"{_number(item['doc_count'])} alertas da regra {_safe(item['key'])} "
                             f"({_safe(_description(item))})" for item in top_priority)
        story.append(P("Entre os alertas de maior severidade: " + findings + ". "
                       "A descrição das regras requer validação com os eventos originais."))
    else:
        story.append(P("Não houve alertas de nível 10 ou superior no intervalo consultado."))

    story += [
        PageBreak(), P("Distribuição dos alertas", "title"),
        P("O volume por agente e regra ajuda a distinguir atividade frequente dos eventos que exigem investigação.", "subtitle"),
        P("Agentes com maior volume", "h1"),
        BarChart([(_agent_name(item), item["doc_count"]) for item in agents[:5]]),
        P("Os nomes longos podem aparecer abreviados no gráfico. A tabela de regras usa contagens da mesma consulta.", "caption"),
        P("Regras mais frequentes", "h1"),
        _table([["Regra", "Descrição", "Alertas"]] +
               [[item["key"], _description(item)[:95], _number(item["doc_count"])] for item in rules[:6]],
               [52, 330, 68], styles),
        Spacer(1, 7),
        P("Falhas de autenticação por agente", "h1"),
        BarChart([(item["key"], item["doc_count"]) for item in failed_agents[:5]]),
        PageBreak(), P("Alertas prioritários", "title"),
        P("Regras com nível 10 ou superior no intervalo analisado.", "subtitle"),
        BarChart([(f"{item['key']}  {_description(item)}", item["doc_count"]) for item in high_rules[:7]], row=22),
        P("Achados de maior severidade", "h1"),
    ]
    for item in high_rules[:4]:
        agent_buckets = item.get("agents", {}).get("buckets", [])
        agent_text = agent_buckets[0]["key"] if agent_buckets else "agente não identificado"
        story.append(P(f"<b>Regra {_safe(item['key'])}:</b> {_number(item['doc_count'])} alertas. "
                       f"{_safe(_description(item))}. Principal agente: {_safe(agent_text)}.", "small"))
    story += [
        P("Ações recomendadas", "h1"),
        P("1. Validar as regras de maior severidade nos eventos brutos, correlacionando horário, agente, origem e mudanças autorizadas.", "small"),
        P("2. Investigar as falhas de autenticação por origem e conta, verificando se houve sucesso posterior e se há repetição de tentativas.", "small"),
        P("3. Confirmar a saúde da coleta e a cobertura dos agentes antes de concluir sobre ausência ou concentração de atividade.", "small"),
        P("Método e limitações", "h1"),
        P(f"Consulta ao índice de alertas com filtro exato "
          f"agent.labels.customer = {_safe(customer)} e timestamp de "
          f"{_safe(snapshot['start_utc'])} (inclusive) a {_safe(snapshot['end_utc'])} (exclusive). "
          "O indexador confirmou total exato, sem timeout ou falha de shard. Regras correlacionadas podem emitir "
          "múltiplos alertas para a mesma condição. O relatório não confirma comprometimento ou impacto.", "small"),
    ]
    return story


def render_report(snapshot: dict, destination: Path | str) -> Path:
    """Render atomically to a PDF, preserving the supplied letterhead on each page."""
    _register_fonts()
    destination = Path(destination).expanduser().resolve()
    if not LETTERHEAD.is_file():
        raise RuntimeError(f"Papel timbrado não encontrado: {LETTERHEAD}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="wazuh-report-") as temp_dir:
        overlay_path = Path(temp_dir) / "content.pdf"
        document = SimpleDocTemplate(str(overlay_path), pagesize=(595.28, 841.89),
                                     leftMargin=73, rightMargin=72, topMargin=113,
                                     bottomMargin=145, title=f"Relatório de Segurança {_public_text(snapshot['customer'])}")
        document.build(_story(snapshot), onFirstPage=_page_chrome, onLaterPages=_page_chrome)
        content = PdfReader(str(overlay_path))
        writer = PdfWriter()
        for content_page in content.pages:
            writer.add_page(PdfReader(str(LETTERHEAD)).pages[0])
            writer.pages[-1].merge_page(content_page)
        writer.add_metadata({"/Title": f"Relatório de Segurança {_public_text(snapshot['customer'])}",
                             "/Author": "HostDime Brasil"})
        temporary_destination = destination.with_suffix(".pdf.tmp")
        try:
            with temporary_destination.open("wb") as stream:
                writer.write(stream)
            temporary_destination.replace(destination)
        finally:
            temporary_destination.unlink(missing_ok=True)
    return destination


def default_filename(customer: str, *, now: datetime | None = None) -> str:
    customer = validate_customer(customer)
    safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "_", customer).strip("._") or "cliente"
    local_stamp = (now or datetime.now(timezone.utc)).astimezone(LOCAL_TZ).strftime("%Y-%m-%d_%H%M%S")
    return f"Relatorio_de_Seguranca_{safe_name}_{local_stamp}.pdf"
