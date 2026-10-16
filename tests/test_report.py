"""Regression checks for report meaning, legacy data and customer isolation."""

import copy
import io
import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfReader

from wazuh_report import (_average_eps, _percent, _priority_data, _severity_items, fetch_summary,
                          render_report, render_template)


def sample_snapshot(total=20):
    end = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
    rule = {"key": "100", "doc_count": total,
            "description": {"buckets": [{"key": "Wazuh agent <teste> & validação (nível 12)"}]},
            "agents": {"buckets": [{"key": "COLETOR", "doc_count": total}]}}
    return {
        "customer": "CLIENTE_TESTE", "hours": 24, "priority_scope": "high_critical",
        "start_utc": (end - timedelta(hours=24)).isoformat(), "end_utc": end.isoformat(),
        "extracted_at_utc": end.isoformat(),
        "result": {"timed_out": False, "_shards": {"failed": 0},
                   "hits": {"total": {"value": total, "relation": "eq"}},
                   "aggregations": {
                       "by_hour": {"buckets": [{"key": int(end.timestamp() * 1000),
                                                  "doc_count": total}] if total else []},
                       "by_level": {"buckets": [{"key": 12, "doc_count": total}] if total else []},
                       "by_agent": {"sum_other_doc_count": 0, "doc_count_error_upper_bound": 0,
                                    "buckets": [{"key": "001", "doc_count": total,
                                                 "name": {"buckets": [{"key": "COLETOR"}]}}] if total else []},
                       "by_rule": {"buckets": [rule] if total else []},
                       "high": {"doc_count": total, "rules": {"buckets": [rule] if total else []}},
                       "failed_auth": {"doc_count": 0, "agents": {"buckets": []}},
                       "agents_observed": {"value": 1 if total else 0},
                       "missing_agent": {"doc_count": 0}, "missing_level": {"doc_count": 0},
                       "first_event": {"value": int(end.timestamp() * 1000) if total else None},
                       "last_event": {"value": int(end.timestamp() * 1000) if total else None},
                   }},
    }


class ReportTests(unittest.TestCase):
    def test_average_eps_uses_actual_period_including_empty_intervals(self):
        for hours in (24, 168, 720):
            with self.subTest(hours=hours):
                snapshot = sample_snapshot(hours * 3600 * 3)
                end = datetime.fromisoformat(snapshot['end_utc'])
                snapshot['start_utc'] = (end - timedelta(hours=hours)).isoformat()
                snapshot['hours'] = hours
                self.assertEqual(_average_eps(snapshot), '3,00')
        self.assertEqual(_average_eps(sample_snapshot(1966492)), '22,76')
        self.assertEqual(_average_eps(sample_snapshot(0)), '0,00')
        self.assertEqual(_average_eps(sample_snapshot(1)), 'menos de 0,0001')
        snapshot = sample_snapshot()
        snapshot['start_utc'] = snapshot['end_utc']
        with self.assertRaises(ValueError):
            _average_eps(snapshot)

    def test_severity_boundaries_follow_customer_legend(self):
        levels = {0: 1, 6: 2, 7: 4, 9: 8, 10: 16, 11: 32, 12: 64, 14: 128, 15: 256}
        total = sum(levels.values())
        aggs = {"by_level": {"buckets": [{"key": level, "doc_count": count}
                                         for level, count in levels.items()]}}
        items = _severity_items(aggs, total)
        self.assertEqual([count for _, count in items], [3, 60, 192, 256])
        for (label, _), name in zip(items, ("Baixo", "Médio", "Alto", "Crítico")):
            self.assertTrue(label.startswith(name))
            self.assertNotRegex(label, r"\b(?:lv|nível)\s*\d")
        self.assertEqual(sum(count for _, count in items), total)

    def test_legacy_priority_details_are_not_mislabeled_as_high(self):
        snapshot = sample_snapshot()
        del snapshot['priority_scope']
        snapshot['result']['aggregations']['by_level']['buckets'] = [
            {'key': 11, 'doc_count': 19}, {'key': 15, 'doc_count': 1}]
        count, rules, available = _priority_data(snapshot)
        self.assertEqual(count, 1)
        self.assertEqual(rules, [])
        self.assertFalse(available)

    def test_every_period_preserves_customer_and_utc_scope(self):
        now = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)
        response = sample_snapshot()["result"]
        for hours, kind, interval in ((24, "fixed_interval", "1h"),
                                      (168, "fixed_interval", "6h"),
                                      (720, "calendar_interval", "1d")):
            with self.subTest(hours=hours):
                with patch("urllib.request.urlopen", return_value=io.BytesIO(json.dumps(response).encode())) as call:
                    snapshot = fetch_summary("CLIENTE_TESTE", "https://127.0.0.1:9200", "user", "secret",
                                             hours=hours, now=now)
                body = json.loads(call.call_args.args[0].data)
                filters = body["query"]["bool"]["filter"]
                self.assertEqual(filters[0], {"term": {"agent.labels.customer": "CLIENTE_TESTE"}})
                self.assertEqual(filters[1]["range"]["timestamp"],
                                 {"gte": (now - timedelta(hours=hours)).isoformat(), "lt": now.isoformat()})
                self.assertEqual(body["aggs"]["by_hour"]["date_histogram"][kind], interval)
                self.assertEqual(body["aggs"]["by_hour"]["date_histogram"]["time_zone"], "America/Recife")
                priority_filters = body['aggs']['high']['filter']['bool']['filter']
                self.assertIn({'range': {'rule.level': {'gte': 12, 'lte': 15}}}, priority_filters)
                self.assertEqual(snapshot["hours"], hours)

    def test_small_nonzero_shares_remain_visible(self):
        self.assertEqual(_percent(409, 1966492), "0,02%")
        self.assertEqual(_percent(1, 1966492), "menos de 0,001%")
        self.assertEqual(_percent(0, 0), "0,0%")

    def test_pdf_supports_single_bucket_empty_and_legacy_snapshots(self):
        legacy = copy.deepcopy(sample_snapshot())
        del legacy['priority_scope']
        for key in ("agents_observed", "missing_agent", "missing_level", "first_event", "last_event"):
            del legacy["result"]["aggregations"][key]
        cases = [("single", sample_snapshot()), ("empty", sample_snapshot(0)), ("legacy", legacy)]
        with tempfile.TemporaryDirectory() as folder:
            for name, snapshot in cases:
                with self.subTest(case=name):
                    path = render_report(snapshot, Path(folder) / f"{name}.pdf")
                    reader = PdfReader(str(path))
                    text = "\n".join(page.extract_text() or "" for page in reader.pages)
                    self.assertEqual(len(reader.pages), 6)
                    headings = ["Relatório de Segurança", "Volume e severidade",
                                "Ativos e regras com maior volume", "Acessos e sinais para investigação",
                                "Plano de ação e acompanhamento", "Referência técnica e confiança dos dados"]
                    for page, heading in zip(reader.pages, headings):
                        page_text = page.extract_text() or ""
                        self.assertIn(heading, page_text)
                        self.assertEqual(page_text.count("Página"), 1)
                        self.assertTrue(page.get("/Resources").get("/XObject"))
                    self.assertNotIn("wazuh", (text + str(reader.metadata)).lower())
                    self.assertNotIn("{{", text)
                    self.assertIn('EPS médio (alertas)', text)
                    self.assertNotRegex(text, r"(?i)\b(?:lv|nível|níveis|level|severity|severidade)[ \t]*[:=]?[ \t]*\d")
                    self.assertNotIn('10+', text)
                    self.assertIn("evidência", text.lower())
                    if name == "single":
                        self.assertIn("<teste> & validação", text)
                    if name == "legacy":
                        self.assertIn("Não coletado na extração original", text)

    def test_template_keeps_guidance_and_has_no_customer_data(self):
        with tempfile.TemporaryDirectory() as folder:
            reader = PdfReader(str(render_template(Path(folder) / "model.pdf")))
            text = "\n".join(page.extract_text() or "" for page in reader.pages)
            self.assertEqual(len(reader.pages), 6)
            self.assertIn("{{CLIENTE}}", text)
            self.assertIn("Indicadores úteis para a próxima evolução", text)
            self.assertNotIn("wazuh", (text + str(reader.metadata)).lower())
            self.assertNotIn("CLIENTE_TESTE", text)
            self.assertNotRegex(text, r"(?i)\b(?:lv|nível|níveis)\s*\d")
            self.assertNotIn('10+', text)


if __name__ == "__main__":
    unittest.main()
