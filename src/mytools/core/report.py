#!/usr/bin/env python3
"""HTML Report Generator — transforma scans JSON em relatorio HTML.

Le um ou mais arquivos de resultado (.json) gerados por ferramentas MyTools
(workspace de scan via --output-dir, ou arquivos unicos via -o) e gera um
relatorio HTML com findings, severidade, evidencias, timeline e diff entre scans.

Fontes de entrada:
  -f/--file  um ou mais arquivos JSON (scans individuais)
  -d/--dir   diretorio de workspace (outputs/<host>/<timestamp>.json), recursivo

Diff entre scans:
  Compara scans do MESMO host (baseline vs. mais recente) por fingerprint do
  finding (multiset/Counter), mostrando added/removed/unchanged.

Exemplos:
  mytools-report -d outputs/
  mytools-report -d outputs/ --diff --title "Auditoria Q3"
  mytools-report -f a.json b.json --diff
  mytools-report -f scan.json --tool charsetbypass -o relatorio.html
"""

import argparse
import json
import logging
import re
import sys
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from jinja2 import Template

from mytools.core.utils import (
    __version__,
    run_interactive_shell,
    setup_logging,
)

logger = logging.getLogger("mytools.report")

# ---------------------------------------------------------------------------
# Severidade
# ---------------------------------------------------------------------------

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

_SEVERITY_COLORS = {
    "critical": "#ff4444",
    "high": "#ff8800",
    "medium": "#ffcc00",
    "low": "#4488ff",
    "info": "#888888",
}


def _derive_severity(severity: object | None, vulnerable: bool = True) -> str:
    """Normaliza severidade; fallback para high/info por vulnerabilidade."""
    if isinstance(severity, str):
        sev = severity.strip().lower()
        if sev in _SEVERITY_ORDER:
            return sev
    return "high" if vulnerable else "info"


# ---------------------------------------------------------------------------
# Modelo de dados
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Finding:
    """Finding normalizado para o relatorio."""

    fingerprint: str
    title: str
    severity: str
    evidence: str = ""
    recommendation: str = ""
    tool: str = ""


@dataclass
class ScanResult:
    """Scan normalizado (um arquivo JSON)."""

    path: Path
    host: str
    timestamp: str
    overall_status: str = ""
    tool: str = ""
    findings: list[Finding] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def vulnerable_count(self) -> int:
        return sum(1 for f in self.findings if f.severity not in ("info", "low"))


@dataclass
class DiffResult:
    """Resultado do diff entre dois scans do mesmo host."""

    baseline: ScanResult
    current: ScanResult
    added: list[Finding] = field(default_factory=list)
    removed: list[Finding] = field(default_factory=list)
    unchanged: list[tuple[str, str, int]] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return bool(self.added or self.removed)


@dataclass
class HostReport:
    """Conjunto de scans de um mesmo host."""

    host: str
    tool: str = ""
    scans: list[ScanResult] = field(default_factory=list)

    @property
    def sorted_scans(self) -> list[ScanResult]:
        return sorted(self.scans, key=lambda s: s.timestamp)

    @property
    def diff(self) -> DiffResult | None:
        """Diff entre os 2 scans mais recentes, se houver >= 2."""
        scans = self.sorted_scans
        if len(scans) < 2:
            return None
        return _diff_scans(scans[-2], scans[-1])

    @property
    def all_findings(self) -> list[Finding]:
        out: list[Finding] = []
        for scan in self.sorted_scans:
            out.extend(scan.findings)
        return out

    def severity_counts(self) -> list[tuple[str, int]]:
        counts = Counter(f.severity for f in self.all_findings)
        return [(sev, counts.get(sev, 0)) for sev in _SEVERITY_ORDER]


# ---------------------------------------------------------------------------
# Extração de findings
# ---------------------------------------------------------------------------


def _iterable_findings(data: dict) -> list[dict]:
    """Encontra listas de dicts candidatas a findings dentro de um scan."""
    found: list[dict] = []
    for key in ("attempts", "findings", "results", "items", "records"):
        value = data.get(key)
        if isinstance(value, list):
            found.extend(item for item in value if isinstance(item, dict))
    return found


def _attempt_title(item: dict) -> str:
    technique = item.get("technique") or item.get("name") or item.get("type")
    category = item.get("category")
    title = str(technique) if technique else "Attempt"
    if category:
        title = f"{category}: {title}"
    return title


def _legacy_title(item: dict) -> str:
    url = item.get("url") or item.get("path")
    if url:
        status = item.get("status")
        suffix = f" [{status}]" if status not in (None, "", 0) else ""
        return f"{url}{suffix}"
    return "Item"


def _item_fingerprint(item: dict) -> str:
    technique = item.get("technique") or item.get("name") or item.get("type")
    if technique:
        return f"technique:{technique}"
    url = item.get("url") or item.get("path")
    if url:
        return f"url:{url}"
    category = item.get("category") or item.get("item")
    if category:
        item_name = item.get("item")
        if item_name and item_name != category:
            return f"category:{category}|item:{item_name}"
        return f"category:{category}"
    return "item:unknown"


def _is_vulnerable_item(item: dict) -> bool:
    for key in ("vulnerable", "is_vulnerable", "found", "confirmed"):
        if isinstance(item.get(key), bool):
            return bool(item[key])
    status = item.get("status")
    if isinstance(status, int) and status > 0:
        return status < 500 and status != 404
    return True


def _findings_from_attempts(items: list[dict], tool: str) -> list[Finding]:
    out: list[Finding] = []
    for item in items:
        if not _is_vulnerable_item(item):
            continue
        vulnerable = bool(item.get("vulnerable", True))
        severity = _derive_severity(item.get("severity"), vulnerable)
        out.append(
            Finding(
                fingerprint=_item_fingerprint(item),
                title=_attempt_title(item),
                severity=severity,
                evidence=str(item.get("details") or item.get("evidence") or ""),
                recommendation=str(item.get("recommendation") or item.get("fix") or ""),
                tool=tool,
            )
        )
    return out


def _findings_from_findings(items: list[dict], tool: str) -> list[Finding]:
    out: list[Finding] = []
    for item in items:
        category = item.get("category") or ""
        item_name = item.get("item") or ""
        title = f"{category}: {item_name}".strip(": ") or "Finding"
        severity = _derive_severity(item.get("severity"))
        out.append(
            Finding(
                fingerprint=_item_fingerprint(item),
                title=title,
                severity=severity,
                evidence=str(item.get("evidence") or item.get("details") or ""),
                recommendation=str(item.get("recommendation") or ""),
                tool=tool,
            )
        )
    return out


def _findings_from_legacy(items: list[dict], tool: str) -> list[Finding]:
    out: list[Finding] = []
    for item in items:
        if not _is_vulnerable_item(item):
            continue
        out.append(
            Finding(
                fingerprint=_item_fingerprint(item),
                title=_legacy_title(item),
                severity=_derive_severity(item.get("severity"), True),
                evidence=str(item.get("detail") or item.get("evidence") or ""),
                recommendation="",
                tool=tool,
            )
        )
    return out


def _extract_findings(data: dict | list, tool: str = "") -> list[Finding]:
    """Extrai findings normalizados de um scan, por formato conhecido."""
    if isinstance(data, list):
        if all(isinstance(i, dict) for i in data):
            return _findings_from_legacy(data, tool)
        return []

    if "findings" in data:
        items = data["findings"]
        if (
            isinstance(items, list)
            and items
            and all(isinstance(i, dict) for i in items)
        ):
            return _findings_from_findings(items, tool)

    iterable = _iterable_findings(data)
    if iterable:
        if any("technique" in i or "vulnerable" in i for i in iterable):
            return _findings_from_attempts(iterable, tool)
        return _findings_from_legacy(iterable, tool)

    for key in ("issues", "vulnerable_techniques", "blocked_techniques"):
        value = data.get(key)
        if isinstance(value, list) and value:
            items = [
                {"technique": str(v), "vulnerable": key != "blocked_techniques"}
                for v in value
            ]
            return _findings_from_attempts(items, tool)

    return []


# ---------------------------------------------------------------------------
# Normalização de scans
# ---------------------------------------------------------------------------

_FILENAME_TIMESTAMP_RE = r"(\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2})"


def _host_from_path(path: Path) -> str:
    """Infere o host do caminho (outputs/<host>/<ts>.json)."""
    parts = path.parts
    for i in range(len(parts) - 2, -1, -1):
        if parts[i + 1].startswith("20") and parts[i + 1].endswith(".json"):
            return parts[i]
    return path.stem


def _timestamp_from_path(path: Path) -> str:
    """Extrai timestamp do nome do arquivo (formato ISO do workspace)."""
    match = re.search(_FILENAME_TIMESTAMP_RE, path.stem)
    return match.group(1) if match else path.stem


def _load_json(path: Path) -> dict | list | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.warning("Ignorando arquivo invalido %s: %s", path, exc)
        return None
    return data if isinstance(data, (dict, list)) else None


def _normalize(path: Path, data: dict | list, tool: str = "") -> ScanResult:
    if isinstance(data, list):
        host = _host_from_path(path)
        timestamp = _timestamp_from_path(path)
        findings = _findings_from_legacy(data, tool) if data else []
        return ScanResult(path=path, host=host, timestamp=timestamp, findings=findings)

    host = str(data.get("target") or _host_from_path(path))
    timestamp = _timestamp_from_path(path)
    overall = str(data.get("overall_status") or "ok")
    scan_tool = tool or ""
    findings = _extract_findings(data, scan_tool)
    return ScanResult(
        path=path,
        host=host,
        timestamp=timestamp,
        overall_status=overall,
        tool=scan_tool,
        findings=findings,
    )


def _load_scan_files(directory: str | Path) -> list[Path]:
    """Lista arquivos .json do diretorio, ordenados lexicograficamente."""
    root = Path(directory)
    if not root.is_dir():
        return []
    return sorted(p for p in root.rglob("*.json"))


def _group_by_host(paths: list[Path], tool: str = "") -> list[HostReport]:
    reports: dict[str, HostReport] = {}
    for path in paths:
        data = _load_json(path)
        if data is None:
            continue
        scan = _normalize(path, data, tool)
        report = reports.setdefault(scan.host, HostReport(host=scan.host, tool=tool))
        report.scans.append(scan)
    return list(reports.values())


# ---------------------------------------------------------------------------
# Diff entre scans
# ---------------------------------------------------------------------------


def _diff_scans(baseline: ScanResult, current: ScanResult) -> DiffResult:
    """Diff por fingerprint/multiset entre dois scans do mesmo host."""
    base_counter = Counter(f.fingerprint for f in baseline.findings)
    curr_counter = Counter(f.fingerprint for f in current.findings)

    current_by_fp: dict[str, list[Finding]] = {}
    for f in current.findings:
        current_by_fp.setdefault(f.fingerprint, []).append(f)
    base_by_fp: dict[str, list[Finding]] = {}
    for f in baseline.findings:
        base_by_fp.setdefault(f.fingerprint, []).append(f)

    added_delta = curr_counter - base_counter
    removed_delta = base_counter - curr_counter

    added = [f for fp, n in added_delta.items() for f in current_by_fp[fp][:n]]
    removed = [f for fp, n in removed_delta.items() for f in base_by_fp[fp][:n]]

    unchanged: list[tuple[str, str, int]] = []
    for fp in base_counter & curr_counter:
        count = curr_counter[fp]
        sample = current_by_fp[fp][0]
        unchanged.append((sample.title, sample.severity, count))

    return DiffResult(
        baseline=baseline,
        current=current,
        added=added,
        removed=removed,
        unchanged=unchanged,
    )


# ---------------------------------------------------------------------------
# Renderização HTML
# ---------------------------------------------------------------------------

_TEMPLATE = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }}</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    margin: 0; padding: 24px; font-family: -apple-system, "Segoe UI", Roboto, sans-serif;
    background: #0d1117; color: #e6edf3;
  }
  h1 { font-size: 1.6rem; margin: 0 0 4px; }
  h2 { font-size: 1.15rem; margin: 32px 0 12px; border-bottom: 1px solid #30363d; padding-bottom: 6px; }
  .meta { color: #8b949e; font-size: .9rem; margin-bottom: 16px; }
  .cards { display: flex; gap: 10px; flex-wrap: wrap; margin: 16px 0; }
  .card {
    padding: 10px 16px; border-radius: 8px; border: 1px solid #30363d;
    background: #161b22; min-width: 90px; text-align: center;
  }
  .card .num { font-size: 1.4rem; font-weight: 700; }
  .card .lbl { font-size: .72rem; letter-spacing: 1px; text-transform: uppercase; color: #8b949e; }
  .sev-critical { border-color: #ff4444; } .sev-critical .num { color: #ff4444; }
  .sev-high { border-color: #ff8800; } .sev-high .num { color: #ff8800; }
  .sev-medium { border-color: #ffcc00; } .sev-medium .num { color: #ffcc00; }
  .sev-low { border-color: #4488ff; } .sev-low .num { color: #4488ff; }
  .sev-info { border-color: #888888; } .sev-info .num { color: #888888; }
  table { width: 100%; border-collapse: collapse; margin: 8px 0; font-size: .9rem; }
  th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid #21262d; }
  th { color: #8b949e; font-weight: 600; }
  tr:hover td { background: #161b22; }
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 10px;
    font-size: .75rem; font-weight: 700; text-transform: uppercase;
  }
  .badge-added { background: #3d1d1d; color: #ff7b72; }
  .badge-removed { background: #1c3d2a; color: #7ee787; }
  .badge-unchanged { background: #30363d; color: #8b949e; }
  .status-vulnerable { color: #ff7b72; font-weight: 600; }
  .status-secure { color: #7ee787; font-weight: 600; }
  .status-error { color: #f0883e; font-weight: 600; }
  .finding {
    border: 1px solid #30363d; border-left: 4px solid #888888;
    border-radius: 8px; padding: 12px 16px; margin: 10px 0; background: #161b22;
  }
  .finding.f-critical { border-left-color: #ff4444; }
  .finding.f-high { border-left-color: #ff8800; }
  .finding.f-medium { border-left-color: #ffcc00; }
  .finding.f-low { border-left-color: #4488ff; }
  .finding h3 { margin: 0 0 6px; font-size: 1rem; }
  .finding .sev {
    float: right; padding: 2px 8px; border-radius: 10px; font-size: .72rem;
    font-weight: 700; text-transform: uppercase; background: #30363d;
  }
  .finding pre {
    background: #0d1117; border: 1px solid #21262d; border-radius: 6px;
    padding: 8px 10px; overflow-x: auto; font-size: .82rem; white-space: pre-wrap;
  }
  .finding p.rec { color: #8b949e; font-size: .85rem; margin: 6px 0 0; }
  .diff-arrow { margin: 0 6px; color: #8b949e; }
  .footer { margin-top: 40px; color: #484f58; font-size: .78rem; }
</style>
</head>
<body>
  <h1>{{ title }}</h1>
  <div class="meta">
    Gerado em {{ generated_at }} &middot; {{ hosts|length }} host(s)
    {% if tool %}&middot; Ferramenta: {{ tool }}{% endif %}
  </div>

  {% for report in hosts %}
  <section>
    <h2>{{ report.host }}
      {%- if report.tool %} <span class="meta">({{ report.tool }})</span>{% endif %}</h2>

    <div class="cards">
      {% for sev, n in report.severity_counts() %}
      <div class="card sev-{{ sev }}">
        <div class="num">{{ n }}</div>
        <div class="lbl">{{ sev }}</div>
      </div>
      {% endfor %}
    </div>

    <h3>Timeline</h3>
    <table>
      <thead><tr><th>Timestamp</th><th>Status</th><th>Findings</th><th>Vulneraveis</th></tr></thead>
      <tbody>
        {% for scan in report.sorted_scans %}
        <tr>
          <td>{{ scan.timestamp }}</td>
          <td><span class="status-{{ scan.overall_status }}">{{ scan.overall_status }}</span></td>
          <td>{{ scan.count }}</td>
          <td>{{ scan.vulnerable_count }}</td>
        </tr>
        {% endfor %}
      </tbody>
    </table>

    {% if diff and report.diff %}
    <h3>Diff ({{ report.diff.baseline.timestamp }} <span class="diff-arrow">&#8594;</span> {{ report.diff.current.timestamp }})</h3>
    <table>
      <thead><tr><th>Tipo</th><th>Finding</th><th>Severidade</th></tr></thead>
      <tbody>
        {% for f in report.diff.added %}
        <tr><td><span class="badge badge-added">+ Added</span></td><td>{{ f.title }}</td><td>{{ f.severity }}</td></tr>
        {% endfor %}
        {% for f in report.diff.removed %}
        <tr><td><span class="badge badge-removed">- Removed</span></td><td>{{ f.title }}</td><td>{{ f.severity }}</td></tr>
        {% endfor %}
        {% for title, sev, n in report.diff.unchanged %}
        <tr><td><span class="badge badge-unchanged">= Unchanged ({{ n }})</span></td><td>{{ title }}</td><td>{{ sev }}</td></tr>
        {% endfor %}
      </tbody>
    </table>
    {% endif %}

    <h3>Findings ({{ report.all_findings|length }})</h3>
    {% for f in report.all_findings %}
    <div class="finding f-{{ f.severity }}">
      <span class="sev">{{ f.severity }}</span>
      <h3>{{ f.title }}</h3>
      {% if f.evidence %}<pre>{{ f.evidence }}</pre>{% endif %}
      {% if f.recommendation %}<p class="rec">Recomendacao: {{ f.recommendation }}</p>{% endif %}
    </div>
    {% endfor %}
  </section>
  {% endfor %}

  <div class="footer">Gerado por mytools v{{ version }} &middot; mytools-report</div>
</body>
</html>
"""


def _render_html(
    title: str, reports: list[HostReport], tool: str = "", diff: bool = False
) -> str:
    """Renderiza o relatorio HTML com jinja2."""
    template = Template(_TEMPLATE)
    return template.render(
        title=title,
        generated_at=datetime.now().strftime("%Y-%m-%dT%H-%M-%S"),
        hosts=reports,
        tool=tool,
        diff=diff,
        version=__version__,
    )


# ---------------------------------------------------------------------------
# Processamento
# ---------------------------------------------------------------------------


def _process(
    files: list[str], directories: list[str], tool: str = ""
) -> list[HostReport]:
    paths: list[Path] = [Path(f) for f in files if Path(f).is_file()]
    for directory in directories:
        paths.extend(_load_scan_files(directory))
    return _group_by_host(paths, tool)


def _print_json(reports: list[HostReport], diff: bool) -> None:
    payload: dict = {
        "hosts": [
            {
                "host": r.host,
                "tool": r.tool,
                "scans": [
                    {
                        "timestamp": s.timestamp,
                        "overall_status": s.overall_status,
                        "findings": [
                            {
                                "fingerprint": f.fingerprint,
                                "title": f.title,
                                "severity": f.severity,
                                "evidence": f.evidence,
                                "recommendation": f.recommendation,
                            }
                            for f in s.findings
                        ],
                    }
                    for s in r.sorted_scans
                ],
                "diff": (
                    {
                        "added": [f.title for f in r.diff.added],
                        "removed": [f.title for f in r.diff.removed],
                        "unchanged": [t for t, _s, _n in r.diff.unchanged],
                    }
                    if diff and r.diff
                    else None
                ),
            }
            for r in reports
        ]
    }
    json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)
    print()


def build_parser() -> argparse.ArgumentParser:
    """Monta parser CLI para mytools-report."""
    parser = argparse.ArgumentParser(
        prog="mytools-report",
        description="Gera relatorio HTML a partir de scans JSON do MyTools (findings, severidade, timeline e diff entre scans).",
    )
    parser.add_argument(
        "-f",
        "--file",
        action="append",
        default=[],
        help="Arquivo(s) JSON de scan (pode repetir).",
    )
    parser.add_argument(
        "-d",
        "--dir",
        action="append",
        default=[],
        help="Diretorio de workspace (outputs/<host>/<ts>.json), recursivo.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="report.html",
        help="Arquivo HTML de saida (default: report.html).",
    )
    parser.add_argument(
        "--title",
        default="MyTools Scan Report",
        help="Titulo do relatorio (default: MyTools Scan Report).",
    )
    parser.add_argument(
        "--tool",
        default="",
        help="Nome da ferramenta que gerou os scans (opcional).",
    )
    parser.add_argument(
        "--diff",
        action="store_true",
        help="Inclui diff entre os 2 scans mais recentes de cada host.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Imprime dados normalizados em JSON (debug) e sai.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suprime mensagens de progresso.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Mostra mensagens de debug.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa a geracao de relatorio a partir de argumentos parseados."""
    setup_logging(verbose=getattr(args, "verbose", False))

    if not args.file and not args.dir:
        build_parser().print_usage(sys.stderr)
        print("Erro: informe ao menos um --file ou --dir.", file=sys.stderr)
        return 1

    reports = _process(args.file, args.dir, tool=args.tool)
    if not reports:
        print("Nenhum scan JSON encontrado nos inputs informados.", file=sys.stderr)
        return 1

    if args.json:
        _print_json(reports, args.diff)
        return 0

    html = _render_html(args.title, reports, tool=args.tool, diff=args.diff)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    if not args.quiet:
        print(f"Relatorio salvo em {out_path} ({len(html)} bytes)")
    return 0


def main() -> int:
    """Entry point para mytools-report."""
    parser = build_parser()

    if len(sys.argv) <= 1:
        return run_interactive_shell(
            parser,
            prompt="report> ",
            run_fn=run_once,
            description="Gera relatorio HTML a partir de scans JSON (findings, severidade, timeline e diff).",
            example="-d outputs/ --title Auditoria",
            contextual_help=(
                "Uso: <arquivos|diretorios> [opcoes]\n"
                "Exemplos:\n"
                "  -d outputs/\n"
                "  -d outputs/ --diff --title Auditoria\n"
                "  -f a.json b.json --diff\n"
                "  -f scan.json --tool charsetbypass -o relatorio.html"
            ),
        )

    args = parser.parse_args()
    setup_logging(verbose=getattr(args, "verbose", False))
    return run_once(args)


if __name__ == "__main__":
    raise SystemExit(main())
