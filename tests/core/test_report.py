import json
from pathlib import Path

from mytools.core.report import (
    Finding,
    HostReport,
    ScanResult,
    _diff_scans,
    _extract_findings,
    _group_by_host,
    _load_scan_files,
    _normalize,
    _render_html,
    build_parser,
    main,
)

# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


class TestParser:
    def test_defaults(self):
        args = build_parser().parse_args(["-d", "out/"])
        assert args.file == []
        assert args.dir == ["out/"]
        assert args.output == "report.html"
        assert args.title == "MyTools Scan Report"
        assert args.tool == ""
        assert args.diff is False
        assert args.json is False

    def test_all_flags(self):
        args = build_parser().parse_args(
            [
                "-f",
                "a.json",
                "-f",
                "b.json",
                "-d",
                "out/",
                "-o",
                "x.html",
                "--title",
                "Rel",
                "--tool",
                "charsetbypass",
                "--diff",
                "--json",
                "-q",
            ]
        )
        assert args.file == ["a.json", "b.json"]
        assert args.dir == ["out/"]
        assert args.output == "x.html"
        assert args.title == "Rel"
        assert args.tool == "charsetbypass"
        assert args.diff is True
        assert args.json is True
        assert args.quiet is True


# ---------------------------------------------------------------------------
# _extract_findings
# ---------------------------------------------------------------------------


class TestExtractFindings:
    def test_group_b_attempts(self):
        data = {
            "target": "http://x.com",
            "overall_status": "vulnerable",
            "attempts": [
                {
                    "technique": "os_command",
                    "vulnerable": True,
                    "details": "uid=0(root)",
                    "exploit": "",
                },
                {
                    "technique": "blind",
                    "vulnerable": False,
                    "details": "nada",
                },
            ],
            "issues": [],
        }
        findings = _extract_findings(data)
        assert len(findings) == 1
        assert findings[0].fingerprint == "technique:os_command"
        assert findings[0].severity == "high"
        assert findings[0].evidence == "uid=0(root)"

    def test_attackaudit_findings(self):
        data = {
            "target": "http://x.com",
            "findings": [
                {
                    "severity": "high",
                    "category": "headers",
                    "item": "server-version",
                    "evidence": "Server: nginx/1.20",
                    "recommendation": "Remover versao",
                }
            ],
        }
        findings = _extract_findings(data)
        assert len(findings) == 1
        assert findings[0].fingerprint == "category:headers|item:server-version"
        assert findings[0].title == "headers: server-version"
        assert findings[0].severity == "high"

    def test_legacy_list(self):
        data = [
            {"url": "http://x.com/.env", "status": 200},
            {"url": "http://x.com/admin", "status": 403},
        ]
        findings = _extract_findings(data)
        assert len(findings) == 2
        assert findings[0].severity == "high"

    def test_empty(self):
        assert _extract_findings({}) == []
        assert _extract_findings({"attempts": []}) == []
        assert _extract_findings({"findings": []}) == []


# ---------------------------------------------------------------------------
# _normalize
# ---------------------------------------------------------------------------


class TestNormalize:
    def test_dict_with_target(self):
        path = Path("out/example.com/2026-08-01T10-00-00.json")
        scan = _normalize(
            path, {"target": "https://example.com", "overall_status": "secure"}
        )
        assert scan.host == "https://example.com"
        assert scan.timestamp == "2026-08-01T10-00-00"
        assert scan.overall_status == "secure"

    def test_dict_infer_host_from_path(self):
        path = Path("out/example.com/2026-08-01T10-00-00.json")
        scan = _normalize(path, {"overall_status": "ok"})
        assert scan.host == "example.com"
        assert scan.timestamp == "2026-08-01T10-00-00"

    def test_legacy_list(self):
        path = Path("out/example.com/2026-08-01T10-00-00.json")
        scan = _normalize(path, [{"url": "http://x/.env", "status": 200}])
        assert scan.host == "example.com"
        assert scan.count == 1


# ---------------------------------------------------------------------------
# _diff_scans
# ---------------------------------------------------------------------------


def _mk_scan(ts: str, findings: list[Finding]) -> ScanResult:
    return ScanResult(
        path=Path("out/x.json"), host="example.com", timestamp=ts, findings=findings
    )


def _f(fp: str, title: str, sev: str = "high") -> Finding:
    return Finding(fingerprint=fp, title=title, severity=sev)


class TestDiffScans:
    def test_added_removed_unchanged(self):
        base = _mk_scan(
            "t1",
            [_f("t:cmd", "Cmd Inject"), _f("t:open_redirect", "Open Redirect")],
        )
        curr = _mk_scan(
            "t2",
            [_f("t:cmd", "Cmd Inject"), _f("t:sqli", "SQLi")],
        )
        diff = _diff_scans(base, curr)
        assert [f.fingerprint for f in diff.added] == ["t:sqli"]
        assert [f.fingerprint for f in diff.removed] == ["t:open_redirect"]
        assert diff.unchanged == [("Cmd Inject", "high", 1)]
        assert diff.has_changes

    def test_multiset_counts(self):
        base = _mk_scan(
            "t1", [_f("t:port", "Port 80", "medium"), _f("t:port", "Port 80", "medium")]
        )
        curr = _mk_scan("t2", [_f("t:port", "Port 80", "medium")])
        diff = _diff_scans(base, curr)
        assert [f.fingerprint for f in diff.removed] == ["t:port"]
        assert diff.unchanged == [("Port 80", "medium", 1)]

    def test_identical_no_changes(self):
        base = _mk_scan("t1", [_f("t:a", "A")])
        curr = _mk_scan("t2", [_f("t:a", "A")])
        diff = _diff_scans(base, curr)
        assert diff.added == []
        assert diff.removed == []
        assert diff.has_changes is False


class TestHostReport:
    def test_no_diff_with_one_scan(self):
        report = HostReport(host="example.com")
        report.scans.append(_mk_scan("t1", []))
        assert report.diff is None

    def test_diff_between_two_latest(self):
        report = HostReport(host="example.com")
        report.scans.append(_mk_scan("t1", [_f("t:a", "A")]))
        report.scans.append(_mk_scan("t2", [_f("t:a", "A"), _f("t:b", "B")]))
        report.scans.append(_mk_scan("t3", [_f("t:a", "A")]))
        diff = report.diff
        assert diff is not None
        assert [f.fingerprint for f in diff.removed] == ["t:b"]

    def test_severity_counts(self):
        report = HostReport(host="example.com")
        report.scans.append(
            _mk_scan("t1", [_f("t:a", "A", "critical"), _f("t:b", "B", "info")])
        )
        counts = report.severity_counts()
        assert counts[0] == ("critical", 1)
        assert counts[4] == ("info", 1)


# ---------------------------------------------------------------------------
# _load_scan_files / _group_by_host
# ---------------------------------------------------------------------------


class TestLoadScanFiles:
    def test_recursive_and_sorted(self, tmp_path: Path):
        (tmp_path / "example.com").mkdir()
        (tmp_path / "b.com").mkdir()
        f1 = tmp_path / "example.com" / "2026-08-01T10-00-00.json"
        f2 = tmp_path / "example.com" / "2026-08-01T09-00-00.json"
        f3 = tmp_path / "b.com" / "2026-08-01T10-00-00.json"
        for f in (f1, f2, f3):
            f.write_text('{"target": "x", "overall_status": "ok"}', encoding="utf-8")
        (tmp_path / "ignore.txt").write_text("x", encoding="utf-8")

        paths = _load_scan_files(tmp_path)
        assert paths == sorted([f1, f2, f3])

    def test_group_by_host(self, tmp_path: Path):
        (tmp_path / "example.com").mkdir()
        a = tmp_path / "example.com" / "2026-08-01T09-00-00.json"
        b = tmp_path / "example.com" / "2026-08-01T10-00-00.json"
        a.write_text(
            json.dumps({"overall_status": "ok", "findings": []}), encoding="utf-8"
        )
        b.write_text(
            json.dumps({"overall_status": "vulnerable", "findings": []}),
            encoding="utf-8",
        )

        reports = _group_by_host(_load_scan_files(tmp_path))
        assert len(reports) == 1
        assert reports[0].host == "example.com"
        assert len(reports[0].scans) == 2


# ---------------------------------------------------------------------------
# renderização
# ---------------------------------------------------------------------------


class TestRender:
    def test_html_contains_sections(self):
        report = HostReport(host="example.com", tool="charsetbypass")
        report.scans.append(
            _mk_scan("t1", [_f("t:a", "Cmd Inject", "high"), _f("t:b", "Info", "info")])
        )
        html = _render_html("Meu Relatorio", [report], tool="charsetbypass", diff=False)
        assert "<html" in html
        assert "Meu Relatorio" in html
        assert "example.com" in html
        assert "Cmd Inject" in html
        assert "high" in html
        assert "mytools v" in html

    def test_html_with_diff(self):
        report = HostReport(host="example.com")
        report.scans.append(_mk_scan("t1", [_f("t:a", "A")]))
        report.scans.append(_mk_scan("t2", [_f("t:a", "A"), _f("t:b", "B")]))
        html = _render_html("T", [report], diff=True)
        assert "+ Added" in html
        assert "B" in html
        assert "= Unchanged" in html

    def test_html_without_diff_no_diff_table(self):
        report = HostReport(host="example.com")
        report.scans.append(_mk_scan("t1", [_f("t:a", "A")]))
        report.scans.append(_mk_scan("t2", [_f("t:a", "A")]))
        html = _render_html("T", [report], diff=False)
        assert "+ Added" not in html


# ---------------------------------------------------------------------------
# main end-to-end
# ---------------------------------------------------------------------------


class TestMain:
    def test_no_inputs_returns_1(self, capsys):
        code = main_runner(["--json"])
        assert code == 1

    def test_dir_generates_html(self, tmp_path: Path, capsys):
        host_dir = tmp_path / "example.com"
        host_dir.mkdir()
        (host_dir / "2026-08-01T10-00-00.json").write_text(
            json.dumps(
                {
                    "target": "https://example.com",
                    "overall_status": "vulnerable",
                    "findings": [
                        {
                            "severity": "high",
                            "category": "headers",
                            "item": "server-version",
                            "evidence": "Server: nginx",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        out = tmp_path / "r.html"
        code = main_runner(
            ["-d", str(tmp_path), "-o", str(out), "--title", "Auditoria"]
        )
        assert code == 0
        html = out.read_text(encoding="utf-8")
        assert "Auditoria" in html
        assert "example.com" in html
        assert "headers: server-version" in html

    def test_diff_two_files(self, tmp_path: Path):
        a = tmp_path / "a.json"
        b = tmp_path / "b.json"
        a.write_text(
            json.dumps(
                {
                    "target": "https://example.com",
                    "overall_status": "vulnerable",
                    "findings": [{"severity": "high", "category": "c", "item": "old"}],
                }
            ),
            encoding="utf-8",
        )
        b.write_text(
            json.dumps(
                {
                    "target": "https://example.com",
                    "overall_status": "vulnerable",
                    "findings": [{"severity": "high", "category": "c", "item": "new"}],
                }
            ),
            encoding="utf-8",
        )
        out = tmp_path / "d.html"
        code = main_runner(["-f", str(a), "-f", str(b), "--diff", "-o", str(out)])
        assert code == 0
        html = out.read_text(encoding="utf-8")
        assert "+ Added" in html
        assert "c: new" in html
        assert "c: old" in html

    def test_json_debug_output(self, tmp_path: Path, capsys):
        host_dir = tmp_path / "example.com"
        host_dir.mkdir()
        (host_dir / "2026-08-01T10-00-00.json").write_text(
            json.dumps({"overall_status": "ok", "findings": []}), encoding="utf-8"
        )
        code = main_runner(["-d", str(tmp_path), "--json"])
        assert code == 0
        data = json.loads(capsys.readouterr().out)
        assert data["hosts"][0]["host"] == "example.com"

    def test_no_scans_returns_1(self, tmp_path: Path, capsys):
        code = main_runner(["-d", str(tmp_path)])
        assert code == 1


def main_runner(argv: list[str]):
    """Roda main() com argv stubado e captura a saida."""
    import sys

    old = sys.argv
    sys.argv = ["mytools-report", *argv]
    try:
        return main()
    finally:
        sys.argv = old
