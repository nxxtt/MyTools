import json
from pathlib import Path

from mytools.core.report import (
    Finding,
    HostReport,
    ScanResult,
    _attempt_title,
    _derive_severity,
    _diff_scans,
    _extract_findings,
    _findings_from_legacy,
    _group_by_host,
    _host_from_path,
    _is_vulnerable_item,
    _item_fingerprint,
    _legacy_title,
    _load_json,
    _load_scan_files,
    _normalize,
    _render_html,
    build_parser,
    main,
    run_once,
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
# _derive_severity
# ---------------------------------------------------------------------------


class TestDeriveSeverity:
    def test_known_severity(self):
        assert _derive_severity("high") == "high"
        assert _derive_severity("CRITICAL") == "critical"
        assert _derive_severity("  medium  ") == "medium"

    def test_unknown_severity_high_by_default(self):
        assert _derive_severity("mystery") == "high"

    def test_unknown_severity_info_when_not_vulnerable(self):
        assert _derive_severity("mystery", vulnerable=False) == "info"


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

    def test_findings_unknown_severity_falls_back(self):
        data = {
            "findings": [
                {
                    "severity": "mystery",
                    "category": "headers",
                    "item": "x-powered-by",
                }
            ],
        }
        findings = _extract_findings(data)
        assert len(findings) == 1
        assert findings[0].severity == "high"


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


# ---------------------------------------------------------------------------
# helpers de extração (bordas)
# ---------------------------------------------------------------------------


class TestAttemptTitle:
    def test_with_category(self):
        assert _attempt_title({"technique": "t", "category": "dom"}) == "dom: t"

    def test_with_name_and_type(self):
        assert _attempt_title({"name": "n"}) == "n"
        assert _attempt_title({"type": "ty"}) == "ty"

    def test_default(self):
        assert _attempt_title({}) == "Attempt"


class TestLegacyTitle:
    def test_with_url_and_status(self):
        assert (
            _legacy_title({"url": "http://x/.env", "status": 404})
            == "http://x/.env [404]"
        )

    def test_with_path_no_status(self):
        assert _legacy_title({"path": "/a"}) == "/a"

    def test_no_url(self):
        assert _legacy_title({}) == "Item"


class TestItemFingerprint:
    def test_technique(self):
        assert _item_fingerprint({"technique": "t"}) == "technique:t"

    def test_url(self):
        assert _item_fingerprint({"url": "http://x"}) == "url:http://x"

    def test_category_with_item(self):
        assert _item_fingerprint({"category": "c", "item": "i"}) == "category:c|item:i"

    def test_category_without_item(self):
        assert _item_fingerprint({"category": "c"}) == "category:c"

    def test_unknown(self):
        assert _item_fingerprint({}) == "item:unknown"


class TestIsVulnerableItem:
    def test_bool_keys(self):
        assert _is_vulnerable_item({"vulnerable": True}) is True
        assert _is_vulnerable_item({"confirmed": False}) is False

    def test_status_int(self):
        assert _is_vulnerable_item({"status": 200}) is True
        assert _is_vulnerable_item({"status": 500}) is False
        assert _is_vulnerable_item({"status": 404}) is False

    def test_default_true(self):
        assert _is_vulnerable_item({}) is True
        assert _is_vulnerable_item({"status": "x"}) is True


class TestFindingsFromLegacy:
    def test_skips_non_vulnerable(self):
        out = _findings_from_legacy(
            [
                {"url": "http://x/a", "status": 500},
                {"url": "http://x/b", "status": 200},
            ],
            "legacy",
        )
        assert len(out) == 1
        assert out[0].title == "http://x/b [200]"


class TestExtractFindingsEdges:
    def test_list_with_non_dict(self):
        assert _extract_findings(["a", 1]) == []

    def test_iterable_without_technique_uses_legacy(self):
        data = {"results": [{"url": "http://x/a", "status": 200}]}
        findings = _extract_findings(data, "tool")
        assert len(findings) == 1
        assert findings[0].fingerprint == "url:http://x/a"

    def test_issues_strings(self):
        data = {"issues": ["a", "b"]}
        findings = _extract_findings(data, "tool")
        assert len(findings) == 2
        assert {f.title for f in findings} == {"a", "b"}
        assert all(f.severity == "high" for f in findings)

    def test_vulnerable_techniques(self):
        data = {"vulnerable_techniques": ["xss"]}
        findings = _extract_findings(data, "tool")
        assert len(findings) == 1
        assert findings[0].title == "xss"

    def test_blocked_techniques_not_vulnerable(self):
        data = {"blocked_techniques": ["waf"]}
        findings = _extract_findings(data, "tool")
        assert len(findings) == 0


class TestHostFromPath:
    def test_infers_host(self):
        path = Path("out/example.com/2026-08-01T10-00-00.json")
        assert _host_from_path(path) == "example.com"

    def test_fallback_stem(self):
        assert _host_from_path(Path("out/scan.json")) == "scan"


class TestLoadJson:
    def test_invalid_json(self, tmp_path: Path):
        p = tmp_path / "bad.json"
        p.write_text("{not json", encoding="utf-8")
        assert _load_json(p) is None

    def test_missing_file(self, tmp_path: Path):
        assert _load_json(tmp_path / "missing.json") is None

    def test_non_dict_list(self, tmp_path: Path):
        p = tmp_path / "n.json"
        p.write_text("42", encoding="utf-8")
        assert _load_json(p) is None

    def test_valid(self, tmp_path: Path):
        p = tmp_path / "ok.json"
        p.write_text('{"a": 1}', encoding="utf-8")
        assert _load_json(p) == {"a": 1}


class TestLoadScanFilesEdges:
    def test_not_a_dir(self, tmp_path: Path):
        assert _load_scan_files(tmp_path / "nope") == []

    def test_group_by_host_skips_invalid(self, tmp_path: Path):
        host_dir = tmp_path / "example.com"
        host_dir.mkdir()
        (host_dir / "bad.json").write_text("{oops", encoding="utf-8")
        (host_dir / "good.json").write_text(
            json.dumps({"overall_status": "ok", "findings": []}), encoding="utf-8"
        )
        reports = _group_by_host(_load_scan_files(tmp_path))
        assert len(reports) == 1
        assert len(reports[0].scans) == 1


# ---------------------------------------------------------------------------
# run_once / main shell
# ---------------------------------------------------------------------------


class TestRunOnceEdges:
    def test_no_inputs(self, capsys):

        from mytools.core.report import build_parser

        args = build_parser().parse_args([])
        assert run_once(args) == 1
        assert "Erro: informe ao menos um --file ou --dir." in capsys.readouterr().err

    def test_quiet_writes_report(self, tmp_path: Path):
        from mytools.core.report import build_parser

        host_dir = tmp_path / "example.com"
        host_dir.mkdir()
        (host_dir / "2026-08-01T10-00-00.json").write_text(
            json.dumps({"overall_status": "ok", "findings": []}), encoding="utf-8"
        )
        out = tmp_path / "q.html"
        args = build_parser().parse_args(["-d", str(tmp_path), "-o", str(out), "-q"])
        assert run_once(args) == 0
        assert out.exists()
        assert "Relatorio salvo" not in args.output

    def test_json_output(self, tmp_path: Path, capsys):
        from mytools.core.report import build_parser

        host_dir = tmp_path / "example.com"
        host_dir.mkdir()
        (host_dir / "2026-08-01T10-00-00.json").write_text(
            json.dumps({"overall_status": "ok", "findings": []}), encoding="utf-8"
        )
        args = build_parser().parse_args(["-d", str(tmp_path), "--json"])
        assert run_once(args) == 0
        data = json.loads(capsys.readouterr().out)
        assert data["hosts"][0]["host"] == "example.com"


class TestMainShell:
    def test_no_args_enters_shell(self):
        import sys
        from unittest.mock import patch

        from mytools.core.report import main

        with patch("mytools.core.report.run_interactive_shell") as mock_shell:
            mock_shell.return_value = 0
            with patch.object(sys, "argv", ["mytools-report"]):
                assert main() == 0
            assert mock_shell.call_args.kwargs["prompt"] == "report> "

    def test_main_guard_runs(self, tmp_path: Path):
        import runpy
        import sys
        from unittest.mock import patch

        host_dir = tmp_path / "example.com"
        host_dir.mkdir()
        (host_dir / "2026-08-01T10-00-00.json").write_text(
            json.dumps({"overall_status": "ok", "findings": []}), encoding="utf-8"
        )
        out = tmp_path / "r.html"
        with patch.object(
            sys,
            "argv",
            ["mytools-report", "-d", str(tmp_path), "-o", str(out), "-q"],
        ):
            import pytest

            with pytest.raises(SystemExit) as exc:
                runpy.run_module("mytools.core.report", run_name="__main__")
            assert exc.value.code == 0
