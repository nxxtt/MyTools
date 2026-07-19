#!/usr/bin/env python3
"""Tests for attackanalysis.py."""

from __future__ import annotations

from pathlib import Path

import pytest

from mytools.web.attackanalysis import (
    _SEVERITY_COLORS,
    AttackEdge,
    AttackGraph,
    AttackNode,
    build_graph,
    build_parser,
    export_dot,
    print_results,
    render_png,
    render_svg,
    suggest_exploits,
)


class TestAttackNode:
    def test_creation(self) -> None:
        node = AttackNode(
            id="vuln_0", label="XSS\n(critical)", severity="critical",
            category="xss", module="xssvectors", exploit="curl <TARGET>",
        )
        assert node.id == "vuln_0"
        assert node.severity == "critical"
        assert node.exploit == "curl <TARGET>"

    def test_frozen(self) -> None:
        node = AttackNode(
            id="v", label="l", severity="info",
            category="c", module="m",
        )
        with pytest.raises(AttributeError):
            node.id = "changed"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(AttackNode, "__slots__")

    def test_default_exploit(self) -> None:
        node = AttackNode(
            id="v", label="l", severity="info",
            category="c", module="m",
        )
        assert node.exploit == ""


class TestAttackEdge:
    def test_creation(self) -> None:
        edge = AttackEdge(source="vuln_0", target="vuln_1", relationship="same_category")
        assert edge.source == "vuln_0"
        assert edge.relationship == "same_category"

    def test_frozen(self) -> None:
        edge = AttackEdge(source="a", target="b", relationship="r")
        with pytest.raises(AttributeError):
            edge.source = "changed"  # type: ignore[misc]


class TestAttackGraph:
    def test_creation(self) -> None:
        graph = AttackGraph(
            nodes=[], edges=[], target="test.com",
            total_vulnerabilities=5,
            critical_count=1, high_count=2,
            medium_count=1, low_count=1, info_count=0,
        )
        assert graph.target == "test.com"
        assert graph.total_vulnerabilities == 5
        assert graph.critical_count == 1

    def test_frozen(self) -> None:
        graph = AttackGraph(
            nodes=[], edges=[], target="t",
            total_vulnerabilities=0,
            critical_count=0, high_count=0,
            medium_count=0, low_count=0, info_count=0,
        )
        with pytest.raises(AttributeError):
            graph.target = "changed"  # type: ignore[misc]


class TestBuildGraph:
    def test_empty_findings(self) -> None:
        graph = build_graph([], "test.com")
        assert graph.total_vulnerabilities == 0
        assert len(graph.nodes) == 0

    def test_single_finding(self) -> None:
        findings = [{"severity": "high", "category": "xss", "item": "XSS Reflected"}]
        graph = build_graph(findings, "test.com")
        assert graph.total_vulnerabilities == 1
        assert graph.high_count == 1
        assert len(graph.nodes) == 1
        assert graph.nodes[0].severity == "high"

    def test_multiple_findings_same_category(self) -> None:
        findings = [
            {"severity": "high", "category": "xss", "item": "XSS1"},
            {"severity": "medium", "category": "xss", "item": "XSS2"},
        ]
        graph = build_graph(findings, "test.com")
        assert graph.total_vulnerabilities == 2
        assert len(graph.edges) == 1
        assert graph.edges[0].relationship == "same_category"

    def test_multiple_findings_different_category(self) -> None:
        findings = [
            {"severity": "high", "category": "xss", "item": "XSS"},
            {"severity": "medium", "category": "sqli", "item": "SQLi"},
        ]
        graph = build_graph(findings, "test.com")
        assert graph.total_vulnerabilities == 2
        assert len(graph.edges) == 0

    def test_severity_counts(self) -> None:
        findings = [
            {"severity": "critical", "category": "c", "item": "C"},
            {"severity": "high", "category": "h", "item": "H"},
            {"severity": "medium", "category": "m", "item": "M"},
            {"severity": "low", "category": "l", "item": "L"},
            {"severity": "info", "category": "i", "item": "I"},
        ]
        graph = build_graph(findings, "test.com")
        assert graph.critical_count == 1
        assert graph.high_count == 1
        assert graph.medium_count == 1
        assert graph.low_count == 1
        assert graph.info_count == 1

    def test_exploit_preserved(self) -> None:
        findings = [{"severity": "high", "category": "xss", "item": "XSS", "exploit": "curl <TARGET>"}]
        graph = build_graph(findings, "test.com")
        assert graph.nodes[0].exploit == "curl <TARGET>"


class TestSuggestExploits:
    def test_empty_findings(self) -> None:
        exploits = suggest_exploits([])
        assert exploits == []

    def test_no_exploits(self) -> None:
        findings = [{"severity": "high", "category": "xss", "item": "XSS"}]
        exploits = suggest_exploits(findings)
        assert exploits == []

    def test_with_exploits(self) -> None:
        findings = [
            {"severity": "high", "category": "xss", "item": "XSS", "exploit": "curl <TARGET>"},
            {"severity": "medium", "category": "sqli", "item": "SQLi", "exploit": "sqlmap <TARGET>"},
        ]
        exploits = suggest_exploits(findings)
        assert len(exploits) == 2
        assert exploits[0]["module"] == "XSS"
        assert exploits[1]["module"] == "SQLi"

    def test_mixed_exploits(self) -> None:
        findings = [
            {"severity": "high", "category": "xss", "item": "XSS", "exploit": "curl <TARGET>"},
            {"severity": "medium", "category": "sqli", "item": "SQLi"},
        ]
        exploits = suggest_exploits(findings)
        assert len(exploits) == 1


class TestRenderPNG:
    def test_render_png(self, tmp_path: Path) -> None:
        findings = [{"severity": "high", "category": "xss", "item": "XSS"}]
        graph = build_graph(findings, "test.com")
        output = str(tmp_path / "test.png")
        render_png(graph, output)
        assert Path(output).exists()
        assert Path(output).stat().st_size > 0

    def test_render_png_empty(self, tmp_path: Path) -> None:
        graph = build_graph([], "test.com")
        output = str(tmp_path / "empty.png")
        render_png(graph, output)
        assert Path(output).exists()


class TestRenderSVG:
    def test_render_svg(self, tmp_path: Path) -> None:
        findings = [{"severity": "high", "category": "xss", "item": "XSS"}]
        graph = build_graph(findings, "test.com")
        output = str(tmp_path / "test.svg")
        render_svg(graph, output)
        assert Path(output).exists()
        assert Path(output).stat().st_size > 0


class TestExportDot:
    def test_export_dot(self, tmp_path: Path) -> None:
        findings = [{"severity": "high", "category": "xss", "item": "XSS"}]
        graph = build_graph(findings, "test.com")
        output = str(tmp_path / "test.dot")
        export_dot(graph, output)
        content = Path(output).read_text(encoding="utf-8")
        assert "digraph AttackGraph" in content
        assert "XSS" in content

    def test_export_dot_empty(self, tmp_path: Path) -> None:
        graph = build_graph([], "test.com")
        output = str(tmp_path / "empty.dot")
        export_dot(graph, output)
        content = Path(output).read_text(encoding="utf-8")
        assert "digraph AttackGraph" in content


class TestPrintResults:
    def test_print_results(self, capsys: pytest.CaptureFixture[str]) -> None:
        findings = [{"severity": "high", "category": "xss", "item": "XSS", "exploit": "curl <TARGET>"}]
        graph = build_graph(findings, "test.com")
        exploits = suggest_exploits(findings)
        print_results(graph, exploits)
        captured = capsys.readouterr()
        assert "Attack Analysis" in captured.out
        assert "test.com" in captured.out

    def test_print_results_no_exploits(self, capsys: pytest.CaptureFixture[str]) -> None:
        graph = build_graph([], "test.com")
        print_results(graph, [])
        captured = capsys.readouterr()
        assert "No exploits suggested" in captured.out


class TestSeverityColors:
    def test_all_severities_have_colors(self) -> None:
        expected = {"critical", "high", "medium", "low", "info"}
        assert set(_SEVERITY_COLORS.keys()) == expected

    def test_colors_are_hex(self) -> None:
        for color_val in _SEVERITY_COLORS.values():
            assert color_val.startswith("#")
            assert len(color_val) == 7


@pytest.mark.smoke
class TestBuildParser:
    def test_parser_creation(self) -> None:
        parser = build_parser()
        assert parser.prog == "mytools-analysis"

    def test_parser_args(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["findings.json"])
        assert args.findings_file == "findings.json"

    def test_parser_with_options(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["findings.json", "--png", "out.png", "--svg", "out.svg", "--dot", "out.dot"])
        assert args.png == "out.png"
        assert args.svg == "out.svg"
        assert args.dot == "out.dot"

    def test_parser_exploits_only(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["findings.json", "--exploits-only"])
        assert args.exploits_only is True
