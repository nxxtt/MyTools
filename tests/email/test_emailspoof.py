#!/usr/bin/env python3
"""Testes unitarios do modulo de Email Spoofing."""

import asyncio
import runpy
from unittest.mock import MagicMock, patch

import pytest

from mytools.email.emailsecurity import DmarcRecord, EmailSecurityResult, SpfRecord
from mytools.email.emailspoof import (
    SpoofResult,
    SpoofVector,
    _async_run_once,
    _max_severity,
    analyze_spoofing,
    banner,
    build_parser,
    main,
    print_results,
    run_once,
)


class TestSpoofVector:
    def test_frozen(self) -> None:
        v = SpoofVector(name="test", severity="high", description="d", remediation="r")
        with pytest.raises(AttributeError):
            v.name = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(SpoofVector, "__slots__")


class TestSpoofResult:
    def test_frozen(self) -> None:
        r = SpoofResult(
            domain="a",
            risk_score="none",
            vectors=[],
            issues=[],
            spf_status="strict",
            dmarc_status="reject",
            dkim_status="present",
            overall_protection="protected",
        )
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(SpoofResult, "__slots__")


class TestMaxSeverity:
    def test_empty(self) -> None:
        assert _max_severity([]) == "none"

    def test_critical_wins(self) -> None:
        vectors = [
            SpoofVector("a", "low", "d", "r"),
            SpoofVector("b", "critical", "d", "r"),
            SpoofVector("c", "medium", "d", "r"),
        ]
        assert _max_severity(vectors) == "critical"

    def test_high_wins(self) -> None:
        vectors = [
            SpoofVector("a", "low", "d", "r"),
            SpoofVector("b", "high", "d", "r"),
        ]
        assert _max_severity(vectors) == "high"


class TestParser:
    def test_basic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_nameserver(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--nameserver", "1.1.1.1"])
        assert args.nameserver == "1.1.1.1"

    def test_selectors(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--selectors", "a,b"])
        assert args.selectors == "a,b"

    def test_query_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--query-timeout", "10.0"])
        assert args.query_timeout == 10.0


class TestAnalyzeSpoofing:
    """Testes da funcao analyze_spoofing com mocks."""

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_no_records(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="bad.com",
            spf=None,
            dkim_selectors=[],
            dmarc=None,
            overall_status="critical",
            issues=[],
        )
        result = analyze_spoofing("bad.com")
        assert result.risk_score == "critical"
        assert result.overall_protection == "vulnerable"
        assert len(result.vectors) >= 2

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_full_protection(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="good.com",
            spf=SpfRecord("v=spf1 -all", "spf1", [], True, "-", []),
            dkim_selectors=["default"],
            dmarc=DmarcRecord(
                "v=DMARC1; p=reject; rua=mailto:d@example.com",
                "reject",
                "reject",
                "mailto:d@example.com",
                100,
            ),
            overall_status="secure",
            issues=[],
        )
        result = analyze_spoofing("good.com")
        assert result.risk_score == "none"
        assert result.overall_protection == "protected"
        assert len(result.vectors) == 0

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_spf_plus_all(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="open.com",
            spf=SpfRecord("v=spf1 +all", "spf1", [], True, "+", []),
            dkim_selectors=[],
            dmarc=None,
            overall_status="critical",
            issues=[],
        )
        result = analyze_spoofing("open.com")
        assert result.risk_score == "critical"
        assert result.spf_status == "critical"
        assert any("SPF +all" in v.name for v in result.vectors)

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_spf_bare_all(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="open2.com",
            spf=SpfRecord("v=spf1 all", "spf1", [], True, "", []),
            dkim_selectors=[],
            dmarc=None,
            overall_status="critical",
            issues=[],
        )
        result = analyze_spoofing("open2.com")
        assert result.risk_score == "critical"
        assert result.spf_status == "critical"
        assert any("all sem qualificador" in v.name for v in result.vectors)

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_dmarc_none(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="weak.com",
            spf=SpfRecord("v=spf1 ~all", "spf1", [], True, "~", []),
            dkim_selectors=[],
            dmarc=DmarcRecord("v=DMARC1; p=none", "none", "none", "", 100),
            overall_status="warning",
            issues=[],
        )
        result = analyze_spoofing("weak.com")
        assert result.dmarc_status == "monitor_only"
        assert any("DMARC p=none" in v.name for v in result.vectors)

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_dmarc_pct_low(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="partial.com",
            spf=SpfRecord("v=spf1 -all", "spf1", [], True, "-", []),
            dkim_selectors=["default"],
            dmarc=DmarcRecord("v=DMARC1; p=reject; pct=50", "reject", "reject", "", 50),
            overall_status="good",
            issues=[],
        )
        result = analyze_spoofing("partial.com")
        assert any("pct=50" in v.name for v in result.vectors)

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_subdomain_sp_none(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="sub.com",
            spf=SpfRecord("v=spf1 -all", "spf1", [], True, "-", []),
            dkim_selectors=["default"],
            dmarc=DmarcRecord("v=DMARC1; p=reject; sp=none", "reject", "none", "", 100),
            overall_status="good",
            issues=[],
        )
        result = analyze_spoofing("sub.com")
        assert any("sp=none" in v.name for v in result.vectors)

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_spf_softfail(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="soft.com",
            spf=SpfRecord("v=spf1 ~all", "spf1", [], True, "~", []),
            dkim_selectors=["default"],
            dmarc=DmarcRecord("v=DMARC1; p=reject", "reject", "reject", "", 100),
            overall_status="good",
            issues=[],
        )
        result = analyze_spoofing("soft.com")
        assert result.spf_status == "softfail"

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_dmarc_quarantine(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="q.com",
            spf=SpfRecord("v=spf1 -all", "spf1", [], True, "-", []),
            dkim_selectors=["default"],
            dmarc=DmarcRecord(
                "v=DMARC1; p=quarantine", "quarantine", "quarantine", "", 100
            ),
            overall_status="good",
            issues=[],
        )
        result = analyze_spoofing("q.com")
        assert result.dmarc_status == "quarantine"
        assert result.risk_score in ("none", "low")

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_no_rua(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="nrua.com",
            spf=SpfRecord("v=spf1 -all", "spf1", [], True, "-", []),
            dkim_selectors=["default"],
            dmarc=DmarcRecord("v=DMARC1; p=reject", "reject", "reject", "", 100),
            overall_status="secure",
            issues=[],
        )
        result = analyze_spoofing("nrua.com")
        assert any("relatorio" in v.name.lower() for v in result.vectors)

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_spf_without_all(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="weakspf.com",
            spf=SpfRecord("v=spf1 include:_spf.google.com", "spf1", [], False, "", []),
            dkim_selectors=[],
            dmarc=None,
            overall_status="warning",
            issues=[],
        )
        result = analyze_spoofing("weakspf.com")
        assert result.spf_status == "weak"
        assert any("sem terminador" in v.name for v in result.vectors)

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_spf_neutral(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="neutral.com",
            spf=SpfRecord("v=spf1 ?all", "spf1", [], True, "?", []),
            dkim_selectors=[],
            dmarc=None,
            overall_status="warning",
            issues=[],
        )
        result = analyze_spoofing("neutral.com")
        assert result.spf_status == "neutral"
        assert any("?all" in v.name for v in result.vectors)

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_dmarc_reject_inherits(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="inherit.com",
            spf=SpfRecord("v=spf1 -all", "spf1", [], True, "-", []),
            dkim_selectors=["default"],
            dmarc=DmarcRecord("v=DMARC1; p=reject", "reject", "", "", 100),
            overall_status="secure",
            issues=[],
        )
        result = analyze_spoofing("inherit.com")
        assert result.dmarc_status == "reject"
        assert not any("sp=none" in v.name for v in result.vectors)

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_bypass_forwarders(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="fwd.com",
            spf=SpfRecord("v=spf1 -all", "spf1", [], True, "-", []),
            dkim_selectors=[],
            dmarc=DmarcRecord("v=DMARC1; p=none", "none", "none", "", 100),
            overall_status="warning",
            issues=[],
        )
        result = analyze_spoofing("fwd.com")
        assert any("forwarders" in v.name.lower() for v in result.vectors)

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_spf_unknown_qualifier(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="unknown.com",
            spf=SpfRecord("v=spf1 all", "spf1", [], True, "x", []),
            dkim_selectors=[],
            dmarc=None,
            overall_status="critical",
            issues=[],
        )
        result = analyze_spoofing("unknown.com")
        assert result.spf_status == "missing"

    @patch("mytools.email.emailspoof.scan_email_security")
    def test_dmarc_malformed(self, mock_scan: MagicMock) -> None:
        mock_scan.return_value = EmailSecurityResult(
            domain="malformed.com",
            spf=SpfRecord("v=spf1 -all", "spf1", [], True, "-", []),
            dkim_selectors=[],
            dmarc=DmarcRecord("v=DMARC1", "malformed", "malformed", "", 100),
            overall_status="warning",
            issues=[],
        )
        result = analyze_spoofing("malformed.com")
        assert result.dmarc_status == "missing"


class TestPrintResults:
    def test_protected(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = SpoofResult(
            domain="ok.com",
            risk_score="none",
            vectors=[],
            issues=[],
            spf_status="strict",
            dmarc_status="reject",
            dkim_status="present",
            overall_protection="protected",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "PROTECTED" in out

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = SpoofResult(
            domain="bad.com",
            risk_score="critical",
            vectors=[SpoofVector("SPF +all", "critical", "desc", "fix")],
            issues=[],
            spf_status="critical",
            dmarc_status="missing",
            dkim_status="missing",
            overall_protection="vulnerable",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "VULNERAVEL" in out
        assert "SPF +all" in out

    def test_high_risk(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = SpoofResult(
            domain="high.com",
            risk_score="high",
            vectors=[SpoofVector("DMARC p=none", "high", "desc", "fix")],
            issues=[],
            spf_status="strict",
            dmarc_status="monitor_only",
            dkim_status="present",
            overall_protection="partially_protected",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "melhorias" in out

    def test_medium_risk(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = SpoofResult(
            domain="med.com",
            risk_score="medium",
            vectors=[SpoofVector("DKIM ausente", "medium", "desc", "fix")],
            issues=[],
            spf_status="strict",
            dmarc_status="reject",
            dkim_status="missing",
            overall_protection="partially_protected",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "protecao basica" in out

    def test_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = SpoofResult(
            domain="iss.com",
            risk_score="low",
            vectors=[],
            issues=["SPF ~all: emails marcados mas nao rejeitados"],
            spf_status="softfail",
            dmarc_status="reject",
            dkim_status="present",
            overall_protection="partially_protected",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "SPF ~all" in out


class TestBanner:
    def test_banner(self, capsys: pytest.CaptureFixture[str]) -> None:
        banner()
        captured = capsys.readouterr()
        assert "email spoofing" in captured.out


class TestRunOnce:
    def test_run_once(self) -> None:
        args = build_parser().parse_args(["example.com"])
        with (
            patch(
                "mytools.email.emailspoof._async_run_once",
                new_callable=MagicMock,
                return_value=0,
            ),
            patch(
                "mytools.email.emailspoof.safe_asyncio_run",
                new_callable=MagicMock,
            ) as mock_safe,
        ):
            mock_safe.return_value = 0
            result = run_once(args)
            assert result == 0
        mock_safe.assert_called_once()


class TestAsyncRunOnce:
    def test_no_domain(self) -> None:
        args = build_parser().parse_args([])
        result = asyncio.run(_async_run_once(args))
        assert result == 1

    def test_dry_run(self, capsys: pytest.CaptureFixture[str]) -> None:
        args = build_parser().parse_args(["example.com", "--dry-run"])
        result = asyncio.run(_async_run_once(args))
        captured = capsys.readouterr().out
        assert "DRY-RUN" in captured
        assert result == 0

    def test_print_results(self) -> None:
        result = SpoofResult(
            domain="example.com",
            risk_score="none",
            vectors=[],
            issues=[],
            spf_status="strict",
            dmarc_status="reject",
            dkim_status="present",
            overall_protection="protected",
        )
        args = build_parser().parse_args(["example.com"])
        with patch(
            "mytools.email.emailspoof.analyze_spoofing",
            return_value=result,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0

    def test_output_flag(self, tmp_path) -> None:
        result = SpoofResult(
            domain="example.com",
            risk_score="none",
            vectors=[],
            issues=[],
            spf_status="strict",
            dmarc_status="reject",
            dkim_status="present",
            overall_protection="protected",
        )
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(["example.com", "-o", str(out_file)])
        with (
            patch(
                "mytools.email.emailspoof.analyze_spoofing",
                return_value=result,
            ),
            patch("mytools.email.emailspoof.write_output") as mock_write,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0
        mock_write.assert_called_once()

    def test_quiet(self) -> None:
        result = SpoofResult(
            domain="example.com",
            risk_score="none",
            vectors=[],
            issues=[],
            spf_status="strict",
            dmarc_status="reject",
            dkim_status="present",
            overall_protection="protected",
        )
        args = build_parser().parse_args(["example.com", "--quiet"])
        with patch(
            "mytools.email.emailspoof.analyze_spoofing",
            return_value=result,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0

    def test_json_output(self) -> None:
        result = SpoofResult(
            domain="example.com",
            risk_score="none",
            vectors=[],
            issues=[],
            spf_status="strict",
            dmarc_status="reject",
            dkim_status="present",
            overall_protection="protected",
        )
        args = build_parser().parse_args(["example.com", "--json"])
        with (
            patch(
                "mytools.email.emailspoof.analyze_spoofing",
                return_value=result,
            ),
            patch("mytools.email.emailspoof.print_json") as mock_print,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0
        mock_print.assert_called_once()


class TestMain:
    def test_main(self) -> None:
        with patch(
            "mytools.email.emailspoof.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-spoof", "example.com"]),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.email.emailspoof", run_name="__main__")


class TestEmailSecurityResult:
    """Verificar que emailsecurity dataclasses sao usadas corretamente."""

    def test_spoof_uses_base_result(self) -> None:
        from mytools.email.emailsecurity import EmailSecurityResult as ESR

        r = ESR(
            domain="x",
            spf=None,
            dkim_selectors=[],
            dmarc=None,
            overall_status="critical",
            issues=[],
        )
        assert r.domain == "x"
