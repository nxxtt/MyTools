#!/usr/bin/env python3
"""Testes unitarios do modulo de Email Security (DMARC/SPF/DKIM)."""

import asyncio
import runpy
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from mytools.email.emailsecurity import (
    DNS_ERROR,
    DmarcRecord,
    EmailSecurityResult,
    SpfRecord,
    _async_run_once,
    _parse_dmarc,
    _parse_spf,
    _query_txt,
    banner,
    build_parser,
    main,
    print_results,
    run_once,
    scan_email_security,
)


class TestSpfRecord:
    """Testes do dataclass SpfRecord."""

    def test_frozen(self) -> None:
        r = SpfRecord(
            raw="v=spf1 ~all",
            version="spf1",
            mechanisms=[],
            has_all=True,
            all_qualifier="~",
            includes=[],
        )
        with pytest.raises(AttributeError):
            r.raw = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(SpfRecord, "__slots__")


class TestDmarcRecord:
    """Testes do dataclass DmarcRecord."""

    def test_frozen(self) -> None:
        r = DmarcRecord(
            raw="v=DMARC1; p=reject", policy="reject", sp="reject", rua="", pct=100
        )
        with pytest.raises(AttributeError):
            r.raw = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(DmarcRecord, "__slots__")


class TestEmailSecurityResult:
    """Testes do dataclass EmailSecurityResult."""

    def test_frozen(self) -> None:
        r = EmailSecurityResult(
            domain="a",
            spf=None,
            dkim_selectors=[],
            dmarc=None,
            overall_status="missing",
            issues=[],
        )
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(EmailSecurityResult, "__slots__")


class TestParseSpf:
    """Testes da funcao _parse_spf."""

    def test_basic(self) -> None:
        spf = _parse_spf("v=spf1 include:_spf.google.com ~all")
        assert spf.version == "spf1"
        assert "_spf.google.com" in spf.includes
        assert spf.has_all is True
        assert spf.all_qualifier == "~"

    def test_plus_all(self) -> None:
        spf = _parse_spf("v=spf1 +all")
        assert spf.has_all is True
        assert spf.all_qualifier == "+"

    def test_mechanisms(self) -> None:
        spf = _parse_spf("v=spf1 ip4:1.2.3.4 ip6:::1 a mx -all")
        assert "ip4:1.2.3.4" in spf.mechanisms
        assert "a" in spf.mechanisms

    def test_no_all(self) -> None:
        spf = _parse_spf("v=spf1 include:_spf.google.com")
        assert spf.has_all is False
        assert spf.all_qualifier == ""

    def test_bare_all(self) -> None:
        spf = _parse_spf("v=spf1 all")
        assert spf.has_all is True
        assert spf.all_qualifier == ""


class TestParseDmarc:
    """Testes da funcao _parse_dmarc."""

    def test_reject(self) -> None:
        dmarc = _parse_dmarc("v=DMARC1; p=reject; rua=mailto:d@example.com")
        assert dmarc.policy == "reject"
        assert dmarc.rua == "mailto:d@example.com"

    def test_quarantine(self) -> None:
        dmarc = _parse_dmarc("v=DMARC1; p=quarantine; pct=50")
        assert dmarc.policy == "quarantine"
        assert dmarc.pct == 50

    def test_none(self) -> None:
        dmarc = _parse_dmarc("v=DMARC1; p=none")
        assert dmarc.policy == "none"

    def test_subdomain_policy(self) -> None:
        dmarc = _parse_dmarc("v=DMARC1; p=reject; sp=quarantine")
        assert dmarc.policy == "reject"
        assert dmarc.sp == "quarantine"

    def test_malformed_missing_p(self) -> None:
        dmarc = _parse_dmarc("v=DMARC1")
        assert dmarc.policy == "malformed"
        assert dmarc.sp == "malformed"


class TestQueryTxt:
    def test_returns_joined_strings(self) -> None:
        class FakeRR:
            strings = (b"v=spf1 ", b"~all")

        resolver = MagicMock()
        resolver.resolve.return_value = [FakeRR()]
        assert _query_txt("test.com", resolver) == "v=spf1 ~all"

    def test_str_strings(self) -> None:
        class FakeRR:
            strings = ("v=spf1 ", "~all")

        resolver = MagicMock()
        resolver.resolve.return_value = [FakeRR()]
        assert _query_txt("test.com", resolver) == "v=spf1 ~all"

    def test_multiple_records_first_wins(self) -> None:
        class FakeRR1:
            strings = (b"first",)

        class FakeRR2:
            strings = (b"second",)

        resolver = MagicMock()
        resolver.resolve.return_value = [FakeRR1(), FakeRR2()]
        assert _query_txt("test.com", resolver) == "first"

    def test_empty_answer(self) -> None:
        resolver = MagicMock()
        resolver.resolve.return_value = []
        assert _query_txt("test.com", resolver) is None

    def test_no_answer(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.resolver.NoAnswer
        assert _query_txt("test.com", resolver) is None

    def test_nxdomain(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.resolver.NXDOMAIN
        assert _query_txt("test.com", resolver) is None

    def test_timeout(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.exception.Timeout
        assert _query_txt("test.com", resolver) == DNS_ERROR

    def test_generic_dns_exception(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.exception.DNSException("boom")
        assert _query_txt("test.com", resolver) == DNS_ERROR


class TestParser:
    """Testes do build_parser."""

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
        args = parser.parse_args(["example.com", "--selectors", "default,google"])
        assert args.selectors == "default,google"

    def test_query_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--query-timeout", "10.0"])
        assert args.query_timeout == 10.0


class TestPrintResults:
    """Testes da funcao print_results."""

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = EmailSecurityResult(
            domain="secure.com",
            spf=SpfRecord("v=spf1 ~all", "spf1", [], True, "~", []),
            dkim_selectors=["default"],
            dmarc=DmarcRecord("v=DMARC1; p=reject", "reject", "reject", "", 100),
            overall_status="secure",
            issues=[],
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Email Security" in out
        assert "SECURE" in out

    def test_critical(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = EmailSecurityResult(
            domain="bad.com",
            spf=None,
            dkim_selectors=[],
            dmarc=None,
            overall_status="critical",
            issues=["Nenhum registro SPF", "Nenhum registro DMARC"],
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "CRITICAL" in out

    def test_good(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = EmailSecurityResult(
            domain="good.com",
            spf=SpfRecord("v=spf1 ~all", "spf1", [], True, "~", []),
            dkim_selectors=["default"],
            dmarc=DmarcRecord("v=DMARC1; p=reject", "reject", "reject", "", 100),
            overall_status="good",
            issues=[],
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "GOOD" in out

    def test_missing(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = EmailSecurityResult(
            domain="none.com",
            spf=None,
            dkim_selectors=[],
            dmarc=None,
            overall_status="missing",
            issues=[],
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "nenhum registro" in out.lower()

    def test_spf_includes(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = EmailSecurityResult(
            domain="inc.com",
            spf=SpfRecord(
                "v=spf1 include:_spf.google.com ~all",
                "spf1",
                [],
                True,
                "~",
                ["_spf.google.com"],
            ),
            dkim_selectors=["default"],
            dmarc=DmarcRecord("v=DMARC1; p=reject", "reject", "reject", "", 100),
            overall_status="secure",
            issues=[],
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "_spf.google.com" in out

    def test_dmarc_rua(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = EmailSecurityResult(
            domain="rua.com",
            spf=SpfRecord("v=spf1 ~all", "spf1", [], True, "~", []),
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
        print_results(result)
        out = capsys.readouterr().out
        assert "mailto:d@example.com" in out


class TestScanEmailSecurity:
    """Testes da funcao scan_email_security com mocks."""

    @patch("mytools.email.emailsecurity._query_txt")
    def test_no_records(self, mock_txt: MagicMock) -> None:
        mock_txt.return_value = None
        result = scan_email_security("test.com")
        assert result.overall_status == "critical"
        assert len(result.issues) >= 2

    @patch("mytools.email.emailsecurity._query_txt")
    def test_full_config(self, mock_txt: MagicMock) -> None:
        def side_effect(domain: str, resolver: object) -> str | None:
            if "_dmarc" in domain:
                return "v=DMARC1; p=reject; rua=mailto:d@example.com"
            if "_domainkey" in domain:
                return "v=DKIM1; p=MIGf..."
            return "v=spf1 include:_spf.google.com ~all"

        mock_txt.side_effect = side_effect
        result = scan_email_security("good.com")
        assert result.spf is not None
        assert result.dmarc is not None
        assert len(result.dkim_selectors) > 0
        assert result.overall_status == "secure"

    @patch("mytools.email.emailsecurity._query_txt")
    def test_dns_error_spf(self, mock_txt: MagicMock) -> None:
        mock_txt.return_value = DNS_ERROR
        result = scan_email_security("test.com")
        assert any("Erro DNS ao consultar SPF" in i for i in result.issues)

    @patch("mytools.email.emailsecurity._query_txt")
    def test_dns_error_dmarc(self, mock_txt: MagicMock) -> None:
        def side_effect(domain: str, resolver: object) -> str | None:
            if "_dmarc" in domain:
                return DNS_ERROR
            return "v=spf1 ~all"

        mock_txt.side_effect = side_effect
        result = scan_email_security("test.com")
        assert any("Erro DNS ao consultar DMARC" in i for i in result.issues)

    @patch("mytools.email.emailsecurity._query_txt")
    def test_malformed_dmarc(self, mock_txt: MagicMock) -> None:
        def side_effect(domain: str, resolver: object) -> str | None:
            if "_dmarc" in domain:
                return "v=DMARC1"
            return "v=spf1 ~all"

        mock_txt.side_effect = side_effect
        result = scan_email_security("test.com")
        assert result.dmarc is not None
        assert result.dmarc.policy == "malformed"
        assert result.overall_status == "warning"
        assert any("DMARC invalido" in i for i in result.issues)

    @patch("mytools.email.emailsecurity._query_txt")
    def test_spf_bare_all(self, mock_txt: MagicMock) -> None:
        mock_txt.return_value = "v=spf1 all"
        result = scan_email_security("test.com")
        assert result.spf is not None
        assert result.spf.has_all is True
        assert result.spf.all_qualifier == ""
        assert any("all sem qualificador" in i for i in result.issues)

    @patch("mytools.email.emailsecurity._query_txt")
    def test_spf_plus_all(self, mock_txt: MagicMock) -> None:
        mock_txt.return_value = "v=spf1 +all"
        result = scan_email_security("test.com")
        assert result.spf is not None
        assert result.spf.all_qualifier == "+"
        assert any("SPF usa +all" in i for i in result.issues)
        assert result.overall_status == "critical"

    @patch("mytools.email.emailsecurity._query_txt")
    def test_txt_not_spf(self, mock_txt: MagicMock) -> None:
        mock_txt.return_value = "v=DKIM1; p=abc"
        result = scan_email_security("test.com")
        assert any("nao e SPF" in i for i in result.issues)

    @patch("mytools.email.emailsecurity._query_txt")
    def test_dmarc_none(self, mock_txt: MagicMock) -> None:
        def side_effect(domain: str, resolver: object) -> str | None:
            if "_dmarc" in domain:
                return "v=DMARC1; p=none"
            return "v=spf1 ~all"

        mock_txt.side_effect = side_effect
        result = scan_email_security("test.com")
        assert result.dmarc is not None
        assert result.dmarc.policy == "none"
        assert any("DMARC p=none" in i for i in result.issues)
        assert result.overall_status == "warning"

    @patch("mytools.email.emailsecurity._query_txt")
    def test_dmarc_pct_low(self, mock_txt: MagicMock) -> None:
        def side_effect(domain: str, resolver: object) -> str | None:
            if "_dmarc" in domain:
                return "v=DMARC1; p=reject; pct=50"
            return "v=spf1 ~all"

        mock_txt.side_effect = side_effect
        result = scan_email_security("test.com")
        assert result.dmarc is not None
        assert result.dmarc.pct == 50
        assert any("pct=50" in i for i in result.issues)

    @patch("mytools.email.emailsecurity._query_txt")
    def test_status_good(self, mock_txt: MagicMock) -> None:
        def side_effect(domain: str, resolver: object) -> str | None:
            if "_dmarc" in domain:
                return "v=DMARC1; p=reject"
            if "_domainkey" in domain:
                return None
            return "v=spf1 ~all"

        mock_txt.side_effect = side_effect
        result = scan_email_security("test.com")
        assert result.spf is not None
        assert result.dmarc is not None
        assert result.dkim_selectors == []
        assert result.overall_status == "good"

    @patch("mytools.email.emailsecurity._query_txt")
    def test_status_missing(self, mock_txt: MagicMock) -> None:
        def side_effect(domain: str, resolver: object) -> str | None:
            if "_dmarc" in domain:
                return "v=DMARC1; p=reject"
            if "_domainkey" in domain:
                return None
            return None

        mock_txt.side_effect = side_effect
        result = scan_email_security("test.com")
        assert result.spf is None
        assert result.dmarc is not None
        assert result.dkim_selectors == []
        assert result.overall_status == "missing"


class TestBanner:
    def test_banner(self, capsys: pytest.CaptureFixture[str]) -> None:
        banner()
        captured = capsys.readouterr()
        assert "email security" in captured.out


class TestRunOnce:
    def test_run_once(self) -> None:
        args = build_parser().parse_args(["example.com"])
        with (
            patch(
                "mytools.email.emailsecurity._async_run_once",
                new_callable=MagicMock,
                return_value=0,
            ),
            patch(
                "mytools.email.emailsecurity.safe_asyncio_run",
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

    def test_dry_run(self) -> None:
        args = build_parser().parse_args(["example.com", "--dry-run"])
        result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_print_results(self) -> None:
        result = EmailSecurityResult(
            domain="example.com",
            spf=None,
            dkim_selectors=[],
            dmarc=None,
            overall_status="warning",
            issues=[],
        )
        args = build_parser().parse_args(["example.com"])
        with patch(
            "mytools.email.emailsecurity.scan_email_security",
            return_value=result,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0

    def test_output_flag(self, tmp_path) -> None:
        result = EmailSecurityResult(
            domain="example.com",
            spf=None,
            dkim_selectors=[],
            dmarc=None,
            overall_status="warning",
            issues=[],
        )
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(["example.com", "-o", str(out_file)])
        with (
            patch(
                "mytools.email.emailsecurity.scan_email_security",
                return_value=result,
            ),
            patch("mytools.email.emailsecurity.write_output") as mock_write,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0
        mock_write.assert_called_once()

    def test_quiet(self) -> None:
        result = EmailSecurityResult(
            domain="example.com",
            spf=None,
            dkim_selectors=[],
            dmarc=None,
            overall_status="warning",
            issues=[],
        )
        args = build_parser().parse_args(["example.com", "--quiet"])
        with patch(
            "mytools.email.emailsecurity.scan_email_security",
            return_value=result,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0


class TestMain:
    def test_main(self) -> None:
        with patch(
            "mytools.email.emailsecurity.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-secemail", "example.com"]),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.email.emailsecurity", run_name="__main__")
