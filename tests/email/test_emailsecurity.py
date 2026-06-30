#!/usr/bin/env python3
"""Testes unitarios do modulo de Email Security (DMARC/SPF/DKIM)."""
from unittest.mock import MagicMock, patch

import pytest

from mytools.email.emailsecurity import (
    DmarcRecord,
    EmailSecurityResult,
    SpfRecord,
    _parse_dmarc,
    _parse_spf,
    build_parser,
    print_results,
    scan_email_security,
)


class TestSpfRecord:
    """Testes do dataclass SpfRecord."""

    def test_frozen(self) -> None:
        r = SpfRecord(raw="v=spf1 ~all", version="spf1",
                      mechanisms=[], has_all=True, all_qualifier="~", includes=[])
        with pytest.raises(AttributeError):
            r.raw = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(SpfRecord, "__slots__")


class TestDmarcRecord:
    """Testes do dataclass DmarcRecord."""

    def test_frozen(self) -> None:
        r = DmarcRecord(raw="v=DMARC1; p=reject", policy="reject",
                        sp="reject", rua="", pct=100)
        with pytest.raises(AttributeError):
            r.raw = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(DmarcRecord, "__slots__")


class TestEmailSecurityResult:
    """Testes do dataclass EmailSecurityResult."""

    def test_frozen(self) -> None:
        r = EmailSecurityResult(
            domain="a", spf=None, dkim_selectors=[],
            dmarc=None, overall_status="missing", issues=[],
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
