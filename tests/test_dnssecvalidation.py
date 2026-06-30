#!/usr/bin/env python3
"""Testes unitarios do modulo de DNSSEC Validation."""
from unittest.mock import MagicMock, patch

import pytest

from dnssecvalidation import (
    DnssecCheck,
    DnssecResult,
    build_parser,
    print_results,
    scan_dnssec,
)


class TestDnssecCheck:
    """Testes do dataclass DnssecCheck."""

    def test_frozen(self) -> None:
        c = DnssecCheck(check="test", status="pass", detail="ok", severity="low")
        with pytest.raises(AttributeError):
            c.check = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(DnssecCheck, "__slots__")


class TestDnssecResult:
    """Testes do dataclass DnssecResult."""

    def test_frozen(self) -> None:
        r = DnssecResult(
            domain="a", nameserver="b", is_signed=False,
            has_ds=False, has_dnskey=False, has_rrsig=False,
            chain_valid=False, algorithm_strength="unknown",
            checks=[], overall_status="unsigned",
        )
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(DnssecResult, "__slots__")


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

    def test_query_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--query-timeout", "10.0"])
        assert args.query_timeout == 10.0


class TestPrintResults:
    """Testes da funcao print_results."""

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = DnssecResult(
            domain="example.com", nameserver="8.8.8.8",
            is_signed=True, has_ds=True, has_dnskey=True,
            has_rrsig=True, chain_valid=True,
            algorithm_strength="strong",
            checks=[
                DnssecCheck("dnskey_ksk", "pass", "1 KSK", "low"),
                DnssecCheck("ds_record", "pass", "1 DS", "low"),
            ],
            overall_status="secure",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "DNSSEC Validation" in out
        assert "SECURE" in out

    def test_unsigned(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = DnssecResult(
            domain="test.com", nameserver="8.8.8.8",
            is_signed=False, has_ds=False, has_dnskey=False,
            has_rrsig=False, chain_valid=False,
            algorithm_strength="unknown",
            checks=[
                DnssecCheck("dnskey", "missing", "Nenhum DNSKEY", "high"),
            ],
            overall_status="unsigned",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "NAO CONFIGURADO" in out or "unsigned" in out.lower()

    def test_broken(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = DnssecResult(
            domain="broken.com", nameserver="8.8.8.8",
            is_signed=True, has_ds=False, has_dnskey=True,
            has_rrsig=True, chain_valid=False,
            algorithm_strength="medium",
            checks=[
                DnssecCheck("rrsig_expiry", "warn", "2 expiradas", "high"),
            ],
            overall_status="insecure",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "INSECURE" in out


class TestScanDnssec:
    """Testes da funcao scan_dnssec com mocks."""

    @patch("dnssecvalidation._evaluate_algorithm_strength", return_value="strong")
    @patch("dnssecvalidation._check_nsec", return_value=[])
    @patch("dnssecvalidation._check_rrsig")
    @patch("dnssecvalidation._check_ds")
    @patch("dnssecvalidation._check_dnskey")
    def test_secure(
        self, mock_dnskey: MagicMock, mock_ds: MagicMock,
        mock_rrsig: MagicMock, mock_nsec: MagicMock,
        mock_algo: MagicMock,
    ) -> None:
        mock_dnskey.return_value = (True, [DnssecCheck("dnskey_ksk", "pass", "1 KSK", "low")])
        mock_ds.return_value = (True, [DnssecCheck("ds_record", "pass", "1 DS", "low")])
        mock_rrsig.return_value = (True, [DnssecCheck("rrsig_expiry", "pass", "1 valida", "low")])

        result = scan_dnssec("example.com")
        assert result.overall_status == "secure"
        assert result.chain_valid is True

    @patch("dnssecvalidation._evaluate_algorithm_strength", return_value="unknown")
    @patch("dnssecvalidation._check_nsec", return_value=[])
    @patch("dnssecvalidation._check_rrsig")
    @patch("dnssecvalidation._check_ds")
    @patch("dnssecvalidation._check_dnskey")
    def test_unsigned(
        self, mock_dnskey: MagicMock, mock_ds: MagicMock,
        mock_rrsig: MagicMock, mock_nsec: MagicMock,
        mock_algo: MagicMock,
    ) -> None:
        mock_dnskey.return_value = (False, [DnssecCheck("dnskey", "missing", "Nenhum", "high")])
        mock_ds.return_value = (False, [DnssecCheck("ds_record", "missing", "Nenhum", "medium")])
        mock_rrsig.return_value = (False, [DnssecCheck("rrsig", "missing", "Nenhum", "high")])

        result = scan_dnssec("test.com")
        assert result.overall_status == "unsigned"
        assert result.chain_valid is False

    @patch("dnssecvalidation._evaluate_algorithm_strength", return_value="weak")
    @patch("dnssecvalidation._check_nsec", return_value=[])
    @patch("dnssecvalidation._check_rrsig")
    @patch("dnssecvalidation._check_ds")
    @patch("dnssecvalidation._check_dnskey")
    def test_weak_algo(
        self, mock_dnskey: MagicMock, mock_ds: MagicMock,
        mock_rrsig: MagicMock, mock_nsec: MagicMock,
        mock_algo: MagicMock,
    ) -> None:
        mock_dnskey.return_value = (True, [DnssecCheck("dnskey_ksk", "pass", "1 KSK", "low")])
        mock_ds.return_value = (True, [DnssecCheck("ds_record", "pass", "1 DS", "low")])
        mock_rrsig.return_value = (True, [DnssecCheck("rrsig_expiry", "pass", "1 valida", "low")])

        result = scan_dnssec("weak.com")
        assert result.algorithm_strength == "weak"
        assert any(c.check == "algorithm_strength" for c in result.checks)
