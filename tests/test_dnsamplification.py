#!/usr/bin/env python3
"""Testes unitarios do modulo de DNS Amplification Detection."""
from unittest.mock import MagicMock, patch

import pytest

from dnsamplification import (
    AmplificationResult,
    RecordAmplification,
    build_parser,
    classify_severity,
    print_results,
    scan_amplification,
)


class TestRecordAmplification:
    """Testes do dataclass RecordAmplification."""

    def test_frozen(self) -> None:
        r = RecordAmplification(record_type="A", response_bytes=100,
                                amplification_factor=2.0, success=True, error="")
        with pytest.raises(AttributeError):
            r.record_type = "B"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(RecordAmplification, "__slots__")


class TestAmplificationResult:
    """Testes do dataclass AmplificationResult."""

    def test_frozen(self) -> None:
        r = AmplificationResult(
            domain="a", nameserver="b", recursion_available=False,
            is_open_resolver=False, records=[], max_amplification=0.0,
            severity="safe", request_size=50,
        )
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(AmplificationResult, "__slots__")


class TestClassifySeverity:
    """Testes da funcao classify_severity."""

    def test_critical(self) -> None:
        assert classify_severity(15.0) == "critical"

    def test_critical_boundary(self) -> None:
        assert classify_severity(10.0) == "critical"

    def test_high(self) -> None:
        assert classify_severity(7.0) == "high"

    def test_high_boundary(self) -> None:
        assert classify_severity(5.0) == "high"

    def test_medium(self) -> None:
        assert classify_severity(3.0) == "medium"

    def test_medium_boundary(self) -> None:
        assert classify_severity(2.0) == "medium"

    def test_low(self) -> None:
        assert classify_severity(1.5) == "low"

    def test_low_boundary(self) -> None:
        assert classify_severity(1.0) == "low"

    def test_safe(self) -> None:
        assert classify_severity(0.5) == "safe"

    def test_safe_zero(self) -> None:
        assert classify_severity(0.0) == "safe"


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

    def test_record_types(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--record-types", "ANY,TXT"])
        assert args.record_types == "ANY,TXT"

    def test_query_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--query-timeout", "10.0"])
        assert args.query_timeout == 10.0


class TestPrintResults:
    """Testes da funcao print_results."""

    def test_output_safe(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = AmplificationResult(
            domain="example.com", nameserver="8.8.8.8",
            recursion_available=False, is_open_resolver=False,
            records=[
                RecordAmplification("A", 80, 1.6, True, ""),
                RecordAmplification("ANY", 500, 10.0, True, ""),
            ],
            max_amplification=10.0, severity="critical", request_size=50,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "DNS Amplification Detection" in out
        assert "example.com" in out

    def test_output_open_resolver(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = AmplificationResult(
            domain="test.com", nameserver="1.1.1.1",
            recursion_available=True, is_open_resolver=True,
            records=[
                RecordAmplification("TXT", 4000, 80.0, True, ""),
            ],
            max_amplification=80.0, severity="critical", request_size=50,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "ABERTO" in out or "OPEN" in out.upper()

    def test_output_with_errors(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = AmplificationResult(
            domain="bad.com", nameserver="8.8.8.8",
            recursion_available=False, is_open_resolver=False,
            records=[
                RecordAmplification("A", 0, 0.0, False, "TIMEOUT"),
                RecordAmplification("MX", 0, 0.0, False, "NXDOMAIN"),
            ],
            max_amplification=0.0, severity="safe", request_size=50,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "FALHA" in out


class TestScanAmplification:
    """Testes da funcao scan_amplification com mocks."""

    @patch("dnsamplification._check_recursion", return_value=False)
    @patch("dnsamplification._query_record")
    def test_basic(self, mock_query: MagicMock, mock_rec: MagicMock) -> None:
        mock_query.return_value = RecordAmplification("A", 80, 1.6, True, "")
        result = scan_amplification("example.com")
        assert result.domain == "example.com"
        assert result.recursion_available is False
        assert len(result.records) == 6

    @patch("dnsamplification._check_recursion", return_value=True)
    @patch("dnsamplification._query_record")
    def test_open_resolver(self, mock_query: MagicMock, mock_rec: MagicMock) -> None:
        mock_query.return_value = RecordAmplification("TXT", 4000, 80.0, True, "")
        result = scan_amplification("example.com")
        assert result.is_open_resolver is True
        assert result.severity == "critical"

    @patch("dnsamplification._check_recursion", return_value=False)
    @patch("dnsamplification._query_record")
    def test_custom_record_types(self, mock_query: MagicMock, mock_rec: MagicMock) -> None:
        mock_query.return_value = RecordAmplification("A", 80, 1.6, True, "")
        result = scan_amplification("example.com", record_types=["A", "MX"])
        assert len(result.records) == 2

    @patch("dnsamplification._check_recursion", return_value=False)
    @patch("dnsamplification._query_record")
    def test_all_failures(self, mock_query: MagicMock, mock_rec: MagicMock) -> None:
        mock_query.return_value = RecordAmplification("A", 0, 0.0, False, "TIMEOUT")
        result = scan_amplification("example.com")
        assert result.max_amplification == 0.0
        assert result.severity == "safe"
