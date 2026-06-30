#!/usr/bin/env python3
"""Testes unitarios do modulo de DNS Tunnel Detection."""
from unittest.mock import MagicMock, patch

import pytest

from mytools.dns.dnstunnel import (
    TunnelIndicator,
    TunnelResult,
    _generate_synthetic_labels,
    _is_base64,
    _is_hex,
    analyze_labels,
    build_parser,
    print_results,
    scan_tunnel,
    shannon_entropy,
)


class TestTunnelIndicator:
    """Testes do dataclass TunnelIndicator."""

    def test_frozen(self) -> None:
        i = TunnelIndicator(indicator="test", value=1.0, threshold=2.0, severity="low")
        with pytest.raises(AttributeError):
            i.indicator = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(TunnelIndicator, "__slots__")


class TestTunnelResult:
    """Testes do dataclass TunnelResult."""

    def test_frozen(self) -> None:
        r = TunnelResult(
            domain="a", indicators=[], overall_severity="safe",
            is_tunneling=False, confidence=0.0, labels_analyzed=0,
            avg_label_length=0.0, max_label_length=0.0,
            avg_entropy=0.0, max_entropy=0.0,
            txt_ratio=0.0, base64_count=0, hex_count=0, nxdomain_ratio=0.0,
        )
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(TunnelResult, "__slots__")


class TestShannonEntropy:
    """Testes da funcao shannon_entropy."""

    def test_empty(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_single_char(self) -> None:
        assert shannon_entropy("a") == 0.0

    def test_uniform(self) -> None:
        result = shannon_entropy("ab")
        assert abs(result - 1.0) < 0.01

    def test_high_entropy(self) -> None:
        result = shannon_entropy("abcdefghij")
        assert result > 3.0

    def test_low_entropy(self) -> None:
        result = shannon_entropy("aaaaaaaaaa")
        assert result == 0.0

    def test_base64_high(self) -> None:
        result = shannon_entropy("aGVsbG8gd29ybGQgdGVzdA==")
        assert result > 3.0


class TestIsBase64:
    """Testes da funcao _is_base64."""

    def test_valid(self) -> None:
        assert _is_base64("aGVsbG8gd29ybGQgdGVzdA==") is True

    def test_short(self) -> None:
        assert _is_base64("abc") is False

    def test_with_padding(self) -> None:
        assert _is_base64("dGVzdGluZyB0ZXN0IGRhdGE=") is True

    def test_with_special(self) -> None:
        assert _is_base64("abc-def_ghi-jkl_mno-pqr-stu") is True


class TestIsHex:
    """Testes da funcao _is_hex."""

    def test_valid(self) -> None:
        assert _is_hex("0123456789abcdef0123") is True

    def test_short(self) -> None:
        assert _is_hex("abc") is False

    def test_with_uppercase(self) -> None:
        assert _is_hex("0123456789ABCDEF01234567") is True

    def test_invalid_chars(self) -> None:
        assert _is_hex("0123456789abcdefg0123456") is False


class TestAnalyzeLabels:
    """Testes da funcao analyze_labels."""

    def test_empty(self) -> None:
        result = analyze_labels([])
        assert result["avg_length"] == 0.0

    def test_normal_labels(self) -> None:
        labels = ["www", "mail", "api"]
        result = analyze_labels(labels)
        assert result["avg_length"] == pytest.approx(3.33, abs=0.01)

    def test_long_labels(self) -> None:
        labels = ["a" * 50, "b" * 60]
        result = analyze_labels(labels)
        assert result["max_length"] == 60

    def test_high_entropy(self) -> None:
        labels = ["aGVsbG8gd29ybGQgdGVzdA=="]
        result = analyze_labels(labels)
        assert result["avg_entropy"] > 3.0


class TestGenerateSyntheticLabels:
    """Testes da funcao _generate_synthetic_labels."""

    def test_count(self) -> None:
        labels = _generate_synthetic_labels("test.com", 10)
        assert len(labels) == 10

    def test_domain_not_in_labels(self) -> None:
        labels = _generate_synthetic_labels("test.com", 5)
        for label in labels:
            assert "test.com" not in label


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

    def test_queries(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--num-queries", "200"])
        assert args.num_queries == 200

    def test_min_entropy(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--min-entropy", "4.0"])
        assert args.min_entropy == 4.0

    def test_max_label_length(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--max-label-length", "50"])
        assert args.max_label_length == 50


class TestPrintResults:
    """Testes da funcao print_results."""

    def test_safe(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = TunnelResult(
            domain="example.com", indicators=[], overall_severity="safe",
            is_tunneling=False, confidence=0.0, labels_analyzed=100,
            avg_label_length=8.0, max_label_length=15.0,
            avg_entropy=2.5, max_entropy=3.0,
            txt_ratio=0.2, base64_count=0, hex_count=0, nxdomain_ratio=0.1,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "DNS Tunnel Detection" in out
        assert "NAO" in out

    def test_tunneling(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = TunnelResult(
            domain="evil.com",
            indicators=[
                TunnelIndicator("avg_entropy", 4.2, 3.5, "high"),
                TunnelIndicator("max_label_length", 55.0, 30.0, "high"),
            ],
            overall_severity="high", is_tunneling=True, confidence=0.6,
            labels_analyzed=100, avg_label_length=35.0, max_label_length=55.0,
            avg_entropy=4.2, max_entropy=4.5,
            txt_ratio=0.8, base64_count=15, hex_count=0, nxdomain_ratio=0.1,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "TUNNELING DETECTADO" in out


class TestScanTunnel:
    """Testes da funcao scan_tunnel com mocks."""

    @patch("mytools.dns.dnstunnel._generate_synthetic_labels")
    @patch("mytools.dns.dnstunnel.analyze_labels")
    def test_safe_result(self, mock_analyze: MagicMock, mock_gen: MagicMock) -> None:
        mock_gen.return_value = ["www", "mail", "api"]
        mock_analyze.return_value = {
            "avg_length": 4.0, "max_length": 6.0,
            "avg_entropy": 2.0, "max_entropy": 2.5,
            "base64_count": 0, "hex_count": 0,
        }
        result = scan_tunnel("example.com", num_queries=3)
        assert result.is_tunneling is False
        assert result.overall_severity == "safe"

    @patch("mytools.dns.dnstunnel._generate_synthetic_labels")
    @patch("mytools.dns.dnstunnel.analyze_labels")
    def test_tunneling_result(self, mock_analyze: MagicMock, mock_gen: MagicMock) -> None:
        mock_gen.return_value = ["a" * 50] * 3
        mock_analyze.return_value = {
            "avg_length": 50.0, "max_length": 55.0,
            "avg_entropy": 4.0, "max_entropy": 4.5,
            "base64_count": 3, "hex_count": 0,
        }
        result = scan_tunnel("evil.com", num_queries=3)
        assert result.is_tunneling is True

    def test_empty_domain(self) -> None:
        result = scan_tunnel("", num_queries=0)
        assert result.labels_analyzed == 0
