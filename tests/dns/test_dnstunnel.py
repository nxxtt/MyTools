#!/usr/bin/env python3
"""Testes unitarios do modulo de DNS Tunnel Detection."""

import argparse
import runpy
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from mytools.dns.dnstunnel import (
    DEFAULT_ENTROPY_THRESHOLD,
    DEFAULT_LABEL_LENGTH,
    DEFAULT_NUM_QUERIES,
    TunnelIndicator,
    TunnelResult,
    _async_run_once,
    _generate_candidate_labels,
    _is_base64,
    _is_hex,
    _query_candidate_labels,
    analyze_labels,
    banner,
    build_parser,
    main,
    print_results,
    run_once,
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
            domain="a",
            indicators=[],
            overall_severity="safe",
            is_tunneling=False,
            confidence=0.0,
            labels_analyzed=0,
            avg_label_length=0.0,
            max_label_length=0.0,
            avg_entropy=0.0,
            max_entropy=0.0,
            txt_ratio=0.0,
            base64_count=0,
            hex_count=0,
            nxdomain_ratio=0.0,
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

    def test_hex_not_counted_as_base64(self) -> None:
        labels = ["0123456789abcdef0123456789abcdef0123456789abcdef"]
        result = analyze_labels(labels)
        assert result["hex_count"] == 1
        assert result["base64_count"] == 0


class TestGenerateCandidateLabels:
    """Testes da funcao _generate_candidate_labels."""

    def test_count(self) -> None:
        labels = _generate_candidate_labels(10)
        assert len(labels) == 10

    def test_mix_of_lengths(self) -> None:
        labels = _generate_candidate_labels(20)
        assert any(len(label) > 20 for label in labels)
        assert any(len(label) <= 12 for label in labels)


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
            domain="example.com",
            indicators=[],
            overall_severity="safe",
            is_tunneling=False,
            confidence=0.0,
            labels_analyzed=100,
            avg_label_length=8.0,
            max_label_length=15.0,
            avg_entropy=2.5,
            max_entropy=3.0,
            txt_ratio=0.2,
            base64_count=0,
            hex_count=0,
            nxdomain_ratio=0.1,
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
            overall_severity="high",
            is_tunneling=True,
            confidence=0.6,
            labels_analyzed=100,
            avg_label_length=35.0,
            max_label_length=55.0,
            avg_entropy=4.2,
            max_entropy=4.5,
            txt_ratio=0.8,
            base64_count=15,
            hex_count=0,
            nxdomain_ratio=0.1,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "TUNNELING DETECTADO" in out


class TestScanTunnel:
    """Testes da funcao scan_tunnel com mocks."""

    @patch("mytools.dns.dnstunnel._query_candidate_labels")
    @patch("mytools.dns.dnstunnel._generate_candidate_labels")
    @patch("mytools.dns.dnstunnel.analyze_labels")
    def test_safe_result(
        self,
        mock_analyze: MagicMock,
        mock_gen: MagicMock,
        mock_query: MagicMock,
    ) -> None:
        mock_gen.return_value = ["www", "mail", "api"]
        mock_query.return_value = [("www", "answer"), ("mail", "answer")]
        mock_analyze.return_value = {
            "avg_length": 4.0,
            "max_length": 6.0,
            "avg_entropy": 2.0,
            "max_entropy": 2.5,
            "base64_count": 0,
            "hex_count": 0,
        }
        result = scan_tunnel("example.com", num_queries=3)
        assert result.is_tunneling is False
        assert result.overall_severity == "safe"
        assert result.labels_analyzed == 2

    @patch("mytools.dns.dnstunnel._query_candidate_labels")
    @patch("mytools.dns.dnstunnel._generate_candidate_labels")
    @patch("mytools.dns.dnstunnel.analyze_labels")
    def test_tunneling_result(
        self,
        mock_analyze: MagicMock,
        mock_gen: MagicMock,
        mock_query: MagicMock,
    ) -> None:
        mock_gen.return_value = ["a" * 50] * 3
        mock_query.return_value = [("a" * 50, "answer")] * 3
        mock_analyze.return_value = {
            "avg_length": 50.0,
            "max_length": 55.0,
            "avg_entropy": 4.0,
            "max_entropy": 4.5,
            "base64_count": 3,
            "hex_count": 0,
        }
        result = scan_tunnel("evil.com", num_queries=3)
        assert result.is_tunneling is True

    def test_empty_domain(self) -> None:
        result = scan_tunnel("", num_queries=0)
        assert result.labels_analyzed == 0


class TestDnsResolution:
    """Testes da logica de resolucao DNS em scan_tunnel."""

    @patch("mytools.dns.dnstunnel._query_candidate_labels")
    @patch("mytools.dns.dnstunnel._generate_candidate_labels")
    @patch("mytools.dns.dnstunnel.analyze_labels")
    @patch("mytools.dns.dnstunnel.dns.resolver.Resolver")
    def test_dns_resolution_increments_queries(
        self,
        mock_resolver_cls: MagicMock,
        mock_analyze: MagicMock,
        mock_gen: MagicMock,
        mock_query: MagicMock,
    ) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.return_value = [MagicMock()]
        mock_gen.return_value = ["test"]
        mock_query.return_value = [("test", "answer")]
        mock_analyze.return_value = {
            "avg_length": 4.0,
            "max_length": 6.0,
            "avg_entropy": 2.0,
            "max_entropy": 2.5,
            "base64_count": 0,
            "hex_count": 0,
        }
        result = scan_tunnel("example.com", num_queries=1)
        assert result.labels_analyzed == 1

    @patch("mytools.dns.dnstunnel._query_candidate_labels")
    @patch("mytools.dns.dnstunnel._generate_candidate_labels")
    @patch("mytools.dns.dnstunnel.analyze_labels")
    @patch("mytools.dns.dnstunnel.dns.resolver.Resolver")
    def test_nxdomain_increments_count(
        self,
        mock_resolver_cls: MagicMock,
        mock_analyze: MagicMock,
        mock_gen: MagicMock,
        mock_query: MagicMock,
    ) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        mock_gen.return_value = ["test"]
        mock_query.return_value = [("test", "nxdomain")]
        mock_analyze.return_value = {
            "avg_length": 4.0,
            "max_length": 6.0,
            "avg_entropy": 2.0,
            "max_entropy": 2.5,
            "base64_count": 0,
            "hex_count": 0,
        }
        result = scan_tunnel("example.com", num_queries=1)
        assert result.nxdomain_ratio == 1.0

    @patch("mytools.dns.dnstunnel._query_candidate_labels")
    @patch("mytools.dns.dnstunnel._generate_candidate_labels")
    @patch("mytools.dns.dnstunnel.analyze_labels")
    @patch("mytools.dns.dnstunnel.dns.resolver.Resolver")
    def test_no_nameservers_increments_count(
        self,
        mock_resolver_cls: MagicMock,
        mock_analyze: MagicMock,
        mock_gen: MagicMock,
        mock_query: MagicMock,
    ) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoNameservers()
        mock_gen.return_value = ["test"]
        mock_query.return_value = [("test", "error")]
        mock_analyze.return_value = {
            "avg_length": 4.0,
            "max_length": 6.0,
            "avg_entropy": 2.0,
            "max_entropy": 2.5,
            "base64_count": 0,
            "hex_count": 0,
        }
        result = scan_tunnel("example.com", num_queries=1)
        assert result.labels_analyzed == 0

    @patch("mytools.dns.dnstunnel._query_candidate_labels")
    @patch("mytools.dns.dnstunnel._generate_candidate_labels")
    @patch("mytools.dns.dnstunnel.analyze_labels")
    @patch("mytools.dns.dnstunnel.dns.resolver.Resolver")
    def test_timeout_increments_count(
        self,
        mock_resolver_cls: MagicMock,
        mock_analyze: MagicMock,
        mock_gen: MagicMock,
        mock_query: MagicMock,
    ) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.Timeout()
        mock_gen.return_value = ["test"]
        mock_query.return_value = [("test", "error")]
        mock_analyze.return_value = {
            "avg_length": 4.0,
            "max_length": 6.0,
            "avg_entropy": 2.0,
            "max_entropy": 2.5,
            "base64_count": 0,
            "hex_count": 0,
        }
        result = scan_tunnel("example.com", num_queries=1)
        assert result.labels_analyzed == 0

    @patch("mytools.dns.dnstunnel._query_candidate_labels")
    @patch("mytools.dns.dnstunnel._generate_candidate_labels")
    @patch("mytools.dns.dnstunnel.analyze_labels")
    @patch("mytools.dns.dnstunnel.dns.resolver.Resolver")
    def test_dns_exception_increments_count(
        self,
        mock_resolver_cls: MagicMock,
        mock_analyze: MagicMock,
        mock_gen: MagicMock,
        mock_query: MagicMock,
    ) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.DNSException("boom")
        mock_gen.return_value = ["test"]
        mock_query.return_value = [("test", "error")]
        mock_analyze.return_value = {
            "avg_length": 4.0,
            "max_length": 6.0,
            "avg_entropy": 2.0,
            "max_entropy": 2.5,
            "base64_count": 0,
            "hex_count": 0,
        }
        result = scan_tunnel("example.com", num_queries=1)
        assert result.labels_analyzed == 0


class TestTxtRatio:
    """Testes do indicador txt_ratio em scan_tunnel."""

    @patch("mytools.dns.dnstunnel._query_candidate_labels")
    @patch("mytools.dns.dnstunnel._generate_candidate_labels")
    @patch("mytools.dns.dnstunnel.analyze_labels")
    @patch("mytools.dns.dnstunnel.dns.resolver.Resolver")
    def test_txt_ratio_below_threshold_with_defaults(
        self,
        mock_resolver_cls: MagicMock,
        mock_analyze: MagicMock,
        mock_gen: MagicMock,
        mock_query: MagicMock,
    ) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.return_value = [MagicMock()]
        mock_gen.return_value = ["test"]
        mock_query.return_value = [("test", "answer")]
        mock_analyze.return_value = {
            "avg_length": 4.0,
            "max_length": 6.0,
            "avg_entropy": 2.0,
            "max_entropy": 2.5,
            "base64_count": 0,
            "hex_count": 0,
        }
        result = scan_tunnel("example.com", num_queries=1)
        indicators = {i.indicator for i in result.indicators}
        assert "txt_ratio" not in indicators

    @patch("mytools.dns.dnstunnel._query_candidate_labels")
    @patch("mytools.dns.dnstunnel._generate_candidate_labels")
    @patch("mytools.dns.dnstunnel.analyze_labels")
    @patch("mytools.dns.dnstunnel.dns.resolver.Resolver")
    def test_txt_ratio_above_threshold(
        self,
        mock_resolver_cls: MagicMock,
        mock_analyze: MagicMock,
        mock_gen: MagicMock,
        mock_query: MagicMock,
    ) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.return_value = [MagicMock()]
        mock_gen.return_value = ["test"]
        mock_query.return_value = [("test", "answer")]
        mock_analyze.return_value = {
            "avg_length": 4.0,
            "max_length": 6.0,
            "avg_entropy": 2.0,
            "max_entropy": 2.5,
            "base64_count": 0,
            "hex_count": 0,
        }
        with patch(
            "mytools.dns.dnstunnel.DEFAULT_RECORD_TYPES", ["TXT"]
        ):
            result = scan_tunnel("example.com", num_queries=1)
        indicators = {i.indicator for i in result.indicators}
        assert "txt_ratio" in indicators


class TestQueryCandidateLabels:
    """Testes da funcao _query_candidate_labels."""

    def _resolver(self) -> MagicMock:
        return MagicMock()

    def test_answer(self) -> None:
        resolver = self._resolver()
        resolver.resolve.return_value = MagicMock()
        result = _query_candidate_labels(resolver, "example.com", ["www"])
        assert result == [("www", "answer")]

    def test_nxdomain(self) -> None:
        resolver = self._resolver()
        resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        result = _query_candidate_labels(resolver, "example.com", ["www"])
        assert result == [("www", "nxdomain")]

    def test_no_answer(self) -> None:
        resolver = self._resolver()
        resolver.resolve.side_effect = dns.resolver.NoAnswer()
        result = _query_candidate_labels(resolver, "example.com", ["www"])
        assert result == [("www", "noanswer")]

    def test_no_nameservers(self) -> None:
        resolver = self._resolver()
        resolver.resolve.side_effect = dns.resolver.NoNameservers()
        result = _query_candidate_labels(resolver, "example.com", ["www"])
        assert result == [("www", "error")]

    def test_timeout(self) -> None:
        resolver = self._resolver()
        resolver.resolve.side_effect = dns.exception.Timeout()
        result = _query_candidate_labels(resolver, "example.com", ["www"])
        assert result == [("www", "error")]

    def test_dns_exception(self) -> None:
        resolver = self._resolver()
        resolver.resolve.side_effect = dns.exception.DNSException("boom")
        result = _query_candidate_labels(resolver, "example.com", ["www"])
        assert result == [("www", "error")]

    def test_multiple_labels(self) -> None:
        resolver = self._resolver()
        resolver.resolve.side_effect = [
            MagicMock(),
            dns.resolver.NXDOMAIN(),
            dns.exception.Timeout(),
        ]
        result = _query_candidate_labels(
            resolver, "example.com", ["a", "b", "c"]
        )
        assert result == [("a", "answer"), ("b", "nxdomain"), ("c", "error")]


class TestHexLabels:
    """Testes do indicador hex_labels em scan_tunnel."""

    @patch("mytools.dns.dnstunnel._query_candidate_labels")
    @patch("mytools.dns.dnstunnel._generate_candidate_labels")
    @patch("mytools.dns.dnstunnel.analyze_labels")
    @patch("mytools.dns.dnstunnel.dns.resolver.Resolver")
    def test_hex_labels_flagged(
        self,
        mock_resolver_cls: MagicMock,
        mock_analyze: MagicMock,
        mock_gen: MagicMock,
        mock_query: MagicMock,
    ) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.return_value = [MagicMock()]
        mock_gen.return_value = ["a" * 50] * 3
        mock_query.return_value = [("a" * 50, "answer")] * 3
        mock_analyze.return_value = {
            "avg_length": 50.0,
            "max_length": 55.0,
            "avg_entropy": 4.0,
            "max_entropy": 4.5,
            "base64_count": 0,
            "hex_count": 3,
        }
        result = scan_tunnel("evil.com", num_queries=3)
        indicators = {i.indicator for i in result.indicators}
        assert "hex_labels" in indicators


class TestBanner:
    """Testes da funcao banner."""

    def test_calls_create_banner(self) -> None:
        with patch("mytools.dns.dnstunnel.create_banner") as mock_banner:
            banner()
        mock_banner.assert_called_once()
        mock_banner.return_value.assert_called_once()


class TestPrintResultsPartial:
    """Testes de print_results para confianca parcial."""

    def test_partial_patterns(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = TunnelResult(
            domain="example.com",
            indicators=[TunnelIndicator("avg_entropy", 3.6, 3.5, "high")],
            overall_severity="high",
            is_tunneling=False,
            confidence=0.2,
            labels_analyzed=100,
            avg_label_length=8.0,
            max_label_length=15.0,
            avg_entropy=3.6,
            max_entropy=3.8,
            txt_ratio=0.2,
            base64_count=0,
            hex_count=0,
            nxdomain_ratio=0.1,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Padroes parciais" in out


def _make_args(**overrides: object) -> argparse.Namespace:
    defaults: dict[str, object] = {
        "domain": "example.com",
        "nameserver": "8.8.8.8",
        "num_queries": DEFAULT_NUM_QUERIES,
        "min_entropy": DEFAULT_ENTROPY_THRESHOLD,
        "max_label_length": DEFAULT_LABEL_LENGTH,
        "query_timeout": 3.0,
        "dry_run": False,
        "output": None,
        "verbose": False,
        "quiet": False,
        "color": None,
        "log_file": None,
        "theme": "cyber",
        "severity_override": None,
        "timeout": 3.0,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestAsyncRunOnce:
    """Testes do _async_run_once."""

    @pytest.mark.asyncio
    async def test_no_domain_returns_one(self) -> None:
        args = _make_args(domain=None)
        assert await _async_run_once(args) == 1

    @pytest.mark.asyncio
    async def test_dry_run(self) -> None:
        args = _make_args(dry_run=True)
        assert await _async_run_once(args) == 0

    @pytest.mark.asyncio
    async def test_normal_runs_scan(self) -> None:
        args = _make_args()
        mock_result = TunnelResult(
            domain="example.com",
            indicators=[],
            overall_severity="safe",
            is_tunneling=False,
            confidence=0.0,
            labels_analyzed=0,
            avg_label_length=0.0,
            max_label_length=0.0,
            avg_entropy=0.0,
            max_entropy=0.0,
            txt_ratio=0.0,
            base64_count=0,
            hex_count=0,
            nxdomain_ratio=0.0,
        )
        with (
            patch("mytools.dns.dnstunnel.scan_tunnel", return_value=mock_result),
            patch("mytools.dns.dnstunnel.print_results") as mock_print,
        ):
            result = await _async_run_once(args)
        assert result == 0
        mock_print.assert_called_once()

    @pytest.mark.asyncio
    async def test_quiet_skips_print(self) -> None:
        args = _make_args(quiet=True)
        mock_result = TunnelResult(
            domain="example.com",
            indicators=[],
            overall_severity="safe",
            is_tunneling=False,
            confidence=0.0,
            labels_analyzed=0,
            avg_label_length=0.0,
            max_label_length=0.0,
            avg_entropy=0.0,
            max_entropy=0.0,
            txt_ratio=0.0,
            base64_count=0,
            hex_count=0,
            nxdomain_ratio=0.0,
        )
        with (
            patch("mytools.dns.dnstunnel.scan_tunnel", return_value=mock_result),
            patch("mytools.dns.dnstunnel.print_results") as mock_print,
        ):
            result = await _async_run_once(args)
        assert result == 0
        mock_print.assert_not_called()

    @pytest.mark.asyncio
    async def test_writes_output(self) -> None:
        args = _make_args(output="out.json")
        mock_result = TunnelResult(
            domain="example.com",
            indicators=[],
            overall_severity="safe",
            is_tunneling=False,
            confidence=0.0,
            labels_analyzed=0,
            avg_label_length=0.0,
            max_label_length=0.0,
            avg_entropy=0.0,
            max_entropy=0.0,
            txt_ratio=0.0,
            base64_count=0,
            hex_count=0,
            nxdomain_ratio=0.0,
        )
        with (
            patch("mytools.dns.dnstunnel.scan_tunnel", return_value=mock_result),
            patch("mytools.dns.dnstunnel.write_output") as mock_write,
        ):
            result = await _async_run_once(args)
        assert result == 0
        mock_write.assert_called_once()

    @pytest.mark.asyncio
    async def test_json_output(self) -> None:
        args = _make_args(json_output=True)
        mock_result = TunnelResult(
            domain="example.com",
            indicators=[],
            overall_severity="safe",
            is_tunneling=False,
            confidence=0.0,
            labels_analyzed=0,
            avg_label_length=0.0,
            max_label_length=0.0,
            avg_entropy=0.0,
            max_entropy=0.0,
            txt_ratio=0.0,
            base64_count=0,
            hex_count=0,
            nxdomain_ratio=0.0,
        )
        with (
            patch("mytools.dns.dnstunnel.scan_tunnel", return_value=mock_result),
            patch("mytools.dns.dnstunnel.print_json") as mock_json,
        ):
            result = await _async_run_once(args)
        assert result == 0
        mock_json.assert_called_once()

    @pytest.mark.asyncio
    async def test_output_dir(self) -> None:
        args = _make_args(output_dir="reports")
        mock_result = TunnelResult(
            domain="example.com",
            indicators=[],
            overall_severity="safe",
            is_tunneling=False,
            confidence=0.0,
            labels_analyzed=0,
            avg_label_length=0.0,
            max_label_length=0.0,
            avg_entropy=0.0,
            max_entropy=0.0,
            txt_ratio=0.0,
            base64_count=0,
            hex_count=0,
            nxdomain_ratio=0.0,
        )
        with (
            patch("mytools.dns.dnstunnel.scan_tunnel", return_value=mock_result),
            patch(
                "mytools.dns.dnstunnel.ensure_output_dir"
            ) as mock_ensure,
            patch("mytools.dns.dnstunnel.write_output") as mock_write,
        ):
            result = await _async_run_once(args)
        assert result == 0
        mock_ensure.assert_called_once_with("reports")
        mock_write.assert_called_once()


class TestRunOnce:
    """Testes da funcao run_once."""

    def test_delegates_to_safe_asyncio_run(self) -> None:
        args = _make_args()
        with patch(
            "mytools.dns.dnstunnel._async_run_once",
            new_callable=AsyncMock,
            return_value=0,
        ) as mock_async:
            result = run_once(args)
        assert result == 0
        mock_async.assert_called_once_with(args)


class TestMain:
    """Testes da funcao main."""

    def test_delegates_to_run_main_loop(self) -> None:
        with patch("mytools.dns.dnstunnel.run_main_loop", return_value=0) as mock_loop:
            result = main()
        assert result == 0
        mock_loop.assert_called_once()

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-tunnel"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.dns.dnstunnel", run_name="__main__")
        assert exc_info.value.code == 0
