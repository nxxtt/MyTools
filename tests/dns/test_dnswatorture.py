#!/usr/bin/env python3
"""Testes unitarios do modulo de DNS Water Torture."""

import argparse
from unittest.mock import MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from mytools.dns.dnswatorture import (
    QueryResult,
    WaterTortureResult,
    _gen_random_label,
    _gen_sequential_label,
    _gen_uuid_label,
    _gen_wordlist_label,
    _generate_domains,
    _send_query,
    banner,
    build_parser,
    main,
    print_results,
    run_once,
    run_water_torture,
)


class TestQueryResult:
    """Testes do dataclass QueryResult."""

    def test_frozen(self) -> None:
        r = QueryResult(domain="a", response_code="b", latency_ms=1.0, error="")
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(QueryResult, "__slots__")


class TestWaterTortureResult:
    """Testes do dataclass WaterTortureResult."""

    def test_frozen(self) -> None:
        r = WaterTortureResult(
            domain="a",
            nameserver="b",
            pattern="c",
            queries_sent=0,
            nxdomain_count=0,
            noerror_count=0,
            other_count=0,
            timeout_count=0,
            avg_latency_ms=0.0,
            p95_latency_ms=0.0,
            p99_latency_ms=0.0,
            loss_rate=0.0,
            duration_s=0.0,
            qps=0.0,
        )
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(WaterTortureResult, "__slots__")


class TestGenRandomLabel:
    """Testes da funcao _gen_random_label."""

    def test_length(self) -> None:
        label = _gen_random_label(8)
        assert len(label) == 8

    def test_custom_length(self) -> None:
        label = _gen_random_label(12)
        assert len(label) == 12

    def test_alphanumeric(self) -> None:
        label = _gen_random_label(20)
        assert label.isalnum()

    def test_lowercase(self) -> None:
        label = _gen_random_label(20)
        assert label == label.lower()


class TestGenUuidLabel:
    """Testes da funcao _gen_uuid_label."""

    def test_length(self) -> None:
        label = _gen_uuid_label()
        assert len(label) == 12

    def test_alphanumeric(self) -> None:
        label = _gen_uuid_label()
        assert label.isalnum()

    def test_unique(self) -> None:
        labels = {_gen_uuid_label() for _ in range(100)}
        assert len(labels) == 100


class TestGenSequentialLabel:
    """Testes da funcao _gen_sequential_label."""

    def test_format(self) -> None:
        label = _gen_sequential_label(0)
        assert label == "000000000000"

    def test_hex(self) -> None:
        label = _gen_sequential_label(255)
        assert label == "0000000000ff"

    def test_length(self) -> None:
        label = _gen_sequential_label(12345)
        assert len(label) == 12


class TestGenWordlistLabel:
    """Testes da funcao _gen_wordlist_label."""

    def test_not_empty(self) -> None:
        label = _gen_wordlist_label()
        assert len(label) > 0

    def test_has_digits(self) -> None:
        label = _gen_wordlist_label()
        assert any(c.isdigit() for c in label)


class TestGenerateDomains:
    """Testes da funcao _generate_domains."""

    def test_random(self) -> None:
        domains = _generate_domains("example.com", 5, "random")
        assert len(domains) == 5
        for d in domains:
            assert d.endswith(".example.com")

    def test_uuid(self) -> None:
        domains = _generate_domains("test.com", 3, "uuid")
        assert len(domains) == 3
        for d in domains:
            assert d.endswith(".test.com")

    def test_sequential(self) -> None:
        domains = _generate_domains("test.com", 3, "sequential")
        assert len(domains) == 3

    def test_wordlist(self) -> None:
        domains = _generate_domains("test.com", 3, "wordlist")
        assert len(domains) == 3


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

    def test_rate(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--rate", "500"])
        assert args.rate == 500

    def test_duration(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--duration", "30"])
        assert args.duration == 30

    def test_concurrency(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--concurrency", "100"])
        assert args.concurrency == 100

    def test_pattern(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--pattern", "uuid"])
        assert args.pattern == "uuid"

    def test_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--query-timeout", "5.0"])
        assert args.query_timeout == 5.0


class TestPrintResults:
    """Testes da funcao print_results."""

    def test_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = WaterTortureResult(
            domain="example.com",
            nameserver="8.8.8.8",
            pattern="random",
            queries_sent=100,
            nxdomain_count=90,
            noerror_count=5,
            other_count=3,
            timeout_count=2,
            avg_latency_ms=15.5,
            p95_latency_ms=30.0,
            p99_latency_ms=45.0,
            loss_rate=0.02,
            duration_s=10.0,
            qps=10.0,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "DNS Water Torture" in out
        assert "example.com" in out
        assert "100" in out
        assert "NXDOMAIN" in out

    def test_high_loss(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = WaterTortureResult(
            domain="test.com",
            nameserver="8.8.8.8",
            pattern="random",
            queries_sent=100,
            nxdomain_count=50,
            noerror_count=10,
            other_count=0,
            timeout_count=40,
            avg_latency_ms=50.0,
            p95_latency_ms=100.0,
            p99_latency_ms=150.0,
            loss_rate=0.4,
            duration_s=10.0,
            qps=10.0,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert (
            "sobrecarregado" in out.lower()
            or "rate limiting" in out.lower()
            or "Loss rate" in out
        )


class TestSendQuery:
    """Testes da funcao _send_query."""

    @patch("mytools.dns.dnswatorture.dns.resolver.Resolver")
    def test_noerror(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        result = _send_query("a.example.com", "8.8.8.8", 2.0)
        assert result.response_code == "NOERROR"
        assert result.error == ""
        assert result.domain == "a.example.com"

    @patch("mytools.dns.dnswatorture.dns.resolver.Resolver")
    def test_nxdomain(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        result = _send_query("x.example.com", "8.8.8.8", 2.0)
        assert result.response_code == "NXDOMAIN"

    @patch("mytools.dns.dnswatorture.dns.resolver.Resolver")
    def test_noanswer(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
        result = _send_query("x.example.com", "8.8.8.8", 2.0)
        assert result.response_code == "NOANSWER"

    @patch("mytools.dns.dnswatorture.dns.resolver.Resolver")
    def test_timeout(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.Timeout()
        result = _send_query("x.example.com", "8.8.8.8", 2.0)
        assert result.response_code == "TIMEOUT"
        assert result.error == "timeout"

    @patch("mytools.dns.dnswatorture.dns.resolver.Resolver")
    def test_dns_exception(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.DNSException("fail")
        result = _send_query("x.example.com", "8.8.8.8", 2.0)
        assert result.response_code == "ERROR"
        assert "fail" in result.error


class TestRunWaterTorture:
    """Testes da funcao run_water_torture."""

    @patch("mytools.dns.dnswatorture.time.sleep")
    @patch("mytools.dns.dnswatorture._send_query")
    def test_all_noerror(self, mock_send: MagicMock, mock_sleep: MagicMock) -> None:
        mock_send.return_value = QueryResult(
            domain="x.example.com", response_code="NOERROR", latency_ms=1.0, error=""
        )
        result = run_water_torture(
            "example.com", rate=10, duration=1, concurrency=2, timeout=2.0
        )
        assert result.queries_sent == 10
        assert result.noerror_count == 10
        assert result.nxdomain_count == 0
        assert result.loss_rate == 0.0
        assert result.tool == "dig"

    @patch("mytools.dns.dnswatorture.time.sleep")
    @patch("mytools.dns.dnswatorture._send_query")
    def test_mixed_with_high_loss(
        self, mock_send: MagicMock, mock_sleep: MagicMock
    ) -> None:
        results = [
            QueryResult("a", "NXDOMAIN", 1.0, ""),
            QueryResult("b", "TIMEOUT", 1.0, "timeout"),
            QueryResult("c", "ERROR", 1.0, "boom"),
            QueryResult("d", "NOERROR", 1.0, ""),
            QueryResult("e", "NXDOMAIN", 1.0, ""),
        ]
        mock_send.side_effect = results
        result = run_water_torture(
            "example.com", rate=5, duration=1, concurrency=2, timeout=2.0
        )
        assert result.queries_sent == 5
        assert result.nxdomain_count == 2
        assert result.timeout_count == 1
        assert result.other_count == 1
        assert result.loss_rate == 0.2
        assert "dig" in result.exploit

    @patch("mytools.dns.dnswatorture.time.sleep")
    @patch("mytools.dns.dnswatorture._send_query")
    def test_zero_rate(self, mock_send: MagicMock, mock_sleep: MagicMock) -> None:
        result = run_water_torture(
            "example.com", rate=0, duration=1, concurrency=2, timeout=2.0
        )
        assert result.queries_sent == 0
        assert result.avg_latency_ms == 0.0
        assert result.p95_latency_ms == 0.0
        assert result.p99_latency_ms == 0.0

    @patch("mytools.dns.dnswatorture.time.sleep")
    @patch("mytools.dns.dnswatorture._send_query")
    def test_worker_exception(
        self, mock_send: MagicMock, mock_sleep: MagicMock
    ) -> None:
        mock_send.side_effect = RuntimeError("unexpected")
        result = run_water_torture(
            "example.com", rate=3, duration=1, concurrency=2, timeout=2.0
        )
        assert result.queries_sent == 0
        assert result.nxdomain_count == 0


class TestPrintResultsMidLoss:
    """Cobertura do branch de loss rate entre 5%% e 10%% em print_results."""

    def test_mid_loss(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = WaterTortureResult(
            domain="mid.com",
            nameserver="8.8.8.8",
            pattern="random",
            queries_sent=100,
            nxdomain_count=90,
            noerror_count=3,
            other_count=0,
            timeout_count=7,
            avg_latency_ms=15.5,
            p95_latency_ms=30.0,
            p99_latency_ms=45.0,
            loss_rate=0.07,
            duration_s=10.0,
            qps=10.0,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "5%" in out or "rate limiting" in out.lower()


class TestBanner:
    """Testes da funcao banner."""

    def test_banner_calls_create_banner(self) -> None:
        with patch("mytools.dns.dnswatorture.create_banner") as mock_cb:
            mock_banner = MagicMock()
            mock_cb.return_value = mock_banner
            banner()
            mock_cb.assert_called_once()
            mock_banner.assert_called_once()


def _make_run_once_args(**overrides: object) -> argparse.Namespace:
    """Cria namespace de args para run_once do dnswatorture."""
    defaults = {
        "domain": "example.com",
        "dry_run": False,
        "nameserver": "8.8.8.8",
        "rate": 10,
        "duration": 1,
        "concurrency": 2,
        "pattern": "random",
        "query_timeout": 2.0,
        "output": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestRunOnce:
    """Testes do run_once/_async_run_once."""

    @patch("mytools.dns.dnswatorture.init_scanner", return_value=False)
    def test_no_domain(self, mock_init: MagicMock) -> None:
        assert run_once(_make_run_once_args(domain=None)) == 1

    @patch("mytools.dns.dnswatorture.init_scanner", return_value=False)
    def test_dry_run(self, mock_init: MagicMock) -> None:
        assert run_once(_make_run_once_args(dry_run=True)) == 0

    @patch("mytools.dns.dnswatorture.print_results")
    @patch("mytools.dns.dnswatorture.run_water_torture")
    @patch("mytools.dns.dnswatorture.init_scanner", return_value=False)
    def test_full_run(
        self,
        mock_init: MagicMock,
        mock_torture: MagicMock,
        mock_print: MagicMock,
    ) -> None:
        result = WaterTortureResult(
            domain="example.com",
            nameserver="8.8.8.8",
            pattern="random",
            queries_sent=10,
            nxdomain_count=0,
            noerror_count=10,
            other_count=0,
            timeout_count=0,
            avg_latency_ms=1.0,
            p95_latency_ms=2.0,
            p99_latency_ms=3.0,
            loss_rate=0.0,
            duration_s=0.1,
            qps=100.0,
        )
        mock_torture.return_value = result
        assert run_once(_make_run_once_args()) == 0
        mock_torture.assert_called_once()
        mock_print.assert_called_once_with(result)

    @patch("mytools.dns.dnswatorture.write_output")
    @patch("mytools.dns.dnswatorture.print_results")
    @patch("mytools.dns.dnswatorture.run_water_torture")
    @patch("mytools.dns.dnswatorture.init_scanner", return_value=False)
    def test_with_output(
        self,
        mock_init: MagicMock,
        mock_torture: MagicMock,
        mock_print: MagicMock,
        mock_write: MagicMock,
    ) -> None:
        result = WaterTortureResult(
            domain="example.com",
            nameserver="8.8.8.8",
            pattern="random",
            queries_sent=0,
            nxdomain_count=0,
            noerror_count=0,
            other_count=0,
            timeout_count=0,
            avg_latency_ms=0.0,
            p95_latency_ms=0.0,
            p99_latency_ms=0.0,
            loss_rate=0.0,
            duration_s=0.0,
            qps=0.0,
        )
        mock_torture.return_value = result
        assert run_once(_make_run_once_args(output="out.json")) == 0
        mock_write.assert_called_once()

    @patch("mytools.dns.dnswatorture.write_output")
    @patch("mytools.dns.dnswatorture.print_results")
    @patch("mytools.dns.dnswatorture.run_water_torture")
    @patch("mytools.dns.dnswatorture.init_scanner", return_value=True)
    def test_quiet_skips_print(
        self,
        mock_init: MagicMock,
        mock_torture: MagicMock,
        mock_print: MagicMock,
        mock_write: MagicMock,
    ) -> None:
        result = WaterTortureResult(
            domain="example.com",
            nameserver="8.8.8.8",
            pattern="random",
            queries_sent=0,
            nxdomain_count=0,
            noerror_count=0,
            other_count=0,
            timeout_count=0,
            avg_latency_ms=0.0,
            p95_latency_ms=0.0,
            p99_latency_ms=0.0,
            loss_rate=0.0,
            duration_s=0.0,
            qps=0.0,
        )
        mock_torture.return_value = result
        assert run_once(_make_run_once_args(quiet=True)) == 0
        mock_print.assert_not_called()
        mock_write.assert_not_called()


class TestMain:
    """Testes da funcao main."""

    def test_main_calls_run_main_loop(self) -> None:
        with patch(
            "mytools.dns.dnswatorture.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
            mock_loop.assert_called_once()


class TestMainGuard:
    """Testes do guard `if __name__ == \"__main__\"`."""

    def test_guard_runs(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-dwt", "example.com"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.dns.dnswatorture", run_name="__main__")
        assert exc_info.value.code == 0
