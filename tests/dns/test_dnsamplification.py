#!/usr/bin/env python3
"""Testes unitarios do modulo de DNS Amplification Detection."""

import argparse
import runpy
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.flags
import dns.resolver
import pytest

from mytools.dns.dnsamplification import (
    AmplificationResult,
    RecordAmplification,
    _async_run_once,
    _check_recursion,
    _is_valid_nameserver,
    _query_record,
    banner,
    build_parser,
    classify_severity,
    main,
    print_results,
    run_once,
    scan_amplification,
)


class TestRecordAmplification:
    """Testes do dataclass RecordAmplification."""

    def test_frozen(self) -> None:
        r = RecordAmplification(
            record_type="A",
            response_bytes=100,
            amplification_factor=2.0,
            success=True,
            error="",
        )
        with pytest.raises(AttributeError):
            r.record_type = "B"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(RecordAmplification, "__slots__")


class TestAmplificationResult:
    """Testes do dataclass AmplificationResult."""

    def test_frozen(self) -> None:
        r = AmplificationResult(
            domain="a",
            nameserver="b",
            recursion_available=False,
            is_open_resolver=False,
            records=[],
            max_amplification=0.0,
            severity="safe",
            request_size=50,
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
            domain="example.com",
            nameserver="8.8.8.8",
            recursion_available=False,
            is_open_resolver=False,
            records=[
                RecordAmplification("A", 80, 1.6, True, ""),
                RecordAmplification("ANY", 500, 10.0, True, ""),
            ],
            max_amplification=10.0,
            severity="critical",
            request_size=50,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "DNS Amplification Detection" in out
        assert "example.com" in out

    def test_output_open_resolver(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = AmplificationResult(
            domain="test.com",
            nameserver="1.1.1.1",
            recursion_available=True,
            is_open_resolver=True,
            records=[
                RecordAmplification("TXT", 4000, 80.0, True, ""),
            ],
            max_amplification=80.0,
            severity="critical",
            request_size=50,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "ABERTO" in out or "OPEN" in out.upper()

    def test_output_with_errors(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = AmplificationResult(
            domain="bad.com",
            nameserver="8.8.8.8",
            recursion_available=False,
            is_open_resolver=False,
            records=[
                RecordAmplification("A", 0, 0.0, False, "TIMEOUT"),
                RecordAmplification("MX", 0, 0.0, False, "NXDOMAIN"),
            ],
            max_amplification=0.0,
            severity="safe",
            request_size=50,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "FALHA" in out

    def test_output_recursion_with_amplification(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = AmplificationResult(
            domain="mid.com",
            nameserver="8.8.8.8",
            recursion_available=True,
            is_open_resolver=False,
            records=[
                RecordAmplification("TXT", 300, 6.0, True, ""),
            ],
            max_amplification=6.0,
            severity="high",
            request_size=50,
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "amplificacao potencial" in out or "recursao habilitada" in out.lower()


class TestIsValidNameserver:
    """Testes da funcao _is_valid_nameserver."""

    def test_valid_ip(self) -> None:
        assert _is_valid_nameserver("8.8.8.8") is True

    def test_valid_hostname(self) -> None:
        assert _is_valid_nameserver("ns1.example.com") is True

    def test_valid_ipv6(self) -> None:
        assert _is_valid_nameserver("2001:4860:4860::8888") is True

    def test_empty(self) -> None:
        assert _is_valid_nameserver("   ") is False

    def test_too_long(self) -> None:
        assert _is_valid_nameserver("a" * 254) is False

    def test_whitespace(self) -> None:
        assert _is_valid_nameserver("8.8.8.8 1.1.1.1") is False

    def test_leading_dot(self) -> None:
        assert _is_valid_nameserver(".example.com") is False

    def test_trailing_dash(self) -> None:
        assert _is_valid_nameserver("example.com-") is False


class TestBanner:
    """Testes da funcao banner."""

    def test_calls_create_banner(self) -> None:
        with patch("mytools.dns.dnsamplification.create_banner") as mock_banner:
            banner()
        mock_banner.assert_called_once()
        mock_banner.return_value.assert_called_once()


def _make_args(**overrides: object) -> argparse.Namespace:
    defaults: dict[str, object] = {
        "domain": "example.com",
        "nameserver": "8.8.8.8",
        "record_types": "ANY,TXT",
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
    async def test_invalid_nameserver_returns_one(self) -> None:
        args = _make_args(nameserver="invalid name server")
        assert await _async_run_once(args) == 1

    @pytest.mark.asyncio
    async def test_normal_runs_scan(self) -> None:
        args = _make_args()
        mock_result = AmplificationResult(
            domain="example.com",
            nameserver="8.8.8.8",
            recursion_available=False,
            is_open_resolver=False,
            records=[],
            max_amplification=0.0,
            severity="safe",
            request_size=50,
        )
        with (
            patch(
                "mytools.dns.dnsamplification.scan_amplification",
                return_value=mock_result,
            ),
            patch("mytools.dns.dnsamplification.print_results") as mock_print,
        ):
            result = await _async_run_once(args)
        assert result == 0
        mock_print.assert_called_once()

    @pytest.mark.asyncio
    async def test_quiet_skips_print(self) -> None:
        args = _make_args(quiet=True)
        mock_result = AmplificationResult(
            domain="example.com",
            nameserver="8.8.8.8",
            recursion_available=False,
            is_open_resolver=False,
            records=[],
            max_amplification=0.0,
            severity="safe",
            request_size=50,
        )
        with (
            patch(
                "mytools.dns.dnsamplification.scan_amplification",
                return_value=mock_result,
            ),
            patch("mytools.dns.dnsamplification.print_results") as mock_print,
        ):
            result = await _async_run_once(args)
        assert result == 0
        mock_print.assert_not_called()

    @pytest.mark.asyncio
    async def test_writes_output(self) -> None:
        args = _make_args(output="out.json")
        mock_result = AmplificationResult(
            domain="example.com",
            nameserver="8.8.8.8",
            recursion_available=False,
            is_open_resolver=False,
            records=[],
            max_amplification=0.0,
            severity="safe",
            request_size=50,
        )
        with (
            patch(
                "mytools.dns.dnsamplification.scan_amplification",
                return_value=mock_result,
            ),
            patch("mytools.dns.dnsamplification.write_output") as mock_write,
        ):
            result = await _async_run_once(args)
        assert result == 0
        mock_write.assert_called_once()

    @pytest.mark.asyncio
    async def test_json_output(self) -> None:
        args = _make_args(json_output=True)
        mock_result = AmplificationResult(
            domain="example.com",
            nameserver="8.8.8.8",
            recursion_available=False,
            is_open_resolver=False,
            records=[],
            max_amplification=0.0,
            severity="safe",
            request_size=50,
        )
        with (
            patch(
                "mytools.dns.dnsamplification.scan_amplification",
                return_value=mock_result,
            ),
            patch("mytools.dns.dnsamplification.print_json") as mock_json,
        ):
            result = await _async_run_once(args)
        assert result == 0
        mock_json.assert_called_once()

    @pytest.mark.asyncio
    async def test_output_dir(self) -> None:
        args = _make_args(output_dir="reports")
        mock_result = AmplificationResult(
            domain="example.com",
            nameserver="8.8.8.8",
            recursion_available=False,
            is_open_resolver=False,
            records=[],
            max_amplification=0.0,
            severity="safe",
            request_size=50,
        )
        with (
            patch(
                "mytools.dns.dnsamplification.scan_amplification",
                return_value=mock_result,
            ),
            patch(
                "mytools.dns.dnsamplification.ensure_output_dir"
            ) as mock_ensure,
            patch("mytools.dns.dnsamplification.write_output") as mock_write,
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
            "mytools.dns.dnsamplification._async_run_once",
            new_callable=AsyncMock,
            return_value=0,
        ) as mock_async:
            result = run_once(args)
        assert result == 0
        mock_async.assert_called_once_with(args)


class TestMain:
    """Testes da funcao main."""

    def test_delegates_to_run_main_loop(self) -> None:
        with patch(
            "mytools.dns.dnsamplification.run_main_loop", return_value=0
        ) as mock_loop:
            result = main()
        assert result == 0
        mock_loop.assert_called_once()

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-amp"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.dns.dnsamplification", run_name="__main__")
        assert exc_info.value.code == 0


class TestQueryRecord:
    """Testes da funcao _query_record com mocks DNS."""

    @patch("mytools.dns.dnsamplification.dns.resolver.Resolver")
    def test_success(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        answer = MagicMock()
        answer.response.to_wire.return_value = b"\x00" * 200
        mock_resolver.resolve.return_value = answer

        result = _query_record(mock_resolver, "example.com", "A", 3.0)
        assert result.success is True
        assert result.response_bytes == 200
        assert result.amplification_factor == 4.0
        assert result.error == ""

    @patch("mytools.dns.dnsamplification.dns.resolver.Resolver")
    def test_nxdomain(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        result = _query_record(mock_resolver, "example.com", "A", 3.0)
        assert result.success is False
        assert result.error == "NXDOMAIN"

    @patch("mytools.dns.dnsamplification.dns.resolver.Resolver")
    def test_no_answer(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
        result = _query_record(mock_resolver, "example.com", "A", 3.0)
        assert result.success is False
        assert result.error == "NOANSWER"

    @patch("mytools.dns.dnsamplification.dns.resolver.Resolver")
    def test_no_nameservers(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoNameservers()
        result = _query_record(mock_resolver, "example.com", "A", 3.0)
        assert result.success is False
        assert result.error == "NAMESERVERS"

    @patch("mytools.dns.dnsamplification.dns.resolver.Resolver")
    def test_timeout(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.Timeout()
        result = _query_record(mock_resolver, "example.com", "A", 3.0)
        assert result.success is False
        assert result.error == "TIMEOUT"

    @patch("mytools.dns.dnsamplification.dns.resolver.Resolver")
    def test_dns_exception(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.DNSException("boom")
        result = _query_record(mock_resolver, "example.com", "A", 3.0)
        assert result.success is False
        assert result.error == "boom"


class TestCheckRecursion:
    """Testes da funcao _check_recursion."""

    @patch("mytools.dns.dnsamplification.dns.query.udp")
    def test_ra_set(self, mock_udp: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.flags = dns.flags.RA
        mock_udp.return_value = mock_response
        assert _check_recursion("8.8.8.8", "example.com", 3.0) is True

    @patch("mytools.dns.dnsamplification.dns.query.udp")
    def test_ra_not_set(self, mock_udp: MagicMock) -> None:
        mock_response = MagicMock()
        mock_response.flags = 0
        mock_udp.return_value = mock_response
        assert _check_recursion("8.8.8.8", "example.com", 3.0) is False

    @patch(
        "mytools.dns.dnsamplification.dns.query.udp",
        side_effect=RuntimeError("boom"),
    )
    def test_exception(self, mock_udp: MagicMock) -> None:
        assert _check_recursion("8.8.8.8", "example.com", 3.0) is False


class TestScanAmplification:
    """Testes da funcao scan_amplification com mocks."""

    @patch("mytools.dns.dnsamplification._check_recursion", return_value=False)
    @patch("mytools.dns.dnsamplification._query_record")
    def test_basic(self, mock_query: MagicMock, mock_rec: MagicMock) -> None:
        mock_query.return_value = RecordAmplification("A", 80, 1.6, True, "")
        result = scan_amplification("example.com")
        assert result.domain == "example.com"
        assert result.recursion_available is False
        assert len(result.records) == 5

    @patch("mytools.dns.dnsamplification._check_recursion", return_value=True)
    @patch("mytools.dns.dnsamplification._query_record")
    def test_open_resolver(self, mock_query: MagicMock, mock_rec: MagicMock) -> None:
        mock_query.return_value = RecordAmplification("TXT", 4000, 80.0, True, "")
        result = scan_amplification("example.com")
        assert result.is_open_resolver is True
        assert result.severity == "critical"

    @patch("mytools.dns.dnsamplification._check_recursion", return_value=False)
    @patch("mytools.dns.dnsamplification._query_record")
    def test_custom_record_types(
        self, mock_query: MagicMock, mock_rec: MagicMock
    ) -> None:
        mock_query.return_value = RecordAmplification("A", 80, 1.6, True, "")
        result = scan_amplification("example.com", record_types=["A", "MX"])
        assert len(result.records) == 2

    @patch("mytools.dns.dnsamplification._check_recursion", return_value=False)
    @patch("mytools.dns.dnsamplification._query_record")
    def test_all_failures(self, mock_query: MagicMock, mock_rec: MagicMock) -> None:
        mock_query.return_value = RecordAmplification("A", 0, 0.0, False, "TIMEOUT")
        result = scan_amplification("example.com")
        assert result.max_amplification == 0.0
        assert result.severity == "safe"
