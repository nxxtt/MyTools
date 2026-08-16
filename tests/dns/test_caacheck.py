#!/usr/bin/env python3
"""Testes unitarios do modulo de CAA Record Check."""

import argparse
import runpy
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.resolver
import pytest

from mytools.dns.caacheck import (
    CaaRecord,
    CaaResult,
    _async_run_once,
    _identify_ca,
    _parse_caa_rdata,
    banner,
    build_parser,
    main,
    print_results,
    run_once,
    scan_caa,
)


class TestCaaRecord:
    """Testes do dataclass CaaRecord."""

    def test_frozen(self) -> None:
        r = CaaRecord(tag="issue", value="letsencrypt.org", flags=0)
        with pytest.raises(AttributeError):
            r.tag = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(CaaRecord, "__slots__")


class TestCaaResult:
    """Testes do dataclass CaaResult."""

    def test_frozen(self) -> None:
        r = CaaResult(
            domain="a",
            records=[],
            has_caa=False,
            authorized_cas=[],
            has_iodef=False,
            policy_status="none",
        )
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(CaaResult, "__slots__")


class TestIdentifyCa:
    """Testes da funcao _identify_ca."""

    def test_letsencrypt(self) -> None:
        assert _identify_ca("letsencrypt.org") == "Let's Encrypt"

    def test_digicert(self) -> None:
        assert _identify_ca("digicert.com") == "DigiCert"

    def test_unknown(self) -> None:
        assert _identify_ca("unknown-ca.com") == "unknown-ca.com"

    def test_with_dot(self) -> None:
        assert _identify_ca("letsencrypt.org.") == "Let's Encrypt"

    def test_subdomain_boundary(self) -> None:
        assert _identify_ca("sub.sectigo.com") == "Sectigo"

    def test_no_false_positive_on_dot_boundary(self) -> None:
        assert _identify_ca("evsectigo.com.evil.com") == "evsectigo.com.evil.com"


class TestParseCaaRdata:
    """Testes da funcao _parse_caa_rdata."""

    def test_valid(self) -> None:
        result = _parse_caa_rdata('0 issue "letsencrypt.org"')
        assert result is not None
        assert result.tag == "issue"
        assert result.value == "letsencrypt.org"
        assert result.flags == 0

    def test_issuewild(self) -> None:
        result = _parse_caa_rdata('0 issuewild "digicert.com"')
        assert result is not None
        assert result.tag == "issuewild"

    def test_iodef(self) -> None:
        result = _parse_caa_rdata('0 iodef "mailto:admin@example.com"')
        assert result is not None
        assert result.tag == "iodef"

    def test_critical(self) -> None:
        result = _parse_caa_rdata('128 issue "letsencrypt.org"')
        assert result is not None
        assert result.flags == 128

    def test_invalid(self) -> None:
        result = _parse_caa_rdata("invalid")
        assert result is None

    def test_non_numeric_flags(self) -> None:
        result = _parse_caa_rdata("abc issue letsencrypt.org")
        assert result is None


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

    def test_no_caa(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CaaResult(
            domain="test.com",
            records=[],
            has_caa=False,
            authorized_cas=[],
            has_iodef=False,
            policy_status="none",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "CAA Record Check" in out
        assert "NAO" in out

    def test_restrictive(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CaaResult(
            domain="secure.com",
            records=[CaaRecord("issue", "letsencrypt.org", 0)],
            has_caa=True,
            authorized_cas=["Let's Encrypt"],
            has_iodef=False,
            policy_status="restrictive",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "RESTRITIVA" in out or "restrictive" in out.lower()

    def test_permissive(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CaaResult(
            domain="open.com",
            records=[
                CaaRecord("issue", "letsencrypt.org", 0),
                CaaRecord("issue", "digicert.com", 0),
                CaaRecord("issue", "globalsign.com", 0),
            ],
            has_caa=True,
            authorized_cas=["DigiCert", "GlobalSign", "Let's Encrypt"],
            has_iodef=True,
            policy_status="permissive",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "PERMISSIVA" in out or "permissive" in out.lower()

    def test_open(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CaaResult(
            domain="open.com",
            records=[CaaRecord("issue", "letsencrypt.org", 0)],
            has_caa=True,
            authorized_cas=["Let's Encrypt"],
            has_iodef=False,
            policy_status="open",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "aberta" in out or "ABERTA" in out


class TestScanCaa:
    """Testes da funcao scan_caa com mocks."""

    @patch("mytools.dns.caacheck.dns.resolver.Resolver")
    def test_no_caa(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
        result = scan_caa("test.com")
        assert result.has_caa is False
        assert result.policy_status == "none"

    @patch("mytools.dns.caacheck.dns.resolver.Resolver")
    def test_empty_domain(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
        result = scan_caa("")
        assert result.has_caa is False

    def _make_rdata(self, text: str) -> MagicMock:
        rdata = MagicMock()
        rdata.__str__ = MagicMock(return_value=text)
        return rdata

    @patch("mytools.dns.caacheck.dns.resolver.Resolver")
    def test_with_records(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.return_value = [
            self._make_rdata('0 issue "letsencrypt.org"'),
            self._make_rdata('0 iodef "mailto:admin@example.com"'),
        ]
        result = scan_caa("example.com")
        assert result.has_caa is True
        assert result.authorized_cas == ["Let's Encrypt"]
        assert result.has_iodef is True
        assert result.policy_status == "restrictive"

    @patch("mytools.dns.caacheck.dns.resolver.Resolver")
    def test_issuewild_not_counted(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.return_value = [
            self._make_rdata('0 issue "letsencrypt.org"'),
            self._make_rdata('0 issuewild "digicert.com"'),
        ]
        result = scan_caa("example.com")
        assert result.policy_status == "restrictive"
        assert result.authorized_cas == ["Let's Encrypt"]

    @patch("mytools.dns.caacheck.dns.resolver.Resolver")
    def test_permissive_policy(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.return_value = [
            self._make_rdata('0 issue "letsencrypt.org"'),
            self._make_rdata('0 issue "digicert.com"'),
            self._make_rdata('0 issue "globalsign.com"'),
        ]
        result = scan_caa("example.com")
        assert result.policy_status == "permissive"

    @patch("mytools.dns.caacheck.dns.resolver.Resolver")
    def test_open_policy(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.return_value = [
            self._make_rdata(f'0 issue "ca{i}.com"') for i in range(1, 5)
        ]
        result = scan_caa("example.com")
        assert result.policy_status == "open"

    @patch("mytools.dns.caacheck.dns.resolver.Resolver")
    def test_semicolon_value_not_counted(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.return_value = [
            self._make_rdata('0 issue "letsencrypt.org"'),
            self._make_rdata("0 issue ;"),
        ]
        result = scan_caa("example.com")
        assert result.policy_status == "restrictive"

    @patch("mytools.dns.caacheck.dns.resolver.Resolver")
    def test_invalid_rdata_skipped(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.return_value = [
            self._make_rdata("invalid"),
            self._make_rdata('0 issue "letsencrypt.org"'),
        ]
        result = scan_caa("example.com")
        assert result.has_caa is True
        assert result.authorized_cas == ["Let's Encrypt"]

    @patch("mytools.dns.caacheck.dns.resolver.Resolver")
    def test_nxdomain(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        result = scan_caa("nonexistent.com")
        assert result.error == "domain_not_found"
        assert result.policy_status == "none"

    @patch("mytools.dns.caacheck.dns.resolver.Resolver")
    def test_timeout(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.Timeout()
        result = scan_caa("timeout.com")
        assert result.error == "dns_timeout"

    @patch("mytools.dns.caacheck.dns.resolver.Resolver")
    def test_dns_error(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.DNSException("boom")
        result = scan_caa("error.com")
        assert result.error is not None
        assert "dns_error" in result.error


class TestBanner:
    """Testes da funcao banner."""

    def test_calls_create_banner(self) -> None:
        with patch("mytools.dns.caacheck.create_banner") as mock_banner:
            banner()
        mock_banner.assert_called_once()
        mock_banner.return_value.assert_called_once()


def _make_args(**overrides: object) -> argparse.Namespace:
    defaults: dict[str, object] = {
        "domain": "example.com",
        "nameserver": "8.8.8.8",
        "query_timeout": 5.0,
        "dry_run": False,
        "output": None,
        "verbose": False,
        "quiet": False,
        "color": None,
        "log_file": None,
        "theme": "cyber",
        "severity_override": None,
        "timeout": 5.0,
        "json_output": False,
        "output_dir": None,
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
        with (
            patch("mytools.dns.caacheck.scan_caa") as mock_scan,
            patch("mytools.dns.caacheck.print_results") as mock_print,
        ):
            mock_scan.return_value = CaaResult(
                domain="example.com",
                records=[CaaRecord("issue", "letsencrypt.org", 0)],
                has_caa=True,
                authorized_cas=["Let's Encrypt"],
                has_iodef=False,
                policy_status="restrictive",
            )
            result = await _async_run_once(args)
        assert result == 0
        mock_scan.assert_called_once_with(
            domain="example.com", nameserver="8.8.8.8", timeout=5.0
        )
        mock_print.assert_called_once()

    @pytest.mark.asyncio
    async def test_quiet_skips_print(self) -> None:
        args = _make_args(quiet=True)
        mock_scan_result = CaaResult(
            domain="example.com",
            records=[CaaRecord("issue", "letsencrypt.org", 0)],
            has_caa=True,
            authorized_cas=["Let's Encrypt"],
            has_iodef=False,
            policy_status="restrictive",
        )
        with (
            patch("mytools.dns.caacheck.scan_caa", return_value=mock_scan_result),
            patch("mytools.dns.caacheck.print_results") as mock_print,
        ):
            result = await _async_run_once(args)
        assert result == 0
        mock_print.assert_not_called()

    @pytest.mark.asyncio
    async def test_writes_output(self) -> None:
        args = _make_args(output="out.json")
        with (
            patch("mytools.dns.caacheck.scan_caa") as mock_scan,
            patch("mytools.dns.caacheck.write_output") as mock_write,
        ):
            mock_scan.return_value = CaaResult(
                domain="example.com",
                records=[CaaRecord("issue", "letsencrypt.org", 0)],
                has_caa=True,
                authorized_cas=["Let's Encrypt"],
                has_iodef=False,
                policy_status="restrictive",
            )
            result = await _async_run_once(args)
        assert result == 0
        mock_write.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_caa_returns_vulnerable_exit(self) -> None:
        args = _make_args()
        mock_scan_result = CaaResult(
            domain="example.com",
            records=[],
            has_caa=False,
            authorized_cas=[],
            has_iodef=False,
            policy_status="none",
        )
        with (
            patch("mytools.dns.caacheck.scan_caa", return_value=mock_scan_result),
            patch("mytools.dns.caacheck.print_results"),
        ):
            result = await _async_run_once(args)
        assert result == 1

    @pytest.mark.asyncio
    async def test_open_policy_zero_issue_exit(self) -> None:
        args = _make_args()
        mock_scan_result = CaaResult(
            domain="example.com",
            records=[CaaRecord("issue", "letsencrypt.org", 0)],
            has_caa=True,
            authorized_cas=["Let's Encrypt"],
            has_iodef=False,
            policy_status="open",
        )
        with (
            patch("mytools.dns.caacheck.scan_caa", return_value=mock_scan_result),
            patch("mytools.dns.caacheck.print_results"),
        ):
            result = await _async_run_once(args)
        assert result == 0

    @pytest.mark.asyncio
    async def test_json_prints_and_still_writes_output_dir(self) -> None:
        args = _make_args(json_output=True, output_dir="out")
        mock_scan_result = CaaResult(
            domain="example.com",
            records=[CaaRecord("issue", "letsencrypt.org", 0)],
            has_caa=True,
            authorized_cas=["Let's Encrypt"],
            has_iodef=False,
            policy_status="restrictive",
        )
        with (
            patch("mytools.dns.caacheck.scan_caa", return_value=mock_scan_result),
            patch("mytools.dns.caacheck.print_json") as mock_print_json,
            patch("mytools.dns.caacheck.ensure_output_dir") as mock_ensure,
            patch("mytools.dns.caacheck.write_output") as mock_write,
        ):
            result = await _async_run_once(args)
        assert result == 0
        mock_print_json.assert_called_once()
        mock_ensure.assert_called_once_with("out")
        mock_write.assert_called_once()


class TestRunOnce:
    """Testes da funcao run_once."""

    def test_delegates_to_safe_asyncio_run(self) -> None:
        args = _make_args()
        with patch(
            "mytools.dns.caacheck._async_run_once",
            new_callable=AsyncMock,
            return_value=0,
        ) as mock_async:
            result = run_once(args)
        assert result == 0
        mock_async.assert_called_once_with(args)


class TestMain:
    """Testes da funcao main."""

    def test_delegates_to_run_main_loop(self) -> None:
        with patch("mytools.dns.caacheck.run_main_loop", return_value=0) as mock_loop:
            result = main()
        assert result == 0
        mock_loop.assert_called_once()

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-caa"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.dns.caacheck", run_name="__main__")
        assert exc_info.value.code == 0
