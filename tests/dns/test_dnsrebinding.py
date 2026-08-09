#!/usr/bin/env python3
"""Testes unitarios do modulo de DNS Rebinding Detection."""

import argparse
import runpy
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.name
import dns.resolver
import pytest

from mytools.dns.dnsrebinding import (
    RebindingResult,
    _async_run_once,
    _check_cname_chain,
    _check_ip_flip,
    _check_private_ips,
    _check_ttl,
    _check_wildcard,
    _is_cloud_metadata,
    _is_private_ip,
    banner,
    build_parser,
    main,
    print_results,
    run_once,
    scan_rebinding,
)


class TestRebindingResult:
    """Testes do dataclass RebindingResult."""

    def test_frozen(self) -> None:
        r = RebindingResult(domain="a", check="b", severity="c", detail="d")
        with pytest.raises(AttributeError):
            r.domain = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(RebindingResult, "__slots__")

    def test_default_records(self) -> None:
        r = RebindingResult(domain="a", check="b", severity="c", detail="d")
        assert r.records == []


class TestIsPrivateIp:
    """Testes da funcao _is_private_ip."""

    def test_private_10(self) -> None:
        assert _is_private_ip("10.0.0.1")

    def test_private_172(self) -> None:
        assert _is_private_ip("172.16.0.1")

    def test_private_192(self) -> None:
        assert _is_private_ip("192.168.1.1")

    def test_loopback(self) -> None:
        assert _is_private_ip("127.0.0.1")

    def test_link_local(self) -> None:
        assert _is_private_ip("169.254.169.254")

    def test_carrier_grade(self) -> None:
        assert _is_private_ip("100.64.0.1")

    def test_public(self) -> None:
        assert not _is_private_ip("8.8.8.8")

    def test_public_2(self) -> None:
        assert not _is_private_ip("1.1.1.1")

    def test_invalid(self) -> None:
        assert not _is_private_ip("not-an-ip")


class TestIsCloudMetadata:
    """Testes da funcao _is_cloud_metadata."""

    def test_aws(self) -> None:
        assert _is_cloud_metadata("169.254.169.254")

    def test_alibaba(self) -> None:
        assert _is_cloud_metadata("100.100.100.200")

    def test_not_metadata(self) -> None:
        assert not _is_cloud_metadata("8.8.8.8")


class TestCheckTtl:
    """Testes da funcao _check_ttl."""

    def _make_answers(self, ttl: int) -> MagicMock:
        mock_answers = MagicMock()
        mock_answers.rrset.ttl = ttl
        return mock_answers

    def test_ttl_zero(self) -> None:
        result = _check_ttl("example.com", self._make_answers(0))
        assert result is not None
        assert result.severity == "critical"

    def test_ttl_one(self) -> None:
        result = _check_ttl("example.com", self._make_answers(1))
        assert result is not None
        assert result.severity == "high"

    def test_ttl_three(self) -> None:
        result = _check_ttl("example.com", self._make_answers(3))
        assert result is not None
        assert result.severity == "medium"

    def test_ttl_ten(self) -> None:
        result = _check_ttl("example.com", self._make_answers(10))
        assert result is not None
        assert result.severity == "low"

    def test_ttl_normal(self) -> None:
        result = _check_ttl("example.com", self._make_answers(3600))
        assert result is None


class TestCheckPrivateIps:
    """Testes da funcao _check_private_ips."""

    def _make_answers(self, ips: list[str]) -> MagicMock:
        mock_answers = MagicMock()
        rdatas = []
        for ip in ips:
            rdata = MagicMock()
            rdata.address = ip
            rdatas.append(rdata)
        mock_answers.__iter__ = MagicMock(return_value=iter(rdatas))
        return mock_answers

    def test_private_ip(self) -> None:
        results = _check_private_ips("example.com", self._make_answers(["192.168.1.1"]))
        assert len(results) == 1
        assert results[0].severity == "critical"

    def test_cloud_metadata(self) -> None:
        results = _check_private_ips(
            "example.com", self._make_answers(["169.254.169.254"])
        )
        assert len(results) == 1
        assert results[0].severity == "critical"
        assert "cloud" in results[0].detail.lower()

    def test_public_ip(self) -> None:
        results = _check_private_ips("example.com", self._make_answers(["8.8.8.8"]))
        assert results == []

    def test_mixed(self) -> None:
        results = _check_private_ips(
            "example.com", self._make_answers(["8.8.8.8", "192.168.1.1"])
        )
        assert len(results) == 1


class TestParser:
    """Testes do build_parser."""

    def test_basic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_queries(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--queries", "10"])
        assert args.queries == 10

    def test_list_file(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-l", "domains.txt"])
        assert args.target_list == "domains.txt"


class TestPrintResults:
    """Testes da funcao print_results."""

    def test_empty(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_results([])
        out = capsys.readouterr().out
        assert "Nenhuma vulnerabilidade" in out

    def test_with_vulns(self, capsys: pytest.CaptureFixture[str]) -> None:
        results = [
            RebindingResult(
                domain="example.com",
                check="ttl",
                severity="critical",
                detail="TTL=0",
                records=["TTL=0"],
            ),
        ]
        print_results(results)
        out = capsys.readouterr().out
        assert "1 vulnerabilidade" in out
        assert "CRITICAL" in out

    def test_with_info(self, capsys: pytest.CaptureFixture[str]) -> None:
        results = [
            RebindingResult(
                domain="example.com",
                check="resolve",
                severity="info",
                detail="Dominio nao existe",
            ),
        ]
        print_results(results)
        out = capsys.readouterr().out
        assert "1 info" in out


class TestCheckCnameChain:
    """Testes da funcao _check_cname_chain."""

    def _make_chaining(
        self, min_ttl: int | None, cname_names: list[str]
    ) -> tuple[MagicMock, MagicMock, MagicMock]:
        answers = MagicMock()
        chaining = MagicMock()
        chaining.minimum_ttl = min_ttl
        chaining.cnames = [dns.name.from_text(n) for n in cname_names]
        chaining.canonical_name = dns.name.from_text("final.example.com")
        answers.chaining_result = chaining
        return answers, chaining, answers

    def test_no_chaining_result(self) -> None:
        answers = MagicMock(spec=["unused"])
        resolver = MagicMock()
        result = _check_cname_chain("example.com", answers, resolver)
        assert result is None

    def test_empty_cnames(self) -> None:
        answers, _chaining, _ret = self._make_chaining(300, [])
        resolver = MagicMock()
        result = _check_cname_chain("example.com", answers, resolver)
        assert result is None

    def test_private_final_ip(self) -> None:
        answers, _chaining, _ret = self._make_chaining(300, ["a.example.com"])
        resolver = MagicMock()
        rdata = MagicMock()
        rdata.address = "192.168.1.1"
        resolver.resolve.return_value = [rdata]
        result = _check_cname_chain("example.com", answers, resolver)
        assert result is not None
        assert result.severity == "high"
        assert result.check == "cname_chain"

    def test_low_min_ttl(self) -> None:
        answers, _chaining, _ret = self._make_chaining(3, ["a.example.com"])
        resolver = MagicMock()
        rdata = MagicMock()
        rdata.address = "8.8.8.8"
        resolver.resolve.return_value = [rdata]
        result = _check_cname_chain("example.com", answers, resolver)
        assert result is not None
        assert result.severity == "medium"

    def test_deep_chain(self) -> None:
        answers, _chaining, _ret = self._make_chaining(
            300, ["a.example.com", "b.example.com", "c.example.com", "d.example.com"]
        )
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.exception.DNSException("fail")
        result = _check_cname_chain("example.com", answers, resolver)
        assert result is not None
        assert result.severity == "low"

    def test_no_finding(self) -> None:
        answers, _chaining, _ret = self._make_chaining(
            300, ["a.example.com", "b.example.com"]
        )
        resolver = MagicMock()
        rdata = MagicMock()
        rdata.address = "8.8.8.8"
        resolver.resolve.return_value = [rdata]
        result = _check_cname_chain("example.com", answers, resolver)
        assert result is None

    def test_empty_final_answers(self) -> None:
        answers, _chaining, _ret = self._make_chaining(300, ["a.example.com"])
        resolver = MagicMock()
        resolver.resolve.return_value = []
        result = _check_cname_chain("example.com", answers, resolver)
        assert result is None


class TestCheckWildcard:
    """Testes da funcao _check_wildcard."""

    def test_no_resolution(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.exception.DNSException("fail")
        result = _check_wildcard("example.com", resolver)
        assert result is None

    def test_some_resolution(self) -> None:
        resolver = MagicMock()
        rdata = MagicMock()
        rdata.address = "8.8.8.8"
        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter([rdata]))
        resolver.resolve.side_effect = [
            dns.exception.DNSException("fail"),
            mock_answer,
            mock_answer,
            mock_answer,
            mock_answer,
        ]
        result = _check_wildcard("example.com", resolver)
        assert result is not None
        assert result.check == "wildcard"
        assert result.severity == "medium"


class TestCheckIpFlip:
    """Testes da funcao _check_ip_flip."""

    def _make_answer(self, ips: list[str]) -> MagicMock:
        rdatas = [MagicMock(address=ip) for ip in ips]
        mock_answer = MagicMock()
        mock_answer.__iter__ = MagicMock(return_value=iter(rdatas))
        return mock_answer

    def test_flip_detected(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = [
            self._make_answer(["8.8.8.8"]),
            self._make_answer(["192.168.1.1"]),
        ]
        result = _check_ip_flip("example.com", resolver, queries=2)
        assert result is not None
        assert result.check == "ip_flip"
        assert result.severity == "critical"

    def test_no_flip(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = [
            self._make_answer(["8.8.8.8"]),
            self._make_answer(["1.1.1.1"]),
        ]
        result = _check_ip_flip("example.com", resolver, queries=2)
        assert result is None

    def test_all_raise(self) -> None:
        resolver = MagicMock()
        resolver.resolve.side_effect = dns.exception.DNSException("fail")
        result = _check_ip_flip("example.com", resolver, queries=2)
        assert result is None


class TestBanner:
    """Testes da funcao banner."""

    def test_calls_create_banner(self) -> None:
        with patch("mytools.dns.dnsrebinding.create_banner") as mock_banner:
            banner()
        mock_banner.assert_called_once()
        mock_banner.return_value.assert_called_once()


class TestScanRebinding:
    """Testes da funcao scan_rebinding com mocks DNS."""

    @patch("mytools.dns.dnsrebinding.dns.resolver.Resolver")
    def test_nxdomain(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()

        results = scan_rebinding("nonexistent.example.com")
        assert len(results) == 1
        assert results[0].check == "resolve"
        assert results[0].severity == "info"

    @patch("mytools.dns.dnsrebinding.dns.resolver.Resolver")
    def test_timeout(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.Timeout()

        results = scan_rebinding("timeout.example.com")
        assert len(results) == 1
        assert results[0].check == "resolve"

    @patch("mytools.dns.dnsrebinding._check_ip_flip")
    @patch("mytools.dns.dnsrebinding._check_wildcard")
    @patch("mytools.dns.dnsrebinding._check_cname_chain")
    @patch("mytools.dns.dnsrebinding._check_private_ips")
    @patch("mytools.dns.dnsrebinding._check_ttl")
    @patch("mytools.dns.dnsrebinding.dns.resolver.Resolver")
    def test_normal_domain(
        self,
        mock_resolver_cls: MagicMock,
        mock_ttl: MagicMock,
        mock_private: MagicMock,
        mock_cname: MagicMock,
        mock_wildcard: MagicMock,
        mock_flip: MagicMock,
    ) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        mock_answers = MagicMock()
        mock_answers.rrset.ttl = 3600
        mock_answers.__iter__ = MagicMock(return_value=iter([]))
        mock_resolver.resolve.return_value = mock_answers

        mock_ttl.return_value = None
        mock_private.return_value = []
        mock_cname.return_value = None
        mock_wildcard.return_value = None
        mock_flip.return_value = None

        results = scan_rebinding("example.com")
        assert results == []

    @patch("mytools.dns.dnsrebinding._check_ip_flip")
    @patch("mytools.dns.dnsrebinding._check_wildcard")
    @patch("mytools.dns.dnsrebinding._check_cname_chain")
    @patch("mytools.dns.dnsrebinding._check_private_ips")
    @patch("mytools.dns.dnsrebinding._check_ttl")
    @patch("mytools.dns.dnsrebinding.dns.resolver.Resolver")
    def test_vulnerable_domain(
        self,
        mock_resolver_cls: MagicMock,
        mock_ttl: MagicMock,
        mock_private: MagicMock,
        mock_cname: MagicMock,
        mock_wildcard: MagicMock,
        mock_flip: MagicMock,
    ) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        mock_answers = MagicMock()
        mock_answers.rrset.ttl = 0
        mock_answers.__iter__ = MagicMock(return_value=iter([]))
        mock_resolver.resolve.return_value = mock_answers

        mock_ttl.return_value = RebindingResult(
            domain="example.com",
            check="ttl",
            severity="critical",
            detail="TTL=0",
            records=["TTL=0"],
        )
        mock_private.return_value = []
        mock_cname.return_value = None
        mock_wildcard.return_value = None
        mock_flip.return_value = None

        results = scan_rebinding("example.com")
        assert len(results) == 1
        assert results[0].severity == "critical"

    @patch("mytools.dns.dnsrebinding.dns.resolver.Resolver")
    def test_no_answer(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()

        results = scan_rebinding("noanswer.example.com")
        assert len(results) == 1
        assert results[0].check == "resolve"
        assert "Sem registros" in results[0].detail

    @patch("mytools.dns.dnsrebinding.dns.resolver.Resolver")
    def test_generic_dns_exception(self, mock_resolver_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.DNSException("boom")

        results = scan_rebinding("error.example.com")
        assert len(results) == 1
        assert results[0].check == "resolve"
        assert "Erro DNS" in results[0].detail

    @patch("mytools.dns.dnsrebinding._check_ip_flip")
    @patch("mytools.dns.dnsrebinding._check_wildcard")
    @patch("mytools.dns.dnsrebinding._check_cname_chain")
    @patch("mytools.dns.dnsrebinding._check_private_ips")
    @patch("mytools.dns.dnsrebinding._check_ttl")
    @patch("mytools.dns.dnsrebinding.dns.resolver.Resolver")
    def test_all_checks_flagged(
        self,
        mock_resolver_cls: MagicMock,
        mock_ttl: MagicMock,
        mock_private: MagicMock,
        mock_cname: MagicMock,
        mock_wildcard: MagicMock,
        mock_flip: MagicMock,
    ) -> None:
        mock_resolver = MagicMock()
        mock_resolver_cls.return_value = mock_resolver

        mock_answers = MagicMock()
        mock_answers.rrset.ttl = 3600
        mock_answers.__iter__ = MagicMock(return_value=iter([]))
        mock_resolver.resolve.return_value = mock_answers

        mock_ttl.return_value = RebindingResult(
            domain="example.com", check="ttl", severity="low", detail="TTL baixo"
        )
        mock_private.return_value = []
        mock_cname.return_value = RebindingResult(
            domain="example.com",
            check="cname_chain",
            severity="high",
            detail="CNAME chain",
        )
        mock_wildcard.return_value = RebindingResult(
            domain="example.com",
            check="wildcard",
            severity="medium",
            detail="Wildcard DNS",
        )
        mock_flip.return_value = RebindingResult(
            domain="example.com",
            check="ip_flip",
            severity="critical",
            detail="IP flip",
        )

        results = scan_rebinding("example.com")
        checks = {r.check for r in results}
        assert {"ttl", "cname_chain", "wildcard", "ip_flip"} <= checks


def _make_args(**overrides: object) -> argparse.Namespace:
    defaults: dict[str, object] = {
        "domain": "example.com",
        "target_list": None,
        "queries": 5,
        "dry_run": False,
        "output": None,
        "verbose": False,
        "quiet": False,
        "color": None,
        "log_file": None,
        "theme": "cyber",
        "severity_override": None,
        "timeout": 5.0,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestAsyncRunOnce:
    """Testes do _async_run_once."""

    @pytest.mark.asyncio
    async def test_no_target_returns_one(self) -> None:
        args = _make_args(domain=None, target_list=None)
        assert await _async_run_once(args) == 1

    @pytest.mark.asyncio
    async def test_file_not_found_returns_one(self) -> None:
        args = _make_args(domain=None, target_list="missing.txt")
        assert await _async_run_once(args) == 1

    @pytest.mark.asyncio
    async def test_target_list(self, tmp_path) -> None:
        target_file = tmp_path / "domains.txt"
        target_file.write_text("example.com\nother.com\n", encoding="utf-8")
        args = _make_args(domain=None, target_list=str(target_file))
        with (
            patch("mytools.dns.dnsrebinding.scan_rebinding") as mock_scan,
            patch("mytools.dns.dnsrebinding.print_results") as mock_print,
        ):
            mock_scan.return_value = []
            result = await _async_run_once(args)
        assert result == 0
        assert mock_scan.call_count == 2
        mock_print.assert_called_once()

    @pytest.mark.asyncio
    async def test_domain(self) -> None:
        args = _make_args()
        with (
            patch("mytools.dns.dnsrebinding.scan_rebinding") as mock_scan,
            patch("mytools.dns.dnsrebinding.print_results") as mock_print,
        ):
            mock_scan.return_value = []
            result = await _async_run_once(args)
        assert result == 0
        mock_scan.assert_called_once()
        mock_print.assert_called_once()

    @pytest.mark.asyncio
    async def test_dry_run(self, capsys: pytest.CaptureFixture[str]) -> None:
        args = _make_args(dry_run=True)
        with patch("mytools.dns.dnsrebinding.scan_rebinding") as mock_scan:
            result = await _async_run_once(args)
        assert result == 0
        mock_scan.assert_not_called()
        out = capsys.readouterr().out
        assert "DRY-RUN" in out

    @pytest.mark.asyncio
    async def test_quiet_skips_print(self) -> None:
        args = _make_args(quiet=True)
        with (
            patch("mytools.dns.dnsrebinding.scan_rebinding", return_value=[]),
            patch("mytools.dns.dnsrebinding.print_results") as mock_print,
        ):
            result = await _async_run_once(args)
        assert result == 0
        mock_print.assert_not_called()

    @pytest.mark.asyncio
    async def test_writes_output(self) -> None:
        args = _make_args(output="out.json")
        mock_result = RebindingResult(
            domain="example.com", check="ttl", severity="low", detail="TTL baixo"
        )
        with (
            patch(
                "mytools.dns.dnsrebinding.scan_rebinding", return_value=[mock_result]
            ),
            patch("mytools.dns.dnsrebinding.write_output") as mock_write,
        ):
            result = await _async_run_once(args)
        assert result == 0
        mock_write.assert_called_once()


class TestRunOnce:
    """Testes da funcao run_once."""

    def test_delegates_to_safe_asyncio_run(self) -> None:
        args = _make_args()
        with patch(
            "mytools.dns.dnsrebinding._async_run_once",
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
            "mytools.dns.dnsrebinding.run_main_loop", return_value=0
        ) as mock_loop:
            result = main()
        assert result == 0
        mock_loop.assert_called_once()

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-rebind"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.dns.dnsrebinding", run_name="__main__")
        assert exc_info.value.code == 0
