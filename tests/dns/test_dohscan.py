#!/usr/bin/env python3
"""Tests for dohscan.py."""

from __future__ import annotations

import argparse
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.message
import dns.name
import dns.resolver
import dns.rrset
import httpx
import pytest
import respx

from mytools.dns.dohscan import (
    _DOH_PROVIDERS,
    DohProviderResult,
    DohRecord,
    DohScanResult,
    _build_dns_query,
    _compare_records,
    _doh_query_get,
    _doh_query_post,
    _parse_dns_response,
    _run_scan,
    _safe_run,
    _test_provider,
    _traditional_resolve,
    banner,
    build_parser,
    main,
    print_results,
    scan_doh,
)


class TestDohRecord:
    def test_creation(self) -> None:
        r = DohRecord(name="example.com", rdtype="A", ttl=300, rdata="1.2.3.4")
        assert r.name == "example.com"
        assert r.rdtype == "A"
        assert r.ttl == 300
        assert r.rdata == "1.2.3.4"

    def test_frozen(self) -> None:
        r = DohRecord(name="example.com", rdtype="A", ttl=300, rdata="1.2.3.4")
        with pytest.raises(AttributeError):
            r.name = "changed"  # type: ignore[misc]


class TestDohProviderResult:
    def test_creation(self) -> None:
        r = DohProviderResult(
            provider="google",
            provider_name="Google DNS",
            url="https://dns.google/dns-query",
            records=[],
            latency_ms=50.0,
            status_code=200,
            error="",
            query_method="GET",
        )
        assert r.provider == "google"
        assert r.status_code == 200

    def test_frozen(self) -> None:
        r = DohProviderResult(
            provider="google",
            provider_name="Google DNS",
            url="https://dns.google/dns-query",
            records=[],
            latency_ms=50.0,
            status_code=200,
            error="",
            query_method="GET",
        )
        with pytest.raises(AttributeError):
            r.provider = "changed"  # type: ignore[misc]


class TestDohScanResult:
    def test_creation(self) -> None:
        r = DohScanResult(
            domain="example.com",
            query_type="A",
            providers=[],
            traditional_records=[],
            traditional_latency_ms=10.0,
            filtering_detected=False,
            inconsistencies=[],
            doh_supported=True,
            overall_status="resolved",
            error="",
        )
        assert r.domain == "example.com"
        assert r.overall_status == "resolved"

    def test_frozen(self) -> None:
        r = DohScanResult(
            domain="example.com",
            query_type="A",
            providers=[],
            traditional_records=[],
            traditional_latency_ms=10.0,
            filtering_detected=False,
            inconsistencies=[],
            doh_supported=True,
            overall_status="resolved",
            error="",
        )
        with pytest.raises(AttributeError):
            r.domain = "changed"  # type: ignore[misc]


class TestDohProviders:
    def test_all_providers_present(self) -> None:
        assert set(_DOH_PROVIDERS.keys()) == {
            "google",
            "cloudflare",
            "quad9",
            "adguard",
        }

    def test_provider_has_required_fields(self) -> None:
        for key, prov in _DOH_PROVIDERS.items():
            assert "name" in prov, f"{key} missing name"
            assert "url" in prov, f"{key} missing url"
            assert "method" in prov, f"{key} missing method"
            assert prov["method"] in ("GET", "POST"), f"{key} invalid method"


class TestBuildDnsQuery:
    def test_a_record(self) -> None:
        wire = _build_dns_query("example.com", "A")
        assert isinstance(wire, bytes)
        assert len(wire) > 12

    def test_aaaa_record(self) -> None:
        wire = _build_dns_query("example.com", "AAAA")
        assert isinstance(wire, bytes)

    def test_mx_record(self) -> None:
        wire = _build_dns_query("example.com", "MX")
        assert isinstance(wire, bytes)


class TestParseDnsResponse:
    def test_empty_data(self) -> None:
        records = _parse_dns_response(b"")
        assert records == []

    def test_invalid_data(self) -> None:
        records = _parse_dns_response(b"\x00\x01\x02\x03")
        assert records == []

    def test_garbage(self) -> None:
        records = _parse_dns_response(b"not dns data at all")
        assert records == []


class TestCompareRecords:
    def test_identical_records(self) -> None:
        r1 = [DohRecord("a.com", "A", 300, "1.2.3.4")]
        r2 = [DohRecord("a.com", "A", 300, "1.2.3.4")]
        filtering, incons = _compare_records(r1, r2)
        assert filtering is False
        assert incons == []

    def test_filtering_detected(self) -> None:
        r1 = [DohRecord("a.com", "A", 300, "1.2.3.4")]
        r2 = [DohRecord("a.com", "A", 300, "5.6.7.8")]
        filtering, incons = _compare_records(r1, r2)
        assert filtering is True
        assert len(incons) > 0

    def test_extra_only(self) -> None:
        r1 = [
            DohRecord("a.com", "A", 300, "1.2.3.4"),
            DohRecord("a.com", "A", 300, "5.6.7.8"),
        ]
        r2 = [DohRecord("a.com", "A", 300, "1.2.3.4")]
        filtering, incons = _compare_records(r1, r2)
        assert filtering is True
        assert len(incons) == 1
        assert incons[0].startswith("extra_in_doh")

    def test_missing_only(self) -> None:
        r1 = [DohRecord("a.com", "A", 300, "1.2.3.4")]
        r2 = [
            DohRecord("a.com", "A", 300, "1.2.3.4"),
            DohRecord("a.com", "A", 300, "5.6.7.8"),
        ]
        filtering, incons = _compare_records(r1, r2)
        assert filtering is True
        assert len(incons) == 1
        assert incons[0].startswith("missing_in_doh")

    def test_empty_records(self) -> None:
        filtering, _incons = _compare_records([], [])
        assert filtering is False


class TestPrintResults:
    def test_resolved(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DohScanResult(
            domain="example.com",
            query_type="A",
            providers=[],
            traditional_records=[DohRecord("example.com", "A", 300, "1.2.3.4")],
            traditional_latency_ms=10.0,
            filtering_detected=False,
            inconsistencies=[],
            doh_supported=True,
            overall_status="resolved",
            error="",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "DNS-over-HTTPS" in output
        assert "example.com" in output

    def test_filtering(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DohScanResult(
            domain="example.com",
            query_type="A",
            providers=[],
            traditional_records=[],
            traditional_latency_ms=10.0,
            filtering_detected=True,
            inconsistencies=["missing_in_doh: 1.2.3.4"],
            doh_supported=True,
            overall_status="filtering_detected",
            error="",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "FILTERING DETECTADO" in output

    def test_no_support(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DohScanResult(
            domain="example.com",
            query_type="A",
            providers=[],
            traditional_records=[DohRecord("example.com", "A", 300, "1.2.3.4")],
            traditional_latency_ms=10.0,
            filtering_detected=False,
            inconsistencies=[],
            doh_supported=False,
            overall_status="no_doh_support",
            error="",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "nao suportado" in output


class TestCLI:
    def test_build_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_build_parser_with_type(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "-T", "AAAA"])
        assert args.type == "AAAA"

    def test_build_parser_with_providers(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "-p", "google", "cloudflare"])
        assert args.providers == ["google", "cloudflare"]

    def test_build_parser_with_output(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "-o", "results.json"])
        assert args.output == "results.json"

    def test_build_parser_with_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--timeout", "10"])
        assert args.timeout == 10.0


class TestFreezing:
    def test_record_slots(self) -> None:
        assert hasattr(DohRecord, "__slots__")

    def test_provider_result_slots(self) -> None:
        assert hasattr(DohProviderResult, "__slots__")

    def test_scan_result_slots(self) -> None:
        assert hasattr(DohScanResult, "__slots__")


def _make_doh_result(**overrides: object) -> DohScanResult:
    defaults = {
        "domain": "example.com",
        "query_type": "A",
        "providers": [],
        "traditional_records": [],
        "traditional_latency_ms": 10.0,
        "filtering_detected": False,
        "inconsistencies": [],
        "doh_supported": True,
        "overall_status": "resolved",
        "error": "",
    }
    defaults.update(overrides)
    return DohScanResult(**defaults)


class TestParseDnsResponseValid:
    def test_valid_wire_response(self) -> None:
        query = dns.message.make_query("example.com", "A")
        response = dns.message.make_response(query)
        response.answer.append(
            dns.rrset.from_text("example.com.", 300, "IN", "A", "1.2.3.4")
        )
        records = _parse_dns_response(response.to_wire())
        assert len(records) == 1
        assert records[0].rdata == "1.2.3.4"
        assert records[0].rdtype == "A"
        assert records[0].ttl == 300


class TestTraditionalResolve:
    @patch("mytools.dns.dohscan.dns.resolver.Resolver")
    def test_success(self, mock_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver
        answer = MagicMock()
        answer.qname = dns.name.from_text("example.com.")
        answer.rrset = MagicMock()
        answer.rrset.ttl = 300
        rdata = MagicMock()
        type(rdata).__str__ = MagicMock(return_value="1.2.3.4")
        answer.__iter__ = MagicMock(return_value=iter([rdata]))
        mock_resolver.resolve.return_value = answer

        records, _elapsed, error = _traditional_resolve("example.com", "A", 5.0)
        assert len(records) == 1
        assert records[0].rdata == "1.2.3.4"
        assert error == ""

    @patch("mytools.dns.dohscan.dns.resolver.Resolver")
    def test_no_answer(self, mock_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
        _records, _elapsed, error = _traditional_resolve("example.com", "A", 5.0)
        assert error == "no_answer"

    @patch("mytools.dns.dohscan.dns.resolver.Resolver")
    def test_nxdomain(self, mock_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        _records, _elapsed, error = _traditional_resolve("example.com", "A", 5.0)
        assert error == "nxdomain"

    @patch("mytools.dns.dohscan.dns.resolver.Resolver")
    def test_no_nameservers(self, mock_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoNameservers()
        _records, _elapsed, error = _traditional_resolve("example.com", "A", 5.0)
        assert error == "no_nameservers"

    @patch("mytools.dns.dohscan.dns.resolver.Resolver")
    def test_timeout(self, mock_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.Timeout()
        _records, _elapsed, error = _traditional_resolve("example.com", "A", 5.0)
        assert error == "timeout"

    @patch("mytools.dns.dohscan.dns.resolver.Resolver")
    def test_generic_dns_exception(self, mock_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.DNSException("boom")
        _records, _elapsed, error = _traditional_resolve("example.com", "A", 5.0)
        assert "boom" in error


class TestDohQueryPost:
    @respx.mock
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        respx.post("https://dns.google/dns-query").mock(
            return_value=httpx.Response(
                200,
                content=b"\x00\x01",
                headers={"content-type": "application/dns-message"},
            )
        )
        async with httpx.AsyncClient() as client:
            data, status, error = await _doh_query_post(
                client, "https://dns.google/dns-query", b"\x00\x01"
            )
        assert data == b"\x00\x01"
        assert status == 200
        assert error == ""

    @respx.mock
    @pytest.mark.asyncio
    async def test_unexpected_content_type(self) -> None:
        respx.post("https://dns.google/dns-query").mock(
            return_value=httpx.Response(
                200, content=b"", headers={"content-type": "text/html"}
            )
        )
        async with httpx.AsyncClient() as client:
            data, status, error = await _doh_query_post(
                client, "https://dns.google/dns-query", b"\x00\x01"
            )
        assert data == b""
        assert status == 200
        assert error.startswith("unexpected_content_type")

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        respx.post("https://dns.google/dns-query").mock(
            side_effect=httpx.TimeoutException("slow")
        )
        async with httpx.AsyncClient() as client:
            data, status, error = await _doh_query_post(
                client, "https://dns.google/dns-query", b"\x00\x01"
            )
        assert data == b""
        assert status == 0
        assert error == "timeout"

    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_error(self) -> None:
        respx.post("https://dns.google/dns-query").mock(
            side_effect=httpx.ConnectError("conn")
        )
        async with httpx.AsyncClient() as client:
            _data, status, error = await _doh_query_post(
                client, "https://dns.google/dns-query", b"\x00\x01"
            )
        assert status == 0
        assert error.startswith("connect_error")

    @respx.mock
    @pytest.mark.asyncio
    async def test_generic_exception(self) -> None:
        respx.post("https://dns.google/dns-query").mock(
            side_effect=RuntimeError("boom")
        )
        async with httpx.AsyncClient() as client:
            _data, status, error = await _doh_query_post(
                client, "https://dns.google/dns-query", b"\x00\x01"
            )
        assert status == 0
        assert "boom" in error


class TestDohQueryGet:
    @respx.mock
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        respx.get(url__startswith="https://dns.google/dns-query").mock(
            return_value=httpx.Response(
                200,
                content=b"\x00\x01",
                headers={"content-type": "application/dns-message"},
            )
        )
        async with httpx.AsyncClient() as client:
            data, status, error = await _doh_query_get(
                client, "https://dns.google/dns-query", b"\x00\x01"
            )
        assert data == b"\x00\x01"
        assert status == 200
        assert error == ""

    @respx.mock
    @pytest.mark.asyncio
    async def test_unexpected_content_type(self) -> None:
        respx.get(url__startswith="https://dns.google/dns-query").mock(
            return_value=httpx.Response(
                200, content=b"", headers={"content-type": "text/html"}
            )
        )
        async with httpx.AsyncClient() as client:
            _data, _status, error = await _doh_query_get(
                client, "https://dns.google/dns-query", b"\x00\x01"
            )
        assert error.startswith("unexpected_content_type")

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        respx.get(url__startswith="https://dns.google/dns-query").mock(
            side_effect=httpx.TimeoutException("slow")
        )
        async with httpx.AsyncClient() as client:
            _data, status, error = await _doh_query_get(
                client, "https://dns.google/dns-query", b"\x00\x01"
            )
        assert status == 0
        assert error == "timeout"

    @respx.mock
    @pytest.mark.asyncio
    async def test_connect_error(self) -> None:
        respx.get(url__startswith="https://dns.google/dns-query").mock(
            side_effect=httpx.ConnectError("conn")
        )
        async with httpx.AsyncClient() as client:
            _data, _status, error = await _doh_query_get(
                client, "https://dns.google/dns-query", b"\x00\x01"
            )
        assert error.startswith("connect_error")

    @respx.mock
    @pytest.mark.asyncio
    async def test_generic_exception(self) -> None:
        respx.get(url__startswith="https://dns.google/dns-query").mock(
            side_effect=RuntimeError("boom")
        )
        async with httpx.AsyncClient() as client:
            _data, _status, error = await _doh_query_get(
                client, "https://dns.google/dns-query", b"\x00\x01"
            )
        assert "boom" in error


class TestTestProvider:
    @patch("mytools.dns.dohscan._parse_dns_response", return_value=[])
    @patch(
        "mytools.dns.dohscan._doh_query_get",
        new_callable=AsyncMock,
        return_value=(b"\x00\x01", 200, ""),
    )
    @pytest.mark.asyncio
    async def test_get_method(self, mock_get: AsyncMock, mock_parse: MagicMock) -> None:
        provider = {
            "name": "Google DNS",
            "url": "https://dns.google/dns-query",
            "method": "GET",
        }
        result = await _test_provider(
            MagicMock(), "google", provider, b"\x00\x01", "example.com", "A", 5.0
        )
        assert result.query_method == "GET"
        assert result.status_code == 200
        assert result.error == ""
        mock_get.assert_awaited_once()
        mock_parse.assert_called_once_with(b"\x00\x01")

    @patch("mytools.dns.dohscan._parse_dns_response", return_value=[])
    @patch(
        "mytools.dns.dohscan._doh_query_post",
        new_callable=AsyncMock,
        return_value=(b"", 200, ""),
    )
    @pytest.mark.asyncio
    async def test_post_method(
        self, mock_post: AsyncMock, mock_parse: MagicMock
    ) -> None:
        provider = {
            "name": "Custom",
            "url": "https://example.com/dns-query",
            "method": "POST",
        }
        result = await _test_provider(
            MagicMock(), "custom", provider, b"\x00\x01", "example.com", "A", 5.0
        )
        assert result.query_method == "POST"
        assert result.records == []
        mock_post.assert_awaited_once()


class TestScanDoh:
    @patch("mytools.dns.dohscan._test_provider")
    @patch("mytools.dns.dohscan._traditional_resolve")
    @pytest.mark.asyncio
    async def test_resolved(
        self, mock_trad: MagicMock, mock_provider: MagicMock
    ) -> None:
        trad_records = [DohRecord("example.com", "A", 300, "1.2.3.4")]
        mock_trad.return_value = (trad_records, 10.0, "")
        mock_provider.return_value = DohProviderResult(
            provider="google",
            provider_name="Google DNS",
            url="https://dns.google/dns-query",
            records=trad_records,
            latency_ms=5.0,
            status_code=200,
            error="",
            query_method="GET",
        )
        result = await scan_doh("example.com", providers=["google"])
        assert result.overall_status == "resolved"
        assert result.doh_supported is True
        assert result.filtering_detected is False

    @patch("mytools.dns.dohscan._test_provider")
    @patch("mytools.dns.dohscan._traditional_resolve")
    @pytest.mark.asyncio
    async def test_filtering_detected(
        self, mock_trad: MagicMock, mock_provider: MagicMock
    ) -> None:
        trad_records = [DohRecord("example.com", "A", 300, "1.2.3.4")]
        doh_records = [DohRecord("example.com", "A", 300, "5.6.7.8")]
        mock_trad.return_value = (trad_records, 10.0, "")
        mock_provider.return_value = DohProviderResult(
            provider="google",
            provider_name="Google DNS",
            url="https://dns.google/dns-query",
            records=doh_records,
            latency_ms=5.0,
            status_code=200,
            error="",
            query_method="GET",
        )
        result = await scan_doh("example.com", providers=["google"])
        assert result.overall_status == "filtering_detected"
        assert result.filtering_detected is True
        assert len(result.inconsistencies) > 0

    @patch("mytools.dns.dohscan._test_provider")
    @patch("mytools.dns.dohscan._traditional_resolve")
    @pytest.mark.asyncio
    async def test_nxdomain(
        self, mock_trad: MagicMock, mock_provider: MagicMock
    ) -> None:
        mock_trad.return_value = ([], 10.0, "nxdomain")
        mock_provider.return_value = DohProviderResult(
            provider="google",
            provider_name="Google DNS",
            url="https://dns.google/dns-query",
            records=[],
            latency_ms=5.0,
            status_code=0,
            error="nxdomain",
            query_method="GET",
        )
        result = await scan_doh("example.com", providers=["google"])
        assert result.overall_status == "nxdomain"

    @patch("mytools.dns.dohscan._test_provider")
    @patch("mytools.dns.dohscan._traditional_resolve")
    @pytest.mark.asyncio
    async def test_no_doh_support(
        self, mock_trad: MagicMock, mock_provider: MagicMock
    ) -> None:
        trad_records = [DohRecord("example.com", "A", 300, "1.2.3.4")]
        mock_trad.return_value = (trad_records, 10.0, "")
        mock_provider.return_value = DohProviderResult(
            provider="google",
            provider_name="Google DNS",
            url="https://dns.google/dns-query",
            records=[],
            latency_ms=5.0,
            status_code=0,
            error="timeout",
            query_method="GET",
        )
        result = await scan_doh("example.com", providers=["google"])
        assert result.overall_status == "no_doh_support"
        assert result.doh_supported is False

    @patch("mytools.dns.dohscan._test_provider")
    @patch("mytools.dns.dohscan._traditional_resolve")
    @pytest.mark.asyncio
    async def test_error(self, mock_trad: MagicMock, mock_provider: MagicMock) -> None:
        mock_trad.return_value = ([], 10.0, "")
        mock_provider.return_value = DohProviderResult(
            provider="google",
            provider_name="Google DNS",
            url="https://dns.google/dns-query",
            records=[],
            latency_ms=5.0,
            status_code=0,
            error="timeout",
            query_method="GET",
        )
        result = await scan_doh("example.com", providers=["google"])
        assert result.overall_status == "error"

    @patch("mytools.dns.dohscan._test_provider")
    @patch("mytools.dns.dohscan._traditional_resolve")
    @pytest.mark.asyncio
    async def test_unknown_provider_skipped(
        self, mock_trad: MagicMock, mock_provider: MagicMock
    ) -> None:
        mock_trad.return_value = ([], 10.0, "")
        result = await scan_doh("example.com", providers=["unknown"])
        assert result.overall_status == "error"
        assert result.providers == []
        mock_provider.assert_not_awaited()

    @patch("mytools.dns.dohscan._test_provider")
    @patch("mytools.dns.dohscan._traditional_resolve")
    @pytest.mark.asyncio
    async def test_filtering_when_traditional_blocked(
        self, mock_trad: MagicMock, mock_provider: MagicMock
    ) -> None:
        mock_trad.return_value = ([], 10.0, "timeout")
        mock_provider.return_value = DohProviderResult(
            provider="google",
            provider_name="Google DNS",
            url="https://dns.google/dns-query",
            records=[DohRecord("example.com", "A", 300, "1.2.3.4")],
            latency_ms=5.0,
            status_code=200,
            error="",
            query_method="GET",
        )
        result = await scan_doh("example.com", providers=["google"])
        assert result.overall_status == "filtering_detected"
        assert result.filtering_detected is True
        assert "traditional_dns_blocked_but_doh_resolves" in result.inconsistencies


class TestPrintResultsAdditional:
    def test_trad_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = _make_doh_result(
            traditional_records=[],
            doh_supported=False,
            overall_status="error",
            error="timeout",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "timeout" in out

    def test_provider_display(self, capsys: pytest.CaptureFixture[str]) -> None:
        pr_ok = DohProviderResult(
            provider="google",
            provider_name="Google DNS",
            url="https://dns.google/dns-query",
            records=[DohRecord("example.com", "A", 300, "1.2.3.4")],
            latency_ms=50.0,
            status_code=200,
            error="",
            query_method="GET",
        )
        pr_err = DohProviderResult(
            provider="quad9",
            provider_name="Quad9 DNS",
            url="https://dns.quad9.net/dns-query",
            records=[],
            latency_ms=0.0,
            status_code=0,
            error="connect_error",
            query_method="GET",
        )
        result = _make_doh_result(
            providers=[pr_ok, pr_err],
            traditional_records=[DohRecord("example.com", "A", 300, "1.2.3.4")],
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Google DNS" in out
        assert "Quad9 DNS" in out
        assert "registros" in out


class TestRunScan:
    @patch("mytools.dns.dohscan.scan_doh", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_builds_args(self, mock_scan: AsyncMock) -> None:
        args = argparse.Namespace(
            domain="example.com", type="A", providers=["google"], timeout=7.0
        )
        result = _make_doh_result()
        mock_scan.return_value = result
        out = await _run_scan(args)
        assert out == result
        mock_scan.assert_awaited_once_with("example.com", "A", ["google"], 7.0, True)


class TestBanner:
    def test_banner_calls_create_banner(self) -> None:
        with patch("mytools.dns.dohscan.create_banner") as mock_cb:
            mock_banner = MagicMock()
            mock_cb.return_value = mock_banner
            banner()
            mock_cb.assert_called_once()
            mock_banner.assert_called_once()


class TestMain:
    def test_main_calls_run_main_loop(self) -> None:
        with patch("mytools.dns.dohscan.run_main_loop", return_value=0) as mock_loop:
            assert main() == 0
            mock_loop.assert_called_once()


def _make_safe_run_args(**overrides: object) -> argparse.Namespace:
    defaults = {
        "domain": "example.com",
        "output": None,
        "quiet": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestSafeRun:
    @patch("mytools.dns.dohscan.print_results")
    @patch("mytools.dns.dohscan.init_scanner", return_value=False)
    @patch("mytools.dns.dohscan._run_scan", new_callable=AsyncMock)
    def test_resolved_returns_zero(
        self, mock_scan: AsyncMock, mock_init: MagicMock, mock_print: MagicMock
    ) -> None:
        mock_scan.return_value = _make_doh_result(overall_status="resolved")
        assert _safe_run(_make_safe_run_args()) == 0
        mock_print.assert_called_once()

    @patch("mytools.dns.dohscan.print_results")
    @patch("mytools.dns.dohscan.init_scanner", return_value=False)
    @patch("mytools.dns.dohscan._run_scan", new_callable=AsyncMock)
    def test_error_returns_zero(
        self, mock_scan: AsyncMock, mock_init: MagicMock, mock_print: MagicMock
    ) -> None:
        mock_scan.return_value = _make_doh_result(
            overall_status="error", doh_supported=False
        )
        assert _safe_run(_make_safe_run_args()) == 0

    @patch("mytools.dns.dohscan.write_output")
    @patch("mytools.dns.dohscan.print_results")
    @patch("mytools.dns.dohscan.init_scanner", return_value=False)
    @patch("mytools.dns.dohscan._run_scan", new_callable=AsyncMock)
    def test_with_output(
        self,
        mock_scan: AsyncMock,
        mock_init: MagicMock,
        mock_print: MagicMock,
        mock_write: MagicMock,
    ) -> None:
        mock_scan.return_value = _make_doh_result(overall_status="resolved")
        assert _safe_run(_make_safe_run_args(output="out.json")) == 0
        mock_write.assert_called_once()

    @patch("mytools.dns.dohscan.print_json")
    @patch("mytools.dns.dohscan.print_results")
    @patch("mytools.dns.dohscan.init_scanner", return_value=False)
    @patch("mytools.dns.dohscan._run_scan", new_callable=AsyncMock)
    def test_json_output(
        self,
        mock_scan: AsyncMock,
        mock_init: MagicMock,
        mock_print: MagicMock,
        mock_json: MagicMock,
    ) -> None:
        mock_scan.return_value = _make_doh_result(overall_status="resolved")
        assert _safe_run(_make_safe_run_args(json_output=True)) == 0
        mock_json.assert_called_once()

    @patch("mytools.dns.dohscan.ensure_output_dir")
    @patch("mytools.dns.dohscan.write_output")
    @patch("mytools.dns.dohscan.print_results")
    @patch("mytools.dns.dohscan.init_scanner", return_value=False)
    @patch("mytools.dns.dohscan._run_scan", new_callable=AsyncMock)
    def test_output_dir(
        self,
        mock_scan: AsyncMock,
        mock_init: MagicMock,
        mock_print: MagicMock,
        mock_write: MagicMock,
        mock_ensure: MagicMock,
    ) -> None:
        mock_scan.return_value = _make_doh_result(overall_status="resolved")
        assert _safe_run(_make_safe_run_args(output_dir="reports")) == 0
        mock_ensure.assert_called_once_with("reports")
        mock_write.assert_called_once()

    @patch("mytools.dns.dohscan.print_results")
    @patch("mytools.dns.dohscan.init_scanner", return_value=True)
    @patch("mytools.dns.dohscan._run_scan", new_callable=AsyncMock)
    def test_quiet_skips_print(
        self, mock_scan: AsyncMock, mock_init: MagicMock, mock_print: MagicMock
    ) -> None:
        mock_scan.return_value = _make_doh_result(overall_status="resolved")
        assert _safe_run(_make_safe_run_args(quiet=True)) == 0
        mock_print.assert_not_called()


class TestMainGuard:
    """Testes do guard `if __name__ == \"__main__\"`."""

    def test_guard_runs(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-doh", "example.com"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.dns.dohscan", run_name="__main__")
        assert exc_info.value.code == 0
