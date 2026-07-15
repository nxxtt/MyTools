#!/usr/bin/env python3
"""Tests for dohscan.py."""

from __future__ import annotations

import pytest

from mytools.dns.dohscan import (
    _DOH_PROVIDERS,
    _RDTYPE_MAP,
    DohProviderResult,
    DohRecord,
    DohScanResult,
    _build_dns_query,
    _compare_records,
    _parse_dns_response,
    build_parser,
    print_results,
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
            provider="google", provider_name="Google DNS",
            url="https://dns.google/dns-query", records=[],
            latency_ms=50.0, status_code=200, error="",
            query_method="GET",
        )
        assert r.provider == "google"
        assert r.status_code == 200

    def test_frozen(self) -> None:
        r = DohProviderResult(
            provider="google", provider_name="Google DNS",
            url="https://dns.google/dns-query", records=[],
            latency_ms=50.0, status_code=200, error="",
            query_method="GET",
        )
        with pytest.raises(AttributeError):
            r.provider = "changed"  # type: ignore[misc]


class TestDohScanResult:
    def test_creation(self) -> None:
        r = DohScanResult(
            domain="example.com", query_type="A", providers=[],
            traditional_records=[], traditional_latency_ms=10.0,
            filtering_detected=False, inconsistencies=[],
            doh_supported=True, overall_status="resolved", error="",
        )
        assert r.domain == "example.com"
        assert r.overall_status == "resolved"

    def test_frozen(self) -> None:
        r = DohScanResult(
            domain="example.com", query_type="A", providers=[],
            traditional_records=[], traditional_latency_ms=10.0,
            filtering_detected=False, inconsistencies=[],
            doh_supported=True, overall_status="resolved", error="",
        )
        with pytest.raises(AttributeError):
            r.domain = "changed"  # type: ignore[misc]


class TestDohProviders:
    def test_all_providers_present(self) -> None:
        assert set(_DOH_PROVIDERS.keys()) == {"google", "cloudflare", "quad9", "adguard"}

    def test_provider_has_required_fields(self) -> None:
        for key, prov in _DOH_PROVIDERS.items():
            assert "name" in prov, f"{key} missing name"
            assert "url" in prov, f"{key} missing url"
            assert "method" in prov, f"{key} missing method"
            assert prov["method"] in ("GET", "POST"), f"{key} invalid method"


class TestRdtypeMap:
    def test_common_types(self) -> None:
        assert "A" in _RDTYPE_MAP
        assert "AAAA" in _RDTYPE_MAP
        assert "MX" in _RDTYPE_MAP
        assert "TXT" in _RDTYPE_MAP

    def test_all_values_are_ints(self) -> None:
        for k, v in _RDTYPE_MAP.items():
            assert isinstance(v, int), f"{k} has non-int value"


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

    def test_empty_records(self) -> None:
        filtering, _incons = _compare_records([], [])
        assert filtering is False


class TestPrintResults:
    def test_resolved(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DohScanResult(
            domain="example.com", query_type="A", providers=[],
            traditional_records=[DohRecord("example.com", "A", 300, "1.2.3.4")],
            traditional_latency_ms=10.0, filtering_detected=False,
            inconsistencies=[], doh_supported=True,
            overall_status="resolved", error="",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "DNS-over-HTTPS" in output
        assert "example.com" in output

    def test_filtering(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DohScanResult(
            domain="example.com", query_type="A", providers=[],
            traditional_records=[], traditional_latency_ms=10.0,
            filtering_detected=True, inconsistencies=["missing_in_doh: 1.2.3.4"],
            doh_supported=True, overall_status="filtering_detected", error="",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "FILTERING DETECTADO" in output

    def test_no_support(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DohScanResult(
            domain="example.com", query_type="A", providers=[],
            traditional_records=[DohRecord("example.com", "A", 300, "1.2.3.4")],
            traditional_latency_ms=10.0, filtering_detected=False,
            inconsistencies=[], doh_supported=False,
            overall_status="no_doh_support", error="",
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
