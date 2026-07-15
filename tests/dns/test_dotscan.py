#!/usr/bin/env python3
"""Tests for dotscan.py."""

from __future__ import annotations

import pytest

from mytools.dns.dotscan import (
    _DOT_RESOLVERS,
    _RDTYPE_MAP,
    DotRecord,
    DotResolverResult,
    DotScanResult,
    DotTlsInfo,
    _build_dns_query,
    _compare_records,
    _parse_dns_response,
    build_parser,
    print_results,
)


class TestDotRecord:
    def test_creation(self) -> None:
        r = DotRecord(name="example.com", rdtype="A", ttl=300, rdata="1.2.3.4")
        assert r.name == "example.com"
        assert r.rdtype == "A"
        assert r.ttl == 300
        assert r.rdata == "1.2.3.4"

    def test_frozen(self) -> None:
        r = DotRecord(name="example.com", rdtype="A", ttl=300, rdata="1.2.3.4")
        with pytest.raises(AttributeError):
            r.name = "changed"  # type: ignore[misc]


class TestDotTlsInfo:
    def test_creation(self) -> None:
        t = DotTlsInfo(
            issuer="CN=Google Trust Services",
            subject="CN=dns.google",
            not_before="2024-01-01",
            not_after="2025-01-01",
            san=["dns.google"],
            serial="12345",
            version="TLSv1.3",
        )
        assert t.issuer == "CN=Google Trust Services"
        assert t.version == "TLSv1.3"
        assert len(t.san) == 1

    def test_frozen(self) -> None:
        t = DotTlsInfo(
            issuer="", subject="", not_before="", not_after="",
            san=[], serial="", version="",
        )
        with pytest.raises(AttributeError):
            t.issuer = "changed"  # type: ignore[misc]


class TestDotResolverResult:
    def test_creation(self) -> None:
        r = DotResolverResult(
            resolver="google", resolver_name="Google DNS",
            host="dns.google", port=853, records=[],
            tls_info=DotTlsInfo(issuer="", subject="", not_before="",
                                not_after="", san=[], serial="", version=""),
            latency_ms=50.0, error="",
        )
        assert r.resolver == "google"
        assert r.port == 853

    def test_frozen(self) -> None:
        r = DotResolverResult(
            resolver="google", resolver_name="Google DNS",
            host="dns.google", port=853, records=[],
            tls_info=DotTlsInfo(issuer="", subject="", not_before="",
                                not_after="", san=[], serial="", version=""),
            latency_ms=50.0, error="",
        )
        with pytest.raises(AttributeError):
            r.resolver = "changed"  # type: ignore[misc]


class TestDotScanResult:
    def test_creation(self) -> None:
        r = DotScanResult(
            domain="example.com", query_type="A", resolvers=[],
            traditional_records=[], traditional_latency_ms=10.0,
            filtering_detected=False, inconsistencies=[],
            dot_supported=True, overall_status="resolved", error="",
        )
        assert r.domain == "example.com"
        assert r.overall_status == "resolved"

    def test_frozen(self) -> None:
        r = DotScanResult(
            domain="example.com", query_type="A", resolvers=[],
            traditional_records=[], traditional_latency_ms=10.0,
            filtering_detected=False, inconsistencies=[],
            dot_supported=True, overall_status="resolved", error="",
        )
        with pytest.raises(AttributeError):
            r.domain = "changed"  # type: ignore[misc]


class TestDotResolvers:
    def test_all_resolvers_present(self) -> None:
        assert set(_DOT_RESOLVERS.keys()) == {"google", "cloudflare", "quad9"}

    def test_resolver_has_required_fields(self) -> None:
        for key, prov in _DOT_RESOLVERS.items():
            assert "name" in prov, f"{key} missing name"
            assert "host" in prov, f"{key} missing host"
            assert "port" in prov, f"{key} missing port"
            assert prov["port"] == 853, f"{key} wrong port"


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
        r1 = [DotRecord("a.com", "A", 300, "1.2.3.4")]
        r2 = [DotRecord("a.com", "A", 300, "1.2.3.4")]
        filtering, incons = _compare_records(r1, r2)
        assert filtering is False
        assert incons == []

    def test_filtering_detected(self) -> None:
        r1 = [DotRecord("a.com", "A", 300, "1.2.3.4")]
        r2 = [DotRecord("a.com", "A", 300, "5.6.7.8")]
        filtering, incons = _compare_records(r1, r2)
        assert filtering is True
        assert len(incons) > 0

    def test_empty_records(self) -> None:
        filtering, _incons = _compare_records([], [])
        assert filtering is False


class TestPrintResults:
    def test_resolved(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DotScanResult(
            domain="example.com", query_type="A", resolvers=[],
            traditional_records=[DotRecord("example.com", "A", 300, "1.2.3.4")],
            traditional_latency_ms=10.0, filtering_detected=False,
            inconsistencies=[], dot_supported=True,
            overall_status="resolved", error="",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "DNS-over-TLS" in output
        assert "example.com" in output

    def test_filtering(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DotScanResult(
            domain="example.com", query_type="A", resolvers=[],
            traditional_records=[], traditional_latency_ms=10.0,
            filtering_detected=True, inconsistencies=["missing_in_dot: 1.2.3.4"],
            dot_supported=True, overall_status="filtering_detected", error="",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "FILTERING DETECTADO" in output

    def test_no_support(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DotScanResult(
            domain="example.com", query_type="A", resolvers=[],
            traditional_records=[DotRecord("example.com", "A", 300, "1.2.3.4")],
            traditional_latency_ms=10.0, filtering_detected=False,
            inconsistencies=[], dot_supported=False,
            overall_status="no_dot_support", error="",
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

    def test_build_parser_with_resolvers(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "-r", "google", "cloudflare"])
        assert args.resolvers == ["google", "cloudflare"]

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
        assert hasattr(DotRecord, "__slots__")

    def test_tls_info_slots(self) -> None:
        assert hasattr(DotTlsInfo, "__slots__")

    def test_resolver_result_slots(self) -> None:
        assert hasattr(DotResolverResult, "__slots__")

    def test_scan_result_slots(self) -> None:
        assert hasattr(DotScanResult, "__slots__")
