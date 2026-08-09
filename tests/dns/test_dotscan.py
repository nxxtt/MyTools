#!/usr/bin/env python3
"""Tests for dotscan.py."""

from __future__ import annotations

import argparse
import ssl
import struct
from unittest.mock import AsyncMock, MagicMock, patch

import dns.exception
import dns.message
import dns.name
import dns.resolver
import dns.rrset
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
    _dot_query,
    _extract_tls_info,
    _parse_dns_response,
    _run_scan,
    _safe_run,
    _traditional_resolve,
    banner,
    build_parser,
    main,
    print_results,
    scan_dot,
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
            issuer="",
            subject="",
            not_before="",
            not_after="",
            san=[],
            serial="",
            version="",
        )
        with pytest.raises(AttributeError):
            t.issuer = "changed"  # type: ignore[misc]


class TestDotResolverResult:
    def test_creation(self) -> None:
        r = DotResolverResult(
            resolver="google",
            resolver_name="Google DNS",
            host="dns.google",
            port=853,
            records=[],
            tls_info=DotTlsInfo(
                issuer="",
                subject="",
                not_before="",
                not_after="",
                san=[],
                serial="",
                version="",
            ),
            latency_ms=50.0,
            error="",
        )
        assert r.resolver == "google"
        assert r.port == 853

    def test_frozen(self) -> None:
        r = DotResolverResult(
            resolver="google",
            resolver_name="Google DNS",
            host="dns.google",
            port=853,
            records=[],
            tls_info=DotTlsInfo(
                issuer="",
                subject="",
                not_before="",
                not_after="",
                san=[],
                serial="",
                version="",
            ),
            latency_ms=50.0,
            error="",
        )
        with pytest.raises(AttributeError):
            r.resolver = "changed"  # type: ignore[misc]


class TestDotScanResult:
    def test_creation(self) -> None:
        r = DotScanResult(
            domain="example.com",
            query_type="A",
            resolvers=[],
            traditional_records=[],
            traditional_latency_ms=10.0,
            filtering_detected=False,
            inconsistencies=[],
            dot_supported=True,
            overall_status="resolved",
            error="",
        )
        assert r.domain == "example.com"
        assert r.overall_status == "resolved"

    def test_frozen(self) -> None:
        r = DotScanResult(
            domain="example.com",
            query_type="A",
            resolvers=[],
            traditional_records=[],
            traditional_latency_ms=10.0,
            filtering_detected=False,
            inconsistencies=[],
            dot_supported=True,
            overall_status="resolved",
            error="",
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

    def test_extra_only(self) -> None:
        r1 = [
            DotRecord("a.com", "A", 300, "1.2.3.4"),
            DotRecord("a.com", "A", 300, "5.6.7.8"),
        ]
        r2 = [DotRecord("a.com", "A", 300, "1.2.3.4")]
        filtering, incons = _compare_records(r1, r2)
        assert filtering is True
        assert len(incons) == 1
        assert incons[0].startswith("extra_in_dot")

    def test_missing_only(self) -> None:
        r1 = [DotRecord("a.com", "A", 300, "1.2.3.4")]
        r2 = [
            DotRecord("a.com", "A", 300, "1.2.3.4"),
            DotRecord("a.com", "A", 300, "5.6.7.8"),
        ]
        filtering, incons = _compare_records(r1, r2)
        assert filtering is True
        assert len(incons) == 1
        assert incons[0].startswith("missing_in_dot")

    def test_empty_records(self) -> None:
        filtering, _incons = _compare_records([], [])
        assert filtering is False


class TestPrintResults:
    def test_resolved(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DotScanResult(
            domain="example.com",
            query_type="A",
            resolvers=[],
            traditional_records=[DotRecord("example.com", "A", 300, "1.2.3.4")],
            traditional_latency_ms=10.0,
            filtering_detected=False,
            inconsistencies=[],
            dot_supported=True,
            overall_status="resolved",
            error="",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "DNS-over-TLS" in output
        assert "example.com" in output

    def test_filtering(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DotScanResult(
            domain="example.com",
            query_type="A",
            resolvers=[],
            traditional_records=[],
            traditional_latency_ms=10.0,
            filtering_detected=True,
            inconsistencies=["missing_in_dot: 1.2.3.4"],
            dot_supported=True,
            overall_status="filtering_detected",
            error="",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "FILTERING DETECTADO" in output

    def test_no_support(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DotScanResult(
            domain="example.com",
            query_type="A",
            resolvers=[],
            traditional_records=[DotRecord("example.com", "A", 300, "1.2.3.4")],
            traditional_latency_ms=10.0,
            filtering_detected=False,
            inconsistencies=[],
            dot_supported=False,
            overall_status="no_dot_support",
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


class FakeSock:
    """Fake socket com suporte a context manager, sendall e recv."""

    def __init__(self, recv_data: bytes = b"", max_chunk: int | None = None) -> None:
        self._recv_data = recv_data
        self.max_chunk = max_chunk
        self.sent = b""
        self._peer_cert: object = None
        self._tls_version: str | None = None

    def __enter__(self) -> FakeSock:
        return self

    def __exit__(self, *args: object) -> bool:
        return False

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def recv(self, n: int) -> bytes:
        if self.max_chunk is not None:
            n = min(n, self.max_chunk)
        if not self._recv_data:
            return b""
        chunk = self._recv_data[:n]
        self._recv_data = self._recv_data[n:]
        return chunk

    def getpeercert(self) -> object:
        return self._peer_cert

    def version(self) -> str | None:
        return self._tls_version

    def close(self) -> None:
        pass

    def settimeout(self, _timeout: float) -> None:
        pass


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


class TestExtractTlsInfo:
    def test_no_cert(self) -> None:
        ssock = MagicMock()
        ssock.getpeercert.return_value = None
        info = _extract_tls_info(ssock)
        assert info.issuer == ""
        assert info.san == []
        assert info.version == ""

    def test_full_cert(self) -> None:
        ssock = MagicMock()
        ssock.getpeercert.return_value = {
            "issuer": ((("commonName", "Google Trust Services"),),),
            "subject": ((("commonName", "dns.google"),),),
            "subjectAltName": (("DNS", "dns.google"), ("DNS", "dns.google.com")),
            "notBefore": "Jan 1 00:00:00 2024 GMT",
            "notAfter": "Jan 1 00:00:00 2025 GMT",
            "serialNumber": "ABCDEF",
        }
        ssock.version.return_value = "TLSv1.3"
        info = _extract_tls_info(ssock)
        assert "commonName=Google Trust Services" in info.issuer
        assert "commonName=dns.google" in info.subject
        assert len(info.san) == 2
        assert info.serial == "ABCDEF"
        assert info.version == "TLSv1.3"

    def test_version_none(self) -> None:
        ssock = MagicMock()
        ssock.getpeercert.return_value = {
            "issuer": (),
            "subject": (),
            "subjectAltName": (),
        }
        ssock.version.return_value = None
        info = _extract_tls_info(ssock)
        assert info.version == ""


class TestTraditionalResolve:
    @patch("mytools.dns.dotscan.dns.resolver.Resolver")
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

    @patch("mytools.dns.dotscan.dns.resolver.Resolver")
    def test_no_answer(self, mock_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoAnswer()
        _records, _elapsed, error = _traditional_resolve("example.com", "A", 5.0)
        assert error == "no_answer"

    @patch("mytools.dns.dotscan.dns.resolver.Resolver")
    def test_nxdomain(self, mock_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NXDOMAIN()
        _records, _elapsed, error = _traditional_resolve("example.com", "A", 5.0)
        assert error == "nxdomain"

    @patch("mytools.dns.dotscan.dns.resolver.Resolver")
    def test_no_nameservers(self, mock_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.resolver.NoNameservers()
        _records, _elapsed, error = _traditional_resolve("example.com", "A", 5.0)
        assert error == "no_nameservers"

    @patch("mytools.dns.dotscan.dns.resolver.Resolver")
    def test_timeout(self, mock_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.Timeout()
        _records, _elapsed, error = _traditional_resolve("example.com", "A", 5.0)
        assert error == "timeout"

    @patch("mytools.dns.dotscan.dns.resolver.Resolver")
    def test_generic_dns_exception(self, mock_cls: MagicMock) -> None:
        mock_resolver = MagicMock()
        mock_cls.return_value = mock_resolver
        mock_resolver.resolve.side_effect = dns.exception.DNSException("boom")
        _records, _elapsed, error = _traditional_resolve("example.com", "A", 5.0)
        assert "boom" in error


class TestDotQuery:
    @patch("mytools.dns.dotscan.ssl.create_default_context")
    @patch("mytools.dns.dotscan.socket.create_connection")
    def test_success(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        payload = b"\x00\x01\x02\x03"
        wire = struct.pack("!H", len(payload)) + payload
        sock = FakeSock(wire)
        mock_conn.return_value = sock
        ctx = MagicMock()
        ssock = FakeSock(wire)
        ctx.wrap_socket.return_value = ssock
        mock_ctx.return_value = ctx
        ssock._peer_cert = None
        ssock._tls_version = "TLSv1.3"

        data, _tls_info, error = _dot_query("dns.google", 853, b"\x00\x01", 5.0)
        assert data == payload
        assert error == ""
        assert ssock.sent == struct.pack("!H", len(b"\x00\x01")) + b"\x00\x01"

    @patch("mytools.dns.dotscan.ssl.create_default_context")
    @patch("mytools.dns.dotscan.socket.create_connection")
    def test_chunked_recv(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        payload = b"\x00\x01\x02\x03\x04\x05"
        wire = struct.pack("!H", len(payload)) + payload
        mock_conn.return_value = FakeSock(wire, max_chunk=1)
        ctx = MagicMock()
        ssock = FakeSock(wire, max_chunk=1)
        ctx.wrap_socket.return_value = ssock
        mock_ctx.return_value = ctx
        ssock._peer_cert = None
        ssock._tls_version = "TLSv1.3"

        data, _tls_info, error = _dot_query("dns.google", 853, b"\x00\x01", 5.0)
        assert data == payload
        assert error == ""

    @patch("mytools.dns.dotscan.ssl.create_default_context")
    @patch("mytools.dns.dotscan.socket.create_connection")
    def test_incomplete_payload(
        self, mock_conn: MagicMock, mock_ctx: MagicMock
    ) -> None:
        wire = struct.pack("!H", 2)
        mock_conn.return_value = FakeSock(wire)
        ctx = MagicMock()
        ssock = FakeSock(wire)
        ctx.wrap_socket.return_value = ssock
        mock_ctx.return_value = ctx
        ssock._peer_cert = None
        ssock._tls_version = None

        data, _tls_info, error = _dot_query("dns.google", 853, b"\x00\x01", 5.0)
        assert data == b""
        assert error == ""

    @patch("mytools.dns.dotscan.ssl.create_default_context")
    @patch("mytools.dns.dotscan.socket.create_connection")
    def test_incomplete_length(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        mock_conn.return_value = FakeSock(b"")
        ctx = MagicMock()
        ssock = FakeSock(b"")
        ctx.wrap_socket.return_value = ssock
        mock_ctx.return_value = ctx
        ssock._peer_cert = None
        ssock._tls_version = None

        data, _tls_info, error = _dot_query("dns.google", 853, b"\x00\x01", 5.0)
        assert data == b""
        assert error == "incomplete_length"

    @patch("mytools.dns.dotscan.ssl.create_default_context")
    @patch("mytools.dns.dotscan.socket.create_connection")
    def test_cert_verification_error(
        self, mock_conn: MagicMock, mock_ctx: MagicMock
    ) -> None:
        ctx = MagicMock()
        ctx.wrap_socket.side_effect = ssl.SSLCertVerificationError("bad cert")
        mock_ctx.return_value = ctx
        data, _tls_info, error = _dot_query("dns.google", 853, b"\x00\x01", 5.0)
        assert data == b""
        assert error.startswith("cert_error")

    @patch("mytools.dns.dotscan.ssl.create_default_context")
    @patch("mytools.dns.dotscan.socket.create_connection")
    def test_ssl_error(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        ctx = MagicMock()
        ctx.wrap_socket.side_effect = ssl.SSLError("tls failed")
        mock_ctx.return_value = ctx
        data, _tls_info, error = _dot_query("dns.google", 853, b"\x00\x01", 5.0)
        assert data == b""
        assert error.startswith("tls_error")

    @patch("mytools.dns.dotscan.ssl.create_default_context")
    @patch("mytools.dns.dotscan.socket.create_connection")
    def test_timeout_error(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        mock_conn.side_effect = TimeoutError()
        data, _tls_info, error = _dot_query("dns.google", 853, b"\x00\x01", 5.0)
        assert data == b""
        assert error == "timeout"

    @patch("mytools.dns.dotscan.ssl.create_default_context")
    @patch("mytools.dns.dotscan.socket.create_connection")
    def test_connection_refused(
        self, mock_conn: MagicMock, mock_ctx: MagicMock
    ) -> None:
        mock_conn.side_effect = ConnectionRefusedError()
        data, _tls_info, error = _dot_query("dns.google", 853, b"\x00\x01", 5.0)
        assert data == b""
        assert error == "connection_refused"

    @patch("mytools.dns.dotscan.ssl.create_default_context")
    @patch("mytools.dns.dotscan.socket.create_connection")
    def test_os_error(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        mock_conn.side_effect = OSError("network unreachable")
        data, _tls_info, error = _dot_query("dns.google", 853, b"\x00\x01", 5.0)
        assert data == b""
        assert error.startswith("os_error")

    @patch("mytools.dns.dotscan.ssl.create_default_context")
    @patch("mytools.dns.dotscan.socket.create_connection")
    def test_generic_exception(self, mock_conn: MagicMock, mock_ctx: MagicMock) -> None:
        mock_conn.side_effect = RuntimeError("boom")
        data, _tls_info, error = _dot_query("dns.google", 853, b"\x00\x01", 5.0)
        assert data == b""
        assert "boom" in error


def _make_dot_result(**overrides: object) -> DotScanResult:
    defaults = {
        "domain": "example.com",
        "query_type": "A",
        "resolvers": [],
        "traditional_records": [],
        "traditional_latency_ms": 10.0,
        "filtering_detected": False,
        "inconsistencies": [],
        "dot_supported": True,
        "overall_status": "resolved",
        "error": "",
    }
    defaults.update(overrides)
    return DotScanResult(**defaults)


class TestScanDot:
    @patch("mytools.dns.dotscan._dot_query")
    @patch("mytools.dns.dotscan._traditional_resolve")
    @pytest.mark.asyncio
    async def test_resolved(self, mock_trad: MagicMock, mock_dot: MagicMock) -> None:
        trad_records = [DotRecord("example.com", "A", 300, "1.2.3.4")]
        mock_trad.return_value = (trad_records, 10.0, "")
        mock_dot.return_value = (
            b"\x00\x01",
            DotTlsInfo("", "", "", "", [], "", "TLSv1.3"),
            "",
        )
        with patch(
            "mytools.dns.dotscan._parse_dns_response", return_value=trad_records
        ):
            result = await scan_dot("example.com", resolvers=["google"])
        assert result.overall_status == "resolved"
        assert result.dot_supported is True
        assert result.filtering_detected is False

    @patch("mytools.dns.dotscan._dot_query")
    @patch("mytools.dns.dotscan._traditional_resolve")
    @pytest.mark.asyncio
    async def test_filtering_detected(
        self, mock_trad: MagicMock, mock_dot: MagicMock
    ) -> None:
        trad_records = [DotRecord("example.com", "A", 300, "1.2.3.4")]
        dot_records = [DotRecord("example.com", "A", 300, "5.6.7.8")]
        mock_trad.return_value = (trad_records, 10.0, "")
        mock_dot.return_value = (
            b"\x00\x01",
            DotTlsInfo("", "", "", "", [], "", ""),
            "",
        )
        with patch("mytools.dns.dotscan._parse_dns_response", return_value=dot_records):
            result = await scan_dot("example.com", resolvers=["google"])
        assert result.overall_status == "filtering_detected"
        assert result.filtering_detected is True

    @patch("mytools.dns.dotscan._dot_query")
    @patch("mytools.dns.dotscan._traditional_resolve")
    @pytest.mark.asyncio
    async def test_nxdomain(self, mock_trad: MagicMock, mock_dot: MagicMock) -> None:
        mock_trad.return_value = ([], 10.0, "nxdomain")
        mock_dot.return_value = (
            b"",
            DotTlsInfo("", "", "", "", [], "", ""),
            "nxdomain",
        )
        result = await scan_dot("example.com", resolvers=["google"])
        assert result.overall_status == "nxdomain"

    @patch("mytools.dns.dotscan._dot_query")
    @patch("mytools.dns.dotscan._traditional_resolve")
    @pytest.mark.asyncio
    async def test_no_dot_support(
        self, mock_trad: MagicMock, mock_dot: MagicMock
    ) -> None:
        trad_records = [DotRecord("example.com", "A", 300, "1.2.3.4")]
        mock_trad.return_value = (trad_records, 10.0, "")
        mock_dot.return_value = (b"", DotTlsInfo("", "", "", "", [], "", ""), "timeout")
        result = await scan_dot("example.com", resolvers=["google"])
        assert result.overall_status == "no_dot_support"
        assert result.dot_supported is False

    @patch("mytools.dns.dotscan._dot_query")
    @patch("mytools.dns.dotscan._traditional_resolve")
    @pytest.mark.asyncio
    async def test_error(self, mock_trad: MagicMock, mock_dot: MagicMock) -> None:
        mock_trad.return_value = ([], 10.0, "")
        mock_dot.return_value = (b"", DotTlsInfo("", "", "", "", [], "", ""), "timeout")
        result = await scan_dot("example.com", resolvers=["google"])
        assert result.overall_status == "error"

    @patch("mytools.dns.dotscan._dot_query")
    @patch("mytools.dns.dotscan._traditional_resolve")
    @pytest.mark.asyncio
    async def test_unknown_resolver_skipped(
        self, mock_trad: MagicMock, mock_dot: MagicMock
    ) -> None:
        mock_trad.return_value = ([], 10.0, "")
        result = await scan_dot("example.com", resolvers=["unknown"])
        assert result.overall_status == "error"
        assert result.resolvers == []
        mock_dot.assert_not_called()


class TestPrintResultsAdditional:
    def test_trad_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = _make_dot_result(
            traditional_records=[],
            dot_supported=False,
            overall_status="error",
            error="timeout",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "timeout" in out

    def test_resolver_display(self, capsys: pytest.CaptureFixture[str]) -> None:
        tls_info = DotTlsInfo(
            issuer="CN=Google Trust Services",
            subject="CN=dns.google",
            not_before="2024-01-01",
            not_after="2025-01-01",
            san=["dns.google"],
            serial="12345",
            version="TLSv1.3",
        )
        pr_ok = DotResolverResult(
            resolver="google",
            resolver_name="Google DNS",
            host="dns.google",
            port=853,
            records=[DotRecord("example.com", "A", 300, "1.2.3.4")],
            tls_info=tls_info,
            latency_ms=50.0,
            error="",
        )
        pr_err = DotResolverResult(
            resolver="quad9",
            resolver_name="Quad9 DNS",
            host="dns.quad9.net",
            port=853,
            records=[],
            tls_info=DotTlsInfo("", "", "", "", [], "", ""),
            latency_ms=0.0,
            error="connect_error",
        )
        result = _make_dot_result(
            resolvers=[pr_ok, pr_err],
            traditional_records=[DotRecord("example.com", "A", 300, "1.2.3.4")],
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Google DNS" in out
        assert "Quad9 DNS" in out
        assert "TLSv1.3" in out


class TestRunScan:
    @patch("mytools.dns.dotscan.scan_dot", new_callable=AsyncMock)
    @pytest.mark.asyncio
    async def test_builds_args(self, mock_scan: AsyncMock) -> None:
        args = argparse.Namespace(
            domain="example.com", type="A", resolvers=["google"], timeout=7.0
        )
        result = _make_dot_result()
        mock_scan.return_value = result
        out = await _run_scan(args)
        assert out == result
        mock_scan.assert_awaited_once_with("example.com", "A", ["google"], 7.0)


class TestBanner:
    def test_banner_calls_create_banner(self) -> None:
        with patch("mytools.dns.dotscan.create_banner") as mock_cb:
            mock_banner = MagicMock()
            mock_cb.return_value = mock_banner
            banner()
            mock_cb.assert_called_once()
            mock_banner.assert_called_once()


class TestMain:
    def test_main_calls_run_main_loop(self) -> None:
        with patch("mytools.dns.dotscan.run_main_loop", return_value=0) as mock_loop:
            assert main() == 0
            mock_loop.assert_called_once()


def _make_safe_run_args(**overrides: object) -> argparse.Namespace:
    defaults = {"domain": "example.com", "output": None, "quiet": False}
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestSafeRun:
    @patch("mytools.dns.dotscan.print_results")
    @patch("mytools.dns.dotscan.init_scanner", return_value=False)
    @patch("mytools.dns.dotscan._run_scan", new_callable=AsyncMock)
    def test_resolved_returns_zero(
        self, mock_scan: AsyncMock, mock_init: MagicMock, mock_print: MagicMock
    ) -> None:
        mock_scan.return_value = _make_dot_result(overall_status="resolved")
        assert _safe_run(_make_safe_run_args()) == 0
        mock_print.assert_called_once()

    @patch("mytools.dns.dotscan.print_results")
    @patch("mytools.dns.dotscan.init_scanner", return_value=False)
    @patch("mytools.dns.dotscan._run_scan", new_callable=AsyncMock)
    def test_error_returns_one(
        self, mock_scan: AsyncMock, mock_init: MagicMock, mock_print: MagicMock
    ) -> None:
        mock_scan.return_value = _make_dot_result(
            overall_status="error", dot_supported=False
        )
        assert _safe_run(_make_safe_run_args()) == 1

    @patch("mytools.dns.dotscan.write_output")
    @patch("mytools.dns.dotscan.print_results")
    @patch("mytools.dns.dotscan.init_scanner", return_value=False)
    @patch("mytools.dns.dotscan._run_scan", new_callable=AsyncMock)
    def test_with_output(
        self,
        mock_scan: AsyncMock,
        mock_init: MagicMock,
        mock_print: MagicMock,
        mock_write: MagicMock,
    ) -> None:
        mock_scan.return_value = _make_dot_result(overall_status="resolved")
        assert _safe_run(_make_safe_run_args(output="out.json")) == 0
        mock_write.assert_called_once()

    @patch("mytools.dns.dotscan.print_results")
    @patch("mytools.dns.dotscan.init_scanner", return_value=True)
    @patch("mytools.dns.dotscan._run_scan", new_callable=AsyncMock)
    def test_quiet_skips_print(
        self, mock_scan: AsyncMock, mock_init: MagicMock, mock_print: MagicMock
    ) -> None:
        mock_scan.return_value = _make_dot_result(overall_status="resolved")
        assert _safe_run(_make_safe_run_args(quiet=True)) == 0
        mock_print.assert_not_called()


class TestMainGuard:
    """Testes do guard `if __name__ == \"__main__\"`."""

    def test_guard_runs(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-dot", "example.com"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.dns.dotscan", run_name="__main__")
        assert exc_info.value.code == 0
