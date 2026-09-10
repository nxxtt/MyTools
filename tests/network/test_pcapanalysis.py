"""Tests para PCAP Analysis module."""

from __future__ import annotations

from pathlib import Path

import pytest

from mytools.network._pcap_common import (
    PCAP_SECRET_PATTERNS,
    PcapAttempt,
    PcapResult,
)
from mytools.network.pcapanalysis import (
    PcapAnalysisScanner,
    _check_dns_tunneling,
    _check_large_payloads,
    _check_protocol_anomalies,
    _check_secrets_in_payloads,
    _detect_file_format,
    _proto_name,
    run_pcap_analysis,
)


class TestPcapAttempt:
    def test_frozen(self) -> None:
        att = PcapAttempt(check_name="x", vulnerable=True)
        with pytest.raises(AttributeError):
            att.check_name = "y"  # type: ignore[misc]

    def test_defaults(self) -> None:
        att = PcapAttempt(check_name="x", vulnerable=True)
        assert att.severity == "medium"
        assert att.description == ""
        assert att.details == ""


class TestPcapResult:
    def test_frozen(self) -> None:
        r = PcapResult(target=".", file_size=0, total_packets=0)
        with pytest.raises(AttributeError):
            r.target = "other"  # type: ignore[misc]

    def test_defaults(self) -> None:
        r = PcapResult(target=".", file_size=0, total_packets=0)
        assert r.overall_status == "clean"
        assert r.attempts == []
        assert r.issues == []
        assert r.protocols == []


class TestSecretPatterns:
    def test_all_compiled(self) -> None:
        for name, pat in PCAP_SECRET_PATTERNS.items():
            assert hasattr(pat, "search"), f"{name} not compiled"

    def test_basic_auth_detected(self) -> None:
        data = b"Authorization: Basic dXNlcjpwYXNzd29yZA=="
        found = []
        for name, pat in PCAP_SECRET_PATTERNS.items():
            if pat.search(data):
                found.append(name)
        assert "basic_auth" in found

    def test_bearer_token_detected(self) -> None:
        data = b"Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.test.signature"
        found = []
        for name, pat in PCAP_SECRET_PATTERNS.items():
            if pat.search(data):
                found.append(name)
        assert "bearer_token" in found


class TestProtoName:
    def test_tcp(self) -> None:
        assert _proto_name(6) == "TCP"

    def test_udp(self) -> None:
        assert _proto_name(17) == "UDP"

    def test_icmp(self) -> None:
        assert _proto_name(1) == "ICMP"

    def test_unknown(self) -> None:
        assert _proto_name(99) == "IP-99"


class TestDetectFileFormat:
    def test_nonexistent(self, tmp_path: Path) -> None:
        assert _detect_file_format(tmp_path / "nope.pcap") == "unknown"

    def test_pcap_le(self, tmp_path: Path) -> None:
        f = tmp_path / "test.pcap"
        f.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
        assert _detect_file_format(f) == "pcap_le"

    def test_pcap_be(self, tmp_path: Path) -> None:
        f = tmp_path / "test.pcap"
        f.write_bytes(b"\xa1\xb2\xc3\xd4" + b"\x00" * 20)
        assert _detect_file_format(f) == "pcap_be"

    def test_pcapng(self, tmp_path: Path) -> None:
        f = tmp_path / "test.pcapng"
        f.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)
        assert _detect_file_format(f) == "pcapng"

    def test_unknown(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_bytes(b"hello world")
        assert _detect_file_format(f) == "unknown"


class TestCheckProtocolAnomalies:
    def test_icmp_flood(self) -> None:
        protos = ["ICMP"] * 80 + ["TCP"] * 20
        attempts = _check_protocol_anomalies(protos, 100)
        assert any(a.check_name == "icmp_flood" for a in attempts)

    def test_no_anomaly(self) -> None:
        protos = ["TCP"] * 80 + ["UDP"] * 20
        attempts = _check_protocol_anomalies(protos, 100)
        assert len(attempts) == 0

    def test_gre_detected(self) -> None:
        protos = ["GRE", "TCP"]
        attempts = _check_protocol_anomalies(protos, 10)
        assert any(a.check_name == "gre_tunnel" for a in attempts)

    def test_esp_detected(self) -> None:
        protos = ["ESP", "TCP"]
        attempts = _check_protocol_anomalies(protos, 10)
        assert any(a.check_name == "ipsec_traffic" for a in attempts)


class TestCheckSecrets:
    def test_basic_auth_in_payload(self) -> None:
        payloads = [b"GET / HTTP/1.1\r\nAuthorization: Basic dXNlcjpwYXNzd29yZA==\r\n"]
        attempts = _check_secrets_in_payloads(payloads)
        assert any("basic_auth" in a.check_name for a in attempts)

    def test_no_secrets(self) -> None:
        payloads = [b"GET / HTTP/1.1\r\nHost: example.com\r\n"]
        attempts = _check_secrets_in_payloads(payloads)
        assert len(attempts) == 0

    def test_empty_payloads(self) -> None:
        attempts = _check_secrets_in_payloads([])
        assert len(attempts) == 0


class TestCheckDnsTunneling:
    def test_empty(self) -> None:
        attempts = _check_dns_tunneling([])
        assert len(attempts) == 0


class TestCheckLargePayloads:
    def test_large_found(self) -> None:
        payloads = [b"x" * 10000]
        attempts = _check_large_payloads(payloads)
        assert any(a.check_name == "large_payloads" for a in attempts)

    def test_all_small(self) -> None:
        payloads = [b"small", b"data"]
        attempts = _check_large_payloads(payloads)
        assert len(attempts) == 0


class TestRunPcapAnalysis:
    def test_nonexistent(self, tmp_path: Path) -> None:
        import asyncio

        result = asyncio.run(run_pcap_analysis(str(tmp_path / "nope.pcap")))
        assert result.overall_status == "error"

    def test_not_a_file(self, tmp_path: Path) -> None:
        import asyncio

        result = asyncio.run(run_pcap_analysis(str(tmp_path)))
        assert result.overall_status == "error"

    def test_unknown_format(self, tmp_path: Path) -> None:
        import asyncio

        f = tmp_path / "bad.pcap"
        f.write_bytes(b"not a pcap file")
        result = asyncio.run(run_pcap_analysis(str(f)))
        assert result.overall_status == "error"


class TestPcapAnalysisScanner:
    def test_build_parser(self) -> None:
        scanner = PcapAnalysisScanner()
        parser = scanner.build_parser()
        args = parser.parse_args([])
        assert args.target is None

    def test_build_parser_with_target(self) -> None:
        scanner = PcapAnalysisScanner()
        parser = scanner.build_parser()
        args = parser.parse_args(["capture.pcap"])
        assert args.target == "capture.pcap"

    def test_get_target(self) -> None:
        import argparse

        ns = argparse.Namespace(target="capture.pcap")
        assert PcapAnalysisScanner._get_target(ns) == "capture.pcap"

    def test_get_target_none(self) -> None:
        import argparse

        ns = argparse.Namespace()
        assert PcapAnalysisScanner._get_target(ns) is None

    def test_module_level_exports(self) -> None:
        from mytools.network.pcapanalysis import build_parser, main, run_once

        assert callable(build_parser)
        assert callable(main)
        assert callable(run_once)
