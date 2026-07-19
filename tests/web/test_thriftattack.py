"""Testes do modulo thriftattack.py — Thrift Attack Testing."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mytools.web.thriftattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    _COMMON_THRIFT_SERVICES,
    _MINIMAL_THRIFT_IDL,
    ThriftAttackAttempt,
    ThriftAttackResult,
    _create_probe_thrift,
    _parse_url,
    build_parser,
    print_results,
)

# ─── Dataclass Tests ─────────────────────────────────────────────────────────


class TestThriftAttackAttempt:
    def test_creation(self) -> None:
        a = ThriftAttackAttempt(
            technique="service_enumeration", category="method_enumeration",
            description="desc", vulnerable=False, details="test", error="",
            host="target.com", port=9090, protocol="binary", response_code=200,
        )
        assert a.technique == "service_enumeration"
        assert a.category == "method_enumeration"
        assert a.vulnerable is False

    def test_frozen(self) -> None:
        a = ThriftAttackAttempt(
            technique="t", category="c", description="d",
            vulnerable=False, details="", error="",
            host="h", port=9090, protocol="binary", response_code=0,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestThriftAttackResult:
    def test_creation(self) -> None:
        r = ThriftAttackResult(
            target="thrift://target.com:9090", host="target.com", port=9090, tls=False,
            services_found=3, methods_found=10, protocol_detected="binary",
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.protocol_detected == "binary"

    def test_frozen(self) -> None:
        r = ThriftAttackResult(
            target="t", host="h", port=9090, tls=False,
            services_found=0, methods_found=0, protocol_detected="binary",
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]


# ─── Category Map Tests ─────────────────────────────────────────────────────


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        expected = {"method_enumeration", "binary_protocol"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_category_counts(self) -> None:
        assert len(_CATEGORY_MAP["method_enumeration"]) == 4
        assert len(_CATEGORY_MAP["binary_protocol"]) == 4

    def test_total_techniques(self) -> None:
        total = sum(len(v) for v in _CATEGORY_MAP.values())
        assert total == 8

    def test_dispatch_matches_map(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_DISPATCH

    def test_all_dispatches_are_coroutines(self) -> None:
        import inspect
        for cat, fn in _CATEGORY_DISPATCH.items():
            assert inspect.iscoroutinefunction(fn), f"{cat} is not a coroutine"


# ─── Constants Tests ─────────────────────────────────────────────────────────


class TestConstants:
    def test_common_services_not_empty(self) -> None:
        assert len(_COMMON_THRIFT_SERVICES) > 0

    def test_minimal_thrift_idl_has_service(self) -> None:
        assert "service ProbeService" in _MINIMAL_THRIFT_IDL
        assert "void ping()" in _MINIMAL_THRIFT_IDL


# ─── Thrift IDL Loader Tests ────────────────────────────────────────────────


class TestThriftLoader:
    def test_create_probe_thrift(self) -> None:
        mod = _create_probe_thrift()
        assert hasattr(mod, "ProbeService")

    def test_probe_thrift_has_methods(self) -> None:
        mod = _create_probe_thrift()
        svc = mod.ProbeService
        assert hasattr(svc, "thrift_services")
        assert "ping" in svc.thrift_services


# ─── URL Parser Tests ────────────────────────────────────────────────────────


class TestParseUrl:
    def test_thrift(self) -> None:
        host, _path, port, tls = _parse_url("thrift://example.com:9090")
        assert host == "example.com"
        assert port == 9090
        assert tls is False

    def test_thrifts(self) -> None:
        host, _path, _port, tls = _parse_url("thrifts://example.com:443")
        assert host == "example.com"
        assert tls is True

    def test_no_scheme(self) -> None:
        host, _path, _port, tls = _parse_url("example.com:9090")
        assert host == "example.com"
        assert tls is False

    def test_default_port(self) -> None:
        _host, _path, port, _tls = _parse_url("thrift://example.com")
        assert port == 9090


# ─── Print Results Tests ─────────────────────────────────────────────────────


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = ThriftAttackResult(
            target="thrift://target.com:9090", host="target.com", port=9090, tls=False,
            services_found=0, methods_found=0, protocol_detected="binary",
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Thrift Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = ThriftAttackResult(
            target="thrift://target.com:9090", host="target.com", port=9090, tls=False,
            services_found=3, methods_found=10, protocol_detected="binary",
            attempts=[], vulnerable_techniques=["service_enumeration"],
            issues=["Errors: test_error"], overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output
        assert "Issues:" in output


# ─── CLI Tests ───────────────────────────────────────────────────────────────


class TestCLI:
    def test_build_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["thrift://target.com:9090"])
        assert args.url == "thrift://target.com:9090"

    def test_build_parser_with_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["thrift://target.com:9090", "-c", "method_enumeration"])
        assert args.categories == ["method_enumeration"]

    def test_build_parser_all_choices(self) -> None:
        parser = build_parser()
        for cat in _CATEGORY_MAP:
            args = parser.parse_args(["thrift://target.com:9090", "-c", cat])
            assert args.categories == [cat]


# ─── Async Category Tests (Mocked) ──────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.network
@patch("mytools.web.thriftattack.make_client")
async def test_category_dispatch_all_return_lists(mock_make: MagicMock) -> None:
    """All category dispatchers should return a list."""
    mock_client = MagicMock()
    mock_client.ping.return_value = None
    mock_client.getData.return_value = ""
    mock_client.getStatus.return_value = 0
    mock_client.isAlive.return_value = True
    mock_client.close.return_value = None
    mock_client.listMethods.return_value = []
    mock_client.getMetadata.return_value = {}
    mock_make.return_value = mock_client
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn("target.com", 9090, 0.1, False)
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, ThriftAttackAttempt)
            assert attempt.category == cat
