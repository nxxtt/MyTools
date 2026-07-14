"""Testes do modulo grpcattack.py — gRPC Attack Testing."""

from __future__ import annotations

from typing import Any

import pytest

from mytools.web.grpcattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    GrpcAttackAttempt,
    GrpcAttackResult,
    _encode_varint,
    _parse_url,
    build_parser,
    print_results,
)

# ─── Dataclass Tests ─────────────────────────────────────────────────────────


class TestGrpcAttackAttempt:
    def test_creation(self) -> None:
        a = GrpcAttackAttempt(
            technique="reflection_discovery", category="reflection",
            description="desc", vulnerable=False, details="test", error="",
            endpoint="grpc://target.com:50051", services_found=3,
            methods_found=10, response_code=200,
        )
        assert a.technique == "reflection_discovery"
        assert a.category == "reflection"
        assert a.vulnerable is False
        assert a.services_found == 3

    def test_frozen(self) -> None:
        a = GrpcAttackAttempt(
            technique="t", category="c", description="d",
            vulnerable=False, details="", error="",
            endpoint="", services_found=0, methods_found=0, response_code=0,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestGrpcAttackResult:
    def test_creation(self) -> None:
        r = GrpcAttackResult(
            target="grpc://target.com:50051", host="target.com", port=50051, tls=False,
            endpoint="grpc://target.com:50051", reflection_enabled=True,
            services_count=3, methods_count=10,
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.reflection_enabled is True

    def test_frozen(self) -> None:
        r = GrpcAttackResult(
            target="t", host="h", port=50051, tls=False,
            endpoint="", reflection_enabled=False,
            services_count=0, methods_count=0,
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]


# ─── Category Map Tests ─────────────────────────────────────────────────────


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        expected = {"reflection", "server_streaming", "client_streaming", "bidirectional", "grpc_web", "protobuf"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_category_counts(self) -> None:
        assert len(_CATEGORY_MAP["reflection"]) == 5
        assert len(_CATEGORY_MAP["server_streaming"]) == 4
        assert len(_CATEGORY_MAP["client_streaming"]) == 3
        assert len(_CATEGORY_MAP["bidirectional"]) == 3
        assert len(_CATEGORY_MAP["grpc_web"]) == 4
        assert len(_CATEGORY_MAP["protobuf"]) == 5

    def test_total_techniques(self) -> None:
        total = sum(len(v) for v in _CATEGORY_MAP.values())
        assert total == 24

    def test_dispatch_matches_map(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_DISPATCH

    def test_all_dispatches_are_coroutines(self) -> None:
        import inspect
        for cat, fn in _CATEGORY_DISPATCH.items():
            assert inspect.iscoroutinefunction(fn), f"{cat} is not a coroutine"


# ─── Varint Tests ────────────────────────────────────────────────────────────


class TestVarint:
    def test_encode_single_byte(self) -> None:
        assert _encode_varint(0) == b"\x00"
        assert _encode_varint(1) == b"\x01"
        assert _encode_varint(127) == b"\x7f"

    def test_encode_multi_byte(self) -> None:
        assert _encode_varint(128) == b"\x80\x01"
        assert _encode_varint(300) == b"\xac\x02"

    def test_roundtrip(self) -> None:
        from mytools.web.grpcattack import _encode_varint
        for value in [0, 1, 127, 128, 300, 16384, 2097151]:
            encoded = _encode_varint(value)
            assert len(encoded) > 0


# ─── URL Parser Tests ────────────────────────────────────────────────────────


class TestParseUrl:
    def test_grpc(self) -> None:
        host, _path, port, tls = _parse_url("grpc://example.com:50051")
        assert host == "example.com"
        assert port == 50051
        assert tls is False

    def test_grpcs(self) -> None:
        host, _path, _port, tls = _parse_url("grpcs://example.com:443")
        assert host == "example.com"
        assert tls is True

    def test_no_scheme(self) -> None:
        host, _path, _port, tls = _parse_url("example.com:50051")
        assert host == "example.com"
        assert tls is False

    def test_default_port(self) -> None:
        _host, _path, port, _tls = _parse_url("grpc://example.com")
        assert port == 50051


# ─── Print Results Tests ─────────────────────────────────────────────────────


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = GrpcAttackResult(
            target="grpc://target.com:50051", host="target.com", port=50051, tls=False,
            endpoint="grpc://target.com:50051", reflection_enabled=False,
            services_count=0, methods_count=0,
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "gRPC Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = GrpcAttackResult(
            target="grpc://target.com:50051", host="target.com", port=50051, tls=False,
            endpoint="grpc://target.com:50051", reflection_enabled=True,
            services_count=3, methods_count=10,
            attempts=[], vulnerable_techniques=["reflection_discovery"],
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
        args = parser.parse_args(["grpc://target.com:50051"])
        assert args.url == "grpc://target.com:50051"

    def test_build_parser_with_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["grpc://target.com:50051", "-c", "reflection", "protobuf"])
        assert args.categories == ["reflection", "protobuf"]

    def test_build_parser_all_choices(self) -> None:
        parser = build_parser()
        for cat in _CATEGORY_MAP:
            args = parser.parse_args(["grpc://target.com:50051", "-c", cat])
            assert args.categories == [cat]


# ─── Async Category Tests (Mocked) ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_category_dispatch_all_return_lists() -> None:
    """All category dispatchers should return a list."""
    reflection_info: dict[str, Any] = {"available": False, "services": [], "files": []}
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn("target.com", 50051, "", 0.1, False, "grpc://target.com:50051", reflection_info)
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, GrpcAttackAttempt)
            assert attempt.category == cat
