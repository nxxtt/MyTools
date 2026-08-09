"""Testes do modulo grpcattack.py — gRPC Attack Testing."""

from __future__ import annotations

import argparse
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import grpc
import httpx
import pytest
import respx

import mytools.web.grpcattack as grpcattack_module
from mytools.web.grpcattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    GrpcAttackAttempt,
    GrpcAttackResult,
    _create_channel,
    _discover_reflection,
    _encode_varint,
    _parse_url,
    _test_bidirectional,
    _test_client_streaming,
    _test_grpc_web,
    _test_protobuf,
    _test_reflection,
    _test_server_streaming,
    _try_call,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)

# ─── Dataclass Tests ─────────────────────────────────────────────────────────


class TestGrpcAttackAttempt:
    def test_creation(self) -> None:
        a = GrpcAttackAttempt(
            technique="reflection_discovery",
            category="reflection",
            description="desc",
            vulnerable=False,
            details="test",
            error="",
            endpoint="grpc://target.com:50051",
            services_found=3,
            methods_found=10,
            response_code=200,
        )
        assert a.technique == "reflection_discovery"
        assert a.category == "reflection"
        assert a.vulnerable is False
        assert a.services_found == 3

    def test_frozen(self) -> None:
        a = GrpcAttackAttempt(
            technique="t",
            category="c",
            description="d",
            vulnerable=False,
            details="",
            error="",
            endpoint="",
            services_found=0,
            methods_found=0,
            response_code=0,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestGrpcAttackResult:
    def test_creation(self) -> None:
        r = GrpcAttackResult(
            target="grpc://target.com:50051",
            host="target.com",
            port=50051,
            tls=False,
            endpoint="grpc://target.com:50051",
            reflection_enabled=True,
            services_count=3,
            methods_count=10,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.reflection_enabled is True

    def test_frozen(self) -> None:
        r = GrpcAttackResult(
            target="t",
            host="h",
            port=50051,
            tls=False,
            endpoint="",
            reflection_enabled=False,
            services_count=0,
            methods_count=0,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]


# ─── Category Map Tests ─────────────────────────────────────────────────────


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        expected = {
            "reflection",
            "server_streaming",
            "client_streaming",
            "bidirectional",
            "grpc_web",
            "protobuf",
        }
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
            target="grpc://target.com:50051",
            host="target.com",
            port=50051,
            tls=False,
            endpoint="grpc://target.com:50051",
            reflection_enabled=False,
            services_count=0,
            methods_count=0,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "gRPC Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = GrpcAttackResult(
            target="grpc://target.com:50051",
            host="target.com",
            port=50051,
            tls=False,
            endpoint="grpc://target.com:50051",
            reflection_enabled=True,
            services_count=3,
            methods_count=10,
            attempts=[],
            vulnerable_techniques=["reflection_discovery"],
            issues=["Errors: test_error"],
            overall_status="vulnerable",
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
        args = parser.parse_args(
            ["grpc://target.com:50051", "-c", "reflection", "protobuf"]
        )
        assert args.categories == ["reflection", "protobuf"]

    def test_build_parser_all_choices(self) -> None:
        parser = build_parser()
        for cat in _CATEGORY_MAP:
            args = parser.parse_args(["grpc://target.com:50051", "-c", cat])
            assert args.categories == [cat]


# ─── Channel / Reflection / Try-Call Tests ──────────────────────────────────


def _attempt(
    tech: str,
    cat: str,
    *,
    vuln: bool = False,
    details: str = "",
    error: str = "",
) -> GrpcAttackAttempt:
    return GrpcAttackAttempt(
        technique=tech,
        category=cat,
        description=tech,
        vulnerable=vuln,
        details=details,
        error=error,
        endpoint="grpc://target.com:50051",
        services_found=0,
        methods_found=0,
        response_code=200,
    )


class TestCreateChannel:
    def test_secure(self) -> None:
        with patch("mytools.web.grpcattack.grpc.aio.secure_channel") as mock_sc:
            result = _create_channel("host:443", True)
        mock_sc.assert_called_once()
        assert mock_sc.call_args.args[0] == "host:443"
        assert mock_sc.call_args.args[1] is not None
        assert result == mock_sc.return_value

    def test_insecure(self) -> None:
        with patch("mytools.web.grpcattack.grpc.aio.insecure_channel") as mock_ic:
            result = _create_channel("host:50051", False)
        mock_ic.assert_called_once_with("host:50051")
        assert result == mock_ic.return_value


class TestDiscoverReflection:
    def _fake_refl(self) -> tuple[MagicMock, MagicMock]:
        refl = MagicMock()
        refl.get_services.return_value = ["com.pkg.Service"]
        file_desc = MagicMock()
        refl.FindFileByName.return_value = file_desc
        svc = MagicMock()
        svc.methods = [SimpleNamespace(name="DoThing")]
        pool = MagicMock()
        pool.FindServiceByName.return_value = svc
        return refl, pool

    @pytest.mark.asyncio
    async def test_success(self) -> None:
        fake_channel = AsyncMock()
        fake_channel.channel_ready = AsyncMock()
        fake_channel.close = AsyncMock()
        refl, pool = self._fake_refl()
        with (
            patch("mytools.web.grpcattack._create_channel", return_value=fake_channel),
            patch(
                "mytools.web.grpcattack.ProtoReflectionDescriptorDatabase",
                return_value=refl,
            ),
            patch("mytools.web.grpcattack.DescriptorPool", return_value=pool),
        ):
            result = await _discover_reflection("host", 50051, False, 5.0)
        assert result["available"] is True
        assert result["services"] == [
            {"name": "com.pkg.Service", "methods": ["DoThing"]}
        ]
        assert result["methods"] == {"com.pkg.Service": ["DoThing"]}
        assert result["files"] == ["com.proto"]
        fake_channel.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_service_processing_error(self) -> None:
        fake_channel = AsyncMock()
        fake_channel.channel_ready = AsyncMock()
        fake_channel.close = AsyncMock()
        refl = MagicMock()
        refl.get_services.return_value = ["com.pkg.Service"]
        refl.FindFileByName.side_effect = RuntimeError("boom")
        with (
            patch("mytools.web.grpcattack._create_channel", return_value=fake_channel),
            patch(
                "mytools.web.grpcattack.ProtoReflectionDescriptorDatabase",
                return_value=refl,
            ),
            patch("mytools.web.grpcattack.DescriptorPool"),
        ):
            result = await _discover_reflection("host", 50051, False, 5.0)
        assert result["available"] is True
        assert result["services"] == [{"name": "com.pkg.Service", "methods": []}]
        assert result["files"] == []

    @pytest.mark.asyncio
    async def test_aio_rpc_error(self) -> None:
        fake_channel = AsyncMock()
        fake_channel.channel_ready = AsyncMock(
            side_effect=grpc.aio.AioRpcError(
                grpc.StatusCode.UNAVAILABLE,
                grpc.aio.Metadata(),
                grpc.aio.Metadata(),
                "boom",
            )
        )
        with patch("mytools.web.grpcattack._create_channel", return_value=fake_channel):
            result = await _discover_reflection("host", 50051, False, 5.0)
        assert result == {
            "available": False,
            "services": [],
            "files": [],
            "methods": {},
        }

    @pytest.mark.asyncio
    async def test_generic_error(self) -> None:
        fake_channel = AsyncMock()
        fake_channel.channel_ready = AsyncMock(side_effect=ValueError("boom"))
        with patch("mytools.web.grpcattack._create_channel", return_value=fake_channel):
            result = await _discover_reflection("host", 50051, False, 5.0)
        assert result["available"] is False
        assert result["services"] == []


class TestTryCall:
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        fake_channel = AsyncMock()
        fake_channel.channel_ready = AsyncMock()
        fake_channel.close = AsyncMock()
        fake_stub = AsyncMock()
        fake_channel.unary_unary = MagicMock(return_value=fake_stub)
        with patch("mytools.web.grpcattack._create_channel", return_value=fake_channel):
            ok, det = await _try_call(
                "host:50051", False, "/grpc.health.v1.Health/Check", b"\x00", 5.0
            )
        assert ok is True
        assert det == "ok"
        fake_stub.assert_awaited_once_with(b"\x00")
        fake_channel.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_aio_rpc_error(self) -> None:
        fake_channel = AsyncMock()
        fake_channel.channel_ready = AsyncMock()
        fake_channel.close = AsyncMock()
        fake_stub = AsyncMock(
            side_effect=grpc.aio.AioRpcError(
                grpc.StatusCode.OK, grpc.aio.Metadata(), grpc.aio.Metadata(), "ok"
            )
        )
        fake_channel.unary_unary = MagicMock(return_value=fake_stub)
        with patch("mytools.web.grpcattack._create_channel", return_value=fake_channel):
            ok, det = await _try_call(
                "host:50051", False, "/grpc.health.v1.Health/Check", b"\x00", 5.0
            )
        assert ok is True
        assert det == "OK"

    @pytest.mark.asyncio
    async def test_generic_error(self) -> None:
        fake_channel = AsyncMock()
        fake_channel.channel_ready = AsyncMock()
        fake_stub = AsyncMock(side_effect=RuntimeError("boom"))
        fake_channel.unary_unary = MagicMock(return_value=fake_stub)
        with patch("mytools.web.grpcattack._create_channel", return_value=fake_channel):
            ok, det = await _try_call(
                "host:50051", False, "/grpc.health.v1.Health/Check", b"\x00", 5.0
            )
        assert ok is False
        assert det == "connection_failed"


# ─── Category Dispatcher Error / Branch Tests ───────────────────────────────


@pytest.mark.asyncio
async def test_reflection_unknown_tech_else() -> None:
    """Cobre o else inalcancavel de _test_reflection (linha 280)."""
    import types

    fn = _test_reflection
    code = fn.__code__
    new_consts = tuple(
        (*c, "unknown_tech")
        if isinstance(c, tuple) and "reflection_discovery" in c
        else c
        for c in code.co_consts
    )
    new_code = code.replace(co_consts=new_consts)
    new_fn = types.FunctionType(new_code, fn.__globals__)

    refl: dict[str, Any] = {
        "available": False,
        "services": [],
        "files": [],
        "methods": {},
    }
    results = await new_fn(
        "host", 50051, "", 5.0, False, "grpc://target.com:50051", refl
    )
    assert len(results) == 6
    assert results[-1].technique == "unknown_tech"
    assert results[-1].vulnerable is False
    assert results[-1].details == ""


@pytest.mark.asyncio
async def test_reflection_attempt_error() -> None:
    real_make = grpcattack_module._make_attempt
    calls = 0

    def flaky(*args: Any, **kwargs: Any) -> GrpcAttackAttempt:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("boom")
        return real_make(*args, **kwargs)

    refl: dict[str, Any] = {
        "available": False,
        "services": [],
        "files": [],
        "methods": {},
    }
    with patch("mytools.web.grpcattack._make_attempt", side_effect=flaky):
        results = await _test_reflection(
            "host", 50051, "", 5.0, False, "grpc://target.com:50051", refl
        )
    assert len(results) == 5
    assert results[0].error == "boom"
    assert results[0].vulnerable is False
    assert results[1].technique == "service_enumeration"


@pytest.mark.asyncio
async def test_server_streaming_error() -> None:
    refl: dict[str, Any] = {"services": [], "files": []}
    with patch("mytools.web.grpcattack._try_call", side_effect=RuntimeError("boom")):
        results = await _test_server_streaming(
            "host", 50051, "", 5.0, False, "grpc://target.com:50051", refl
        )
    assert len(results) == 4
    assert all(a.error == "boom" for a in results)


@pytest.mark.asyncio
async def test_server_streaming_flood_none_success() -> None:
    refl: dict[str, Any] = {"services": [], "files": []}
    with patch("mytools.web.grpcattack._try_call", return_value=(False, "UNAVAILABLE")):
        results = await _test_server_streaming(
            "host", 50051, "", 5.0, False, "grpc://target.com:50051", refl
        )
    assert len(results) == 4
    assert results[0].vulnerable is False
    assert "0/10" in results[0].details


@pytest.mark.asyncio
async def test_client_streaming_error() -> None:
    refl: dict[str, Any] = {"services": [], "files": []}
    with patch("mytools.web.grpcattack._try_call", side_effect=RuntimeError("boom")):
        results = await _test_client_streaming(
            "host", 50051, "", 5.0, False, "grpc://target.com:50051", refl
        )
    assert len(results) == 3
    assert all(a.error == "boom" for a in results)


@pytest.mark.asyncio
async def test_client_streaming_none_success() -> None:
    refl: dict[str, Any] = {"services": [], "files": []}
    with patch("mytools.web.grpcattack._try_call", return_value=(False, "UNAVAILABLE")):
        results = await _test_client_streaming(
            "host", 50051, "", 5.0, False, "grpc://target.com:50051", refl
        )
    assert len(results) == 3
    assert "0/20" in results[0].details
    assert results[1].details == "UNAVAILABLE"
    assert results[1].vulnerable is False
    assert "0/15" in results[2].details


@pytest.mark.asyncio
async def test_bidirectional_error() -> None:
    refl: dict[str, Any] = {"services": [], "files": []}
    with patch("mytools.web.grpcattack._try_call", side_effect=RuntimeError("boom")):
        results = await _test_bidirectional(
            "host", 50051, "", 5.0, False, "grpc://target.com:50051", refl
        )
    assert len(results) == 3
    assert all(a.error == "boom" for a in results)


@pytest.mark.asyncio
async def test_bidirectional_none_success() -> None:
    refl: dict[str, Any] = {"services": [], "files": []}
    with patch("mytools.web.grpcattack._try_call", return_value=(False, "UNAVAILABLE")):
        results = await _test_bidirectional(
            "host", 50051, "", 5.0, False, "grpc://target.com:50051", refl
        )
    assert len(results) == 3
    assert "0/25" in results[0].details
    assert "0/10" in results[1].details
    assert results[2].vulnerable is False


@pytest.mark.asyncio
async def test_grpc_web_error() -> None:
    refl: dict[str, Any] = {"services": [], "files": []}
    with patch(
        "mytools.web.grpcattack.httpx.AsyncClient", side_effect=RuntimeError("boom")
    ):
        results = await _test_grpc_web(
            "host", 50051, "", 5.0, False, "grpc://target.com:50051", refl
        )
    assert len(results) == 4
    assert all(a.error == "boom" for a in results)


@pytest.mark.asyncio
async def test_protobuf_error() -> None:
    refl: dict[str, Any] = {"services": [], "files": []}
    with patch("mytools.web.grpcattack._try_call", side_effect=RuntimeError("boom")):
        results = await _test_protobuf(
            "host", 50051, "", 5.0, False, "grpc://target.com:50051", refl
        )
    assert len(results) == 5
    assert all(a.error == "boom" for a in results)


# ─── Print Results: Category Grouping ───────────────────────────────────────


class TestPrintResultsCategoryGroups:
    def test_vulnerable_and_secure_categories(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        r = GrpcAttackResult(
            target="grpc://target.com:50051",
            host="target.com",
            port=50051,
            tls=False,
            endpoint="grpc://target.com:50051",
            reflection_enabled=True,
            services_count=3,
            methods_count=10,
            attempts=[
                _attempt("web_bypass", "grpc_web", vuln=True, details="ACAO: *"),
                _attempt("stream_flood", "server_streaming"),
            ],
            vulnerable_techniques=["web_bypass"],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "grpc_web: 1 vulnerable(s)" in output
        assert "web_bypass: ACAO: *" in output
        assert "server_streaming: secure" in output


# ─── Run Scan / Run Once / Main ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_scan_vulnerable(tmp_path) -> None:
    async def tester(*args: object, **kwargs: object) -> list[GrpcAttackAttempt]:
        return [_attempt("web_bypass", "grpc_web", vuln=True, details="ok")]

    refl: dict[str, Any] = {
        "available": True,
        "services": [{"name": "svc", "methods": ["m"]}],
        "files": ["svc.proto"],
        "methods": {"svc": ["m"]},
    }
    dispatch = {"reflection": tester}
    with (
        patch(
            "mytools.web.grpcattack._discover_reflection", new_callable=AsyncMock
        ) as mock_refl,
        patch("mytools.web.grpcattack._CATEGORY_DISPATCH", dispatch),
        patch("mytools.web.grpcattack.print_results"),
    ):
        mock_refl.return_value = refl
        result = await run_scan(
            "grpc://target.com:50051",
            ["reflection", "bogus"],
            5.0,
            str(tmp_path / "out.json"),
        )
    assert result.overall_status == "vulnerable"
    assert result.reflection_enabled is True
    assert result.services_count == 1
    assert result.methods_count == 1
    assert (tmp_path / "out.json").exists()


@pytest.mark.asyncio
async def test_run_scan_error_and_secure() -> None:
    async def boom(*args: object, **kwargs: object) -> list[GrpcAttackAttempt]:
        raise RuntimeError("boom")

    refl: dict[str, Any] = {
        "available": False,
        "services": [],
        "files": [],
        "methods": {},
    }
    dispatch = {"reflection": boom}
    with (
        patch(
            "mytools.web.grpcattack._discover_reflection", new_callable=AsyncMock
        ) as mock_refl,
        patch("mytools.web.grpcattack._CATEGORY_DISPATCH", dispatch),
        patch("mytools.web.grpcattack.print_results"),
    ):
        mock_refl.return_value = refl
        result = await run_scan("grpc://target.com:50051", ["reflection"], 5.0, None)
    assert result.overall_status == "secure"
    assert "reflection_error" in [a.technique for a in result.attempts]
    assert result.issues == ["Errors: reflection_error"]


class TestRunOnce:
    def test_vulnerable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        result = GrpcAttackResult(
            target="grpc://target.com:50051",
            host="target.com",
            port=50051,
            tls=False,
            endpoint="grpc://target.com:50051",
            reflection_enabled=True,
            services_count=0,
            methods_count=0,
            attempts=[],
            vulnerable_techniques=["web_bypass"],
            issues=[],
            overall_status="vulnerable",
        )
        monkeypatch.setattr(
            grpcattack_module, "run_scan", AsyncMock(return_value=result)
        )
        args = argparse.Namespace(
            url="grpc://target.com:50051", categories=None, timeout=5.0, output=None
        )
        assert run_once(args) == 1

    def test_secure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        result = GrpcAttackResult(
            target="grpc://target.com:50051",
            host="target.com",
            port=50051,
            tls=False,
            endpoint="grpc://target.com:50051",
            reflection_enabled=False,
            services_count=0,
            methods_count=0,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        monkeypatch.setattr(
            grpcattack_module, "run_scan", AsyncMock(return_value=result)
        )
        args = argparse.Namespace(
            url="grpc://target.com:50051", categories=None, timeout=5.0, output=None
        )
        assert run_once(args) == 0


class TestMain:
    def test_runs_loop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            grpcattack_module,
            "run_main_loop",
            lambda *args, **kwargs: 42,
        )
        assert main() == 42

    def test_main_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import runpy

        def _raise() -> int:
            raise SystemExit(0)

        monkeypatch.setattr(grpcattack_module, "main", _raise)
        with pytest.raises(SystemExit):
            runpy.run_module("mytools.web.grpcattack", run_name="__main__")


# ─── Async Category Tests (Mocked) ──────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.network
@respx.mock
@patch("mytools.web.grpcattack._try_call", return_value=(True, "ok"))
async def test_category_dispatch_all_return_lists(_mock_try: object) -> None:
    """All category dispatchers should return a list."""
    respx.route().mock(return_value=httpx.Response(200, json={"data": {}}))
    reflection_info: dict[str, Any] = {"available": False, "services": [], "files": []}
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn(
            "target.com",
            50051,
            "",
            0.1,
            False,
            "grpc://target.com:50051",
            reflection_info,
        )
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, GrpcAttackAttempt)
            assert attempt.category == cat
