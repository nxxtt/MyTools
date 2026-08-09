"""Testes do modulo thriftattack.py — Thrift Attack Testing."""

from __future__ import annotations

import argparse
import types
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from thriftpy2.thrift import TApplicationException

import mytools.web.thriftattack as thriftattack_module
from mytools.web.thriftattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    _COMMON_THRIFT_SERVICES,
    _MINIMAL_THRIFT_IDL,
    ThriftAttackAttempt,
    ThriftAttackResult,
    _create_probe_thrift,
    _make_attempt,
    _parse_url,
    _test_binary_protocol,
    _test_method_enumeration,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)

# ─── Dataclass Tests ─────────────────────────────────────────────────────────


class TestThriftAttackAttempt:
    def test_creation(self) -> None:
        a = ThriftAttackAttempt(
            technique="service_enumeration",
            category="method_enumeration",
            description="desc",
            vulnerable=False,
            details="test",
            error="",
            host="target.com",
            port=9090,
            protocol="binary",
            response_code=200,
        )
        assert a.technique == "service_enumeration"
        assert a.category == "method_enumeration"
        assert a.vulnerable is False

    def test_frozen(self) -> None:
        a = ThriftAttackAttempt(
            technique="t",
            category="c",
            description="d",
            vulnerable=False,
            details="",
            error="",
            host="h",
            port=9090,
            protocol="binary",
            response_code=0,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestThriftAttackResult:
    def test_creation(self) -> None:
        r = ThriftAttackResult(
            target="thrift://target.com:9090",
            host="target.com",
            port=9090,
            tls=False,
            services_found=3,
            methods_found=10,
            protocol_detected="binary",
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.protocol_detected == "binary"

    def test_frozen(self) -> None:
        r = ThriftAttackResult(
            target="t",
            host="h",
            port=9090,
            tls=False,
            services_found=0,
            methods_found=0,
            protocol_detected="binary",
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
            target="thrift://target.com:9090",
            host="target.com",
            port=9090,
            tls=False,
            services_found=0,
            methods_found=0,
            protocol_detected="binary",
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Thrift Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = ThriftAttackResult(
            target="thrift://target.com:9090",
            host="target.com",
            port=9090,
            tls=False,
            services_found=3,
            methods_found=10,
            protocol_detected="binary",
            attempts=[],
            vulnerable_techniques=["service_enumeration"],
            issues=["Errors: test_error"],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output
        assert "Issues:" in output


# ─── Print Results: Category Grouping ───────────────────────────────────────


class TestPrintResultsCategoryGroups:
    def test_vulnerable_and_secure_categories(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        r = ThriftAttackResult(
            target="thrift://target.com:9090",
            host="target.com",
            port=9090,
            tls=False,
            services_found=3,
            methods_found=10,
            protocol_detected="binary",
            attempts=[
                _attempt(
                    "service_enumeration",
                    "method_enumeration",
                    vuln=True,
                    details="Services: DataService",
                ),
                _attempt("field_type_confusion", "binary_protocol"),
            ],
            vulnerable_techniques=["service_enumeration"],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "method_enumeration: 1 vulnerable(s)" in output
        assert "service_enumeration: Services: DataService" in output
        assert "binary_protocol: secure" in output


# ─── CLI Tests ───────────────────────────────────────────────────────────────


class TestCLI:
    def test_build_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["thrift://target.com:9090"])
        assert args.url == "thrift://target.com:9090"

    def test_build_parser_with_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["thrift://target.com:9090", "-c", "method_enumeration"]
        )
        assert args.categories == ["method_enumeration"]

    def test_build_parser_all_choices(self) -> None:
        parser = build_parser()
        for cat in _CATEGORY_MAP:
            args = parser.parse_args(["thrift://target.com:9090", "-c", cat])
            assert args.categories == [cat]


# ─── Async Category Tests (Mocked) ──────────────────────────────────────────


def _attempt(
    tech: str,
    cat: str,
    *,
    vuln: bool = False,
    details: str = "",
    error: str = "",
) -> ThriftAttackAttempt:
    return _make_attempt(tech, cat, tech, vuln, details, error, "target.com", 9090)


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


# ─── _test_method_enumeration: Exception / Else Branches ────────────────────


class _MissingMethodsClient:
    def close(self) -> None:
        return None


class TestMethodEnumerationBranches:
    @pytest.mark.asyncio
    async def test_method_discovery_missing_attrs(self) -> None:
        with patch(
            "mytools.web.thriftattack.make_client",
            return_value=_MissingMethodsClient(),
        ):
            results = await _test_method_enumeration("target.com", 9090, 0.1, False)
        md = results[1]
        assert md.technique == "method_discovery"
        assert md.vulnerable is False
        assert md.details == "No methods"

    @pytest.mark.asyncio
    async def test_service_enumeration_tapp_and_generic_errors(self) -> None:
        calls = 0

        def factory(*args: Any, **kwargs: Any) -> MagicMock:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise TApplicationException(type=TApplicationException.UNKNOWN_METHOD)
            raise ConnectionRefusedError("refused")

        with patch("mytools.web.thriftattack.make_client", side_effect=factory):
            results = await _test_method_enumeration("target.com", 9090, 0.1, False)
        svc = results[0]
        assert svc.vulnerable is True
        assert "DataService" in svc.details

    @pytest.mark.asyncio
    async def test_method_discovery_tapp_and_generic_errors(self) -> None:
        calls = 0

        def factory(*args: Any, **kwargs: Any) -> MagicMock:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise TApplicationException(type=TApplicationException.UNKNOWN_METHOD)
            raise ConnectionRefusedError("refused")

        with patch("mytools.web.thriftattack.make_client", side_effect=factory):
            results = await _test_method_enumeration("target.com", 9090, 0.1, False)
        md = results[1]
        assert md.vulnerable is False
        assert md.details == "No methods"

    @pytest.mark.asyncio
    async def test_parameter_leak_tapp_exception(self) -> None:
        client = MagicMock()
        client.getData.side_effect = TApplicationException(
            type=TApplicationException.UNKNOWN_METHOD, message="Unknown method getData"
        )
        with patch("mytools.web.thriftattack.make_client", return_value=client):
            results = await _test_method_enumeration("target.com", 9090, 0.1, False)
        pl = results[2]
        assert pl.vulnerable is True
        assert "Error:" in pl.details

    @pytest.mark.asyncio
    async def test_parameter_leak_generic_exception(self) -> None:
        client = MagicMock()
        client.getData.side_effect = ConnectionRefusedError("refused")
        with patch("mytools.web.thriftattack.make_client", return_value=client):
            results = await _test_method_enumeration("target.com", 9090, 0.1, False)
        pl = results[2]
        assert pl.vulnerable is False
        assert pl.details == "Connection failed"

    @pytest.mark.asyncio
    async def test_version_fingerprint_tapp_exception(self) -> None:
        client = MagicMock()
        client.ping.side_effect = TApplicationException(
            type=TApplicationException.UNKNOWN_METHOD
        )
        with patch("mytools.web.thriftattack.make_client", return_value=client):
            results = await _test_method_enumeration("target.com", 9090, 0.1, False)
        vf = results[3]
        assert vf.vulnerable is True
        assert vf.details == "Thrift server responded"

    @pytest.mark.asyncio
    async def test_version_fingerprint_generic_exception(self) -> None:
        client = MagicMock()
        client.ping.side_effect = ConnectionRefusedError("refused")
        with patch("mytools.web.thriftattack.make_client", return_value=client):
            results = await _test_method_enumeration("target.com", 9090, 0.1, False)
        vf = results[3]
        assert vf.vulnerable is False
        assert vf.details == "Connection failed"

    @pytest.mark.asyncio
    async def test_unknown_tech_else(self) -> None:
        fn = _test_method_enumeration
        code = fn.__code__
        new_consts = tuple(
            (*c, "unknown_tech")
            if isinstance(c, tuple) and "service_enumeration" in c
            else c
            for c in code.co_consts
        )
        new_fn: Any = types.FunctionType(
            code.replace(co_consts=new_consts), fn.__globals__
        )
        with patch("mytools.web.thriftattack.make_client", return_value=MagicMock()):
            results = await new_fn("target.com", 9090, 0.1, False)
        assert len(results) == 5
        assert results[-1].technique == "unknown_tech"
        assert results[-1].vulnerable is False
        assert results[-1].details == ""

    @pytest.mark.asyncio
    async def test_outer_attempt_error(self) -> None:
        real_make = thriftattack_module._make_attempt
        calls = 0

        def flaky(*args: Any, **kwargs: Any) -> ThriftAttackAttempt:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("boom")
            return real_make(*args, **kwargs)

        with (
            patch("mytools.web.thriftattack.make_client", return_value=MagicMock()),
            patch("mytools.web.thriftattack._make_attempt", side_effect=flaky),
        ):
            results = await _test_method_enumeration("target.com", 9090, 0.1, False)
        assert results[0].error == "boom"
        assert results[0].vulnerable is False
        assert results[0].response_code == 0
        assert results[1].technique == "method_discovery"


# ─── _test_binary_protocol: Exception / Else Branches ───────────────────────


class TestBinaryProtocolBranches:
    @pytest.mark.asyncio
    async def test_field_type_confusion_tapp_exception(self) -> None:
        client = MagicMock()
        client.getData.side_effect = TApplicationException(
            type=TApplicationException.INVALID_MESSAGE_TYPE
        )
        with patch("mytools.web.thriftattack.make_client", return_value=client):
            results = await _test_binary_protocol("target.com", 9090, 0.1, False)
        ftc = results[0]
        assert ftc.vulnerable is True
        assert "Type confusion" in ftc.details

    @pytest.mark.asyncio
    async def test_field_type_confusion_generic_exception(self) -> None:
        client = MagicMock()
        client.getData.side_effect = ConnectionRefusedError("refused")
        with patch("mytools.web.thriftattack.make_client", return_value=client):
            results = await _test_binary_protocol("target.com", 9090, 0.1, False)
        ftc = results[0]
        assert ftc.vulnerable is False
        assert ftc.details == "Connection failed"

    @pytest.mark.asyncio
    async def test_collection_overflow_generic_exception(self) -> None:
        client = MagicMock()
        client.getData.side_effect = ConnectionRefusedError("refused")
        with patch("mytools.web.thriftattack.make_client", return_value=client):
            results = await _test_binary_protocol("target.com", 9090, 0.1, False)
        co = results[1]
        assert co.vulnerable is False
        assert "timeout" in co.details

    @pytest.mark.asyncio
    async def test_string_encoding_abuse_connection_error(self) -> None:
        def factory(*args: Any, **kwargs: Any) -> MagicMock:
            raise ConnectionRefusedError("refused")

        with patch("mytools.web.thriftattack.make_client", side_effect=factory):
            results = await _test_binary_protocol("target.com", 9090, 0.1, False)
        sea = results[2]
        assert sea.vulnerable is False
        assert sea.details == "Connection failed"

    @pytest.mark.asyncio
    async def test_boolean_coercion_tapp_exception(self) -> None:
        client = MagicMock()
        client.isAlive.side_effect = TApplicationException(
            type=TApplicationException.UNKNOWN_METHOD
        )
        with patch("mytools.web.thriftattack.make_client", return_value=client):
            results = await _test_binary_protocol("target.com", 9090, 0.1, False)
        bc = results[3]
        assert bc.vulnerable is True
        assert "Boolean coercion" in bc.details

    @pytest.mark.asyncio
    async def test_boolean_coercion_generic_exception(self) -> None:
        client = MagicMock()
        client.isAlive.side_effect = ConnectionRefusedError("refused")
        with patch("mytools.web.thriftattack.make_client", return_value=client):
            results = await _test_binary_protocol("target.com", 9090, 0.1, False)
        bc = results[3]
        assert bc.vulnerable is False
        assert bc.details == "Connection failed"

    @pytest.mark.asyncio
    async def test_unknown_tech_else(self) -> None:
        fn = _test_binary_protocol
        code = fn.__code__
        new_consts = tuple(
            (*c, "unknown_tech")
            if isinstance(c, tuple) and "field_type_confusion" in c
            else c
            for c in code.co_consts
        )
        new_fn: Any = types.FunctionType(
            code.replace(co_consts=new_consts), fn.__globals__
        )
        with patch("mytools.web.thriftattack.make_client", return_value=MagicMock()):
            results = await new_fn("target.com", 9090, 0.1, False)
        assert len(results) == 5
        assert results[-1].technique == "unknown_tech"
        assert results[-1].vulnerable is False
        assert results[-1].details == ""

    @pytest.mark.asyncio
    async def test_outer_attempt_error(self) -> None:
        real_make = thriftattack_module._make_attempt
        calls = 0

        def flaky(*args: Any, **kwargs: Any) -> ThriftAttackAttempt:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("boom")
            return real_make(*args, **kwargs)

        with (
            patch("mytools.web.thriftattack.make_client", return_value=MagicMock()),
            patch("mytools.web.thriftattack._make_attempt", side_effect=flaky),
        ):
            results = await _test_binary_protocol("target.com", 9090, 0.1, False)
        assert results[0].error == "boom"
        assert results[0].vulnerable is False
        assert results[0].response_code == 0
        assert results[1].technique == "collection_overflow"


# ─── run_scan ────────────────────────────────────────────────────────────────


class TestRunScan:
    @pytest.mark.asyncio
    async def test_vulnerable_with_output_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path
    ) -> None:
        async def tester(*args: Any, **kwargs: Any) -> list[ThriftAttackAttempt]:
            return [_attempt("service_enumeration", "method_enumeration", vuln=True)]

        dispatch: dict[str, Any] = {"method_enumeration": tester}
        monkeypatch.setattr(thriftattack_module, "_CATEGORY_DISPATCH", dispatch)
        monkeypatch.setattr(thriftattack_module, "print_results", lambda r: None)
        result = await run_scan(
            "thrift://target.com:9090",
            ["bogus", "method_enumeration"],
            5.0,
            str(tmp_path / "out.json"),
        )
        assert result.overall_status == "vulnerable"
        assert result.host == "target.com"
        assert result.port == 9090
        assert result.protocol_detected == "binary"
        assert (tmp_path / "out.json").exists()

    @pytest.mark.asyncio
    async def test_error_and_secure_default_categories(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        async def boom(*args: Any, **kwargs: Any) -> list[ThriftAttackAttempt]:
            raise RuntimeError("boom")

        dispatch: dict[str, Any] = {
            "method_enumeration": boom,
            "binary_protocol": boom,
        }
        monkeypatch.setattr(thriftattack_module, "_CATEGORY_DISPATCH", dispatch)
        monkeypatch.setattr(thriftattack_module, "print_results", lambda r: None)
        result = await run_scan("thrift://target.com:9090", None, 5.0, None)
        assert result.overall_status == "secure"
        assert result.issues == [
            "Errors: method_enumeration_error, binary_protocol_error"
        ]
        assert any(a.technique == "method_enumeration_error" for a in result.attempts)


# ─── run_once / main ─────────────────────────────────────────────────────────


class TestRunOnce:
    def test_vulnerable_returns_1(self) -> None:
        result = ThriftAttackResult(
            target="thrift://target.com:9090",
            host="target.com",
            port=9090,
            tls=False,
            services_found=0,
            methods_found=0,
            protocol_detected="binary",
            attempts=[],
            vulnerable_techniques=["service_enumeration"],
            issues=[],
            overall_status="vulnerable",
        )
        with patch(
            "mytools.web.thriftattack.run_scan",
            new_callable=AsyncMock,
            return_value=result,
        ):
            args = argparse.Namespace(
                url="thrift://target.com:9090",
                categories=None,
                timeout=5.0,
                output=None,
            )
            assert run_once(args) == 1

    def test_secure_returns_0(self) -> None:
        result = ThriftAttackResult(
            target="thrift://target.com:9090",
            host="target.com",
            port=9090,
            tls=False,
            services_found=0,
            methods_found=0,
            protocol_detected="binary",
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with patch(
            "mytools.web.thriftattack.run_scan",
            new_callable=AsyncMock,
            return_value=result,
        ):
            args = argparse.Namespace(
                url="thrift://target.com:9090",
                categories=None,
                timeout=5.0,
                output=None,
            )
            assert run_once(args) == 0


class TestMain:
    def test_runs_loop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            thriftattack_module,
            "run_main_loop",
            lambda *args, **kwargs: 42,
        )
        assert main() == 42

    def test_main_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import runpy

        with (
            patch("sys.argv", ["mytools-thrift"]),
            patch(
                "mytools.core.utils.run_main_loop", side_effect=SystemExit(0)
            ) as mock_loop,
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.thriftattack", run_name="__main__")
        assert exc_info.value.code == 0
        assert mock_loop.call_count == 1
