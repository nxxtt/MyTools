#!/usr/bin/env python3
"""Tests for serverlessattack.py."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mytools.web.serverlessattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    ServerlessAttackAttempt,
    ServerlessAttackResult,
    _make_attempt,
    _parse_url,
    _test_cold_start_leak,
    _test_generic,
    _test_timeout_abuse,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)


class TestServerlessAttackAttempt:
    def test_creation(self) -> None:
        a = ServerlessAttackAttempt(
            technique="cold_start_leak",
            category="generic",
            description="desc",
            vulnerable=False,
            details="test",
            error="",
            endpoint="https://target.com",
            response_code=200,
            timing_ms=150.0,
        )
        assert a.technique == "cold_start_leak"
        assert a.timing_ms == 150.0

    def test_frozen(self) -> None:
        a = ServerlessAttackAttempt(
            technique="t",
            category="c",
            description="d",
            vulnerable=False,
            details="",
            error="",
            endpoint="e",
            response_code=200,
            timing_ms=0.0,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestServerlessAttackResult:
    def test_creation(self) -> None:
        r = ServerlessAttackResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            techniques_count=2,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.techniques_count == 2

    def test_frozen(self) -> None:
        r = ServerlessAttackResult(
            target="t",
            host="h",
            port=443,
            tls=True,
            endpoint="e",
            techniques_count=0,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.host = "changed"  # type: ignore[misc]


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        assert set(_CATEGORY_MAP.keys()) == {"generic"}

    def test_generic_techniques(self) -> None:
        assert set(_CATEGORY_MAP["generic"]) == {"cold_start_leak", "timeout_abuse"}

    def test_total_techniques(self) -> None:
        total = sum(len(v) for v in _CATEGORY_MAP.values())
        assert total == 2

    def test_dispatch_matches_map(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_DISPATCH

    def test_all_dispatches_are_coroutines(self) -> None:
        import inspect

        for cat, fn in _CATEGORY_DISPATCH.items():
            assert inspect.iscoroutinefunction(fn), f"{cat} is not a coroutine"


class TestParseUrl:
    def test_https(self) -> None:
        host, path, _port, tls = _parse_url("https://target.com/api")
        assert host == "target.com"
        assert tls is True
        assert path == "/api"

    def test_http(self) -> None:
        host, _path, _port, tls = _parse_url("http://target.com")
        assert host == "target.com"
        assert tls is False

    def test_custom_port(self) -> None:
        _host, _path, port, _tls = _parse_url("https://target.com:8080/api")
        assert port == 8080

    def test_no_scheme(self) -> None:
        host, _path, _port, tls = _parse_url("target.com")
        assert host == "target.com"
        assert tls is True


class TestMakeAttempt:
    def test_creation(self) -> None:
        a = _make_attempt(
            "cold_start_leak",
            "generic",
            "desc",
            True,
            "details",
            "",
            "url",
            200,
            1500.0,
        )
        assert a.vulnerable is True
        assert a.timing_ms == 1500.0

    def test_no_timing(self) -> None:
        a = _make_attempt(
            "cold_start_leak", "generic", "desc", False, "details", "", "url", 200
        )
        assert a.timing_ms == 0.0


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = ServerlessAttackResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            techniques_count=2,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Serverless Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = ServerlessAttackAttempt(
            technique="cold_start_leak",
            category="generic",
            description="desc",
            vulnerable=True,
            details="leak found",
            error="",
            endpoint="https://target.com",
            response_code=200,
            timing_ms=1500.0,
        )
        r = ServerlessAttackResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            techniques_count=2,
            attempts=[a],
            vulnerable_techniques=["cold_start_leak"],
            issues=["Test issue"],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output
        assert "Issues:" in output


class TestCLI:
    def test_build_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com/api"])
        assert args.url == "https://target.com/api"

    def test_build_parser_with_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com/api", "-c", "generic"])
        assert args.categories == ["generic"]


@pytest.mark.asyncio
@pytest.mark.network
@respx.mock
async def test_category_dispatch_all_return_lists() -> None:
    """All category dispatchers should return a list."""
    respx.route().mock(
        return_value=httpx.Response(
            200, json={"status": "ok"}, headers={"content-type": "application/json"}
        )
    )
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn("target.com", 443, "", 0.1, True, "https://target.com")
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, ServerlessAttackAttempt)
            assert attempt.category == cat


class TestColdStartLeak:
    def _client(self, resp) -> MagicMock:
        client = MagicMock()
        client.get = AsyncMock(return_value=resp)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        return client

    @pytest.mark.asyncio
    async def test_timing_signals(self) -> None:
        resp = MagicMock()
        resp.status_code = 200
        resp.text = ""
        resp.headers = {}
        client = self._client(resp)
        values: list[float] = [1000.0, 5000.0]
        for i in range(7):
            base = 6000.0 + i * 10
            values.extend([base, base + 0.5])
        with patch("mytools.web.serverlessattack.time.monotonic", side_effect=values):
            attempt = await _test_cold_start_leak("https://target.com", 5.0, client)
        assert attempt.vulnerable is True
        assert "slow_first_request" in attempt.details
        assert "timing_diff" in attempt.details

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        client = MagicMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        attempt = await _test_cold_start_leak("https://target.com", 5.0, client)
        assert attempt.vulnerable is False


class TestTimeoutAbuse:
    def _resp(self) -> MagicMock:
        resp = MagicMock()
        resp.status_code = 503
        resp.text = "request timeout"
        resp.headers = {}
        return resp

    @pytest.mark.asyncio
    async def test_slow_and_chunked(self) -> None:
        client = MagicMock()
        resp = self._resp()
        client.post = AsyncMock(return_value=resp)
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        values: list[float] = []
        for i in range(6):
            base = float(100 * i)
            values.extend([base, base + 11.0])
        values.extend([700.0, 707.0])
        with patch("mytools.web.serverlessattack.time.monotonic", side_effect=values):
            attempt = await _test_timeout_abuse("https://target.com", 5.0, client)
        assert attempt.vulnerable is True
        assert "status:503" in attempt.details
        assert "slow_response" in attempt.details
        assert "chunked_slow" in attempt.details

    @pytest.mark.asyncio
    async def test_client_timeout(self) -> None:
        client = MagicMock()
        client.post = AsyncMock(side_effect=httpx.TimeoutException("timed out"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        attempt = await _test_timeout_abuse("https://target.com", 5.0, client)
        assert attempt.vulnerable is True
        assert "client_timeout" in attempt.details

    @pytest.mark.asyncio
    async def test_generic_error(self) -> None:
        client = MagicMock()
        client.post = AsyncMock(side_effect=RuntimeError("boom"))
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        attempt = await _test_timeout_abuse("https://target.com", 5.0, client)
        assert attempt.vulnerable is True
        assert "connection_error" in attempt.details

    @pytest.mark.asyncio
    async def test_chunked_exception(self) -> None:
        client = MagicMock()
        resp = self._resp()
        client.post = AsyncMock(
            side_effect=[resp] * 6 + [httpx.TimeoutException("timed out")]
        )
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        values: list[float] = []
        for i in range(6):
            base = float(100 * i)
            values.extend([base, base + 0.5])
        values.extend([700.0])
        with patch("mytools.web.serverlessattack.time.monotonic", side_effect=values):
            attempt = await _test_timeout_abuse("https://target.com", 5.0, client)
        assert attempt.vulnerable is True


class TestGeneric:
    @pytest.mark.asyncio
    async def test_exception_in_tester(self) -> None:
        ok = _make_attempt(
            "timeout_abuse",
            "generic",
            "",
            False,
            "",
            "",
            "https://target.com",
            200,
        )
        with (
            patch(
                "mytools.web.serverlessattack._test_cold_start_leak",
                AsyncMock(side_effect=OSError("boom")),
            ),
            patch(
                "mytools.web.serverlessattack._test_timeout_abuse",
                AsyncMock(return_value=[ok]),
            ),
        ):
            results = await _test_generic(
                "target.com", 443, "", 5.0, True, "https://target.com"
            )
        assert len(results) == 2
        assert results[0].error != ""
        assert results[0].technique == "cold_start_leak"


class TestPrintResultsExtra:
    def test_secure_category(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = ServerlessAttackAttempt(
            technique="cold_start_leak",
            category="generic",
            description="desc",
            vulnerable=False,
            details="no signals",
            error="",
            endpoint="https://target.com",
            response_code=200,
            timing_ms=100.0,
        )
        r = ServerlessAttackResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            techniques_count=1,
            attempts=[a],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "generic: secure" in output


class TestRunScan:
    def _make_attempt(self, vulnerable: bool) -> ServerlessAttackAttempt:
        return ServerlessAttackAttempt(
            technique="cold_start_leak",
            category="generic",
            description="desc",
            vulnerable=vulnerable,
            details="signals" if vulnerable else "no signals",
            error="",
            endpoint="https://target.com",
            response_code=200,
            timing_ms=100.0,
        )

    @pytest.mark.asyncio
    async def test_vulnerable_with_output(self) -> None:
        attempt = self._make_attempt(True)
        with (
            patch(
                "mytools.web.serverlessattack._CATEGORY_DISPATCH",
                {"generic": AsyncMock(return_value=[attempt])},
            ),
            patch("mytools.web.serverlessattack.print_results"),
            patch("mytools.web.serverlessattack.write_output") as mock_write,
        ):
            result = await run_scan(
                "https://target.com:8080/api", ["generic"], 5.0, "out.json"
            )
        assert result.overall_status == "vulnerable"
        assert result.endpoint == "https://target.com:8080/api"
        mock_write.assert_called_once()

    @pytest.mark.asyncio
    async def test_secure_unknown_category(self) -> None:
        with (
            patch("mytools.web.serverlessattack._CATEGORY_DISPATCH", {}),
            patch("mytools.web.serverlessattack.print_results"),
        ):
            result = await run_scan("https://target.com/api", None, 5.0, None)
        assert result.overall_status == "secure"
        assert result.attempts == []

    @pytest.mark.asyncio
    async def test_tester_error(self) -> None:
        with (
            patch(
                "mytools.web.serverlessattack._CATEGORY_DISPATCH",
                {"generic": AsyncMock(side_effect=OSError("boom"))},
            ),
            patch("mytools.web.serverlessattack.print_results"),
        ):
            result = await run_scan("https://target.com/api", ["generic"], 5.0, None)
        assert result.overall_status == "secure"
        assert len(result.attempts) == 1
        assert result.attempts[0].error != ""
        assert result.issues

    @pytest.mark.asyncio
    async def test_no_path_target(self) -> None:
        with (
            patch(
                "mytools.web.serverlessattack._CATEGORY_DISPATCH",
                {"generic": AsyncMock(return_value=[])},
            ),
            patch("mytools.web.serverlessattack.print_results"),
        ):
            result = await run_scan("https://target.com", None, 5.0, None)
        assert result.overall_status == "secure"
        assert result.endpoint == "https://target.com"


class TestRunOnce:
    def _make_result(self, status: str) -> ServerlessAttackResult:
        return ServerlessAttackResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            techniques_count=0,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status=status,
        )

    def test_vulnerable(self, base_ns) -> None:
        base_ns.url = "https://target.com/api"
        base_ns.timeout = 5.0
        base_ns.output = None
        with patch(
            "mytools.web.serverlessattack.run_scan",
            AsyncMock(return_value=self._make_result("vulnerable")),
        ) as mock_run:
            assert run_once(base_ns) == 1
        mock_run.assert_called_once()

    def test_secure(self, base_ns) -> None:
        base_ns.url = "https://target.com/api"
        base_ns.timeout = 5.0
        base_ns.output = None
        with patch(
            "mytools.web.serverlessattack.run_scan",
            AsyncMock(return_value=self._make_result("secure")),
        ):
            assert run_once(base_ns) == 0


class TestMain:
    def test_main(self) -> None:
        with patch(
            "mytools.web.serverlessattack.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()


class TestMainGuard:
    def test_guard(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-serverless"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.serverlessattack", run_name="__main__")
        assert exc_info.value.code == 0
