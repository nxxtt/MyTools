#!/usr/bin/env python3
"""Tests for lambdaattack.py."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mytools.web.lambdaattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    LambdaAttackAttempt,
    LambdaAttackResult,
    _extract_env_vars,
    _extract_error_details,
    _is_lambda_response,
    _make_attempt,
    _parse_url,
    _test_env_var_leak,
    _test_lambda,
    _test_layer_enumeration,
    _test_temp_file_persistence,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)


class TestLambdaAttackAttempt:
    def test_creation(self) -> None:
        a = LambdaAttackAttempt(
            technique="env_var_leak",
            category="lambda",
            description="desc",
            vulnerable=False,
            details="test",
            error="",
            endpoint="https://target.com/api",
            response_code=200,
            leaked_vars=[],
            leak_count=0,
        )
        assert a.technique == "env_var_leak"
        assert a.vulnerable is False
        assert a.leak_count == 0

    def test_frozen(self) -> None:
        a = LambdaAttackAttempt(
            technique="t",
            category="c",
            description="d",
            vulnerable=False,
            details="",
            error="",
            endpoint="e",
            response_code=200,
            leaked_vars=[],
            leak_count=0,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestLambdaAttackResult:
    def test_creation(self) -> None:
        r = LambdaAttackResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            lambda_detected=False,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.lambda_detected is False

    def test_frozen(self) -> None:
        r = LambdaAttackResult(
            target="t",
            host="h",
            port=443,
            tls=True,
            endpoint="e",
            lambda_detected=False,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.host = "changed"  # type: ignore[misc]


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        assert set(_CATEGORY_MAP.keys()) == {"lambda"}

    def test_lambda_techniques(self) -> None:
        assert set(_CATEGORY_MAP["lambda"]) == {
            "env_var_leak",
            "layer_enumeration",
            "temp_file_persistence",
        }

    def test_total_techniques(self) -> None:
        total = sum(len(v) for v in _CATEGORY_MAP.values())
        assert total == 3

    def test_dispatch_matches_map(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_DISPATCH

    def test_all_dispatches_are_coroutines(self) -> None:
        import inspect

        for cat, fn in _CATEGORY_DISPATCH.items():
            assert inspect.iscoroutinefunction(fn), f"{cat} is not a coroutine"


class TestExtractEnvVars:
    def test_finds_aws_keys(self) -> None:
        body = "Error: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        found = _extract_env_vars(body, {})
        assert "AWS_ACCESS_KEY_ID" in found

    def test_finds_secret(self) -> None:
        body = "SECRET_KEY=abc123"
        found = _extract_env_vars(body, {})
        assert any("SECRET_" in f for f in found)

    def test_no_leak(self) -> None:
        body = "Hello world"
        found = _extract_env_vars(body, {})
        assert found == []

    def test_finds_arn(self) -> None:
        body = "arn:aws:lambda:us-east-1:123456789012:function:my-func"
        found = _extract_env_vars(body, {})
        assert any("arn:aws" in f for f in found)


class TestIsLambdaResponse:
    def test_detects_amzn_header(self) -> None:
        assert _is_lambda_response({"x-amzn-requestid": "abc"}, "") is True

    def test_detects_lambda_server(self) -> None:
        assert _is_lambda_response({"server": "aws-lambda"}, "") is True

    def test_detects_body_signature(self) -> None:
        assert _is_lambda_response({}, "REPORT RequestId: abc") is True

    def test_not_lambda(self) -> None:
        assert _is_lambda_response({}, "Hello world") is False


class TestExtractErrorDetails:
    def test_has_traceback(self) -> None:
        body = 'Traceback (most recent call last):\n  File "handler.py", line 1'
        result = _extract_error_details(body)
        assert result["has_traceback"] is True

    def test_finds_signatures(self) -> None:
        body = "ModuleNotFoundError: No module named 'requests'"
        result = _extract_error_details(body)
        assert "ModuleNotFoundError" in result["signatures_found"]

    def test_finds_arns(self) -> None:
        body = "arn:aws:lambda:us-east-1:123456789012:function:my-func"
        result = _extract_error_details(body)
        assert "arns_found" in result
        assert len(result["arns_found"]) > 0


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

    def test_grpc_scheme(self) -> None:
        _host, _path, _port, tls = _parse_url("grpcs://target.com")
        assert tls is True


class TestMakeAttempt:
    def test_creation(self) -> None:
        a = _make_attempt(
            "env_var_leak",
            "lambda",
            "desc",
            True,
            "details",
            "",
            "url",
            200,
            ["AWS_KEY"],
        )
        assert a.vulnerable is True
        assert a.leak_count == 1
        assert a.leaked_vars == ["AWS_KEY"]

    def test_no_leak(self) -> None:
        a = _make_attempt(
            "env_var_leak", "lambda", "desc", False, "details", "", "url", 200
        )
        assert a.leak_count == 0


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = LambdaAttackResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            lambda_detected=False,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Lambda Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = LambdaAttackAttempt(
            technique="env_var_leak",
            category="lambda",
            description="desc",
            vulnerable=True,
            details="leak found",
            error="",
            endpoint="https://target.com",
            response_code=200,
            leaked_vars=["AWS_KEY"],
            leak_count=1,
        )
        r = LambdaAttackResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            lambda_detected=True,
            attempts=[a],
            vulnerable_techniques=["env_var_leak"],
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
        args = parser.parse_args(["https://target.com/api", "-c", "lambda"])
        assert args.categories == ["lambda"]


@pytest.mark.asyncio
@pytest.mark.network
@respx.mock
async def test_category_dispatch_all_return_lists() -> None:
    """All category dispatchers should return a list."""
    respx.route().mock(return_value=httpx.Response(404, text="Not Found"))
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn("target.com", 443, "", 0.1, True, "https://target.com")
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, LambdaAttackAttempt)
            assert attempt.category == cat


class TestEnvVarLeak:
    @pytest.mark.asyncio
    async def test_lambda_response_leak(self) -> None:
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "Error: AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        resp.headers = {"x-amzn-requestid": "abc123"}
        client.post = AsyncMock(return_value=resp)
        attempt = await _test_env_var_leak("https://target.com/api", 5.0, client)
        assert attempt.vulnerable is True
        assert "AWS_ACCESS_KEY_ID" in attempt.leaked_vars

    @pytest.mark.asyncio
    async def test_no_leak(self) -> None:
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "Hello world"
        resp.headers = {}
        client.post = AsyncMock(return_value=resp)
        attempt = await _test_env_var_leak("https://target.com/api", 5.0, client)
        assert attempt.vulnerable is False

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        client = MagicMock()
        client.post = AsyncMock(side_effect=httpx.RequestError("timeout"))
        attempt = await _test_env_var_leak("https://target.com/api", 5.0, client)
        assert attempt.vulnerable is False
        assert attempt.details == "No env vars detected"


class TestLayerEnumerationError:
    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        client = MagicMock()
        client.post = AsyncMock(side_effect=httpx.RequestError("timeout"))
        attempt = await _test_layer_enumeration("https://target.com/api", 5.0, client)
        assert attempt.vulnerable is False
        assert attempt.details == "No layer info leaked"


class TestTempFilePersistence:
    @pytest.mark.asyncio
    async def test_marker_persists(self) -> None:
        async def fake_post(url, content=None, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            text = (
                content.decode("utf-8", errors="ignore")
                if isinstance(content, bytes)
                else str(content)
            )
            resp.text = text
            resp.headers = {}
            return resp

        client = MagicMock()
        client.post = AsyncMock(side_effect=fake_post)
        attempt = await _test_temp_file_persistence(
            "https://target.com/api", 5.0, client
        )
        assert attempt.vulnerable is True

    @pytest.mark.asyncio
    async def test_arns_leak(self) -> None:
        client = MagicMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "arn:aws:lambda:us-east-1:123456789012:function:my-func"
        resp.headers = {}
        client.post = AsyncMock(return_value=resp)
        attempt = await _test_temp_file_persistence(
            "https://target.com/api", 5.0, client
        )
        assert attempt.vulnerable is True
        assert "arns:" in attempt.details

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        client = MagicMock()
        client.post = AsyncMock(side_effect=httpx.RequestError("timeout"))
        attempt = await _test_temp_file_persistence(
            "https://target.com/api", 5.0, client
        )
        assert attempt.vulnerable is False
        assert attempt.details == "No persistence signals detected"


class TestLambda:
    @pytest.mark.asyncio
    async def test_exception_in_tester(self) -> None:
        ok = _make_attempt(
            "layer_enumeration", "lambda", "", False, "", "", "https://target.com", 200
        )
        with (
            patch(
                "mytools.web.lambdaattack._test_env_var_leak",
                AsyncMock(side_effect=OSError("boom")),
            ),
            patch(
                "mytools.web.lambdaattack._test_layer_enumeration",
                AsyncMock(return_value=[ok]),
            ),
            patch(
                "mytools.web.lambdaattack._test_temp_file_persistence",
                AsyncMock(return_value=[ok]),
            ),
        ):
            results = await _test_lambda(
                "target.com", 443, "", 5.0, True, "https://target.com"
            )
        assert len(results) == 3
        assert results[0].error != ""
        assert results[0].technique == "env_var_leak"


class TestPrintResultsExtra:
    def test_secure_category(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = LambdaAttackAttempt(
            technique="env_var_leak",
            category="lambda",
            description="desc",
            vulnerable=False,
            details="No env vars detected",
            error="",
            endpoint="https://target.com",
            response_code=200,
            leaked_vars=[],
            leak_count=0,
        )
        r = LambdaAttackResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            lambda_detected=False,
            attempts=[a],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "lambda: secure" in output


class TestRunScan:
    def _make_result_attempt(self, vulnerable: bool, leak_count: int = 0):
        return LambdaAttackAttempt(
            technique="env_var_leak",
            category="lambda",
            description="desc",
            vulnerable=vulnerable,
            details="leak found" if vulnerable else "no leak",
            error="",
            endpoint="https://target.com",
            response_code=200,
            leaked_vars=["AWS_KEY"] if leak_count else [],
            leak_count=leak_count,
        )

    @pytest.mark.asyncio
    async def test_vulnerable_with_output(self) -> None:
        attempt = self._make_result_attempt(True, 1)
        with (
            patch(
                "mytools.web.lambdaattack._CATEGORY_DISPATCH",
                {"lambda": AsyncMock(return_value=[attempt])},
            ),
            patch("mytools.web.lambdaattack.print_results"),
            patch("mytools.web.lambdaattack.write_output") as mock_write,
        ):
            result = await run_scan(
                "https://target.com:8080/api", ["lambda"], 5.0, "out.json"
            )
        assert result.overall_status == "vulnerable"
        assert result.lambda_detected is True
        assert result.endpoint == "https://target.com:8080/api"
        mock_write.assert_called_once()

    @pytest.mark.asyncio
    async def test_secure(self) -> None:
        attempt = self._make_result_attempt(False, 0)
        with (
            patch(
                "mytools.web.lambdaattack._CATEGORY_DISPATCH",
                {"lambda": AsyncMock(return_value=[attempt])},
            ),
            patch("mytools.web.lambdaattack.print_results"),
        ):
            result = await run_scan("https://target.com/api", ["lambda"], 5.0, None)
        assert result.overall_status == "secure"
        assert result.lambda_detected is False

    @pytest.mark.asyncio
    async def test_unknown_category(self) -> None:
        with (
            patch("mytools.web.lambdaattack._CATEGORY_DISPATCH", {}),
            patch("mytools.web.lambdaattack.print_results"),
        ):
            result = await run_scan("https://target.com/api", None, 5.0, None)
        assert result.overall_status == "secure"
        assert result.attempts == []

    @pytest.mark.asyncio
    async def test_tester_error(self) -> None:
        with (
            patch(
                "mytools.web.lambdaattack._CATEGORY_DISPATCH",
                {"lambda": AsyncMock(side_effect=OSError("boom"))},
            ),
            patch("mytools.web.lambdaattack.print_results"),
        ):
            result = await run_scan("https://target.com/api", ["lambda"], 5.0, None)
        assert result.overall_status == "secure"
        assert len(result.attempts) == 1
        assert result.attempts[0].error != ""
        assert result.issues

    @pytest.mark.asyncio
    async def test_no_path(self) -> None:
        with (
            patch("mytools.web.lambdaattack._CATEGORY_DISPATCH", {}),
            patch("mytools.web.lambdaattack.print_results"),
        ):
            result = await run_scan("https://target.com", None, 5.0, None)
        assert result.overall_status == "secure"
        assert result.endpoint == "https://target.com"


class TestRunOnce:
    def _make_result(self, status: str) -> LambdaAttackResult:
        return LambdaAttackResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            lambda_detected=False,
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
            "mytools.web.lambdaattack.run_scan",
            AsyncMock(return_value=self._make_result("vulnerable")),
        ) as mock_run:
            assert run_once(base_ns) == 1
        mock_run.assert_called_once()

    def test_secure(self, base_ns) -> None:
        base_ns.url = "https://target.com/api"
        base_ns.timeout = 5.0
        base_ns.output = None
        with patch(
            "mytools.web.lambdaattack.run_scan",
            AsyncMock(return_value=self._make_result("secure")),
        ):
            assert run_once(base_ns) == 0


class TestMain:
    def test_main(self) -> None:
        with patch(
            "mytools.web.lambdaattack.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()


class TestMainGuard:
    def test_guard(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-lambda"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.lambdaattack", run_name="__main__")
        assert exc_info.value.code == 0
