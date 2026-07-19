#!/usr/bin/env python3
"""Tests for lambdaattack.py."""

from __future__ import annotations

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
    build_parser,
    print_results,
)


class TestLambdaAttackAttempt:
    def test_creation(self) -> None:
        a = LambdaAttackAttempt(
            technique="env_var_leak", category="lambda",
            description="desc", vulnerable=False, details="test", error="",
            endpoint="https://target.com/api", response_code=200,
            leaked_vars=[], leak_count=0,
        )
        assert a.technique == "env_var_leak"
        assert a.vulnerable is False
        assert a.leak_count == 0

    def test_frozen(self) -> None:
        a = LambdaAttackAttempt(
            technique="t", category="c", description="d",
            vulnerable=False, details="", error="", endpoint="e",
            response_code=200, leaked_vars=[], leak_count=0,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestLambdaAttackResult:
    def test_creation(self) -> None:
        r = LambdaAttackResult(
            target="https://target.com", host="target.com", port=443, tls=True,
            endpoint="https://target.com", lambda_detected=False,
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.lambda_detected is False

    def test_frozen(self) -> None:
        r = LambdaAttackResult(
            target="t", host="h", port=443, tls=True, endpoint="e",
            lambda_detected=False, attempts=[], vulnerable_techniques=[],
            issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.host = "changed"  # type: ignore[misc]


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        assert set(_CATEGORY_MAP.keys()) == {"lambda"}

    def test_lambda_techniques(self) -> None:
        assert set(_CATEGORY_MAP["lambda"]) == {"env_var_leak", "layer_enumeration", "temp_file_persistence"}

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
        body = "Traceback (most recent call last):\n  File \"handler.py\", line 1"
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


class TestMakeAttempt:
    def test_creation(self) -> None:
        a = _make_attempt("env_var_leak", "lambda", "desc", True, "details", "", "url", 200, ["AWS_KEY"])
        assert a.vulnerable is True
        assert a.leak_count == 1
        assert a.leaked_vars == ["AWS_KEY"]

    def test_no_leak(self) -> None:
        a = _make_attempt("env_var_leak", "lambda", "desc", False, "details", "", "url", 200)
        assert a.leak_count == 0


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = LambdaAttackResult(
            target="https://target.com", host="target.com", port=443, tls=True,
            endpoint="https://target.com", lambda_detected=False,
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Lambda Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = LambdaAttackAttempt(
            technique="env_var_leak", category="lambda", description="desc",
            vulnerable=True, details="leak found", error="",
            endpoint="https://target.com", response_code=200,
            leaked_vars=["AWS_KEY"], leak_count=1,
        )
        r = LambdaAttackResult(
            target="https://target.com", host="target.com", port=443, tls=True,
            endpoint="https://target.com", lambda_detected=True,
            attempts=[a], vulnerable_techniques=["env_var_leak"],
            issues=["Test issue"], overall_status="vulnerable",
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
