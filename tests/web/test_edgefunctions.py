#!/usr/bin/env python3
"""Tests for edgefunctions.py."""

from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mytools.web.edgefunctions import (
    _AZURE_SETTINGS_PATTERNS,
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    _VERCEL_SECRET_PATTERNS,
    EdgeFunctionAttempt,
    EdgeFunctionResult,
    _detect_provider,
    _extract_settings,
    _make_attempt,
    _parse_url,
    _test_azure_settings_leak,
    _test_cloud_providers,
    _test_edge_code_injection,
    _test_gcp_iam_bypass,
    _test_kv_store_leak,
    _test_vercel_secret_leak,
    build_parser,
    print_results,
    run_once,
    run_scan,
)


def _ns(**overrides: object) -> argparse.Namespace:
    ns = argparse.Namespace(
        url="https://target.com",
        categories=None,
        timeout=5.0,
        output=None,
    )
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


class TestEdgeFunctionAttempt:
    def test_creation(self) -> None:
        a = EdgeFunctionAttempt(
            technique="azure_settings_leak",
            category="cloud_providers",
            description="desc",
            vulnerable=False,
            details="test",
            error="",
            endpoint="https://target.com",
            provider="azure",
            response_code=200,
        )
        assert a.technique == "azure_settings_leak"
        assert a.provider == "azure"

    def test_frozen(self) -> None:
        a = EdgeFunctionAttempt(
            technique="t",
            category="c",
            description="d",
            vulnerable=False,
            details="",
            error="",
            endpoint="e",
            provider="p",
            response_code=200,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestEdgeFunctionResult:
    def test_creation(self) -> None:
        r = EdgeFunctionResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            provider_detected="vercel",
            techniques_count=5,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.provider_detected == "vercel"

    def test_frozen(self) -> None:
        r = EdgeFunctionResult(
            target="t",
            host="h",
            port=443,
            tls=True,
            endpoint="e",
            provider_detected="p",
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
        assert set(_CATEGORY_MAP.keys()) == {"cloud_providers"}

    def test_cloud_providers_techniques(self) -> None:
        expected = {
            "azure_settings_leak",
            "gcp_iam_bypass",
            "vercel_secret_leak",
            "kv_store_leak",
            "edge_code_injection",
        }
        assert set(_CATEGORY_MAP["cloud_providers"]) == expected

    def test_total_techniques(self) -> None:
        total = sum(len(v) for v in _CATEGORY_MAP.values())
        assert total == 5

    def test_dispatch_matches_map(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_DISPATCH

    def test_all_dispatches_are_coroutines(self) -> None:
        import inspect

        for cat, fn in _CATEGORY_DISPATCH.items():
            assert inspect.iscoroutinefunction(fn), f"{cat} is not a coroutine"


class TestDetectProvider:
    def test_detects_azure(self) -> None:
        headers = {"x-azure-ref": "abc", "server": "Microsoft-IIS"}
        assert _detect_provider(headers, "") == "azure"

    def test_detects_gcp(self) -> None:
        headers = {"x-goog-generation": "123"}
        assert _detect_provider(headers, "") == "gcp"

    def test_detects_vercel(self) -> None:
        headers = {"x-vercel-id": "abc"}
        assert _detect_provider(headers, "") == "vercel"

    def test_detects_cloudflare(self) -> None:
        headers = {"cf-ray": "abc"}
        assert _detect_provider(headers, "") == "cloudflare"

    def test_detects_aws(self) -> None:
        headers = {"x-amz-request-id": "abc"}
        assert _detect_provider(headers, "") == "aws"

    def test_detects_body_signature(self) -> None:
        assert _detect_provider({}, "Edge function error") == "edge_generic"

    def test_unknown(self) -> None:
        assert _detect_provider({}, "Hello world") == "unknown"


class TestExtractSettings:
    def test_finds_azure_settings(self) -> None:
        body = "APPSETTING_WebJobsStorage=DefaultEndpointsProtocol=https"
        found = _extract_settings(body, _AZURE_SETTINGS_PATTERNS)
        assert len(found) > 0

    def test_finds_vercel_secrets(self) -> None:
        body = "sk_live_abc123def456"
        found = _extract_settings(body, _VERCEL_SECRET_PATTERNS)
        assert len(found) > 0

    def test_no_leak(self) -> None:
        body = "Hello world"
        found = _extract_settings(body, _AZURE_SETTINGS_PATTERNS)
        assert found == []


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
        host, path, port, tls = _parse_url("target.com/api")
        assert host == "target.com"
        assert path == "/api"
        assert port == 443
        assert tls is True


class TestMakeAttempt:
    def test_creation(self) -> None:
        a = _make_attempt(
            "azure_settings_leak",
            "cloud_providers",
            "desc",
            True,
            "details",
            "",
            "url",
            "azure",
            200,
        )
        assert a.vulnerable is True
        assert a.provider == "azure"


class TestAzureSettingsLeak:
    @pytest.mark.asyncio
    @respx.mock
    async def test_vulnerable(self) -> None:
        respx.route(method="POST", url__startswith="https://target.com").mock(
            return_value=httpx.Response(
                200,
                text="APPSETTING_Foo=bar WEBSITE_SITE_NAME=example",
                headers={
                    "x-ms-invocation-id": "abc",
                    "x-functions-execution-id": "def",
                },
            )
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_azure_settings_leak(
                "https://target.com", 10.0, client
            )
        assert attempt.vulnerable is True
        assert attempt.response_code == 200
        assert "APPSETTING_" in attempt.details

    @pytest.mark.asyncio
    @respx.mock
    async def test_exception_caught(self) -> None:
        respx.route(method="POST", url__startswith="https://target.com").mock(
            side_effect=httpx.ConnectError("boom")
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_azure_settings_leak(
                "https://target.com", 10.0, client
            )
        assert attempt.vulnerable is False
        assert attempt.response_code == 0


class TestGcpIamBypass:
    @pytest.mark.asyncio
    @respx.mock
    async def test_vulnerable(self) -> None:
        respx.route(method="POST", url__startswith="https://target.com").mock(
            return_value=httpx.Response(200, text='{"ok": true}')
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_gcp_iam_bypass("https://target.com", 10.0, client)
        assert attempt.vulnerable is True
        assert "Bypasses" in attempt.details

    @pytest.mark.asyncio
    @respx.mock
    async def test_not_a_bypass_on_non_200(self) -> None:
        respx.route(method="POST", url__startswith="https://target.com").mock(
            return_value=httpx.Response(404, text="not found")
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_gcp_iam_bypass("https://target.com", 10.0, client)
        assert attempt.vulnerable is False

    @pytest.mark.asyncio
    @respx.mock
    async def test_empty_body_200_not_a_bypass(self) -> None:
        respx.route(method="POST", url__startswith="https://target.com").mock(
            return_value=httpx.Response(200, text="")
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_gcp_iam_bypass("https://target.com", 10.0, client)
        assert attempt.vulnerable is False

    @pytest.mark.asyncio
    @respx.mock
    async def test_blocked(self) -> None:
        respx.route(method="POST", url__startswith="https://target.com").mock(
            return_value=httpx.Response(403, text="Permission denied")
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_gcp_iam_bypass("https://target.com", 10.0, client)
        assert attempt.vulnerable is False

    @pytest.mark.asyncio
    @respx.mock
    async def test_exception_caught(self) -> None:
        respx.route(method="POST", url__startswith="https://target.com").mock(
            side_effect=httpx.ConnectError("boom")
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_gcp_iam_bypass("https://target.com", 10.0, client)
        assert attempt.vulnerable is False


class TestVercelSecretLeak:
    @pytest.mark.asyncio
    @respx.mock
    async def test_vulnerable(self) -> None:
        respx.route(method="POST", url__startswith="https://target.com").mock(
            return_value=httpx.Response(
                200, text="DATABASE_URL=postgres://x sk_live_abc"
            )
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_vercel_secret_leak("https://target.com", 10.0, client)
        assert attempt.vulnerable is True
        assert "DATABASE_URL" in attempt.details

    @pytest.mark.asyncio
    @respx.mock
    async def test_exception_caught(self) -> None:
        respx.route(method="POST", url__startswith="https://target.com").mock(
            side_effect=httpx.ConnectError("boom")
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_vercel_secret_leak("https://target.com", 10.0, client)
        assert attempt.vulnerable is False


class TestKvStoreLeak:
    @pytest.mark.asyncio
    @respx.mock
    async def test_vulnerable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "../kv" in url:
                return httpx.Response(403, text="forbidden")
            if "?action=" in url:
                return httpx.Response(200, text="{}")
            return httpx.Response(200, text="keys: example")

        respx.route(method="GET", url__startswith="https://target.com").mock(
            side_effect=handler
        )
        respx.route(method="POST", url__startswith="https://target.com").mock(
            side_effect=handler
        )
        with patch("mytools.web.edgefunctions._KV_LEAK_PAYLOADS", ["keys"]):
            async with httpx.AsyncClient(verify=False) as client:
                attempt = await _test_kv_store_leak("https://target.com", 10.0, client)
        assert attempt.vulnerable is True
        assert "path_traversal_kv" in attempt.details
        assert "key=keys" in attempt.details
        assert "action=keys" in attempt.details

    @pytest.mark.asyncio
    @respx.mock
    async def test_exception_caught(self) -> None:
        respx.route(method="GET", url__startswith="https://target.com").mock(
            side_effect=httpx.ConnectError("boom")
        )
        respx.route(method="POST", url__startswith="https://target.com").mock(
            side_effect=httpx.ConnectError("boom")
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_kv_store_leak("https://target.com", 10.0, client)
        assert attempt.vulnerable is False


class TestEdgeCodeInjection:
    @pytest.mark.asyncio
    @respx.mock
    async def test_vulnerable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            content = request.content or b""
            if b"etc/passwd" in content:
                return httpx.Response(200, text="root:x:0:0:root:/root:/bin/bash")
            if b"script" in content:
                return httpx.Response(200, text="<script>alert(1)</script>")
            if "x-custom-header" in request.headers:
                return httpx.Response(200, text="stack traceback error {{7*7}}")
            return httpx.Response(200, text="{}")

        respx.route(method="POST", url__startswith="https://target.com").mock(
            side_effect=handler
        )
        with patch(
            "mytools.web.edgefunctions._EDGE_INJECTION_PAYLOADS",
            [{"header": "X-Custom-Header", "value": "{{7*7}}"}],
        ):
            async with httpx.AsyncClient(verify=False) as client:
                attempt = await _test_edge_code_injection(
                    "https://target.com", 10.0, client
                )
        assert attempt.vulnerable is True
        assert "reflected:X-Custom-Header" in attempt.details
        assert "path_traversal" in attempt.details
        assert "xss_reflection" in attempt.details
        assert "error_leak:X-Custom-Header" in attempt.details

    @pytest.mark.asyncio
    @respx.mock
    async def test_exception_caught(self) -> None:
        respx.route(method="POST", url__startswith="https://target.com").mock(
            side_effect=httpx.ConnectError("boom")
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_edge_code_injection(
                "https://target.com", 10.0, client
            )
        assert attempt.vulnerable is False


class TestCloudProvidersTester:
    @pytest.mark.asyncio
    @respx.mock
    async def test_inner_exception(self) -> None:
        with patch(
            "mytools.web.edgefunctions._test_azure_settings_leak",
            new_callable=AsyncMock,
            side_effect=RuntimeError("boom"),
        ):
            results = await _test_cloud_providers(
                "target.com", 443, "", 10.0, True, "https://target.com"
            )
        assert len(results) == 5
        assert results[0].error == "boom"
        assert results[0].vulnerable is False


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = EdgeFunctionResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            provider_detected="unknown",
            techniques_count=5,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Edge Functions Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = EdgeFunctionAttempt(
            technique="azure_settings_leak",
            category="cloud_providers",
            description="desc",
            vulnerable=True,
            details="leak found",
            error="",
            endpoint="https://target.com",
            provider="azure",
            response_code=200,
        )
        r = EdgeFunctionResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            provider_detected="azure",
            techniques_count=5,
            attempts=[a],
            vulnerable_techniques=["azure_settings_leak"],
            issues=["Test issue"],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output
        assert "Issues:" in output

    def test_secure_category(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = EdgeFunctionAttempt(
            technique="azure_settings_leak",
            category="cloud_providers",
            description="desc",
            vulnerable=False,
            details="No Azure settings detected",
            error="",
            endpoint="https://target.com",
            provider="azure",
            response_code=200,
        )
        r = EdgeFunctionResult(
            target="https://target.com",
            host="target.com",
            port=443,
            tls=True,
            endpoint="https://target.com",
            provider_detected="azure",
            techniques_count=1,
            attempts=[a],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "cloud_providers: secure" in output
        assert "SECURE" in output


class TestCLI:
    def test_build_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com/api"])
        assert args.url == "https://target.com/api"

    def test_build_parser_with_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com/api", "-c", "cloud_providers"])
        assert args.categories == ["cloud_providers"]


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
            assert isinstance(attempt, EdgeFunctionAttempt)
            assert attempt.category == cat


class TestRunScan:
    @pytest.mark.asyncio
    async def test_vulnerable_with_provider_detection(self) -> None:
        vuln = _make_attempt(
            "azure_settings_leak",
            "cloud_providers",
            "d",
            True,
            "det",
            "",
            "u",
            "azure",
            200,
        )
        with patch.dict(
            "mytools.web.edgefunctions._CATEGORY_DISPATCH",
            {"cloud_providers": AsyncMock(return_value=[vuln])},
        ):
            result = await run_scan("https://target.com", None, 5.0, None)
        assert result.overall_status == "vulnerable"
        assert result.provider_detected == "azure"
        assert result.vulnerable_techniques == ["azure_settings_leak"]
        assert result.techniques_count == 1

    @pytest.mark.asyncio
    async def test_port_and_path_endpoint(self) -> None:
        with patch.dict(
            "mytools.web.edgefunctions._CATEGORY_DISPATCH",
            {"cloud_providers": AsyncMock(return_value=[])},
        ):
            result = await run_scan(
                "http://target.com:8080/api", ["cloud_providers"], 5.0, None
            )
        assert result.endpoint == "http://target.com:8080/api"
        assert result.port == 8080
        assert result.tls is False
        assert result.overall_status == "secure"
        assert result.provider_detected == "unknown"

    @pytest.mark.asyncio
    async def test_invalid_category_skipped(self) -> None:
        with patch.dict(
            "mytools.web.edgefunctions._CATEGORY_DISPATCH",
            {"cloud_providers": AsyncMock(return_value=[])},
        ):
            result = await run_scan("https://target.com", ["invalid"], 5.0, None)
        assert result.overall_status == "secure"
        assert result.attempts == []

    @pytest.mark.asyncio
    async def test_tester_error_builds_issue(self) -> None:
        with patch.dict(
            "mytools.web.edgefunctions._CATEGORY_DISPATCH",
            {"cloud_providers": AsyncMock(side_effect=RuntimeError("boom"))},
        ):
            result = await run_scan(
                "https://target.com", ["cloud_providers"], 5.0, None
            )
        assert result.overall_status == "secure"
        assert result.attempts[0].error == "boom"
        assert result.issues == ["Errors: cloud_providers_error"]

    @pytest.mark.asyncio
    async def test_output_file_written(self, tmp_path: Path) -> None:
        out = str(tmp_path / "out.json")
        with patch.dict(
            "mytools.web.edgefunctions._CATEGORY_DISPATCH",
            {"cloud_providers": AsyncMock(return_value=[])},
        ):
            result = await run_scan("https://target.com", ["cloud_providers"], 5.0, out)
        assert result.overall_status == "secure"
        assert (tmp_path / "out.json").exists()


class TestRunOnce:
    def test_vulnerable_returns_1(self) -> None:
        r = EdgeFunctionResult(
            target="t",
            host="h",
            port=443,
            tls=True,
            endpoint="e",
            provider_detected="azure",
            techniques_count=1,
            attempts=[],
            vulnerable_techniques=["azure_settings_leak"],
            issues=[],
            overall_status="vulnerable",
        )
        with patch(
            "mytools.web.edgefunctions.run_scan", new_callable=AsyncMock, return_value=r
        ):
            assert run_once(_ns()) == 1

    def test_secure_returns_0(self) -> None:
        r = EdgeFunctionResult(
            target="t",
            host="h",
            port=443,
            tls=True,
            endpoint="e",
            provider_detected="unknown",
            techniques_count=0,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with patch(
            "mytools.web.edgefunctions.run_scan", new_callable=AsyncMock, return_value=r
        ):
            assert run_once(_ns()) == 0


class TestMainGuard:
    def test_guard_runs(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.web.edgefunctions", run_name="__main__")
