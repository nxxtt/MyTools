#!/usr/bin/env python3
"""Tests for edgefunctions.py."""

from __future__ import annotations

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
    build_parser,
    print_results,
)


class TestEdgeFunctionAttempt:
    def test_creation(self) -> None:
        a = EdgeFunctionAttempt(
            technique="azure_settings_leak", category="cloud_providers",
            description="desc", vulnerable=False, details="test", error="",
            endpoint="https://target.com", provider="azure", response_code=200,
        )
        assert a.technique == "azure_settings_leak"
        assert a.provider == "azure"

    def test_frozen(self) -> None:
        a = EdgeFunctionAttempt(
            technique="t", category="c", description="d",
            vulnerable=False, details="", error="", endpoint="e",
            provider="p", response_code=200,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestEdgeFunctionResult:
    def test_creation(self) -> None:
        r = EdgeFunctionResult(
            target="https://target.com", host="target.com", port=443, tls=True,
            endpoint="https://target.com", provider_detected="vercel",
            techniques_count=5, attempts=[], vulnerable_techniques=[],
            issues=[], overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.provider_detected == "vercel"

    def test_frozen(self) -> None:
        r = EdgeFunctionResult(
            target="t", host="h", port=443, tls=True, endpoint="e",
            provider_detected="p", techniques_count=0, attempts=[],
            vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.host = "changed"  # type: ignore[misc]


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        assert set(_CATEGORY_MAP.keys()) == {"cloud_providers"}

    def test_cloud_providers_techniques(self) -> None:
        expected = {"azure_settings_leak", "gcp_iam_bypass", "vercel_secret_leak", "kv_store_leak", "edge_code_injection"}
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


class TestMakeAttempt:
    def test_creation(self) -> None:
        a = _make_attempt("azure_settings_leak", "cloud_providers", "desc", True, "details", "", "url", "azure", 200)
        assert a.vulnerable is True
        assert a.provider == "azure"


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = EdgeFunctionResult(
            target="https://target.com", host="target.com", port=443, tls=True,
            endpoint="https://target.com", provider_detected="unknown",
            techniques_count=5, attempts=[], vulnerable_techniques=[],
            issues=[], overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Edge Functions Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = EdgeFunctionAttempt(
            technique="azure_settings_leak", category="cloud_providers", description="desc",
            vulnerable=True, details="leak found", error="",
            endpoint="https://target.com", provider="azure", response_code=200,
        )
        r = EdgeFunctionResult(
            target="https://target.com", host="target.com", port=443, tls=True,
            endpoint="https://target.com", provider_detected="azure",
            techniques_count=5, attempts=[a], vulnerable_techniques=["azure_settings_leak"],
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
