#!/usr/bin/env python3
"""Tests for k8sattack.py."""

from __future__ import annotations

import httpx
import pytest
import respx

from mytools.web.k8sattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    K8sAttackAttempt,
    K8sAttackResult,
    _detect_k8s,
    _extract_api_version,
    _make_attempt,
    _parse_url,
    build_parser,
    print_results,
)


class TestK8sAttackAttempt:
    def test_creation(self) -> None:
        a = K8sAttackAttempt(
            technique="api_enumeration", category="kubernetes",
            description="desc", vulnerable=False, details="test", error="",
            endpoint="https://target.com:6443", api_version="v1.28.0", response_code=200,
        )
        assert a.technique == "api_enumeration"
        assert a.api_version == "v1.28.0"

    def test_frozen(self) -> None:
        a = K8sAttackAttempt(
            technique="t", category="c", description="d",
            vulnerable=False, details="", error="", endpoint="e",
            api_version="", response_code=200,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestK8sAttackResult:
    def test_creation(self) -> None:
        r = K8sAttackResult(
            target="https://target.com:6443", host="target.com", port=6443, tls=True,
            endpoint="https://target.com:6443", k8s_detected=False,
            api_versions=[], attempts=[], vulnerable_techniques=[], issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.k8s_detected is False

    def test_frozen(self) -> None:
        r = K8sAttackResult(
            target="t", host="h", port=6443, tls=True, endpoint="e",
            k8s_detected=False, api_versions=[], attempts=[],
            vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.host = "changed"  # type: ignore[misc]


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        assert set(_CATEGORY_MAP.keys()) == {"kubernetes"}

    def test_kubernetes_techniques(self) -> None:
        assert set(_CATEGORY_MAP["kubernetes"]) == {"api_enumeration", "dashboard_exposed"}

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


class TestDetectK8s:
    def test_detects_kubernetes(self) -> None:
        assert _detect_k8s("kubectl get pods", {}) is True

    def test_detects_apiserver(self) -> None:
        assert _detect_k8s("", {"server": "apiserver"}) is True

    def test_not_k8s(self) -> None:
        assert _detect_k8s("Hello world", {}) is False


class TestExtractApiVersion:
    def test_extracts_from_json(self) -> None:
        body = '{"gitVersion":"v1.28.3","major":"1","minor":"28"}'
        ver = _extract_api_version(body)
        assert ver == "v1.28.3"

    def test_extracts_major_minor(self) -> None:
        body = '{"major":"1","minor":"27"}'
        ver = _extract_api_version(body)
        assert ver == "v1.27"

    def test_no_version(self) -> None:
        body = "Hello world"
        ver = _extract_api_version(body)
        assert ver == ""


class TestParseUrl:
    def test_https(self) -> None:
        host, _path, port, tls = _parse_url("https://target.com:6443/api")
        assert host == "target.com"
        assert tls is True
        assert port == 6443

    def test_http(self) -> None:
        host, _path, _port, tls = _parse_url("http://target.com:8080")
        assert host == "target.com"
        assert tls is False

    def test_default_port(self) -> None:
        _, _, port, tls = _parse_url("https://target.com")
        assert port == 6443
        assert tls is True


class TestMakeAttempt:
    def test_creation(self) -> None:
        a = _make_attempt("api_enumeration", "kubernetes", "desc", True, "details", "", "url", "v1.28", 200)
        assert a.vulnerable is True
        assert a.api_version == "v1.28"


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = K8sAttackResult(
            target="https://target.com:6443", host="target.com", port=6443, tls=True,
            endpoint="https://target.com:6443", k8s_detected=False,
            api_versions=[], attempts=[], vulnerable_techniques=[], issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Kubernetes Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = K8sAttackAttempt(
            technique="api_enumeration", category="kubernetes", description="desc",
            vulnerable=True, details="leak found", error="",
            endpoint="https://target.com:6443", api_version="v1.28.3", response_code=200,
        )
        r = K8sAttackResult(
            target="https://target.com:6443", host="target.com", port=6443, tls=True,
            endpoint="https://target.com:6443", k8s_detected=True,
            api_versions=["v1.28.3"], attempts=[a], vulnerable_techniques=["api_enumeration"],
            issues=["Test issue"], overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output
        assert "Issues:" in output


class TestCLI:
    def test_build_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com:6443"])
        assert args.url == "https://target.com:6443"

    def test_build_parser_with_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com:6443", "-c", "kubernetes"])
        assert args.categories == ["kubernetes"]


@pytest.mark.asyncio
@pytest.mark.network
@respx.mock
async def test_category_dispatch_all_return_lists() -> None:
    """All category dispatchers should return a list."""
    respx.route().mock(return_value=httpx.Response(404, text='{"kind":"Status","status":"Failure","message":"not found","reason":"NotFound"}'))
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn("target.com", 6443, "", 0.1, True, "https://target.com:6443")
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, K8sAttackAttempt)
            assert attempt.category == cat
