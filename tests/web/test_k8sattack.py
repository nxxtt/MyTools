#!/usr/bin/env python3
"""Tests for k8sattack.py."""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

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
    main,
    print_results,
    run_once,
    run_scan,
)


class TestK8sAttackAttempt:
    def test_creation(self) -> None:
        a = K8sAttackAttempt(
            technique="api_enumeration",
            category="kubernetes",
            description="desc",
            vulnerable=False,
            details="test",
            error="",
            endpoint="https://target.com:6443",
            api_version="v1.28.0",
            response_code=200,
        )
        assert a.technique == "api_enumeration"
        assert a.api_version == "v1.28.0"

    def test_frozen(self) -> None:
        a = K8sAttackAttempt(
            technique="t",
            category="c",
            description="d",
            vulnerable=False,
            details="",
            error="",
            endpoint="e",
            api_version="",
            response_code=200,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestK8sAttackResult:
    def test_creation(self) -> None:
        r = K8sAttackResult(
            target="https://target.com:6443",
            host="target.com",
            port=6443,
            tls=True,
            endpoint="https://target.com:6443",
            k8s_detected=False,
            api_versions=[],
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.k8s_detected is False

    def test_frozen(self) -> None:
        r = K8sAttackResult(
            target="t",
            host="h",
            port=6443,
            tls=True,
            endpoint="e",
            k8s_detected=False,
            api_versions=[],
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.host = "changed"  # type: ignore[misc]


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        assert set(_CATEGORY_MAP.keys()) == {"kubernetes"}

    def test_kubernetes_techniques(self) -> None:
        assert set(_CATEGORY_MAP["kubernetes"]) == {
            "api_enumeration",
            "dashboard_exposed",
        }

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
        a = _make_attempt(
            "api_enumeration",
            "kubernetes",
            "desc",
            True,
            "details",
            "",
            "url",
            "v1.28",
            200,
        )
        assert a.vulnerable is True
        assert a.api_version == "v1.28"


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = K8sAttackResult(
            target="https://target.com:6443",
            host="target.com",
            port=6443,
            tls=True,
            endpoint="https://target.com:6443",
            k8s_detected=False,
            api_versions=[],
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Kubernetes Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = K8sAttackAttempt(
            technique="api_enumeration",
            category="kubernetes",
            description="desc",
            vulnerable=True,
            details="leak found",
            error="",
            endpoint="https://target.com:6443",
            api_version="v1.28.3",
            response_code=200,
        )
        r = K8sAttackResult(
            target="https://target.com:6443",
            host="target.com",
            port=6443,
            tls=True,
            endpoint="https://target.com:6443",
            k8s_detected=True,
            api_versions=["v1.28.3"],
            attempts=[a],
            vulnerable_techniques=["api_enumeration"],
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
    respx.route().mock(
        return_value=httpx.Response(
            404,
            text='{"kind":"Status","status":"Failure","message":"not found","reason":"NotFound"}',
        )
    )
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn("target.com", 6443, "", 0.1, True, "https://target.com:6443")
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, K8sAttackAttempt)
            assert attempt.category == cat


class TestParseUrlExtra:
    def test_without_scheme(self) -> None:
        host, _path, port, tls = _parse_url("target.com")
        assert host == "target.com"
        assert tls is True
        assert port == 6443

    def test_http_default_port(self) -> None:
        _, _, port, tls = _parse_url("http://target.com")
        assert port == 8080
        assert tls is False

    def test_grpcs_tls(self) -> None:
        host, _path, port, tls = _parse_url("grpcs://target.com:6443")
        assert host == "target.com"
        assert tls is True
        assert port == 6443


class TestExtractApiVersionExtra:
    def test_major_without_minor(self) -> None:
        assert _extract_api_version('{"major":"1"}') == ""

    def test_marker_without_versions(self) -> None:
        assert _extract_api_version('{"serverAddressByClientCIDRs":[]}') == ""


class TestPrintResultsCategories:
    def test_secure_category(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = K8sAttackAttempt(
            technique="dashboard_exposed",
            category="kubernetes",
            description="desc",
            vulnerable=False,
            details="x",
            error="",
            endpoint="https://target.com:6443",
            api_version="",
            response_code=404,
        )
        r = K8sAttackResult(
            target="https://target.com:6443",
            host="target.com",
            port=6443,
            tls=True,
            endpoint="https://target.com:6443",
            k8s_detected=False,
            api_versions=[],
            attempts=[a],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "kubernetes: secure" in output
        assert "SECURE" in output

    def test_api_versions_printed(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = K8sAttackResult(
            target="https://target.com:6443",
            host="target.com",
            port=6443,
            tls=True,
            endpoint="https://target.com:6443",
            k8s_detected=True,
            api_versions=["v1.28.3", "v1.27.0"],
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "v1.28.3" in output
        assert "v1.27.0" in output


def _make_k8s_handler() -> Any:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/version":
            return httpx.Response(
                200,
                text='{"gitVersion":"v1.28.3","major":"1","minor":"28"}',
                headers={"server": "apiserver"},
            )
        if path in ("/healthz", "/readyz", "/livez", "/metrics"):
            return httpx.Response(200, text="kubectl kube-system")
        if path in ("/api", "/apis"):
            return httpx.Response(200, text='{"major":"1","minor":"28"}')
        if path == "/api/v1":
            return httpx.Response(200, text="kubelet coredns")
        if path == "/api/v1/pods":
            return httpx.Response(403, text="forbidden")
        if path == "/api/v1/secrets":
            return httpx.Response(200, text="etcd")
        if "kube-system" in path:
            return httpx.Response(401, text="unauthorized")
        if "kubernetes-dashboard" in path or path.startswith("/dashboard"):
            return httpx.Response(200, text="Kubernetes Dashboard login")
        return httpx.Response(404, text="not found")

    return handler


class TestRunScan:
    @pytest.mark.asyncio
    @respx.mock
    async def test_secure(self) -> None:
        respx.route(method="GET", url__startswith="https://target.com:6443").mock(
            return_value=httpx.Response(404, text="not found")
        )
        result = await run_scan("https://target.com:6443/k8s", None, 0.1, None)
        assert result.overall_status == "secure"
        assert result.k8s_detected is False
        assert result.api_versions == []
        assert result.endpoint == "https://target.com:6443/k8s"

    @pytest.mark.asyncio
    @respx.mock
    async def test_vulnerable(self) -> None:
        respx.route(method="GET", url__startswith="https://target.com:6443").mock(
            side_effect=_make_k8s_handler()
        )
        result = await run_scan("https://target.com:6443", ["kubernetes"], 0.1, None)
        assert result.overall_status == "vulnerable"
        assert result.k8s_detected is True
        assert "api_enumeration" in result.vulnerable_techniques
        assert "dashboard_exposed" in result.vulnerable_techniques
        assert result.api_versions

    @pytest.mark.asyncio
    @respx.mock
    async def test_output_file(self) -> None:
        respx.route(method="GET", url__startswith="https://target.com:6443").mock(
            return_value=httpx.Response(404, text="not found")
        )
        with patch("mytools.web.k8sattack.write_output") as m:
            result = await run_scan("https://target.com:6443", None, 0.1, "out.json")
        m.assert_called_once()
        assert result.overall_status == "secure"

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_category_skipped(self) -> None:
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        result = await run_scan("https://target.com:6443", ["bogus"], 0.1, None)
        assert result.overall_status == "secure"
        assert result.attempts == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_public_endpoints_only_not_vulnerable(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if path in ("/version", "/healthz", "/readyz", "/livez"):
                return httpx.Response(200, text='{"gitVersion":"v1.28.3"}')
            return httpx.Response(404, text="not found")

        respx.route(method="GET", url__startswith="https://target.com:6443").mock(
            side_effect=handler
        )
        result = await run_scan("https://target.com:6443", ["kubernetes"], 0.1, None)
        assert result.overall_status == "secure"
        assert "api_enumeration" not in result.vulnerable_techniques

    @pytest.mark.asyncio
    @respx.mock
    async def test_tester_raises_inside_kubernetes(self) -> None:
        async def boom(*args: object, **kwargs: object) -> None:
            raise RuntimeError("boom")

        respx.route(method="GET").mock(return_value=httpx.Response(404))
        with patch("mytools.web.k8sattack._test_api_enumeration", boom):
            result = await run_scan("https://target.com:6443", None, 0.1, None)
        assert result.overall_status == "secure"
        assert any(a.error == "boom" for a in result.attempts)

    @pytest.mark.asyncio
    @respx.mock
    async def test_request_exception(self) -> None:
        def raise_error(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("boom")

        respx.route(method="GET", url__startswith="https://target.com:6443").mock(
            side_effect=raise_error
        )
        result = await run_scan("https://target.com:6443", None, 0.1, None)
        assert result.overall_status == "secure"

    @pytest.mark.asyncio
    @respx.mock
    async def test_category_dispatch_raises(self) -> None:
        async def boom(*args: object, **kwargs: object) -> None:
            raise RuntimeError("boom")

        respx.route(method="GET").mock(return_value=httpx.Response(404))
        with patch.dict("mytools.web.k8sattack._CATEGORY_DISPATCH", {"boomcat": boom}):
            result = await run_scan("https://target.com:6443", ["boomcat"], 0.1, None)
        assert result.overall_status == "secure"
        assert result.issues
        assert any(a.error == "boom" for a in result.attempts)

    @pytest.mark.asyncio
    @respx.mock
    async def test_dashboard_without_keywords(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            path = request.url.path
            if "kubernetes-dashboard" in path or path.startswith("/dashboard"):
                return httpx.Response(200, text="some random page")
            return httpx.Response(404, text="not found")

        respx.route(method="GET", url__startswith="https://target.com:6443").mock(
            side_effect=handler
        )
        result = await run_scan("https://target.com:6443", None, 0.1, None)
        assert result.overall_status == "secure"
        dashboard = [a for a in result.attempts if a.technique == "dashboard_exposed"]
        assert len(dashboard) == 1
        assert dashboard[0].vulnerable is False


class TestRunOnce:
    def test_vulnerable(self) -> None:
        fake = MagicMock()
        fake.overall_status = "vulnerable"
        with (
            patch("mytools.web.k8sattack.safe_asyncio_run", return_value=fake) as m,
            patch("mytools.web.k8sattack.run_scan", new_callable=MagicMock),
        ):
            code = run_once(MagicMock())
        assert code == 1
        m.assert_called_once()

    def test_secure(self) -> None:
        fake = MagicMock()
        fake.overall_status = "secure"
        with (
            patch("mytools.web.k8sattack.safe_asyncio_run", return_value=fake),
            patch("mytools.web.k8sattack.run_scan", new_callable=MagicMock),
        ):
            code = run_once(MagicMock())
        assert code == 0


class TestMain:
    def test_main(self) -> None:
        with patch("mytools.web.k8sattack.run_main_loop", return_value=0) as m:
            code = main()
        assert code == 0
        m.assert_called_once()

    def test_main_guard(self) -> None:
        import runpy

        with (
            patch("mytools.web.k8sattack.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.web.k8sattack", run_name="__main__")
