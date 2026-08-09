#!/usr/bin/env python3
"""Tests for dockerattack.py."""

from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mytools.web.dockerattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    DockerAttackAttempt,
    DockerAttackResult,
    _make_attempt,
    _parse_url,
    _test_docker,
    _test_registry_exposed,
    build_parser,
    print_results,
    run_once,
    run_scan,
)


def _ns(**overrides: object) -> argparse.Namespace:
    ns = argparse.Namespace(
        url="https://registry.target.com",
        categories=None,
        timeout=5.0,
        output=None,
    )
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


class TestDockerAttackAttempt:
    def test_creation(self) -> None:
        a = DockerAttackAttempt(
            technique="registry_exposed",
            category="docker",
            description="desc",
            vulnerable=False,
            details="test",
            error="",
            endpoint="https://registry.target.com",
            registry_url="https://registry.target.com",
            repositories=[],
            response_code=200,
        )
        assert a.technique == "registry_exposed"
        assert a.repositories == []

    def test_frozen(self) -> None:
        a = DockerAttackAttempt(
            technique="t",
            category="c",
            description="d",
            vulnerable=False,
            details="",
            error="",
            endpoint="e",
            registry_url="r",
            repositories=[],
            response_code=200,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestDockerAttackResult:
    def test_creation(self) -> None:
        r = DockerAttackResult(
            target="https://registry.target.com",
            host="registry.target.com",
            port=443,
            tls=True,
            endpoint="https://registry.target.com",
            registry_detected=False,
            repositories=[],
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.registry_detected is False

    def test_frozen(self) -> None:
        r = DockerAttackResult(
            target="t",
            host="h",
            port=443,
            tls=True,
            endpoint="e",
            registry_detected=False,
            repositories=[],
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.host = "changed"  # type: ignore[misc]


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        assert set(_CATEGORY_MAP.keys()) == {"docker"}

    def test_docker_techniques(self) -> None:
        assert set(_CATEGORY_MAP["docker"]) == {"registry_exposed"}

    def test_total_techniques(self) -> None:
        total = sum(len(v) for v in _CATEGORY_MAP.values())
        assert total == 1

    def test_dispatch_matches_map(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_DISPATCH

    def test_all_dispatches_are_coroutines(self) -> None:
        import inspect

        for cat, fn in _CATEGORY_DISPATCH.items():
            assert inspect.iscoroutinefunction(fn), f"{cat} is not a coroutine"


class TestParseUrl:
    def test_https(self) -> None:
        host, _path, _port, tls = _parse_url("https://registry.target.com")
        assert host == "registry.target.com"
        assert tls is True

    def test_http(self) -> None:
        host, _path, port, tls = _parse_url("http://registry.target.com:5000")
        assert host == "registry.target.com"
        assert tls is False
        assert port == 5000

    def test_custom_port(self) -> None:
        _, _, port, _ = _parse_url("https://target.com:8443")
        assert port == 8443

    def test_no_scheme(self) -> None:
        host, path, port, tls = _parse_url("registry.target.com")
        assert host == "registry.target.com"
        assert path == ""
        assert port == 443
        assert tls is True

    def test_with_path(self) -> None:
        host, path, port, tls = _parse_url("http://registry.target.com:5000/v2/")
        assert host == "registry.target.com"
        assert path == "/v2/"
        assert port == 5000
        assert tls is False


class TestMakeAttempt:
    def test_creation(self) -> None:
        a = _make_attempt(
            "registry_exposed",
            "docker",
            "desc",
            True,
            "details",
            "",
            "url",
            "registry",
            ["repo1"],
            200,
        )
        assert a.vulnerable is True
        assert a.repositories == ["repo1"]

    def test_no_repos(self) -> None:
        a = _make_attempt(
            "registry_exposed",
            "docker",
            "desc",
            False,
            "details",
            "",
            "url",
            "registry",
            None,
            200,
        )
        assert a.repositories == []


class TestRegistryExposed:
    @pytest.mark.asyncio
    @respx.mock
    async def test_detected_with_repositories(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if url.endswith("/v2/"):
                return httpx.Response(200, text="not json")
            if "/v2/_catalog" in url:
                return httpx.Response(200, json={"repositories": ["alpine", "nginx"]})
            return httpx.Response(404, text="not found")

        respx.route(method="GET", url__startswith="https://registry.target.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_registry_exposed(
                "https://registry.target.com", 10.0, client
            )
        assert attempt.vulnerable is True
        assert {"alpine", "nginx"}.issubset(attempt.repositories)
        assert "repos" in attempt.details

    @pytest.mark.asyncio
    @respx.mock
    async def test_detected_via_401_and_tag_probe(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/tags/list" in url:
                repo = url.split("/v2/")[1].split("/")[0]
                if repo == "library":
                    return httpx.Response(200, text="not json")
                return httpx.Response(200, json={"tags": ["latest"]})
            return httpx.Response(
                401, headers={"www-authenticate": 'Bearer realm="https://auth.ex"'}
            )

        respx.route(method="GET", url__startswith="https://registry.target.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_registry_exposed(
                "https://registry.target.com", 10.0, client
            )
        assert attempt.vulnerable is True
        assert "library" not in attempt.repositories
        assert len(attempt.repositories) > 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_tag_probe_exception(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/tags/list" in url:
                raise httpx.ConnectError("boom")
            return httpx.Response(
                401, headers={"www-authenticate": 'Bearer realm="https://auth.ex"'}
            )

        respx.route(method="GET", url__startswith="https://registry.target.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_registry_exposed(
                "https://registry.target.com", 10.0, client
            )
        assert attempt.vulnerable is False
        assert "Registry: accessible" in attempt.details
        assert attempt.repositories == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_401_without_bearer(self) -> None:
        respx.route(method="GET", url__startswith="https://registry.target.com").mock(
            return_value=httpx.Response(401, headers={"x-custom": "1"})
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_registry_exposed(
                "https://registry.target.com", 10.0, client
            )
        assert attempt.vulnerable is False
        assert "not found" in attempt.details

    @pytest.mark.asyncio
    @respx.mock
    async def test_request_exception_is_caught(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if str(request.url).endswith("/v2/"):
                raise httpx.ConnectError("boom")
            return httpx.Response(200, json={"repositories": ["alpine"]})

        respx.route(method="GET", url__startswith="https://registry.target.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_registry_exposed(
                "https://registry.target.com", 10.0, client
            )
        assert attempt.vulnerable is True
        assert "alpine" in attempt.repositories

    @pytest.mark.asyncio
    @respx.mock
    async def test_not_found(self) -> None:
        respx.route(method="GET", url__startswith="https://registry.target.com").mock(
            return_value=httpx.Response(404, text="not found")
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_registry_exposed(
                "https://registry.target.com", 10.0, client
            )
        assert attempt.vulnerable is False
        assert attempt.response_code == 404

    @pytest.mark.asyncio
    @respx.mock
    async def test_200_on_non_catalog_path(self) -> None:
        respx.route(method="GET", url__startswith="https://registry.target.com").mock(
            return_value=httpx.Response(200, text="ok")
        )
        with (
            patch(
                "mytools.web.dockerattack._REGISTRY_V2_PATHS",
                [{"path": "/v2/other", "desc": "non-catalog"}],
            ),
            patch("mytools.web.dockerattack._COMMON_REPO_NAMES", []),
        ):
            async with httpx.AsyncClient(verify=False) as client:
                attempt = await _test_registry_exposed(
                    "https://registry.target.com", 10.0, client
                )
        assert attempt.vulnerable is False
        assert attempt.repositories == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_catalog_without_repositories(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/tags/list" in url:
                return httpx.Response(404, text="not found")
            return httpx.Response(200, json={"foo": "bar"})

        respx.route(method="GET", url__startswith="https://registry.target.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_registry_exposed(
                "https://registry.target.com", 10.0, client
            )
        assert attempt.vulnerable is False
        assert attempt.repositories == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_tag_probe_non_200(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/tags/list" in url:
                return httpx.Response(404, text="not found")
            return httpx.Response(
                401, headers={"www-authenticate": 'Bearer realm="https://auth.ex"'}
            )

        respx.route(method="GET", url__startswith="https://registry.target.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_registry_exposed(
                "https://registry.target.com", 10.0, client
            )
        assert attempt.vulnerable is False
        assert attempt.repositories == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_tag_probe_without_tags(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            url = str(request.url)
            if "/tags/list" in url:
                return httpx.Response(200, json={"errors": []})
            return httpx.Response(
                401, headers={"www-authenticate": 'Bearer realm="https://auth.ex"'}
            )

        respx.route(method="GET", url__startswith="https://registry.target.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient(verify=False) as client:
            attempt = await _test_registry_exposed(
                "https://registry.target.com", 10.0, client
            )
        assert attempt.vulnerable is False
        assert attempt.repositories == []


class TestDockerTester:
    @pytest.mark.asyncio
    @respx.mock
    async def test_inner_exception(self) -> None:
        with patch(
            "mytools.web.dockerattack._test_registry_exposed",
            new_callable=AsyncMock,
            side_effect=RuntimeError("boom"),
        ):
            results = await _test_docker(
                "registry.target.com",
                443,
                "",
                10.0,
                True,
                "https://registry.target.com",
            )
        assert len(results) == 1
        assert results[0].error == "boom"
        assert results[0].vulnerable is False


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DockerAttackResult(
            target="https://registry.target.com",
            host="registry.target.com",
            port=443,
            tls=True,
            endpoint="https://registry.target.com",
            registry_detected=False,
            repositories=[],
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Docker Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = DockerAttackAttempt(
            technique="registry_exposed",
            category="docker",
            description="desc",
            vulnerable=True,
            details="registry accessible",
            error="",
            endpoint="https://registry.target.com",
            registry_url="https://registry.target.com",
            repositories=["library/nginx", "library/alpine"],
            response_code=200,
        )
        r = DockerAttackResult(
            target="https://registry.target.com",
            host="registry.target.com",
            port=443,
            tls=True,
            endpoint="https://registry.target.com",
            registry_detected=True,
            repositories=["library/nginx", "library/alpine"],
            attempts=[a],
            vulnerable_techniques=["registry_exposed"],
            issues=["Test issue"],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output
        assert "Issues:" in output

    def test_secure_category(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = DockerAttackAttempt(
            technique="registry_exposed",
            category="docker",
            description="desc",
            vulnerable=False,
            details="Registry: not found",
            error="",
            endpoint="https://registry.target.com",
            registry_url="https://registry.target.com",
            repositories=[],
            response_code=404,
        )
        r = DockerAttackResult(
            target="https://registry.target.com",
            host="registry.target.com",
            port=443,
            tls=True,
            endpoint="https://registry.target.com",
            registry_detected=False,
            repositories=[],
            attempts=[a],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "docker: secure" in output
        assert "SECURE" in output


class TestCLI:
    def test_build_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://registry.target.com"])
        assert args.url == "https://registry.target.com"

    def test_build_parser_with_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://registry.target.com", "-c", "docker"])
        assert args.categories == ["docker"]


@pytest.mark.asyncio
@pytest.mark.network
@respx.mock
async def test_category_dispatch_all_return_lists() -> None:
    """All category dispatchers should return a list."""
    respx.route().mock(
        return_value=httpx.Response(
            404, text='{"errors":[{"code":"NOT_FOUND","message":"not found"}]}'
        )
    )
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn("target.com", 443, "", 0.1, True, "https://target.com")
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, DockerAttackAttempt)
            assert attempt.category == cat


class TestRunScan:
    @pytest.mark.asyncio
    async def test_vulnerable_default_categories(self) -> None:
        vuln = _make_attempt(
            "registry_exposed",
            "docker",
            "desc",
            True,
            "details",
            "",
            "u",
            "u",
            ["r"],
            200,
        )
        with patch.dict(
            "mytools.web.dockerattack._CATEGORY_DISPATCH",
            {"docker": AsyncMock(return_value=[vuln])},
        ):
            result = await run_scan("https://registry.target.com", None, 5.0, None)
        assert result.overall_status == "vulnerable"
        assert result.vulnerable_techniques == ["registry_exposed"]
        assert result.registry_detected is True
        assert result.repositories == ["r"]

    @pytest.mark.asyncio
    async def test_non_vulnerable_attempt(self) -> None:
        safe = _make_attempt(
            "registry_exposed",
            "docker",
            "desc",
            False,
            "details",
            "",
            "u",
            "u",
            ["r"],
            200,
        )
        with patch.dict(
            "mytools.web.dockerattack._CATEGORY_DISPATCH",
            {"docker": AsyncMock(return_value=[safe])},
        ):
            result = await run_scan(
                "https://registry.target.com", ["docker"], 5.0, None
            )
        assert result.overall_status == "secure"
        assert result.registry_detected is False
        assert result.repositories == ["r"]

    @pytest.mark.asyncio
    async def test_port_and_path_endpoint(self) -> None:
        with patch.dict(
            "mytools.web.dockerattack._CATEGORY_DISPATCH",
            {"docker": AsyncMock(return_value=[])},
        ):
            result = await run_scan(
                "http://registry.target.com:5000/v2", ["docker"], 5.0, None
            )
        assert result.endpoint == "http://registry.target.com:5000/v2"
        assert result.port == 5000
        assert result.tls is False
        assert result.overall_status == "secure"

    @pytest.mark.asyncio
    async def test_invalid_category_skipped(self) -> None:
        with patch.dict(
            "mytools.web.dockerattack._CATEGORY_DISPATCH",
            {"docker": AsyncMock(return_value=[])},
        ):
            result = await run_scan(
                "https://registry.target.com", ["invalid"], 5.0, None
            )
        assert result.overall_status == "secure"
        assert result.attempts == []
        assert result.issues == []

    @pytest.mark.asyncio
    async def test_tester_error_builds_issue(self) -> None:
        with patch.dict(
            "mytools.web.dockerattack._CATEGORY_DISPATCH",
            {"docker": AsyncMock(side_effect=RuntimeError("boom"))},
        ):
            result = await run_scan(
                "https://registry.target.com", ["docker"], 5.0, None
            )
        assert result.overall_status == "secure"
        assert result.attempts[0].error == "boom"
        assert result.issues == ["Errors: docker_error"]

    @pytest.mark.asyncio
    async def test_output_file_written(self, tmp_path: Path) -> None:
        out = str(tmp_path / "out.json")
        with patch.dict(
            "mytools.web.dockerattack._CATEGORY_DISPATCH",
            {"docker": AsyncMock(return_value=[])},
        ):
            result = await run_scan("https://registry.target.com", ["docker"], 5.0, out)
        assert result.overall_status == "secure"
        assert (tmp_path / "out.json").exists()


class TestRunOnce:
    def test_vulnerable_returns_1(self) -> None:
        r = DockerAttackResult(
            target="t",
            host="h",
            port=443,
            tls=True,
            endpoint="e",
            registry_detected=True,
            repositories=[],
            attempts=[],
            vulnerable_techniques=["registry_exposed"],
            issues=[],
            overall_status="vulnerable",
        )
        with patch(
            "mytools.web.dockerattack.run_scan", new_callable=AsyncMock, return_value=r
        ):
            assert run_once(_ns()) == 1

    def test_secure_returns_0(self) -> None:
        r = DockerAttackResult(
            target="t",
            host="h",
            port=443,
            tls=True,
            endpoint="e",
            registry_detected=False,
            repositories=[],
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with patch(
            "mytools.web.dockerattack.run_scan", new_callable=AsyncMock, return_value=r
        ):
            assert run_once(_ns()) == 0

    def test_missing_attrs_default(self) -> None:
        r = DockerAttackResult(
            target="t",
            host="h",
            port=443,
            tls=True,
            endpoint="e",
            registry_detected=False,
            repositories=[],
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        ns = argparse.Namespace(url="https://registry.target.com")
        with patch(
            "mytools.web.dockerattack.run_scan", new_callable=AsyncMock, return_value=r
        ):
            assert run_once(ns) == 0


class TestMainGuard:
    def test_guard_runs(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.web.dockerattack", run_name="__main__")
