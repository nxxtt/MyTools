#!/usr/bin/env python3
"""Tests for dockerattack.py."""

from __future__ import annotations

import pytest

from mytools.web.dockerattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    DockerAttackAttempt,
    DockerAttackResult,
    _make_attempt,
    _parse_url,
    build_parser,
    print_results,
)


class TestDockerAttackAttempt:
    def test_creation(self) -> None:
        a = DockerAttackAttempt(
            technique="registry_exposed", category="docker",
            description="desc", vulnerable=False, details="test", error="",
            endpoint="https://registry.target.com", registry_url="https://registry.target.com",
            repositories=[], response_code=200,
        )
        assert a.technique == "registry_exposed"
        assert a.repositories == []

    def test_frozen(self) -> None:
        a = DockerAttackAttempt(
            technique="t", category="c", description="d",
            vulnerable=False, details="", error="", endpoint="e",
            registry_url="r", repositories=[], response_code=200,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestDockerAttackResult:
    def test_creation(self) -> None:
        r = DockerAttackResult(
            target="https://registry.target.com", host="registry.target.com", port=443, tls=True,
            endpoint="https://registry.target.com", registry_detected=False,
            repositories=[], attempts=[], vulnerable_techniques=[], issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.registry_detected is False

    def test_frozen(self) -> None:
        r = DockerAttackResult(
            target="t", host="h", port=443, tls=True, endpoint="e",
            registry_detected=False, repositories=[], attempts=[],
            vulnerable_techniques=[], issues=[], overall_status="secure",
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


class TestMakeAttempt:
    def test_creation(self) -> None:
        a = _make_attempt("registry_exposed", "docker", "desc", True, "details", "", "url", "registry", ["repo1"], 200)
        assert a.vulnerable is True
        assert a.repositories == ["repo1"]

    def test_no_repos(self) -> None:
        a = _make_attempt("registry_exposed", "docker", "desc", False, "details", "", "url", "registry", None, 200)
        assert a.repositories == []


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DockerAttackResult(
            target="https://registry.target.com", host="registry.target.com", port=443, tls=True,
            endpoint="https://registry.target.com", registry_detected=False,
            repositories=[], attempts=[], vulnerable_techniques=[], issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Docker Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = DockerAttackAttempt(
            technique="registry_exposed", category="docker", description="desc",
            vulnerable=True, details="registry accessible", error="",
            endpoint="https://registry.target.com", registry_url="https://registry.target.com",
            repositories=["library/nginx", "library/alpine"], response_code=200,
        )
        r = DockerAttackResult(
            target="https://registry.target.com", host="registry.target.com", port=443, tls=True,
            endpoint="https://registry.target.com", registry_detected=True,
            repositories=["library/nginx", "library/alpine"], attempts=[a],
            vulnerable_techniques=["registry_exposed"], issues=["Test issue"],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output
        assert "Issues:" in output


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
async def test_category_dispatch_all_return_lists() -> None:
    """All category dispatchers should return a list."""
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn("target.com", 443, "", 0.1, True, "https://target.com")
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, DockerAttackAttempt)
            assert attempt.category == cat
