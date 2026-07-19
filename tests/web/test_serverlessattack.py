#!/usr/bin/env python3
"""Tests for serverlessattack.py."""

from __future__ import annotations

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
    build_parser,
    print_results,
)


class TestServerlessAttackAttempt:
    def test_creation(self) -> None:
        a = ServerlessAttackAttempt(
            technique="cold_start_leak", category="generic",
            description="desc", vulnerable=False, details="test", error="",
            endpoint="https://target.com", response_code=200, timing_ms=150.0,
        )
        assert a.technique == "cold_start_leak"
        assert a.timing_ms == 150.0

    def test_frozen(self) -> None:
        a = ServerlessAttackAttempt(
            technique="t", category="c", description="d",
            vulnerable=False, details="", error="", endpoint="e",
            response_code=200, timing_ms=0.0,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestServerlessAttackResult:
    def test_creation(self) -> None:
        r = ServerlessAttackResult(
            target="https://target.com", host="target.com", port=443, tls=True,
            endpoint="https://target.com", techniques_count=2,
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.techniques_count == 2

    def test_frozen(self) -> None:
        r = ServerlessAttackResult(
            target="t", host="h", port=443, tls=True, endpoint="e",
            techniques_count=0, attempts=[], vulnerable_techniques=[],
            issues=[], overall_status="secure",
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
        a = _make_attempt("cold_start_leak", "generic", "desc", True, "details", "", "url", 200, 1500.0)
        assert a.vulnerable is True
        assert a.timing_ms == 1500.0

    def test_no_timing(self) -> None:
        a = _make_attempt("cold_start_leak", "generic", "desc", False, "details", "", "url", 200)
        assert a.timing_ms == 0.0


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = ServerlessAttackResult(
            target="https://target.com", host="target.com", port=443, tls=True,
            endpoint="https://target.com", techniques_count=2,
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Serverless Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = ServerlessAttackAttempt(
            technique="cold_start_leak", category="generic", description="desc",
            vulnerable=True, details="leak found", error="",
            endpoint="https://target.com", response_code=200, timing_ms=1500.0,
        )
        r = ServerlessAttackResult(
            target="https://target.com", host="target.com", port=443, tls=True,
            endpoint="https://target.com", techniques_count=2,
            attempts=[a], vulnerable_techniques=["cold_start_leak"],
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
        args = parser.parse_args(["https://target.com/api", "-c", "generic"])
        assert args.categories == ["generic"]


@pytest.mark.asyncio
@pytest.mark.network
@respx.mock
async def test_category_dispatch_all_return_lists() -> None:
    """All category dispatchers should return a list."""
    respx.route().mock(return_value=httpx.Response(200, json={"status": "ok"}, headers={"content-type": "application/json"}))
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn("target.com", 443, "", 0.1, True, "https://target.com")
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, ServerlessAttackAttempt)
            assert attempt.category == cat
