#!/usr/bin/env python3
"""Tests for infraattack.py."""

from __future__ import annotations

from unittest.mock import patch

import httpx
import pytest
import respx

from mytools.web.infraattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    InfraAttackAttempt,
    InfraAttackResult,
    _extract_secrets,
    _make_attempt,
    _parse_url,
    build_parser,
    print_results,
)


class TestInfraAttackAttempt:
    def test_creation(self) -> None:
        a = InfraAttackAttempt(
            technique="terraform_state_leak", category="infrastructure",
            description="desc", vulnerable=False, details="test", error="",
            endpoint="https://target.com", service_type="terraform", response_code=200,
        )
        assert a.technique == "terraform_state_leak"
        assert a.service_type == "terraform"

    def test_frozen(self) -> None:
        a = InfraAttackAttempt(
            technique="t", category="c", description="d",
            vulnerable=False, details="", error="", endpoint="e",
            service_type="s", response_code=200,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestInfraAttackResult:
    def test_creation(self) -> None:
        r = InfraAttackResult(
            target="https://target.com", host="target.com", port=443, tls=True,
            endpoint="https://target.com", service_detected="unknown",
            techniques_count=8, attempts=[], vulnerable_techniques=[], issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.techniques_count == 8

    def test_frozen(self) -> None:
        r = InfraAttackResult(
            target="t", host="h", port=443, tls=True, endpoint="e",
            service_detected="s", techniques_count=0, attempts=[],
            vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.host = "changed"  # type: ignore[misc]


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        assert set(_CATEGORY_MAP.keys()) == {"infrastructure"}

    def test_infrastructure_techniques(self) -> None:
        expected = {
            "terraform_state_leak", "vault_exposed", "cicd_pipeline_leak",
            "cicd_secret_detection", "elastic_exposed", "redis_mongo_unauth",
            "debug_endpoints", "debug_mode_detection",
        }
        assert set(_CATEGORY_MAP["infrastructure"]) == expected

    def test_total_techniques(self) -> None:
        total = sum(len(v) for v in _CATEGORY_MAP.values())
        assert total == 8

    def test_dispatch_matches_map(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_DISPATCH

    def test_all_dispatches_are_coroutines(self) -> None:
        import inspect
        for cat, fn in _CATEGORY_DISPATCH.items():
            assert inspect.iscoroutinefunction(fn), f"{cat} is not a coroutine"


class TestExtractSecrets:
    def test_finds_password(self) -> None:
        body = 'password=secret123'
        found = _extract_secrets(body)
        assert len(found) > 0

    def test_finds_api_key(self) -> None:
        body = 'api_key="abc123def456"'
        found = _extract_secrets(body)
        assert len(found) > 0

    def test_no_secrets(self) -> None:
        body = "Hello world"
        found = _extract_secrets(body)
        assert found == []

    def test_filters_short_values(self) -> None:
        body = 'password=x'
        found = _extract_secrets(body)
        assert found == []


class TestParseUrl:
    def test_https(self) -> None:
        host, _path, _port, tls = _parse_url("https://target.com/api")
        assert host == "target.com"
        assert tls is True

    def test_http(self) -> None:
        host, _path, _port, tls = _parse_url("http://target.com")
        assert host == "target.com"
        assert tls is False

    def test_custom_port(self) -> None:
        _, _, port, _ = _parse_url("https://target.com:8080")
        assert port == 8080


class TestMakeAttempt:
    def test_creation(self) -> None:
        a = _make_attempt("terraform_state_leak", "infrastructure", "desc", True, "details", "", "url", "terraform", 200)
        assert a.vulnerable is True
        assert a.service_type == "terraform"

    def test_no_service(self) -> None:
        a = _make_attempt("debug_endpoints", "infrastructure", "desc", False, "details", "", "url", "unknown", 200)
        assert a.service_type == "unknown"


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = InfraAttackResult(
            target="https://target.com", host="target.com", port=443, tls=True,
            endpoint="https://target.com", service_detected="unknown",
            techniques_count=8, attempts=[], vulnerable_techniques=[], issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Infrastructure Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = InfraAttackAttempt(
            technique="terraform_state_leak", category="infrastructure", description="desc",
            vulnerable=True, details="state file found", error="",
            endpoint="https://target.com", service_type="terraform", response_code=200,
        )
        r = InfraAttackResult(
            target="https://target.com", host="target.com", port=443, tls=True,
            endpoint="https://target.com", service_detected="terraform",
            techniques_count=8, attempts=[a], vulnerable_techniques=["terraform_state_leak"],
            issues=["Test issue"], overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output
        assert "Issues:" in output


class TestCLI:
    def test_build_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com"])
        assert args.url == "https://target.com"

    def test_build_parser_with_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com", "-c", "infrastructure"])
        assert args.categories == ["infrastructure"]


@pytest.mark.asyncio
@pytest.mark.network
@respx.mock
@patch("socket.socket")
async def test_category_dispatch_all_return_lists(_mock_sock_cls: object) -> None:
    """All category dispatchers should return a list."""
    import socket as _socket

    mock_sock_inst = _mock_sock_cls.return_value
    mock_sock_inst.connect_ex.return_value = 1
    respx.route().mock(return_value=httpx.Response(404, text="Not Found"))
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn("target.com", 443, "", 0.1, True, "https://target.com")
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, InfraAttackAttempt)
            assert attempt.category == cat
