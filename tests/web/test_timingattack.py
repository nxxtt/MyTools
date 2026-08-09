#!/usr/bin/env python3
"""Tests for timingattack.py."""

from __future__ import annotations

import argparse
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mytools.web.timingattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    TimingAttempt,
    TimingResult,
    _make_attempt,
    _measure_cache_timing,
    _measure_dns_timing,
    _measure_login_timing,
    _measure_token_timing,
    _run_scan,
    _test_timing,
    build_parser,
    main,
    print_results,
    run_once,
)


class TestTimingAttempt:
    def test_creation(self) -> None:
        a = TimingAttempt(
            technique="login_timing",
            category="timing",
            description="Login timing",
            vulnerable=False,
            details="test",
            error="",
            endpoint="https://target.com",
            timing_ms=10.0,
            threshold_ms=50.0,
            samples=10,
            stdev_ms=5.0,
        )
        assert a.technique == "login_timing"
        assert a.vulnerable is False
        assert a.timing_ms == 10.0

    def test_frozen(self) -> None:
        a = TimingAttempt(
            technique="t",
            category="c",
            description="d",
            vulnerable=False,
            details="",
            error="",
            endpoint="e",
            timing_ms=0,
            threshold_ms=0,
            samples=0,
            stdev_ms=0,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestTimingResult:
    def test_creation(self) -> None:
        r = TimingResult(
            target="https://target.com",
            url="https://target.com",
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.url == "https://target.com"

    def test_frozen(self) -> None:
        r = TimingResult(
            target="t",
            url="u",
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        assert set(_CATEGORY_MAP.keys()) == {"timing"}

    def test_timing_techniques(self) -> None:
        assert set(_CATEGORY_MAP["timing"]) == {
            "login_timing",
            "token_timing",
            "cache_timing",
            "dns_timing",
        }

    def test_total_techniques(self) -> None:
        total = sum(len(v) for v in _CATEGORY_MAP.values())
        assert total == 4

    def test_dispatch_matches_map(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_DISPATCH

    def test_all_dispatches_are_coroutines(self) -> None:
        import inspect

        for cat, fn in _CATEGORY_DISPATCH.items():
            assert inspect.iscoroutinefunction(fn), f"{cat} is not a coroutine"


class TestMakeAttempt:
    def test_creation(self) -> None:
        a = _make_attempt(
            "login_timing",
            "timing",
            "Login timing",
            True,
            "details",
            "",
            "https://target.com",
            100.0,
            50.0,
            10,
            25.0,
        )
        assert a.vulnerable is True
        assert a.timing_ms == 100.0
        assert a.stdev_ms == 25.0

    def test_no_vuln(self) -> None:
        a = _make_attempt(
            "token_timing",
            "timing",
            "Token timing",
            False,
            "details",
            "",
            "https://target.com",
            5.0,
            10.0,
            20,
            2.0,
        )
        assert a.vulnerable is False
        assert a.samples == 20


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = TimingResult(
            target="https://target.com",
            url="https://target.com",
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Timing Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = TimingAttempt(
            technique="login_timing",
            category="timing",
            description="desc",
            vulnerable=True,
            details="timing diff: 100ms",
            error="",
            endpoint="https://target.com",
            timing_ms=100.0,
            threshold_ms=50.0,
            samples=10,
            stdev_ms=25.0,
        )
        r = TimingResult(
            target="https://target.com",
            url="https://target.com",
            attempts=[a],
            vulnerable_techniques=["login_timing"],
            issues=["Test issue"],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output
        assert "Issues:" in output

    def test_multiple_categories(self, capsys: pytest.CaptureFixture[str]) -> None:
        a1 = TimingAttempt(
            technique="login_timing",
            category="timing",
            description="d",
            vulnerable=True,
            details="found",
            error="",
            endpoint="e",
            timing_ms=100,
            threshold_ms=50,
            samples=10,
            stdev_ms=25,
        )
        a2 = TimingAttempt(
            technique="dns_timing",
            category="timing",
            description="d",
            vulnerable=False,
            details="none",
            error="",
            endpoint="e",
            timing_ms=5,
            threshold_ms=50,
            samples=10,
            stdev_ms=2,
        )
        r = TimingResult(
            target="t",
            url="u",
            attempts=[a1, a2],
            vulnerable_techniques=["login_timing"],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output

    def test_no_url(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = TimingResult(
            target="https://target.com",
            url="",
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Timing Attack Testing" in output
        assert "URL:" not in output
        assert "SECURE" in output


class TestCLI:
    def test_build_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com/login"])
        assert args.url == "https://target.com/login"

    def test_build_parser_with_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com", "-c", "timing"])
        assert args.categories == ["timing"]

    def test_build_parser_with_usernames(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com", "--usernames", "admin", "root"])
        assert args.usernames == ["admin", "root"]

    def test_build_parser_with_token(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com", "--token", "abc123"])
        assert args.token == "abc123"

    def test_build_parser_with_cache_rounds(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com", "--cache-rounds", "10"])
        assert args.cache_rounds == 10

    def test_build_parser_with_dns_domains(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["https://target.com", "--dns-domains", "example.com", "google.com"]
        )
        assert args.dns_domains == ["example.com", "google.com"]

    def test_build_parser_with_output(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com", "-o", "results.json"])
        assert args.output == "results.json"


class TestFreezing:
    def test_attempt_slots(self) -> None:
        assert hasattr(TimingAttempt, "__slots__")

    def test_result_slots(self) -> None:
        assert hasattr(TimingResult, "__slots__")


# ─── Login Timing Measurement ──────────────────────────────────────────────


class TestMeasureLoginTiming:
    @pytest.mark.asyncio
    async def test_single_user_insufficient(
        self, async_client: httpx.AsyncClient
    ) -> None:
        with respx.mock:
            respx.post("https://target.com/login").mock(
                return_value=httpx.Response(200, text="ok")
            )
            attempt = await _measure_login_timing(
                async_client, "https://target.com/login", ["admin"], 0.0, 5.0
            )
        assert attempt.vulnerable is False
        assert attempt.details == "Insufficient data"

    @pytest.mark.asyncio
    async def test_two_users_not_vulnerable(
        self, async_client: httpx.AsyncClient
    ) -> None:
        with respx.mock:
            respx.post("https://target.com/login").mock(
                return_value=httpx.Response(200, text="ok")
            )
            values: list[float] = []
            for i in range(6):
                values.extend([float(i), float(i) + 0.001])
            with patch("mytools.web.timingattack.time.monotonic", side_effect=values):
                attempt = await _measure_login_timing(
                    async_client,
                    "https://target.com/login",
                    ["admin", "root"],
                    0.0,
                    5.0,
                )
        assert attempt.vulnerable is False
        assert attempt.samples == 6

    @pytest.mark.asyncio
    async def test_two_users_vulnerable(self, async_client: httpx.AsyncClient) -> None:
        with respx.mock:
            respx.post("https://target.com/login").mock(
                return_value=httpx.Response(200, text="ok")
            )
            values = [0.0, 0.001, 1.0, 1.001, 2.0, 2.001, 3.0, 3.1, 4.0, 4.1, 5.0, 5.1]
            with patch("mytools.web.timingattack.time.monotonic", side_effect=values):
                attempt = await _measure_login_timing(
                    async_client,
                    "https://target.com/login",
                    ["admin", "root"],
                    0.0,
                    5.0,
                )
        assert attempt.vulnerable is True
        assert "fastest" in attempt.details
        assert attempt.exploit == "hydra -L users.txt -P pass.txt <TARGET> -t 1"

    @pytest.mark.asyncio
    async def test_with_delay(self, async_client: httpx.AsyncClient) -> None:
        with respx.mock:
            respx.post("https://target.com/login").mock(
                return_value=httpx.Response(200, text="ok")
            )
            attempt = await _measure_login_timing(
                async_client, "https://target.com/login", ["admin"], 0.5, 5.0
            )
        assert attempt.vulnerable is False

    @pytest.mark.asyncio
    async def test_http_exceptions(self, async_client: httpx.AsyncClient) -> None:
        with respx.mock:
            respx.post("https://target.com/login").mock(
                side_effect=[
                    httpx.TimeoutException("timeout"),
                    httpx.ConnectError("connect"),
                    httpx.Response(200, text="ok"),
                ]
            )
            attempt = await _measure_login_timing(
                async_client, "https://target.com/login", ["admin"], 0.0, 5.0
            )
        assert attempt.vulnerable is False
        assert attempt.details == "Insufficient data"


# ─── Token Timing Measurement ──────────────────────────────────────────────


class TestMeasureTokenTiming:
    @pytest.mark.asyncio
    async def test_single_char_insufficient(
        self, async_client: httpx.AsyncClient
    ) -> None:
        with respx.mock:
            respx.route(method="GET", url__startswith="https://target.com").mock(
                return_value=httpx.Response(200, text="ok")
            )
            attempt = await _measure_token_timing(
                async_client, "https://target.com", "a", 0.0, 5.0
            )
        assert attempt.details == "Insufficient data"

    @pytest.mark.asyncio
    async def test_not_vulnerable(self, async_client: httpx.AsyncClient) -> None:
        with respx.mock:
            respx.route(method="GET", url__startswith="https://target.com").mock(
                return_value=httpx.Response(200, text="ok")
            )
            values: list[float] = []
            for _ in range(8):
                for _ in range(3):
                    values.extend([0.0, 0.001])
            with patch("mytools.web.timingattack.time.monotonic", side_effect=values):
                attempt = await _measure_token_timing(
                    async_client, "https://target.com", "abcdefgh", 0.0, 5.0
                )
        assert attempt.vulnerable is False
        assert attempt.samples == 24

    @pytest.mark.asyncio
    async def test_vulnerable(self, async_client: httpx.AsyncClient) -> None:
        with respx.mock:
            respx.route(method="GET", url__startswith="https://target.com").mock(
                return_value=httpx.Response(200, text="ok")
            )
            values: list[float] = []
            for pos in range(8):
                delta = 0.001 if pos % 2 == 0 else 0.1
                for _ in range(3):
                    values.extend([0.0, delta])
            with patch("mytools.web.timingattack.time.monotonic", side_effect=values):
                attempt = await _measure_token_timing(
                    async_client, "https://target.com", "abcdefgh", 0.0, 5.0
                )
        assert attempt.vulnerable is True
        assert "range" in attempt.details

    @pytest.mark.asyncio
    async def test_http_exception(self, async_client: httpx.AsyncClient) -> None:
        with respx.mock:
            respx.route(method="GET", url__startswith="https://target.com").mock(
                side_effect=httpx.ConnectError("boom")
            )
            attempt = await _measure_token_timing(
                async_client, "https://target.com", "ab", 0.0, 5.0
            )
        assert attempt.vulnerable is False

    @pytest.mark.asyncio
    async def test_with_delay(self, async_client: httpx.AsyncClient) -> None:
        with respx.mock:
            respx.route(method="GET", url__startswith="https://target.com").mock(
                return_value=httpx.Response(200, text="ok")
            )
            attempt = await _measure_token_timing(
                async_client, "https://target.com", "ab", 0.5, 5.0
            )
        assert attempt.vulnerable is False


# ─── Cache Timing Measurement ──────────────────────────────────────────────


class TestMeasureCacheTiming:
    @pytest.mark.asyncio
    async def test_no_responses(self, async_client: httpx.AsyncClient) -> None:
        with respx.mock:
            respx.route(method="GET", url__startswith="https://target.com").mock(
                side_effect=[
                    httpx.ConnectError("c"),
                    httpx.TimeoutException("t"),
                    httpx.ConnectError("c"),
                    httpx.TimeoutException("t"),
                    httpx.ConnectError("c"),
                ]
            )
            attempt = await _measure_cache_timing(
                async_client, "https://target.com", 2, 0.0, 5.0
            )
        assert attempt.details == "No responses received"

    @pytest.mark.asyncio
    async def test_not_vulnerable(self, async_client: httpx.AsyncClient) -> None:
        with respx.mock:
            respx.route(method="GET", url__startswith="https://target.com").mock(
                return_value=httpx.Response(200, text="ok")
            )
            values = [0.0, 0.05, 1.0, 1.05, 2.0, 2.05, 3.0, 3.05]
            with patch("mytools.web.timingattack.time.monotonic", side_effect=values):
                attempt = await _measure_cache_timing(
                    async_client, "https://target.com", 2, 0.0, 5.0
                )
        assert attempt.vulnerable is False
        assert attempt.samples == 4

    @pytest.mark.asyncio
    async def test_vulnerable(self, async_client: httpx.AsyncClient) -> None:
        with respx.mock:
            respx.route(method="GET", url__startswith="https://target.com").mock(
                return_value=httpx.Response(
                    200, text="ok", headers={"cache-control": "public, max-age=60"}
                )
            )
            values = [0.0, 0.1, 1.0, 1.001, 2.0, 2.1, 3.0, 3.001]
            with patch("mytools.web.timingattack.time.monotonic", side_effect=values):
                attempt = await _measure_cache_timing(
                    async_client, "https://target.com", 2, 0.0, 5.0
                )
        assert attempt.vulnerable is True
        assert "Cache-Control" in attempt.details

    @pytest.mark.asyncio
    async def test_with_delay(self, async_client: httpx.AsyncClient) -> None:
        with respx.mock:
            respx.route(method="GET", url__startswith="https://target.com").mock(
                return_value=httpx.Response(200, text="ok")
            )
            attempt = await _measure_cache_timing(
                async_client, "https://target.com", 1, 0.5, 5.0
            )
        assert attempt.vulnerable is False

    @pytest.mark.asyncio
    async def test_header_request_error(self, async_client: httpx.AsyncClient) -> None:
        with respx.mock:
            respx.route(method="GET", url__startswith="https://target.com").mock(
                side_effect=[
                    httpx.Response(200, text="ok"),
                    httpx.Response(200, text="ok"),
                    httpx.Response(200, text="ok"),
                    httpx.Response(200, text="ok"),
                    httpx.TimeoutException("t"),
                ]
            )
            attempt = await _measure_cache_timing(
                async_client, "https://target.com", 2, 0.0, 5.0
            )
        assert attempt.vulnerable is False
        assert attempt.samples == 4


# ─── DNS Timing Measurement ────────────────────────────────────────────────


class TestMeasureDnsTiming:
    @pytest.mark.asyncio
    async def test_single_domain_insufficient(self) -> None:
        with patch(
            "mytools.web.timingattack.dns.resolver.Resolver",
            return_value=MagicMock(),
        ):
            attempt = await _measure_dns_timing(["example.com"], 5.0)
        assert attempt.details == "Insufficient data"

    @pytest.mark.asyncio
    async def test_not_vulnerable(self) -> None:
        values = [
            0.0,
            0.001,
            1.0,
            1.001,
            2.0,
            2.001,
            3.0,
            3.001,
            4.0,
            4.001,
            5.0,
            5.001,
        ]
        with (
            patch(
                "mytools.web.timingattack.dns.resolver.Resolver",
                return_value=MagicMock(),
            ),
            patch("mytools.web.timingattack.time.monotonic", side_effect=values),
        ):
            attempt = await _measure_dns_timing(["a.com", "b.com"], 5.0)
        assert attempt.vulnerable is False
        assert attempt.samples == 6

    @pytest.mark.asyncio
    async def test_vulnerable(self) -> None:
        values = [0.0, 0.001, 1.0, 1.001, 2.0, 2.001, 3.0, 3.1, 4.0, 4.1, 5.0, 5.1]
        with (
            patch(
                "mytools.web.timingattack.dns.resolver.Resolver",
                return_value=MagicMock(),
            ),
            patch("mytools.web.timingattack.time.monotonic", side_effect=values),
        ):
            attempt = await _measure_dns_timing(["a.com", "b.com"], 5.0)
        assert attempt.vulnerable is True
        assert "fastest" in attempt.details


# ─── _test_timing Orchestration ────────────────────────────────────────────


class TestTestTiming:
    @pytest.mark.asyncio
    async def test_all_defaults(self) -> None:
        with respx.mock:
            respx.route(method="POST", url__startswith="https://target.com").mock(
                return_value=httpx.Response(200, text="ok")
            )
            respx.route(method="GET", url__startswith="https://target.com").mock(
                return_value=httpx.Response(200, text="ok")
            )
            with patch(
                "mytools.web.timingattack.dns.resolver.Resolver",
                return_value=MagicMock(),
            ):
                results = await _test_timing(
                    "https://target.com", 5.0, 0.0, None, None, 2, None
                )
        assert len(results) == 4
        assert all(r.error == "" for r in results)

    @pytest.mark.asyncio
    async def test_login_suffix_and_explicit_options(self) -> None:
        with respx.mock:
            respx.route(method="POST", url__startswith="https://target.com").mock(
                return_value=httpx.Response(200, text="ok")
            )
            respx.route(method="GET", url__startswith="https://target.com").mock(
                return_value=httpx.Response(200, text="ok")
            )
            with patch(
                "mytools.web.timingattack.dns.resolver.Resolver",
                return_value=MagicMock(),
            ):
                results = await _test_timing(
                    "https://target.com/login",
                    5.0,
                    0.0,
                    ["a", "b"],
                    "abcdefgh",
                    2,
                    ["a.com", "b.com"],
                )
        assert len(results) == 4

    @pytest.mark.asyncio
    async def test_measurement_exceptions(self) -> None:
        with (
            patch(
                "mytools.web.timingattack._measure_login_timing",
                new_callable=AsyncMock,
                side_effect=RuntimeError("boom"),
            ),
            patch(
                "mytools.web.timingattack._measure_token_timing",
                new_callable=AsyncMock,
                side_effect=RuntimeError("boom"),
            ),
            patch(
                "mytools.web.timingattack._measure_cache_timing",
                new_callable=AsyncMock,
                side_effect=RuntimeError("boom"),
            ),
            patch(
                "mytools.web.timingattack._measure_dns_timing",
                new_callable=AsyncMock,
                side_effect=RuntimeError("boom"),
            ),
        ):
            results = await _test_timing(
                "https://target.com", 5.0, 0.0, None, None, 2, None
            )
        assert len(results) == 4
        assert all(r.error for r in results)


# ─── _run_scan ─────────────────────────────────────────────────────────────


class TestRunScan:
    @pytest.mark.asyncio
    async def test_secure(self) -> None:
        args = argparse.Namespace(
            url="https://target.com",
            timeout=5.0,
            delay=0.0,
            categories=None,
            usernames=None,
            token=None,
            cache_rounds=2,
            dns_domains=None,
        )
        with respx.mock:
            respx.route(method="POST", url__startswith="https://target.com").mock(
                return_value=httpx.Response(200, text="ok")
            )
            respx.route(method="GET", url__startswith="https://target.com").mock(
                return_value=httpx.Response(200, text="ok")
            )
            with patch(
                "mytools.web.timingattack.dns.resolver.Resolver",
                return_value=MagicMock(),
            ):
                result = await _run_scan(args)
        assert result.overall_status == "secure"
        assert len(result.attempts) == 4
        assert result.target == "https://target.com"

    @pytest.mark.asyncio
    async def test_category_without_timing(self) -> None:
        args = argparse.Namespace(
            url="https://target.com",
            timeout=5.0,
            delay=0.0,
            categories=["other"],
            usernames=None,
            token=None,
            cache_rounds=2,
            dns_domains=None,
        )
        result = await _run_scan(args)
        assert result.overall_status == "secure"
        assert result.attempts == []

    @pytest.mark.asyncio
    async def test_vulnerable(self) -> None:
        vuln = _make_attempt(
            "login_timing",
            "timing",
            "desc",
            True,
            "found",
            "",
            "u",
            100,
            50,
            10,
            25,
        )
        args = argparse.Namespace(
            url="https://target.com",
            timeout=5.0,
            delay=0.0,
            categories=["timing"],
            usernames=None,
            token=None,
            cache_rounds=2,
            dns_domains=None,
        )
        with patch(
            "mytools.web.timingattack._test_timing",
            new_callable=AsyncMock,
            return_value=[vuln],
        ):
            result = await _run_scan(args)
        assert result.overall_status == "vulnerable"
        assert "login_timing" in result.vulnerable_techniques


# ─── Print Results Branches ────────────────────────────────────────────────


class TestPrintResultsSecureCategory:
    def test_secure_category(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = TimingAttempt(
            technique="login_timing",
            category="timing",
            description="d",
            vulnerable=False,
            details="none",
            error="",
            endpoint="e",
            timing_ms=5,
            threshold_ms=50,
            samples=10,
            stdev_ms=2,
        )
        r = TimingResult(
            target="t",
            url="u",
            attempts=[a],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "timing: secure" in output
        assert "SECURE" in output


# ─── Run Once ──────────────────────────────────────────────────────────────


class TestRunOnce:
    def _result(self, status: str) -> TimingResult:
        return TimingResult(
            target="t",
            url="u",
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status=status,
        )

    def test_vulnerable_returns_1(self) -> None:
        args = argparse.Namespace(url="https://target.com", output=None)
        with (
            patch(
                "mytools.web.timingattack.safe_asyncio_run",
                side_effect=lambda coro: asyncio.run(coro),
            ),
            patch(
                "mytools.web.timingattack._run_scan",
                new_callable=AsyncMock,
                return_value=self._result("vulnerable"),
            ),
            patch("mytools.web.timingattack.print_results"),
        ):
            assert run_once(args) == 1

    def test_secure_returns_0(self) -> None:
        args = argparse.Namespace(url="https://target.com", output=None)
        with (
            patch(
                "mytools.web.timingattack.safe_asyncio_run",
                side_effect=lambda coro: asyncio.run(coro),
            ),
            patch(
                "mytools.web.timingattack._run_scan",
                new_callable=AsyncMock,
                return_value=self._result("secure"),
            ),
            patch("mytools.web.timingattack.print_results"),
        ):
            assert run_once(args) == 0

    def test_output_writes(self) -> None:
        args = argparse.Namespace(url="https://target.com", output="out.json")
        with (
            patch(
                "mytools.web.timingattack.safe_asyncio_run",
                side_effect=lambda coro: asyncio.run(coro),
            ),
            patch(
                "mytools.web.timingattack._run_scan",
                new_callable=AsyncMock,
                return_value=self._result("secure"),
            ),
            patch("mytools.web.timingattack.print_results"),
            patch("mytools.web.timingattack.write_output") as mock_write,
        ):
            assert run_once(args) == 0
        mock_write.assert_called_once()


# ─── Main ──────────────────────────────────────────────────────────────────


class TestMain:
    def test_main(self) -> None:
        with patch(
            "mytools.web.timingattack.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()


class TestMainGuard:
    def test_guard(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-timing", "https://target.com"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.timingattack", run_name="__main__")
        assert exc_info.value.code == 0
