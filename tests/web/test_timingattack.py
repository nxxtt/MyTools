#!/usr/bin/env python3
"""Tests for timingattack.py."""

from __future__ import annotations

import pytest

from mytools.web.timingattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    TimingAttempt,
    TimingResult,
    _make_attempt,
    build_parser,
    print_results,
)


class TestTimingAttempt:
    def test_creation(self) -> None:
        a = TimingAttempt(
            technique="login_timing", category="timing",
            description="Login timing", vulnerable=False,
            details="test", error="", endpoint="https://target.com",
            timing_ms=10.0, threshold_ms=50.0, samples=10, stdev_ms=5.0,
        )
        assert a.technique == "login_timing"
        assert a.vulnerable is False
        assert a.timing_ms == 10.0

    def test_frozen(self) -> None:
        a = TimingAttempt(
            technique="t", category="c", description="d",
            vulnerable=False, details="", error="", endpoint="e",
            timing_ms=0, threshold_ms=0, samples=0, stdev_ms=0,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestTimingResult:
    def test_creation(self) -> None:
        r = TimingResult(
            target="https://target.com", url="https://target.com",
            attempts=[], vulnerable_techniques=[], issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.url == "https://target.com"

    def test_frozen(self) -> None:
        r = TimingResult(
            target="t", url="u", attempts=[],
            vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        assert set(_CATEGORY_MAP.keys()) == {"timing"}

    def test_timing_techniques(self) -> None:
        assert set(_CATEGORY_MAP["timing"]) == {
            "login_timing", "token_timing", "cache_timing", "dns_timing",
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
            "login_timing", "timing", "Login timing", True,
            "details", "", "https://target.com", 100.0, 50.0, 10, 25.0,
        )
        assert a.vulnerable is True
        assert a.timing_ms == 100.0
        assert a.stdev_ms == 25.0

    def test_no_vuln(self) -> None:
        a = _make_attempt(
            "token_timing", "timing", "Token timing", False,
            "details", "", "https://target.com", 5.0, 10.0, 20, 2.0,
        )
        assert a.vulnerable is False
        assert a.samples == 20


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = TimingResult(
            target="https://target.com", url="https://target.com",
            attempts=[], vulnerable_techniques=[], issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Timing Attack Testing" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a = TimingAttempt(
            technique="login_timing", category="timing", description="desc",
            vulnerable=True, details="timing diff: 100ms", error="",
            endpoint="https://target.com", timing_ms=100.0,
            threshold_ms=50.0, samples=10, stdev_ms=25.0,
        )
        r = TimingResult(
            target="https://target.com", url="https://target.com",
            attempts=[a], vulnerable_techniques=["login_timing"],
            issues=["Test issue"], overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output
        assert "Issues:" in output

    def test_multiple_categories(self, capsys: pytest.CaptureFixture[str]) -> None:
        a1 = TimingAttempt(
            technique="login_timing", category="timing", description="d",
            vulnerable=True, details="found", error="",
            endpoint="e", timing_ms=100, threshold_ms=50,
            samples=10, stdev_ms=25,
        )
        a2 = TimingAttempt(
            technique="dns_timing", category="timing", description="d",
            vulnerable=False, details="none", error="",
            endpoint="e", timing_ms=5, threshold_ms=50,
            samples=10, stdev_ms=2,
        )
        r = TimingResult(
            target="t", url="u", attempts=[a1, a2],
            vulnerable_techniques=["login_timing"], issues=[],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output


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
        args = parser.parse_args(["https://target.com", "--dns-domains", "example.com", "google.com"])
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
