#!/usr/bin/env python3
"""Testes unitarios do modulo OAuth 2.0 Misconfiguration."""

from __future__ import annotations

import argparse
import runpy
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mytools.web.oauth import (
    _CATEGORY_MAP,
    _REDIRECT_BYPASS_PAYLOADS,
    _WEAK_SECRETS,
    OAuthAttempt,
    OAuthResult,
    _check_response_indicators,
    _find_authorize_url,
    _test_misconfig_category,
    _test_pkce_bypass_category,
    _test_redirect_uri_category,
    _test_refresh_token_category,
    _test_scope_escalation_category,
    banner_art,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)

_TARGET = "https://example.com/authorize"


def test_category_map_has_five_categories() -> None:
    assert len(_CATEGORY_MAP) == 5


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {
        "misconfig",
        "scope_escalation",
        "redirect_uri",
        "pkce_bypass",
        "refresh_token",
    }


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 27


def test_misconfig_techniques_count() -> None:
    assert len(_CATEGORY_MAP["misconfig"]) == 6


def test_scope_escalation_techniques_count() -> None:
    assert len(_CATEGORY_MAP["scope_escalation"]) == 5


def test_redirect_uri_techniques_count() -> None:
    assert len(_CATEGORY_MAP["redirect_uri"]) == 7


def test_pkce_bypass_techniques_count() -> None:
    assert len(_CATEGORY_MAP["pkce_bypass"]) == 4


def test_refresh_token_techniques_count() -> None:
    assert len(_CATEGORY_MAP["refresh_token"]) == 5


def test_weak_secrets_count() -> None:
    assert len(_WEAK_SECRETS) >= 10


def test_redirect_bypass_payloads_count() -> None:
    assert len(_REDIRECT_BYPASS_PAYLOADS) == 7


def test_redirect_bypass_payloads_have_three_elements() -> None:
    for p in _REDIRECT_BYPASS_PAYLOADS:
        assert len(p) == 3, f"Payload {p[0]} should have 3 elements"


def test_find_authorize_url_with_link() -> None:
    body = '<a href="/oauth/authorize?client_id=123">Login</a>'
    result = _find_authorize_url("https://example.com", body)
    assert result is not None
    assert "authorize" in result


def test_find_authorize_url_with_action() -> None:
    body = '<form action="/auth/login">'
    result = _find_authorize_url("https://example.com", body)
    assert result is not None


def test_find_authorize_url_not_found() -> None:
    body = "<html><body>Safe page</body></html>"
    result = _find_authorize_url("https://example.com", body)
    assert result is None


def test_check_response_indicators_true() -> None:
    body = "<div>You are being redirected to the authorization page</div>"
    assert _check_response_indicators(body, ["redirect", "authorize"]) is True


def test_check_response_indicators_false() -> None:
    body = "<div>Safe content</div>"
    assert _check_response_indicators(body, ["authorize"]) is False


def test_check_response_indicators_case_insensitive() -> None:
    body = "<div>AUTHORIZE Page</div>"
    assert _check_response_indicators(body, ["authorize"]) is True


def test_attempt_dataclass_frozen() -> None:
    a = OAuthAttempt(
        technique="test",
        category="misconfig",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=100,
        status_changed=False,
        size_changed=False,
        vulnerable=True,
        details="test",
        error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False  # type: ignore[reportAttributeAccessIssue]


def test_attempt_dataclass_slots() -> None:
    a = OAuthAttempt(
        technique="test",
        category="misconfig",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=100,
        status_changed=False,
        size_changed=False,
        vulnerable=True,
        details="test",
        error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = OAuthResult(
        target=_TARGET,
        tls=True,
        baseline_status=200,
        baseline_size=100,
        authorize_url=None,
        attempts=[],
        vulnerable_techniques=[],
        blocked_techniques=[],
        issues=[],
        overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"  # type: ignore[reportAttributeAccessIssue]


def test_result_dataclass_slots() -> None:
    r = OAuthResult(
        target=_TARGET,
        tls=True,
        baseline_status=200,
        baseline_size=100,
        authorize_url=None,
        attempts=[],
        vulnerable_techniques=[],
        blocked_techniques=[],
        issues=[],
        overall_status="safe",
    )
    assert not hasattr(r, "__dict__")


def test_no_duplicate_technique_names() -> None:
    all_techniques: list[str] = []
    for techs in _CATEGORY_MAP.values():
        all_techniques.extend(techs)
    assert len(all_techniques) == len(set(all_techniques))


def test_all_techniques_are_strings() -> None:
    for cat, techs in _CATEGORY_MAP.items():
        for t in techs:
            assert isinstance(t, str), f"{cat}/{t} is not a string"


def test_find_authorize_url_absolute_url() -> None:
    body = '<a href="https://idp.example.com/authorize?x=1">Login</a>'
    result = _find_authorize_url("https://example.com", body)
    assert result == "https://idp.example.com/authorize?x=1"


def test_find_authorize_url_relative_urljoin() -> None:
    body = '<form action="/auth/login">'
    result = _find_authorize_url("https://example.com/start", body)
    assert result == "https://example.com/auth/login"


def _mock_response(status: int, text: str, headers: dict | None = None) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.text = text
    resp.headers = headers or {}
    return resp


class TestCategoryTesters:
    @pytest.mark.asyncio
    async def test_misconfig_vulnerable(self) -> None:
        resp = _mock_response(200, "please authorize the application")
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)
        results = await _test_misconfig_category(
            client, "https://e.com/auth", "https://e.com", 10, 200, 100
        )
        assert len(results) == 6
        assert all(r.vulnerable for r in results)
        assert all(r.category == "misconfig" for r in results)
        assert all(r.error == "" for r in results)

    @pytest.mark.asyncio
    async def test_misconfig_not_vulnerable_on_error_body(self) -> None:
        resp = _mock_response(200, "error: access_denied")
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)
        results = await _test_misconfig_category(
            client, "https://e.com/auth", "https://e.com", 10, 200, 100
        )
        assert all(not r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_misconfig_exception(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        results = await _test_misconfig_category(
            client, "https://e.com/auth", "https://e.com", 10, 200, 100
        )
        assert len(results) == 6
        assert all(r.error for r in results)

    @pytest.mark.asyncio
    async def test_scope_escalation_vulnerable(self) -> None:
        resp = _mock_response(200, "consent required for this scope")
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)
        results = await _test_scope_escalation_category(
            client, "https://e.com/auth", 10, 200, 100
        )
        assert len(results) == 5
        assert all(r.vulnerable for r in results)
        assert all(r.category == "scope_escalation" for r in results)

    @pytest.mark.asyncio
    async def test_scope_escalation_exception(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        results = await _test_scope_escalation_category(
            client, "https://e.com/auth", 10, 200, 100
        )
        assert len(results) == 5
        assert all(r.error for r in results)

    @pytest.mark.asyncio
    async def test_redirect_uri_mixed(self) -> None:
        resp = _mock_response(
            302, "", {"location": "https://evil.example.com/callback"}
        )
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)
        results = await _test_redirect_uri_category(
            client, "https://e.com/auth", 10, 200, 100
        )
        assert len(results) == 7
        assert results[0].vulnerable
        assert not results[5].vulnerable
        assert all(r.category == "redirect_uri" for r in results)

    @pytest.mark.asyncio
    async def test_redirect_uri_exception(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        results = await _test_redirect_uri_category(
            client, "https://e.com/auth", 10, 200, 100
        )
        assert len(results) == 7
        assert all(r.error for r in results)

    @pytest.mark.asyncio
    async def test_pkce_bypass_vulnerable(self) -> None:
        resp = _mock_response(200, "please authorize the app")
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)
        results = await _test_pkce_bypass_category(
            client, "https://e.com/auth", 10, 200, 100
        )
        assert len(results) == 4
        assert all(r.vulnerable for r in results)
        assert all(r.category == "pkce_bypass" for r in results)

    @pytest.mark.asyncio
    async def test_pkce_bypass_exception(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        results = await _test_pkce_bypass_category(
            client, "https://e.com/auth", 10, 200, 100
        )
        assert len(results) == 4
        assert all(r.error for r in results)

    @pytest.mark.asyncio
    async def test_refresh_token_vulnerable(self) -> None:
        resp = _mock_response(200, '{"access_token": "abc"}')
        client = AsyncMock()
        client.post = AsyncMock(return_value=resp)
        results = await _test_refresh_token_category(
            client, "https://e.com/token", 10, 200, 100
        )
        assert len(results) == 5
        assert all(r.vulnerable for r in results)
        assert all(r.category == "refresh_token" for r in results)

    @pytest.mark.asyncio
    async def test_refresh_token_not_vulnerable(self) -> None:
        resp = _mock_response(200, '{"error": "invalid_grant"}')
        client = AsyncMock()
        client.post = AsyncMock(return_value=resp)
        results = await _test_refresh_token_category(
            client, "https://e.com/token", 10, 200, 100
        )
        assert all(not r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_refresh_token_exception(self) -> None:
        client = AsyncMock()
        client.post = AsyncMock(side_effect=httpx.RequestError("timeout"))
        results = await _test_refresh_token_category(
            client, "https://e.com/token", 10, 200, 100
        )
        assert len(results) == 5
        assert all(r.error for r in results)


def _attempt(
    technique: str,
    *,
    vulnerable: bool = True,
    error: str = "",
    details: str = "detail",
    category: str = "misconfig",
) -> OAuthAttempt:
    return OAuthAttempt(
        technique=technique,
        category=category,
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=100,
        status_changed=False,
        size_changed=False,
        vulnerable=vulnerable,
        details=details,
        error=error,
        exploit="redirect_uri_manipulation" if vulnerable else "",
        tool="curl" if vulnerable else "",
    )


class TestPrintResults:
    def test_vulnerable_with_dedupe_and_issues(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = OAuthResult(
            target=_TARGET,
            tls=True,
            baseline_status=200,
            baseline_size=100,
            authorize_url=_TARGET,
            attempts=[
                _attempt("missing_state", details="state ausente"),
                _attempt("missing_state"),
                _attempt("empty_state", details=""),
                _attempt("weak_secret", vulnerable=False),
                _attempt("token_in_url", vulnerable=False, error="conn refused"),
            ],
            vulnerable_techniques=["missing_state", "empty_state"],
            blocked_techniques=["weak_secret"],
            issues=["observacao 1", "observacao 2"],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Vulnerabilidades encontradas" in output
        assert "missing_state" in output
        assert "state ausente" in output
        assert "observacao 2" in output
        assert "Erros:" in output

    def test_no_vulns_with_blocked(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = OAuthResult(
            target=_TARGET,
            tls=False,
            baseline_status=200,
            baseline_size=100,
            authorize_url=None,
            attempts=[_attempt("weak_secret", vulnerable=False)],
            vulnerable_techniques=[],
            blocked_techniques=["weak_secret"],
            issues=[],
            overall_status="safe",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Nenhuma vulnerabilidade OAuth detectada" in output
        assert "Bloqueados:" in output


class TestRunScan:
    @pytest.mark.asyncio
    async def test_baseline_fetch_error_returns_1(self) -> None:
        with patch("mytools.web.oauth.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.oauth.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.side_effect = httpx.RequestError("fail")
                result = await run_scan(_TARGET, [], 10, None)
                assert result == 1

    @pytest.mark.asyncio
    async def test_unknown_category_no_attempts_returns_0(self) -> None:
        with patch("mytools.web.oauth.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.oauth.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = (200, {}, b"<html>plain page</html>", b"")
                with patch("mytools.web.oauth._CATEGORY_TESTERS") as mock_testers:
                    mock_testers.get.return_value = None
                    result = await run_scan(_TARGET, ["bogus"], 10, None)
                    assert result == 0
                    mock_testers.get.assert_called_once_with("bogus")

    @pytest.mark.asyncio
    async def test_vulnerable_all_categories_returns_1(self) -> None:
        with patch("mytools.web.oauth.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.oauth.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = (
                    200,
                    {},
                    b'<a href="/authorize">Login</a>',
                    b"",
                )
                with patch("mytools.web.oauth._CATEGORY_TESTERS") as mock_testers:
                    mock_testers.get.return_value = AsyncMock(
                        return_value=[_attempt("missing_state")]
                    )
                    result = await run_scan(_TARGET, [], 10, None)
                    assert result == 1
                    assert mock_testers.get.call_count == 5

    @pytest.mark.asyncio
    async def test_tester_exception_appends_error(self) -> None:
        with patch("mytools.web.oauth.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.oauth.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = (200, {}, b"<html>page</html>", b"")
                with patch("mytools.web.oauth._CATEGORY_TESTERS") as mock_testers:
                    mock_testers.get.return_value = AsyncMock(
                        side_effect=RuntimeError("boom")
                    )
                    result = await run_scan(_TARGET, ["misconfig"], 10, None)
                    assert result == 0

    @pytest.mark.asyncio
    async def test_safe_with_output_returns_0(self) -> None:
        with patch("mytools.web.oauth.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.oauth.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = (200, {}, b"<html>page</html>", b"")
                with patch("mytools.web.oauth._CATEGORY_TESTERS") as mock_testers:
                    mock_testers.get.return_value = AsyncMock(
                        return_value=[_attempt("weak_secret", vulnerable=False)]
                    )
                    with patch("mytools.web.oauth.write_output") as mock_write:
                        result = await run_scan(
                            _TARGET, ["scope_escalation"], 10, "out.json"
                        )
                        assert result == 0
                        mock_write.assert_called_once()


class TestBannerArt:
    def test_banner_art(self) -> None:
        with patch("mytools.web.oauth.create_banner") as mock_banner:
            mock_banner.return_value = MagicMock()
            banner_art()
            mock_banner.assert_called_once()


class TestBuildParser:
    def test_has_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_default_category_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.category == "all"

    def test_category_choices(self) -> None:
        parser = build_parser()
        for action in parser._actions:
            if action.dest == "category":
                assert set(action.choices or []) == {
                    "all",
                    "misconfig",
                    "scope_escalation",
                    "redirect_uri",
                    "pkce_bypass",
                    "refresh_token",
                }


class TestRunOnce:
    def test_all_category_passes_empty_list(self) -> None:
        args = argparse.Namespace(url=_TARGET, category="all", timeout=10, output=None)
        with patch(
            "mytools.web.oauth.run_scan", new_callable=AsyncMock, return_value=0
        ) as mock_scan:
            result = run_once(args)
            assert result == 0
            assert mock_scan.call_args.kwargs["categories"] == []

    def test_specific_category(self) -> None:
        args = argparse.Namespace(
            url=_TARGET, category="pkce_bypass", timeout=5, output=None
        )
        with patch(
            "mytools.web.oauth.run_scan", new_callable=AsyncMock, return_value=1
        ) as mock_scan:
            result = run_once(args)
            assert result == 1
            assert mock_scan.call_args.kwargs["categories"] == ["pkce_bypass"]


class TestMain:
    def test_main_returns_int(self) -> None:
        with patch("mytools.web.oauth.run_main_loop", return_value=0) as mock_loop:
            result = main()
            assert result == 0
            mock_loop.assert_called_once()


class TestMainGuard:
    def test_guard_runs(self) -> None:
        with (
            patch("sys.argv", ["mytools-oauth"]),
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("mytools.core.base.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.web.oauth", run_name="__main__")
