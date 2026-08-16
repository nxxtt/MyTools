"""Testes do modulo loginbruteforce."""

import argparse
from dataclasses import asdict
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import mytools.web.loginbruteforce as loginbruteforce_module
from mytools.web.loginbruteforce import (
    BruteForceAttempt,
    BruteForceResult,
    _check_lockout,
    _check_login_success,
    _check_rate_limit,
    _detect_form,
    _get_lockout_indicators,
    _get_passwords,
    _get_rate_limit_indicators,
    _get_success_indicators,
    _get_usernames,
    _LoginFormParser,
    _test_credentials,
    _test_lockout,
    _test_password_spray,
    _test_rate_limit,
    banner_art,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)

# ---------------------------------------------------------------------------
# _get_usernames / _get_passwords
# ---------------------------------------------------------------------------


class TestPayloads:
    def test_usernames_loaded(self) -> None:
        usernames = _get_usernames()
        assert isinstance(usernames, list)
        assert len(usernames) > 0
        assert "admin" in usernames

    def test_passwords_loaded(self) -> None:
        passwords = _get_passwords()
        assert isinstance(passwords, list)
        assert len(passwords) > 0
        assert "password" in passwords

    def test_lockout_indicators_loaded(self) -> None:
        indicators = _get_lockout_indicators()
        assert isinstance(indicators, list)
        assert len(indicators) > 0

    def test_rate_limit_indicators_loaded(self) -> None:
        indicators = _get_rate_limit_indicators()
        assert isinstance(indicators, list)
        assert len(indicators) > 0

    def test_success_indicators_loaded(self) -> None:
        indicators = _get_success_indicators()
        assert isinstance(indicators, list)
        assert len(indicators) > 0


# ---------------------------------------------------------------------------
# _LoginFormParser
# ---------------------------------------------------------------------------


class TestLoginFormParser:
    def test_parse_simple_form(self) -> None:
        html = '<form action="/login" method="POST"><input type="text" name="username"><input type="password" name="password"><input type="submit" value="Login"></form>'
        parser = _LoginFormParser()
        parser.feed(html)
        assert len(parser.forms) == 1
        assert parser.forms[0]["action"] == "/login"
        assert parser.forms[0]["method"] == "POST"

    def test_parse_no_form(self) -> None:
        html = "<html><body>No form here</body></html>"
        parser = _LoginFormParser()
        parser.feed(html)
        assert len(parser.forms) == 0

    def test_parse_multiple_forms(self) -> None:
        html = '<form method="POST"><input type="password" name="pw"></form><form method="GET"><input type="text" name="q"></form>'
        parser = _LoginFormParser()
        parser.feed(html)
        assert len(parser.forms) == 2

    def test_parse_fields_captured(self) -> None:
        html = '<form><input type="text" name="user"><input type="password" name="pass"><input type="hidden" name="token" value="abc"></form>'
        parser = _LoginFormParser()
        parser.feed(html)
        fields = cast(list[dict[str, str]], parser.forms[0].get("fields", []))
        field_names = [f.get("name", "") for f in fields]
        assert "user" in field_names
        assert "pass" in field_names
        assert "token" not in field_names


# ---------------------------------------------------------------------------
# _detect_form
# ---------------------------------------------------------------------------


class TestDetectForm:
    def test_detect_login_form(self) -> None:
        html = '<form action="/auth" method="POST"><input type="text" name="email"><input type="password" name="pass"></form>'
        result = _detect_form(html, "https://example.com")
        assert result is not None
        _action_url, method, field_map = result
        assert method == "POST"
        assert "password" in field_map
        assert "username" in field_map

    def test_no_password_field(self) -> None:
        html = '<form><input type="text" name="q"></form>'
        result = _detect_form(html, "https://example.com")
        assert result is None

    def test_no_form(self) -> None:
        html = "<html><body>no form</body></html>"
        result = _detect_form(html, "https://example.com")
        assert result is None

    def test_relative_action_url(self) -> None:
        html = '<form action="login" method="POST"><input type="password" name="pw"></form>'
        result = _detect_form(html, "https://example.com/page")
        assert result is not None
        action_url, _, _ = result
        assert "example.com" in action_url

    def test_empty_action_uses_base(self) -> None:
        html = '<form method="POST"><input type="password" name="pw"></form>'
        result = _detect_form(html, "https://example.com/login")
        assert result is not None
        action_url, _, _ = result
        assert action_url == "https://example.com/login"

    def test_feed_exception_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _RaisingParser:
            def __init__(self) -> None:
                self.forms: list[dict[str, object]] = []

            def feed(self, html: str) -> None:
                raise ValueError("boom")

        monkeypatch.setattr(
            "mytools.web.loginbruteforce._LoginFormParser", _RaisingParser
        )
        assert _detect_form("<html></html>", "https://example.com") is None

    def test_non_list_fields_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Parser:
            def __init__(self) -> None:
                self.forms: list[dict[str, object]] = [
                    {"action": "", "method": "POST", "fields": "nope"}
                ]

            def feed(self, html: str) -> None:
                pass

        monkeypatch.setattr("mytools.web.loginbruteforce._LoginFormParser", _Parser)
        assert _detect_form("<html></html>", "https://example.com") is None

    def test_non_dict_field_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Parser:
            def __init__(self) -> None:
                self.forms: list[dict[str, object]] = [
                    {
                        "action": "/login",
                        "method": "POST",
                        "fields": [{"type": "password", "name": "pw"}, "junk"],
                    }
                ]

            def feed(self, html: str) -> None:
                pass

        monkeypatch.setattr("mytools.web.loginbruteforce._LoginFormParser", _Parser)
        result = _detect_form("<html></html>", "https://example.com")
        assert result is not None
        _action_url, method, field_map = result
        assert method == "POST"
        assert field_map["password"] == "pw"

    def test_other_field_type_ignored(self) -> None:
        html = (
            '<form action="/login" method="POST">'
            '<input type="password" name="pw">'
            '<input type="checkbox" name="remember">'
            "</form>"
        )
        result = _detect_form(html, "https://example.com")
        assert result is not None
        _action_url, method, field_map = result
        assert method == "POST"
        assert field_map["password"] == "pw"
        assert "username" not in field_map

    def test_non_string_action_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _Parser:
            def __init__(self) -> None:
                self.forms: list[dict[str, object]] = [
                    {
                        "action": ["/login"],
                        "method": "POST",
                        "fields": [{"type": "password", "name": "pw"}],
                    }
                ]

            def feed(self, html: str) -> None:
                pass

        monkeypatch.setattr("mytools.web.loginbruteforce._LoginFormParser", _Parser)
        assert _detect_form("<html></html>", "https://example.com") is None


# ---------------------------------------------------------------------------
# _check_lockout
# ---------------------------------------------------------------------------


class TestCheckLockout:
    def test_lockout_detected(self) -> None:
        indicators = ["account locked", "too many attempts"]
        detected, detail = _check_lockout(
            "Account locked due to too many attempts", indicators
        )
        assert detected is True
        assert "account locked" in detail.lower()

    def test_lockout_not_detected(self) -> None:
        indicators = ["account locked", "too many attempts"]
        detected, _ = _check_lockout("Welcome back!", indicators)
        assert detected is False

    def test_case_insensitive(self) -> None:
        indicators = ["ACCOUNT LOCKED"]
        detected, _ = _check_lockout("Your ACCOUNT LOCKED", indicators)
        assert detected is True


# ---------------------------------------------------------------------------
# _check_rate_limit
# ---------------------------------------------------------------------------


class TestCheckRateLimit:
    def test_429_detected(self) -> None:
        detected, detail = _check_rate_limit(429, "", [])
        assert detected is True
        assert "429" in detail

    def test_body_indicator(self) -> None:
        detected, detail = _check_rate_limit(200, "Rate limit exceeded", ["rate limit"])
        assert detected is True
        assert "rate limit" in detail.lower()

    def test_not_detected(self) -> None:
        detected, _ = _check_rate_limit(200, "Welcome", ["rate limit"])
        assert detected is False

    def test_403_with_indicator(self) -> None:
        detected, _detail = _check_rate_limit(403, "Request throttled", ["throttle"])
        assert detected is True

    def test_403_with_body_indicator_no_indicators(self) -> None:
        detected, detail = _check_rate_limit(403, "Request throttled", [])
        assert detected is True
        assert "403" in detail


# ---------------------------------------------------------------------------
# _check_login_success
# ---------------------------------------------------------------------------


class TestCheckLoginSuccess:
    def test_redirect_success(self) -> None:
        detected, detail = _check_login_success(302, "", [], "/dashboard")
        assert detected is True
        assert "Redirect" in detail

    def test_body_indicator(self) -> None:
        detected, _detail = _check_login_success(
            200, "Welcome back, admin!", ["welcome back"], ""
        )
        assert detected is True

    def test_not_detected(self) -> None:
        detected, _ = _check_login_success(
            200, "Invalid credentials", ["dashboard"], ""
        )
        assert detected is False

    def test_non_success_status(self) -> None:
        detected, _ = _check_login_success(401, "Unauthorized", ["dashboard"], "")
        assert detected is False

    def test_redirect_without_keyword(self) -> None:
        detected, _ = _check_login_success(302, "", [], "/foo")
        assert detected is False


# ---------------------------------------------------------------------------
# BruteForceAttempt / BruteForceResult dataclasses
# ---------------------------------------------------------------------------


class TestBruteForceAttempt:
    def test_frozen(self) -> None:
        attempt = BruteForceAttempt(
            technique="rate_limit",
            category="rate_limit",
            url="http://x",
            username="admin",
            payload="test",
            status_code=200,
            response_size=100,
            response_time=0.1,
            lockout_detected=False,
            rate_limit_detected=False,
            login_success=False,
            vulnerable=True,
            details="no rate limit",
        )
        with pytest.raises(AttributeError):
            attempt.technique = "lockout"  # type: ignore[misc]

    def test_slots(self) -> None:
        attempt = BruteForceAttempt(
            technique="rate_limit",
            category="rate_limit",
            url="http://x",
            username="admin",
            payload="test",
            status_code=200,
            response_size=100,
            response_time=0.1,
            lockout_detected=False,
            rate_limit_detected=False,
            login_success=False,
            vulnerable=True,
            details="no rate limit",
        )
        assert not hasattr(attempt, "__dict__")

    def test_asdict(self) -> None:
        attempt = BruteForceAttempt(
            technique="rate_limit",
            category="rate_limit",
            url="http://x",
            username="admin",
            payload="test",
            status_code=200,
            response_size=100,
            response_time=0.1,
            lockout_detected=False,
            rate_limit_detected=False,
            login_success=False,
            vulnerable=True,
            details="no rate limit",
        )
        d = asdict(attempt)
        assert d["technique"] == "rate_limit"
        assert d["vulnerable"] is True


class TestBruteForceResult:
    def test_frozen(self) -> None:
        result = BruteForceResult(
            target="http://x",
            login_url="http://x/login",
            attempts=[],
            rate_limit_found=False,
            lockout_found=False,
            weak_credentials=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            result.target = "http://y"  # type: ignore[misc]

    def test_asdict(self) -> None:
        result = BruteForceResult(
            target="http://x",
            login_url="http://x/login",
            attempts=[],
            rate_limit_found=True,
            lockout_found=False,
            weak_credentials=[],
            issues=[],
            overall_status="vulnerable",
        )
        d = asdict(result)
        assert d["rate_limit_found"] is True
        assert d["overall_status"] == "vulnerable"


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


class TestBuildParser:
    def test_url_arg(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["http://target.com/login"])
        assert args.url == "http://target.com/login"

    def test_category_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["http://target.com/login"])
        assert args.category == "all"

    def test_category_rate_limit(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["http://target.com/login", "-c", "rate_limit"])
        assert args.category == "rate_limit"

    def test_category_credential(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["http://target.com/login", "-c", "credential"])
        assert args.category == "credential"

    def test_category_spray(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["http://target.com/login", "-c", "spray"])
        assert args.category == "spray"

    def test_username_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["http://target.com/login"])
        assert args.username == "admin"

    def test_password_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["http://target.com/login"])
        assert args.password == "password"

    def test_concurrency_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["http://target.com/login"])
        assert args.concurrency == 5


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


class TestPrintResults:
    def test_secure_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = BruteForceResult(
            target="http://x",
            login_url="http://x/login",
            attempts=[],
            rate_limit_found=True,
            lockout_found=True,
            weak_credentials=[],
            issues=["Rate limit detectado"],
            overall_status="secure",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "LOGIN BRUTE FORCE" in captured.out
        assert "SECURE" in captured.out

    def test_vulnerable_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = BruteForceResult(
            target="http://x",
            login_url="http://x/login",
            attempts=[],
            rate_limit_found=False,
            lockout_found=False,
            weak_credentials=["admin:password"],
            issues=["Rate limiting NAO detectado"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "VULNERABLE" in captured.out
        assert "admin:password" in captured.out

    def test_vulnerable_attempts_dedup(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        rl = BruteForceAttempt(
            technique="rate_limit",
            category="rate_limit",
            url="http://x/login",
            username="admin",
            payload="password_0",
            status_code=200,
            response_size=100,
            response_time=0.1,
            lockout_detected=False,
            rate_limit_detected=False,
            login_success=False,
            vulnerable=True,
            details="no rate limit",
        )
        lo1 = BruteForceAttempt(
            technique="lockout",
            category="lockout",
            url="http://x/login",
            username="admin",
            payload="wrongpassword_0",
            status_code=200,
            response_size=100,
            response_time=0.1,
            lockout_detected=False,
            rate_limit_detected=False,
            login_success=False,
            vulnerable=True,
            details="no lockout",
        )
        lo2 = BruteForceAttempt(
            technique="lockout",
            category="lockout",
            url="http://x/login",
            username="admin",
            payload="wrongpassword_1",
            status_code=200,
            response_size=100,
            response_time=0.1,
            lockout_detected=False,
            rate_limit_detected=False,
            login_success=False,
            vulnerable=True,
            details="dup",
        )
        result = BruteForceResult(
            target="http://x",
            login_url="http://x/login",
            attempts=[rl, lo1, lo2],
            rate_limit_found=False,
            lockout_found=False,
            weak_credentials=[],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "[VULNERAVEL]" in captured.out
        assert "rate_limit: no rate limit" in captured.out
        assert "lockout: no lockout" in captured.out


# ---------------------------------------------------------------------------
# banner_art
# ---------------------------------------------------------------------------


class TestBanner:
    def test_callable(self) -> None:
        assert callable(banner_art)

    def test_runs(self, capsys: pytest.CaptureFixture[str]) -> None:
        banner_art()
        captured = capsys.readouterr()
        assert "Login Brute Force" in captured.out


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


class TestMain:
    def test_no_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.argv", ["mytools-bruteforce"])
        monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(EOFError))
        result = main()
        assert result == 0

    def test_runs_main_loop(self) -> None:
        with patch(
            "mytools.web.loginbruteforce.run_main_loop", return_value=0
        ) as mock_run_main_loop:
            assert main() == 0
            mock_run_main_loop.assert_called_once()

    def test_main_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import runpy

        def _raise(*_args: object, **_kwargs: object) -> int:
            raise SystemExit(0)

        monkeypatch.setattr("mytools.core.utils.run_main_loop", _raise)
        with pytest.raises(SystemExit):
            runpy.run_module("mytools.web.loginbruteforce", run_name="__main__")


# ---------------------------------------------------------------------------
# run_scan (mocked)
# ---------------------------------------------------------------------------


class TestRunScan:
    @pytest.mark.asyncio()
    async def test_no_form_detected(self) -> None:
        mock_resp = MagicMock()
        mock_resp.text = "<html><body>No form</body></html>"
        mock_resp.status_code = 200
        mock_resp.content = b"<html>"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("mytools.web.loginbruteforce.create_async_client") as mock_factory:
            mock_factory.return_value = mock_client
            result = await run_scan("http://target.com/login", category="all")
            assert result.overall_status == "error"
            assert any("Nenhum formulario" in i for i in result.issues)

    @pytest.mark.asyncio()
    async def test_rate_limit_found(self) -> None:
        login_form = '<form method="POST"><input type="text" name="user"><input type="password" name="pw"></form>'

        get_resp = MagicMock()
        get_resp.text = login_form
        get_resp.status_code = 200
        get_resp.content = b"<form>"

        post_resp = MagicMock()
        post_resp.status_code = 429
        post_resp.text = "Rate limit exceeded"
        post_resp.content = b"Rate limit"
        post_resp.headers = {}

        call_count = 0

        async def mock_post(*args, **kwargs):  # type: ignore[no-untyped-def]
            nonlocal call_count
            call_count += 1
            return post_resp

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=get_resp)
        mock_client.post = mock_post
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("mytools.web.loginbruteforce.create_async_client") as mock_factory:
            mock_factory.return_value = mock_client
            result = await run_scan(
                "http://target.com/login",
                category="rate_limit",
                delay=0.0,
            )
            assert result.rate_limit_found is True
            assert result.overall_status == "secure"

    @pytest.mark.asyncio()
    async def test_lockout_not_found(self) -> None:
        login_form = '<form method="POST"><input type="text" name="user"><input type="password" name="pw"></form>'

        get_resp = MagicMock()
        get_resp.text = login_form
        get_resp.status_code = 200
        get_resp.content = b"<form>"

        post_resp = MagicMock()
        post_resp.status_code = 200
        post_resp.text = "Invalid credentials"
        post_resp.content = b"invalid"
        post_resp.headers = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=get_resp)
        mock_client.post = AsyncMock(return_value=post_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("mytools.web.loginbruteforce.create_async_client") as mock_factory:
            mock_factory.return_value = mock_client
            result = await run_scan(
                "http://target.com/login",
                category="lockout",
                delay=0.0,
            )
            assert result.lockout_found is False
            assert any("NAO detectado" in i for i in result.issues)

    @pytest.mark.asyncio()
    async def test_invalid_category(self) -> None:
        login_form = '<form method="POST"><input type="text" name="user"><input type="password" name="pw"></form>'

        get_resp = MagicMock()
        get_resp.text = login_form
        get_resp.status_code = 200
        get_resp.content = b"<form>"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=get_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("mytools.web.loginbruteforce.create_async_client") as mock_factory:
            mock_factory.return_value = mock_client
            result = await run_scan(
                "http://target.com/login",
                category="invalid",
            )
            assert result.overall_status == "error"
            assert any("Categoria desconhecida" in i for i in result.issues)

    @pytest.mark.asyncio()
    async def test_no_scheme(self) -> None:
        get_resp = MagicMock()
        get_resp.text = "<html>No form</html>"
        get_resp.status_code = 200
        get_resp.content = b"<html>"

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=get_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("mytools.web.loginbruteforce.create_async_client") as mock_factory:
            mock_factory.return_value = mock_client
            result = await run_scan("target.com/login", category="all")
            assert result.overall_status == "error"
            assert result.target == "http://target.com/login"

    @pytest.mark.asyncio()
    async def test_get_request_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("mytools.web.loginbruteforce.create_async_client") as mock_factory:
            mock_factory.return_value = mock_client
            result = await run_scan("http://target.com/login", category="all")
            assert result.overall_status == "error"
            assert any("Falha ao conectar" in i for i in result.issues)

    @pytest.mark.asyncio()
    async def test_rate_limit_not_detected(self) -> None:
        login_form = '<form method="POST"><input type="text" name="user"><input type="password" name="pw"></form>'

        get_resp = MagicMock()
        get_resp.text = login_form
        get_resp.status_code = 200
        get_resp.content = b"<form>"

        post_resp = MagicMock()
        post_resp.status_code = 200
        post_resp.text = "Invalid credentials"
        post_resp.content = b"invalid"
        post_resp.headers = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=get_resp)
        mock_client.post = AsyncMock(return_value=post_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("mytools.web.loginbruteforce.create_async_client") as mock_factory:
            mock_factory.return_value = mock_client
            result = await run_scan(
                "http://target.com/login",
                category="rate_limit",
                delay=0.1,
            )
            assert result.rate_limit_found is False
            assert any("NAO detectado" in i for i in result.issues)
            assert result.overall_status == "vulnerable"

    @pytest.mark.asyncio()
    async def test_lockout_found(self) -> None:
        login_form = '<form method="POST"><input type="text" name="user"><input type="password" name="pw"></form>'

        get_resp = MagicMock()
        get_resp.text = login_form
        get_resp.status_code = 200
        get_resp.content = b"<form>"

        post_invalid = MagicMock()
        post_invalid.status_code = 200
        post_invalid.text = "Invalid credentials"
        post_invalid.content = b"invalid"
        post_invalid.headers = {}

        post_locked = MagicMock()
        post_locked.status_code = 200
        post_locked.text = "Account locked due to too many attempts"
        post_locked.content = b"locked"
        post_locked.headers = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=get_resp)
        mock_client.post = AsyncMock(side_effect=[post_invalid, post_locked])
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("mytools.web.loginbruteforce.create_async_client") as mock_factory:
            mock_factory.return_value = mock_client
            result = await run_scan(
                "http://target.com/login",
                category="lockout",
                delay=0.1,
            )
            assert result.lockout_found is True
            assert any("detectado (bom)" in i for i in result.issues)

    @pytest.mark.asyncio()
    async def test_credential_category(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.loginbruteforce._get_usernames", lambda: ["admin"]
        )
        monkeypatch.setattr(
            "mytools.web.loginbruteforce._get_passwords", lambda: ["password"]
        )
        login_form = '<form method="POST"><input type="text" name="user"><input type="password" name="pw"></form>'

        get_resp = MagicMock()
        get_resp.text = login_form
        get_resp.status_code = 200
        get_resp.content = b"<form>"

        post_resp = MagicMock()
        post_resp.status_code = 200
        post_resp.text = "Welcome to the dashboard"
        post_resp.content = b"dashboard"
        post_resp.headers = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=get_resp)
        mock_client.post = AsyncMock(return_value=post_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("mytools.web.loginbruteforce.create_async_client") as mock_factory:
            mock_factory.return_value = mock_client
            result = await run_scan(
                "http://target.com/login",
                category="credential",
                delay=0.1,
            )
            assert result.weak_credentials == ["admin:password"]
            assert result.overall_status == "vulnerable"

    @pytest.mark.asyncio()
    async def test_spray_category(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.loginbruteforce._get_usernames", lambda: ["admin"]
        )
        login_form = '<form method="POST"><input type="text" name="user"><input type="password" name="pw"></form>'

        get_resp = MagicMock()
        get_resp.text = login_form
        get_resp.status_code = 200
        get_resp.content = b"<form>"

        post_resp = MagicMock()
        post_resp.status_code = 200
        post_resp.text = "dashboard area"
        post_resp.content = b"dashboard"
        post_resp.headers = {}

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=get_resp)
        mock_client.post = AsyncMock(return_value=post_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("mytools.web.loginbruteforce.create_async_client") as mock_factory:
            mock_factory.return_value = mock_client
            result = await run_scan(
                "http://target.com/login",
                category="spray",
                delay=0.1,
                password="123456",
            )
            assert result.weak_credentials == ["admin:123456"]
            assert result.overall_status == "vulnerable"


# ---------------------------------------------------------------------------
# _test_rate_limit / _test_lockout
# ---------------------------------------------------------------------------


class TestRateLimitFunction:
    @pytest.mark.asyncio()
    async def test_request_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("boom"))
        attempts = await _test_rate_limit(
            mock_client,
            "http://target.com/login",
            "admin",
            "password",
            {"username": "user", "password": "pw"},
            count=2,
            delay=0.0,
        )
        assert len(attempts) == 2
        assert all(a.error for a in attempts)
        assert all(not a.vulnerable for a in attempts)


class TestLockoutFunction:
    @pytest.mark.asyncio()
    async def test_request_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("boom"))
        attempts = await _test_lockout(
            mock_client,
            "http://target.com/login",
            "admin",
            "wrongpassword",
            {"username": "user", "password": "pw"},
            count=2,
            delay=0.0,
        )
        assert len(attempts) == 2
        assert all(a.error for a in attempts)


# ---------------------------------------------------------------------------
# _test_credentials
# ---------------------------------------------------------------------------


class TestCredentialsFunction:
    @pytest.mark.asyncio()
    async def test_fail(self) -> None:
        post_resp = MagicMock()
        post_resp.status_code = 200
        post_resp.text = "Invalid credentials"
        post_resp.content = b"invalid"
        post_resp.headers = {}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=post_resp)
        attempts = await _test_credentials(
            mock_client,
            "http://target.com/login",
            ["admin"],
            ["password"],
            {"username": "user", "password": "pw"},
            delay=0.0,
        )
        assert len(attempts) == 1
        assert attempts[0].login_success is False
        assert "sem indicacao" in attempts[0].details

    @pytest.mark.asyncio()
    async def test_request_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("boom"))
        attempts = await _test_credentials(
            mock_client,
            "http://target.com/login",
            ["admin"],
            ["password"],
            {"username": "user", "password": "pw"},
            delay=0.0,
        )
        assert len(attempts) == 1
        assert attempts[0].error


# ---------------------------------------------------------------------------
# _test_password_spray
# ---------------------------------------------------------------------------


class TestPasswordSprayFunction:
    @pytest.mark.asyncio()
    async def test_fail(self) -> None:
        post_resp = MagicMock()
        post_resp.status_code = 200
        post_resp.text = "Invalid credentials"
        post_resp.content = b"invalid"
        post_resp.headers = {}

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=post_resp)
        attempts = await _test_password_spray(
            mock_client,
            "http://target.com/login",
            ["admin"],
            "password",
            {"username": "user", "password": "pw"},
            delay=0.0,
        )
        assert len(attempts) == 1
        assert attempts[0].login_success is False
        assert "sem indicacao" in attempts[0].details

    @pytest.mark.asyncio()
    async def test_request_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.ConnectError("boom"))
        attempts = await _test_password_spray(
            mock_client,
            "http://target.com/login",
            ["admin"],
            "password",
            {"username": "user", "password": "pw"},
            delay=0.0,
        )
        assert len(attempts) == 1
        assert attempts[0].error


# ---------------------------------------------------------------------------
# run_once
# ---------------------------------------------------------------------------


class TestRunOnce:
    def test_secure_prints(self, monkeypatch: pytest.MonkeyPatch) -> None:
        result = BruteForceResult(
            target="http://x",
            login_url="http://x/login",
            attempts=[],
            rate_limit_found=True,
            lockout_found=True,
            weak_credentials=[],
            issues=[],
            overall_status="secure",
        )
        monkeypatch.setattr(
            loginbruteforce_module, "run_scan", AsyncMock(return_value=result)
        )
        monkeypatch.setattr(loginbruteforce_module, "init_scanner", MagicMock())
        mock_print = MagicMock()
        monkeypatch.setattr(loginbruteforce_module, "print_results", mock_print)
        args = argparse.Namespace(
            url="http://x/login",
            category="all",
            timeout=5.0,
            concurrency=5,
            output=None,
            json_output=False,
            username="admin",
            password="password",
            delay=0.0,
        )
        assert run_once(args) == 0
        mock_print.assert_called_once_with(result)

    def test_json_output(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = BruteForceResult(
            target="http://x",
            login_url="http://x/login",
            attempts=[],
            rate_limit_found=False,
            lockout_found=False,
            weak_credentials=[],
            issues=[],
            overall_status="vulnerable",
        )
        monkeypatch.setattr(
            loginbruteforce_module, "run_scan", AsyncMock(return_value=result)
        )
        monkeypatch.setattr(loginbruteforce_module, "init_scanner", MagicMock())
        args = argparse.Namespace(
            url="http://x/login",
            category="all",
            timeout=5.0,
            concurrency=5,
            output=None,
            json_output=True,
            username="admin",
            password="password",
            delay=0.0,
        )
        assert run_once(args) == 1
        captured = capsys.readouterr()
        assert "vulnerable" in captured.out

    def test_writes_output(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        result = BruteForceResult(
            target="http://x",
            login_url="http://x/login",
            attempts=[],
            rate_limit_found=False,
            lockout_found=False,
            weak_credentials=[],
            issues=[],
            overall_status="secure",
        )
        monkeypatch.setattr(
            loginbruteforce_module, "run_scan", AsyncMock(return_value=result)
        )
        monkeypatch.setattr(loginbruteforce_module, "init_scanner", MagicMock())
        args = argparse.Namespace(
            url="http://x/login",
            category="all",
            timeout=5.0,
            concurrency=5,
            output=str(tmp_path / "out.json"),
            json_output=False,
            username="admin",
            password="password",
            delay=0.0,
        )
        assert run_once(args) == 0
        assert (tmp_path / "out.json").exists()

    def test_error_returns_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        result = BruteForceResult(
            target="http://x",
            login_url="http://x/login",
            attempts=[],
            rate_limit_found=False,
            lockout_found=False,
            weak_credentials=[],
            issues=["Falha"],
            overall_status="error",
        )
        monkeypatch.setattr(
            loginbruteforce_module, "run_scan", AsyncMock(return_value=result)
        )
        monkeypatch.setattr(loginbruteforce_module, "init_scanner", MagicMock())
        args = argparse.Namespace(
            url="http://x/login",
            category="all",
            timeout=5.0,
            concurrency=5,
            output=None,
            json_output=False,
            username="admin",
            password="password",
            delay=0.0,
        )
        assert run_once(args) == 1
