"""Testes do modulo loginbruteforce."""

from dataclasses import asdict
from typing import cast
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

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
    banner_art,
    build_parser,
    main,
    print_results,
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
