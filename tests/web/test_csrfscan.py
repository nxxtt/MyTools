"""Testes do modulo csrfscan."""

import argparse
import asyncio
from dataclasses import asdict

import pytest

from mytools.web.csrfscan import (
    CSRFAttempt,
    CSRFResult,
    _FormParser,
    _test_baseline,
    _test_cookie_analysis,
    _test_form_detection,
    _test_origin_referer,
    _test_token_analysis,
    analyze_token,
    banner_art,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)

# ---------------------------------------------------------------------------
# analyze_token
# ---------------------------------------------------------------------------


class TestAnalyzeToken:
    def test_good(self) -> None:
        token = "aB3xK9mNpQ7wR2yL8vJ4cT6gH1sD0fXX"
        assert analyze_token(token) == "good"

    def test_low_entropy(self) -> None:
        assert analyze_token("abc") == "low_entropy"

    def test_sequential(self) -> None:
        assert analyze_token("1234567890123456") == "sequential"

    def test_low_charset(self) -> None:
        assert analyze_token("aaaa" * 10) == "low_charset"

    def test_moderate(self) -> None:
        assert analyze_token("Abc1234567890xyz") == "moderate"


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


class TestBuildParser:
    def test_basic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com"])
        assert args.url == "https://target.com"

    def test_default_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com"])
        assert args.category == "all"

    def test_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com", "-c", "form_detection"])
        assert args.category == "form_detection"

    def test_invalid_category(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["https://target.com", "-c", "invalid"])


# ---------------------------------------------------------------------------
# CSRFAttempt / CSRFResult
# ---------------------------------------------------------------------------


class TestCSRFAttempt:
    def test_frozen(self) -> None:
        a = CSRFAttempt(
            technique="t",
            category="c",
            url="u",
            method="m",
            field_detected=True,
            cookie_detected=False,
            origin_bypassed=False,
            token_entropy="good",
            vulnerable=True,
            details="d",
            error="",
        )
        with pytest.raises(AttributeError):
            a.vulnerable = False  # type: ignore[misc]

    def test_exploit_default(self) -> None:
        a = CSRFAttempt(
            technique="t",
            category="c",
            url="u",
            method="m",
            field_detected=True,
            cookie_detected=False,
            origin_bypassed=False,
            token_entropy="good",
            vulnerable=True,
            details="d",
            error="",
        )
        assert a.exploit == ""
        assert a.tool == ""

    def test_exploit_provided(self) -> None:
        a = CSRFAttempt(
            technique="t",
            category="c",
            url="u",
            method="m",
            field_detected=True,
            cookie_detected=False,
            origin_bypassed=False,
            token_entropy="good",
            vulnerable=True,
            details="d",
            error="",
            exploit="curl -X POST u",
            tool="curl",
        )
        assert a.exploit == "curl -X POST u"
        assert a.tool == "curl"


class TestCSRFResult:
    def test_frozen(self) -> None:
        r = CSRFResult(
            target="t",
            baseline_status=200,
            tls=True,
            attempts=[],
            forms_found=1,
            forms_missing_csrf=0,
            cookies_analyzed=0,
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.overall_status = "x"  # type: ignore[misc]

    def test_asdict(self) -> None:
        r = CSRFResult(
            target="t",
            baseline_status=200,
            tls=True,
            attempts=[],
            forms_found=1,
            forms_missing_csrf=0,
            cookies_analyzed=0,
            issues=[],
            overall_status="secure",
        )
        d = asdict(r)
        assert d["target"] == "t"
        assert d["forms_found"] == 1


# ---------------------------------------------------------------------------
# _FormParser
# ---------------------------------------------------------------------------


class TestFormParser:
    def test_parse_form(self) -> None:
        html = b'<form action="/submit" method="post"><input name="user"><input name="csrf_token" value="abc123"></form>'
        parser = _FormParser()
        parser.feed(html.decode())
        assert len(parser.forms) == 1
        assert parser.forms[0].method == "POST"
        assert parser.forms[0].has_csrf is True
        assert parser.forms[0].csrf_field_name == "csrf_token"

    def test_no_csrf(self) -> None:
        html = b'<form action="/submit" method="post"><input name="user"></form>'
        parser = _FormParser()
        parser.feed(html.decode())
        assert len(parser.forms) == 1
        assert parser.forms[0].has_csrf is False

    def test_multiple_forms(self) -> None:
        html = b'<form method="post"><input name="a"></form><form method="get"><input name="b"></form>'
        parser = _FormParser()
        parser.feed(html.decode())
        assert len(parser.forms) == 2
        assert parser.forms[0].method == "POST"
        assert parser.forms[1].method == "GET"


# ---------------------------------------------------------------------------
# _FormParser edge cases
# ---------------------------------------------------------------------------


class TestFormParserEdge:
    def test_input_without_name(self) -> None:
        html = b'<form method="post"><input type="hidden" value="x"></form>'
        parser = _FormParser()
        parser.feed(html.decode())
        assert len(parser.forms) == 1
        assert parser.forms[0].fields == {}

    def test_unclosed_form(self) -> None:
        html = b'<form method="post"><input name="a">'
        parser = _FormParser()
        parser.feed(html.decode())
        assert len(parser.forms) == 0

    def test_non_form_tags(self) -> None:
        html = b"<div>content</div><a href='/x'>link</a>"
        parser = _FormParser()
        parser.feed(html.decode())
        assert parser.forms == []

    def test_input_outside_form(self) -> None:
        html = b'<input name="x" value="1">'
        parser = _FormParser()
        parser.feed(html.decode())
        assert parser.forms == []

    def test_closing_form_not_in_form(self) -> None:
        html = b"</form><div></div>"
        parser = _FormParser()
        parser.feed(html.decode())
        assert parser.forms == []


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = CSRFResult(
            target="http://test.com",
            baseline_status=200,
            tls=False,
            attempts=[],
            forms_found=0,
            forms_missing_csrf=0,
            cookies_analyzed=0,
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        assert "SECURE" in capsys.readouterr().out

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = CSRFResult(
            target="http://test.com",
            baseline_status=200,
            tls=False,
            attempts=[],
            forms_found=1,
            forms_missing_csrf=1,
            cookies_analyzed=0,
            issues=["1 formulario(s) sem campo CSRF"],
            overall_status="vulnerable",
        )
        print_results(r)
        assert "VULNERABLE" in capsys.readouterr().out

    def test_vulnerable_attempts(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = CSRFResult(
            target="http://test.com",
            baseline_status=200,
            tls=False,
            attempts=[
                CSRFAttempt(
                    technique="token_analysis",
                    category="token_analysis",
                    url="http://test.com/b",
                    method="POST",
                    field_detected=True,
                    cookie_detected=False,
                    origin_bypassed=False,
                    token_entropy="low_entropy",
                    vulnerable=True,
                    details="token fraco",
                    exploit="curl ...",
                    tool="curl",
                    error="",
                )
            ],
            forms_found=1,
            forms_missing_csrf=0,
            cookies_analyzed=0,
            issues=[],
            overall_status="vulnerable",
        )
        print_results(r)
        assert "token fraco" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# banner
# ---------------------------------------------------------------------------


class TestBanner:
    def test_exists(self) -> None:
        assert callable(banner_art)


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_no_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.argv", ["mytools-csrf"])
        monkeypatch.setattr("builtins.input", lambda _: (_ for _ in ()).throw(EOFError))
        result = main()
        assert result == 0


# ---------------------------------------------------------------------------
# _test_form_detection (async tests using asyncio.run)
# ---------------------------------------------------------------------------


class TestFormDetection:
    def test_vulnerable_no_csrf(self) -> None:
        html = b'<form method="post" action="/submit"><input name="user"></form>'

        async def run() -> list[CSRFAttempt]:
            from unittest.mock import AsyncMock, MagicMock

            client = MagicMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _test_form_detection(client, "http://test.com", html)

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].vulnerable is True
        assert attempts[0].category == "form_detection"

    def test_secure_with_csrf(self) -> None:
        html = b'<form method="post" action="/submit"><input name="csrf_token" value="abc123"><input name="user"></form>'

        async def run() -> list[CSRFAttempt]:
            from unittest.mock import AsyncMock, MagicMock

            client = MagicMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _test_form_detection(client, "http://test.com", html)

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].vulnerable is False

    def test_get_forms_ignored(self) -> None:
        html = b'<form method="get"><input name="q"></form>'

        async def run() -> list[CSRFAttempt]:
            from unittest.mock import AsyncMock, MagicMock

            client = MagicMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _test_form_detection(client, "http://test.com", html)

        attempts = asyncio.run(run())
        assert len(attempts) == 0


# ---------------------------------------------------------------------------
# _test_cookie_analysis
# ---------------------------------------------------------------------------


class TestCookieAnalysis:
    def test_no_csrf_cookies(self) -> None:
        async def run() -> list[CSRFAttempt]:
            from unittest.mock import AsyncMock, MagicMock

            class FakeHeaders:
                def get_list(self, _key: str) -> list[str]:
                    return []

            client = MagicMock()
            resp = MagicMock()
            resp.headers = FakeHeaders()
            client.get = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _test_cookie_analysis(
                    client, "http://test.com", {"session": "abc"}
                )

        attempts = asyncio.run(run())
        assert len(attempts) == 0

    def test_csrf_cookie_missing_samesite(self) -> None:
        async def run() -> list[CSRFAttempt]:
            from unittest.mock import AsyncMock, MagicMock

            class FakeHeaders:
                def __init__(self, data: dict[str, str]) -> None:
                    self._data = data

                def get_list(self, key: str) -> list[str]:
                    val = self._data.get(key, "")
                    return [val] if val else []

            client = MagicMock()
            resp = MagicMock()
            resp.headers = FakeHeaders({"set-cookie": "csrftoken=xyz; Path=/"})
            client.get = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _test_cookie_analysis(
                    client, "http://test.com", {"csrftoken": "xyz"}
                )

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].vulnerable is True

    def test_csrf_cookie_with_samesite(self) -> None:
        async def run() -> list[CSRFAttempt]:
            from unittest.mock import AsyncMock, MagicMock

            class FakeHeaders:
                def get_list(self, key: str) -> list[str]:
                    return ["csrftoken=xyz; SameSite=Strict; HttpOnly"]

            client = MagicMock()
            resp = MagicMock()
            resp.headers = FakeHeaders()
            client.get = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _test_cookie_analysis(
                    client, "http://test.com", {"csrftoken": "xyz"}
                )

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].vulnerable is False

    def test_set_cookie_not_matching_name(self) -> None:
        async def run() -> list[CSRFAttempt]:
            from unittest.mock import AsyncMock, MagicMock

            class FakeHeaders:
                def get_list(self, _key: str) -> list[str]:
                    return ["sessionid=abc; Path=/"]

            client = MagicMock()
            resp = MagicMock()
            resp.headers = FakeHeaders()
            client.get = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _test_cookie_analysis(
                    client, "http://test.com", {"csrftoken": "xyz"}
                )

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].vulnerable is True

    def test_csrf_cookie_with_secure(self) -> None:
        async def run() -> list[CSRFAttempt]:
            from unittest.mock import AsyncMock, MagicMock

            class FakeHeaders:
                def get_list(self, _key: str) -> list[str]:
                    return ["csrftoken=xyz; Secure"]

            client = MagicMock()
            resp = MagicMock()
            resp.headers = FakeHeaders()
            client.get = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _test_cookie_analysis(
                    client, "http://test.com", {"csrftoken": "xyz"}
                )

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].vulnerable is True


# ---------------------------------------------------------------------------
# _test_origin_referer
# ---------------------------------------------------------------------------
class TestOriginReferer:
    def test_origin_bypassed(self) -> None:
        html = b'<form method="post" action="/submit"><input name="user"></form>'

        async def run() -> list[CSRFAttempt]:
            from unittest.mock import AsyncMock, MagicMock

            client = MagicMock()
            resp = MagicMock()
            resp.status_code = 200
            client.post = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _test_origin_referer(client, "http://test.com", html)

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].origin_bypassed is True
        assert attempts[0].vulnerable is True

    def test_origin_rejected(self) -> None:
        html = b'<form method="post" action="/submit"><input name="user"></form>'

        async def run() -> list[CSRFAttempt]:
            from unittest.mock import AsyncMock, MagicMock

            client = MagicMock()
            resp = MagicMock()
            resp.status_code = 403
            client.post = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _test_origin_referer(client, "http://test.com", html)

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].origin_bypassed is False

    def test_origin_referer_error(self) -> None:
        html = b'<form method="post" action="/submit"><input name="user"></form>'

        async def run() -> list[CSRFAttempt]:
            from unittest.mock import AsyncMock, MagicMock

            import httpx

            client = MagicMock()
            client.post = AsyncMock(side_effect=httpx.RequestError("timeout"))
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _test_origin_referer(client, "http://test.com", html)

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].error

    def test_get_form_ignored(self) -> None:
        html = b'<form method="get" action="/submit"><input name="q"></form>'

        async def run() -> list[CSRFAttempt]:
            from unittest.mock import AsyncMock, MagicMock

            client = MagicMock()
            client.post = AsyncMock(return_value=MagicMock())
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _test_origin_referer(client, "http://test.com", html)

        attempts = asyncio.run(run())
        assert len(attempts) == 0


# ---------------------------------------------------------------------------
# _test_token_analysis
# ---------------------------------------------------------------------------


class TestTokenAnalysis:
    def test_good_token(self) -> None:
        token = "aB3xK9mNpQ7wR2yL8vJ4cT6gH1sD0fXX"
        html = f'<form method="post"><input name="csrf_token" value="{token}"></form>'.encode()

        async def run() -> list[CSRFAttempt]:
            from unittest.mock import AsyncMock, MagicMock

            client = MagicMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _test_token_analysis(client, "http://test.com", html)

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].token_entropy == "good"
        assert attempts[0].vulnerable is False

    def test_bad_token(self) -> None:
        html = b'<form method="post"><input name="csrf_token" value="123"></form>'

        async def run() -> list[CSRFAttempt]:
            from unittest.mock import AsyncMock, MagicMock

            client = MagicMock()
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            async with client:
                return await _test_token_analysis(client, "http://test.com", html)

        attempts = asyncio.run(run())
        assert len(attempts) == 1
        assert attempts[0].vulnerable is True


# ---------------------------------------------------------------------------
# run_scan
# ---------------------------------------------------------------------------


class TestRunScan:
    def test_invalid_category(self) -> None:
        async def run() -> CSRFResult:
            from unittest.mock import AsyncMock, MagicMock, patch

            client = MagicMock()
            resp = MagicMock()
            resp.status_code = 200
            resp.content = b""
            resp.cookies = {}
            client.get = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.csrfscan.create_async_client") as mock:
                mock.return_value.__aenter__ = AsyncMock(return_value=client)
                mock.return_value.__aexit__ = AsyncMock(return_value=False)
                return await run_scan(url="http://test.com", category="invalid")

        result = asyncio.run(run())
        assert result.overall_status == "error"

    def test_no_scheme_invalid_category(self) -> None:
        async def run() -> CSRFResult:
            from unittest.mock import AsyncMock, MagicMock, patch

            client = MagicMock()
            resp = MagicMock()
            resp.status_code = 200
            resp.content = b""
            resp.cookies = {}
            client.get = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.csrfscan.create_async_client") as mock:
                mock.return_value.__aenter__ = AsyncMock(return_value=client)
                mock.return_value.__aexit__ = AsyncMock(return_value=False)
                return await run_scan(url="test.com", category="invalid")

        result = asyncio.run(run())
        assert result.target == "http://test.com"
        assert result.overall_status == "error"

    def test_baseline_error(self) -> None:
        async def run() -> CSRFResult:
            from unittest.mock import AsyncMock, MagicMock, patch

            client = MagicMock()
            resp = MagicMock()
            resp.status_code = 0
            resp.content = b""
            resp.cookies = {}
            client.get = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.csrfscan.create_async_client") as mock:
                mock.return_value.__aenter__ = AsyncMock(return_value=client)
                mock.return_value.__aexit__ = AsyncMock(return_value=False)
                return await run_scan(url="http://test.com", category="all")

        result = asyncio.run(run())
        assert result.overall_status == "error"
        assert result.baseline_status == 0

    def test_full_scan_vulnerable(self) -> None:
        html = (
            b'<form method="post" action="/a"><input name="user"></form>'
            b'<form method="post" action="/b"><input name="csrf_token" value="123"></form>'
        )

        async def run() -> CSRFResult:
            from unittest.mock import AsyncMock, MagicMock, patch

            client = MagicMock()
            resp1 = MagicMock()
            resp1.status_code = 200
            resp1.content = html
            resp1.cookies = {}
            resp2 = MagicMock()
            resp2.status_code = 200
            client.get = AsyncMock(return_value=resp1)
            client.post = AsyncMock(return_value=resp2)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.csrfscan.create_async_client") as mock:
                mock.return_value.__aenter__ = AsyncMock(return_value=client)
                mock.return_value.__aexit__ = AsyncMock(return_value=False)
                return await run_scan(url="http://test.com", category="all")

        result = asyncio.run(run())
        assert result.overall_status == "vulnerable"
        assert result.forms_missing_csrf == 1
        assert "token_analysis" in {a.technique for a in result.attempts}

    def test_task_exception_skipped(self) -> None:
        async def run() -> CSRFResult:
            from unittest.mock import AsyncMock, MagicMock, patch

            client = MagicMock()
            resp = MagicMock()
            resp.status_code = 200
            resp.content = b""
            resp.cookies = {}
            client.get = AsyncMock(return_value=resp)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            with (
                patch("mytools.web.csrfscan.create_async_client") as mock,
                patch(
                    "mytools.web.csrfscan._test_form_detection",
                    new_callable=AsyncMock,
                    side_effect=RuntimeError("boom"),
                ),
            ):
                mock.return_value.__aenter__ = AsyncMock(return_value=client)
                mock.return_value.__aexit__ = AsyncMock(return_value=False)
                return await run_scan(url="http://test.com", category="all")

        result = asyncio.run(run())
        assert result.overall_status == "secure"
        assert result.attempts == []

    def test_secure_full_scan(self) -> None:
        token = "aB3xK9mNpQ7wR2yL8vJ4cT6gH1sD0fXX"
        html = (
            f'<form method="post" action="/submit">'
            f'<input name="csrf_token" value="{token}"></form>'
        ).encode()

        async def run() -> CSRFResult:
            from unittest.mock import AsyncMock, MagicMock, patch

            client = MagicMock()
            resp1 = MagicMock()
            resp1.status_code = 200
            resp1.content = html
            resp1.cookies = {}
            resp2 = MagicMock()
            resp2.status_code = 403
            client.get = AsyncMock(return_value=resp1)
            client.post = AsyncMock(return_value=resp2)
            client.__aenter__ = AsyncMock(return_value=client)
            client.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.csrfscan.create_async_client") as mock:
                mock.return_value.__aenter__ = AsyncMock(return_value=client)
                mock.return_value.__aexit__ = AsyncMock(return_value=False)
                return await run_scan(url="http://test.com", category="all")

        result = asyncio.run(run())
        assert result.overall_status == "secure"
        assert result.forms_missing_csrf == 0
        assert result.cookies_analyzed == 0


class TestBaselineError:
    def test_request_error(self) -> None:
        from unittest.mock import AsyncMock, MagicMock

        import httpx

        async def run() -> tuple[int, bytes, dict[str, str]]:
            client = MagicMock()
            client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
            return await _test_baseline(client, "http://test.com")

        status, content, cookies = asyncio.run(run())
        assert status == 0
        assert content == b""
        assert cookies == {}


class TestRunOnce:
    def _make_result(self, status: str = "vulnerable") -> CSRFResult:
        return CSRFResult(
            target="http://test.com",
            baseline_status=200,
            tls=False,
            attempts=[],
            forms_found=0,
            forms_missing_csrf=0,
            cookies_analyzed=0,
            issues=[],
            overall_status=status,
        )

    def test_run_once_print(self, base_ns: argparse.Namespace) -> None:
        from unittest.mock import MagicMock, patch

        base_ns.url = "http://test.com"
        base_ns.category = "all"
        base_ns.timeout = 10.0
        base_ns.concurrency = 5
        base_ns.output = None
        base_ns.json_output = False
        with (
            patch(
                "mytools.web.csrfscan.run_scan",
                MagicMock(return_value=self._make_result()),
            ) as mock_run,
            patch(
                "mytools.web.csrfscan.safe_asyncio_run",
                side_effect=lambda coro: coro,
            ),
        ):
            result = run_once(base_ns)
        assert result == 0
        mock_run.assert_called_once()

    def test_run_once_json_output(self, base_ns: argparse.Namespace) -> None:
        from unittest.mock import MagicMock, patch

        base_ns.url = "http://test.com"
        base_ns.category = "all"
        base_ns.timeout = 10.0
        base_ns.concurrency = 5
        base_ns.output = "out.json"
        base_ns.json_output = True
        with (
            patch(
                "mytools.web.csrfscan.run_scan",
                MagicMock(return_value=self._make_result()),
            ),
            patch(
                "mytools.web.csrfscan.safe_asyncio_run",
                side_effect=lambda coro: coro,
            ),
            patch("mytools.web.csrfscan.print_json") as mock_print,
            patch("mytools.web.csrfscan.write_output") as mock_write,
        ):
            result = run_once(base_ns)
        assert result == 0
        mock_print.assert_called_once()
        mock_write.assert_called_once()

    def test_run_once_error(self, base_ns: argparse.Namespace) -> None:
        from unittest.mock import MagicMock, patch

        base_ns.url = "http://test.com"
        base_ns.category = "all"
        base_ns.timeout = 10.0
        base_ns.concurrency = 5
        base_ns.output = None
        base_ns.json_output = False
        with (
            patch(
                "mytools.web.csrfscan.run_scan",
                MagicMock(return_value=self._make_result("error")),
            ),
            patch(
                "mytools.web.csrfscan.safe_asyncio_run",
                side_effect=lambda coro: coro,
            ),
        ):
            result = run_once(base_ns)
        assert result == 1


class TestMainGuard:
    def test_guard(self) -> None:
        import runpy
        from unittest.mock import patch

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-csrf"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.csrfscan", run_name="__main__")
        assert exc_info.value.code == 0
