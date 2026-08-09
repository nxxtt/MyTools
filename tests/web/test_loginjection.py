#!/usr/bin/env python3
"""Testes unitarios do modulo de Log Injection."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mytools.web.loginjection import (
    _CATEGORY_MAP,
    _MARKER,
    LogInjectAttempt,
    LogInjectResult,
    _test_baseline,
    _test_bypass,
    _test_custom_header,
    _test_referer,
    _test_url_path,
    _test_user_agent,
    banner_art,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)


# ─── Category Map ────────────────────────────────────────────────────────────
class TestCategoryMap:
    def test_has_five_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 5

    def test_categories_are_correct(self) -> None:
        expected = {"user_agent", "referer", "custom_header", "url_path", "bypass"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_all_categories_have_5_techniques(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) == 5, f"Categoria {cat} tem {len(techs)} tecnicas"


# ─── Marker ──────────────────────────────────────────────────────────────────
class TestMarker:
    def test_marker_value(self) -> None:
        assert _MARKER == "LOGINJECT_TEST"


# ─── Dataclasses ─────────────────────────────────────────────────────────────
class TestLogInjectAttempt:
    def test_frozen(self) -> None:
        a = LogInjectAttempt(
            technique="test",
            category="user_agent",
            header_name="User-Agent",
            payload="test",
            status=200,
            size=100,
            vulnerable=True,
            details="test",
            error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "other"  # type: ignore[misc]

    def test_slots(self) -> None:
        a = LogInjectAttempt(
            technique="test",
            category="user_agent",
            header_name="User-Agent",
            payload="test",
            status=200,
            size=100,
            vulnerable=True,
            details="test",
            error="",
        )
        assert not hasattr(a, "__dict__")


class TestLogInjectResult:
    def test_frozen(self) -> None:
        r = LogInjectResult(
            target="https://test.com",
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="safe",
        )
        with pytest.raises(AttributeError):
            r.target = "other"  # type: ignore[misc]


# ─── Test Baseline ───────────────────────────────────────────────────────────
class TestBaseline:
    @pytest.mark.asyncio
    async def test_baseline_success(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        status, size, _headers, body = await _test_baseline(
            mock_client, "https://test.com"
        )
        assert status == 200
        assert size == 2
        assert body == b"ok"

    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("fail"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        status, size, headers, body = await _test_baseline(
            mock_client, "https://test.com"
        )
        assert status == 0
        assert size == 0
        assert headers == {}
        assert body == b""


# ─── Test User Agent ─────────────────────────────────────────────────────────
class TestUserAgent:
    @pytest.mark.asyncio
    async def test_vulnerable_ua(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = f"Hello {_MARKER}".encode()
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_user_agent(mock_client, "https://test.com")
        assert len(results) == 5
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) > 0

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_user_agent(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(r.error for r in results)


# ─── Test Referer ────────────────────────────────────────────────────────────
class TestReferer:
    @pytest.mark.asyncio
    async def test_vulnerable_referer(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = f"Referer: {_MARKER}".encode()
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_referer(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(r.category == "referer" for r in results)

    @pytest.mark.asyncio
    async def test_no_reflection(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"just a plain response"
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_referer(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(not r.vulnerable for r in results)


# ─── Test Custom Header ──────────────────────────────────────────────────────
class TestCustomHeader:
    @pytest.mark.asyncio
    async def test_vulnerable_custom(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = f"IP: {_MARKER}".encode()
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_custom_header(mock_client, "https://test.com")
        assert len(results) == 5
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) > 0
        assert all(r.category == "custom_header" for r in results)

    @pytest.mark.asyncio
    async def test_no_reflection(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"just a plain response"
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_custom_header(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(not r.vulnerable for r in results)


# ─── Test URL Path ───────────────────────────────────────────────────────────
class TestUrlPath:
    @pytest.mark.asyncio
    async def test_vulnerable_path(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = f"Path: {_MARKER}".encode()
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_url_path(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(r.category == "url_path" for r in results)

    @pytest.mark.asyncio
    async def test_no_reflection(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"just a plain response"
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_url_path(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(not r.vulnerable for r in results)


# ─── Test Bypass ─────────────────────────────────────────────────────────────
class TestBypass:
    @pytest.mark.asyncio
    async def test_vulnerable_bypass(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = f"Bypass: {_MARKER}".encode()
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_bypass(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(r.category == "bypass" for r in results)

    @pytest.mark.asyncio
    async def test_no_reflection(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"just a plain response"
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_bypass(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(not r.vulnerable for r in results)


# ─── Print Results ───────────────────────────────────────────────────────────
class TestPrintResults:
    def test_vulnerable_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = LogInjectResult(
            target="https://test.com",
            tls=True,
            attempts=[
                LogInjectAttempt(
                    technique="ua_crlf",
                    category="user_agent",
                    header_name="User-Agent",
                    payload="test",
                    status=200,
                    size=100,
                    vulnerable=True,
                    details="User-Agent refletido",
                    error="",
                )
            ],
            vulnerable_techniques=["ua_crlf"],
            blocked_techniques=[],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Vulnerabilidades detectadas" in output
        assert "ua_crlf" in output

    def test_no_vulns_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = LogInjectResult(
            target="https://test.com",
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="safe",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Nenhum Log Injection detectado" in output

    def test_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = LogInjectResult(
            target="https://test.com",
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=["Nenhum teste retornou resultado claro"],
            overall_status="unknown",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Observacoes" in output

    def test_duplicate_technique_deduped(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        attempt = LogInjectAttempt(
            technique="ua_crlf",
            category="user_agent",
            header_name="User-Agent",
            payload="test",
            status=200,
            size=100,
            vulnerable=True,
            details="refletido",
            error="",
        )
        result = LogInjectResult(
            target="https://test.com",
            tls=True,
            attempts=[attempt, attempt],
            vulnerable_techniques=["ua_crlf"],
            blocked_techniques=[],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "ua_crlf" in output

    def test_vulnerable_without_details(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = LogInjectResult(
            target="https://test.com",
            tls=True,
            attempts=[
                LogInjectAttempt(
                    technique="ua_crlf",
                    category="user_agent",
                    header_name="User-Agent",
                    payload="test",
                    status=200,
                    size=100,
                    vulnerable=True,
                    details="",
                    error="",
                )
            ],
            vulnerable_techniques=["ua_crlf"],
            blocked_techniques=[],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "ua_crlf" in output
        assert "Detalhes" not in output


# ─── Build Parser ────────────────────────────────────────────────────────────
@pytest.mark.smoke
class TestBuildParser:
    def test_has_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.url == "https://test.com"

    def test_has_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "-c", "user_agent"])
        assert args.category == "user_agent"

    def test_default_category_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.category == "all"

    def test_all_categories(self) -> None:
        parser = build_parser()
        for cat in [
            "all",
            "user_agent",
            "referer",
            "custom_header",
            "url_path",
            "bypass",
        ]:
            args = parser.parse_args(["https://test.com", "-c", cat])
            assert args.category == cat


# ─── Run Once ────────────────────────────────────────────────────────────────
class TestRunOnce:
    def test_run_once(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        result = run_once(args)
        assert result == 0

    def test_run_once_with_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "-c", "user_agent"])
        with patch(
            "mytools.web.loginjection.run_scan",
            new_callable=AsyncMock,
            return_value=0,
        ) as mock_scan:
            result = run_once(args)
            assert result == 0
            mock_scan.assert_called_once_with(
                target="https://test.com",
                categories=["user_agent"],
                timeout=5.0,
                output_file=None,
            )


# ─── Banner Art ──────────────────────────────────────────────────────────────
class TestBannerArt:
    def test_banner_art(self) -> None:
        with patch("mytools.web.loginjection.create_banner") as mock_banner:
            mock_banner.return_value = MagicMock()
            banner_art()
            mock_banner.assert_called_once()


# ─── Main ────────────────────────────────────────────────────────────────────
class TestMain:
    def test_main(self) -> None:
        with patch(
            "mytools.web.loginjection.run_main_loop", return_value=0
        ) as mock_loop:
            result = main()
            assert result == 0
            mock_loop.assert_called_once()


# ─── Run Scan (output) ───────────────────────────────────────────────────────
class TestRunScan:
    @pytest.mark.asyncio
    @respx.mock
    async def test_run_scan_with_output(self, tmp_path: object) -> None:
        respx.route(method="GET", url__startswith="https://test.com/").mock(
            return_value=httpx.Response(200, text="not vulnerable"),
        )
        output_file = str(tmp_path) + "/output.json"  # type: ignore[operator]
        result = await run_scan(
            target="https://test.com",
            categories=["user_agent"],
            timeout=10,
            output_file=output_file,
        )
        assert result == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_run_scan_unknown_category(self) -> None:
        respx.route(method="GET", url__startswith="https://test.com/").mock(
            return_value=httpx.Response(200, text="not vulnerable"),
        )
        result = await run_scan(
            target="https://test.com",
            categories=["unknown_cat"],
            timeout=10,
            output_file=None,
        )
        assert result == 0


# ─── Main Guard ──────────────────────────────────────────────────────────────
class TestMainGuard:
    def test_main_guard_runs(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import runpy

        import mytools.web.loginjection as loginjection_mod

        monkeypatch.setattr(
            loginjection_mod,
            "main",
            lambda: (_ for _ in ()).throw(SystemExit(0)),
        )
        with patch("sys.argv", ["mytools-loginjection"]), pytest.raises(SystemExit):
            runpy.run_module("mytools.web.loginjection", run_name="__main__")
