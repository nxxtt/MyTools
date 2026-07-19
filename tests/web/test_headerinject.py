#!/usr/bin/env python3
"""Testes unitarios do modulo de Header Injection via URL params."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from mytools.web.headerinject import (
    _CATEGORY_MAP,
    _MARKER,
    HeaderInjectAttempt,
    HeaderInjectResult,
    _test_baseline,
    _test_bypass,
    _test_cookie_inject,
    _test_header_overwrite,
    _test_param_reflected,
    _test_redirect_header,
    build_parser,
    print_results,
)


# ─── Category Map ────────────────────────────────────────────────────────────
class TestCategoryMap:
    def test_has_five_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 5

    def test_categories_are_correct(self) -> None:
        expected = {"param_reflected", "header_overwrite", "redirect_header", "cookie_inject", "bypass"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_all_categories_have_5_techniques(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) == 5, f"Categoria {cat} tem {len(techs)} tecnicas"


# ─── Marker ──────────────────────────────────────────────────────────────────
class TestMarker:
    def test_marker_value(self) -> None:
        assert _MARKER == "HDRINJECT_TEST"


# ─── Dataclasses ─────────────────────────────────────────────────────────────
class TestHeaderInjectAttempt:
    def test_frozen(self) -> None:
        a = HeaderInjectAttempt(
            technique="test", category="param_reflected", param_name="X-Injected",
            param_value="test", injected_header="", status=200, size=100,
            vulnerable=True, details="test", error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "other"  # type: ignore[misc]

    def test_slots(self) -> None:
        a = HeaderInjectAttempt(
            technique="test", category="param_reflected", param_name="X-Injected",
            param_value="test", injected_header="", status=200, size=100,
            vulnerable=True, details="test", error="",
        )
        assert not hasattr(a, "__dict__")


class TestHeaderInjectResult:
    def test_frozen(self) -> None:
        r = HeaderInjectResult(
            target="https://test.com", tls=True, attempts=[],
            vulnerable_techniques=[], blocked_techniques=[],
            issues=[], overall_status="safe",
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

        status, size, _headers, body = await _test_baseline(mock_client, "https://test.com")
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

        status, size, headers, body = await _test_baseline(mock_client, "https://test.com")
        assert status == 0
        assert size == 0
        assert headers == {}
        assert body == b""


# ─── Test Param Reflected ────────────────────────────────────────────────────
class TestParamReflected:
    @pytest.mark.asyncio
    async def test_vulnerable_reflected(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {"x-injected": _MARKER}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_param_reflected(mock_client, "https://test.com")
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

        results = await _test_param_reflected(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(r.error for r in results)


# ─── Test Header Overwrite ───────────────────────────────────────────────────
class TestHeaderOverwrite:
    @pytest.mark.asyncio
    async def test_vulnerable_overwrite(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {"x-frame-options": "ALLOWALL"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_header_overwrite(mock_client, "https://test.com")
        assert len(results) == 5
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) > 0
        assert all(r.category == "header_overwrite" for r in results)


# ─── Test Redirect Header ────────────────────────────────────────────────────
class TestRedirectHeader:
    @pytest.mark.asyncio
    async def test_vulnerable_redirect(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 302
        mock_resp.content = b""
        mock_resp.headers = {"location": f"http://evil.com/?{ _MARKER}"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_redirect_header(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(r.category == "redirect_header" for r in results)


# ─── Test Cookie Inject ──────────────────────────────────────────────────────
class TestCookieInject:
    @pytest.mark.asyncio
    async def test_vulnerable_cookie(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {"set-cookie": f"evil={_MARKER}; Path=/"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_cookie_inject(mock_client, "https://test.com")
        assert len(results) == 5
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) > 0
        assert all(r.category == "cookie_inject" for r in results)


# ─── Test Bypass ─────────────────────────────────────────────────────────────
class TestBypass:
    @pytest.mark.asyncio
    async def test_vulnerable_bypass(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {"x-evil": f"found {_MARKER}"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_bypass(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(r.category == "bypass" for r in results)


# ─── Print Results ───────────────────────────────────────────────────────────
class TestPrintResults:
    def test_vulnerable_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = HeaderInjectResult(
            target="https://test.com", tls=True,
            attempts=[HeaderInjectAttempt(
                technique="x_injected", category="param_reflected",
                param_name="X-Injected", param_value="test",
                injected_header="", status=200, size=100,
                vulnerable=True, details="Header injetado", error="",
            )],
            vulnerable_techniques=["x_injected"],
            blocked_techniques=[], issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Vulnerabilidades detectadas" in output
        assert "x_injected" in output

    def test_no_vulns_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = HeaderInjectResult(
            target="https://test.com", tls=True, attempts=[],
            vulnerable_techniques=[], blocked_techniques=[],
            issues=[], overall_status="safe",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Nenhum Header Injection detectado" in output

    def test_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = HeaderInjectResult(
            target="https://test.com", tls=True, attempts=[],
            vulnerable_techniques=[], blocked_techniques=[],
            issues=["Nenhum teste retornou resultado claro"],
            overall_status="unknown",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Observacoes" in output


# ─── Build Parser ────────────────────────────────────────────────────────────
@pytest.mark.smoke
class TestBuildParser:
    def test_has_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.url == "https://test.com"

    def test_has_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "-c", "param_reflected"])
        assert args.category == "param_reflected"

    def test_default_category_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.category == "all"

    def test_all_categories(self) -> None:
        parser = build_parser()
        for cat in ["all", "param_reflected", "header_overwrite", "redirect_header", "cookie_inject", "bypass"]:
            args = parser.parse_args(["https://test.com", "-c", cat])
            assert args.category == cat


# ─── Run Once ────────────────────────────────────────────────────────────────
class TestRunOnce:
    def test_run_once(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        from mytools.web.headerinject import run_once
        result = run_once(args)
        assert result == 0
