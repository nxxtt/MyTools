#!/usr/bin/env python3
"""Testes unitarios do modulo XSS Vectors."""

from __future__ import annotations

import html
import runpy
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mytools.web.xssvectors import (
    _BASE_PAYLOADS,
    _CATEGORY_MAP,
    _CUSTOM_ELEMENT_PAYLOADS,
    _IFRAME_PAYLOADS,
    _MEDIA_PAYLOADS,
    _SHADOW_DOM_PAYLOADS,
    _SLOT_USE_PAYLOADS,
    _URI_DATA_PAYLOADS,
    _URI_JS_PAYLOADS,
    XSSVectorAttempt,
    XSSVectorResult,
    _check_xss_reflection,
    _confirm_headless_execution,
    _inject_payload,
    _run_scan_core,
    _test_xss_category,
    build_parser,
    print_results,
    scanner,
)

_TARGET = "https://example.com/page"


def test_category_map_has_eight_categories() -> None:
    assert len(_CATEGORY_MAP) == 8


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {
        "media_events",
        "uri_javascript",
        "uri_data",
        "iframe_vectors",
        "base_redirect",
        "custom_elements",
        "shadow_dom",
        "slot_use",
    }


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 45


def test_media_payloads_count() -> None:
    assert len(_MEDIA_PAYLOADS) == 6


def test_uri_js_payloads_count() -> None:
    assert len(_URI_JS_PAYLOADS) == 8


def test_uri_data_payloads_count() -> None:
    assert len(_URI_DATA_PAYLOADS) == 6


def test_iframe_payloads_count() -> None:
    assert len(_IFRAME_PAYLOADS) == 6


def test_base_payloads_count() -> None:
    assert len(_BASE_PAYLOADS) == 4


def test_custom_element_payloads_count() -> None:
    assert len(_CUSTOM_ELEMENT_PAYLOADS) == 5


def test_shadow_dom_payloads_count() -> None:
    assert len(_SHADOW_DOM_PAYLOADS) == 5


def test_slot_use_payloads_count() -> None:
    assert len(_SLOT_USE_PAYLOADS) == 5


def test_all_payloads_have_four_elements() -> None:
    all_lists = (
        _MEDIA_PAYLOADS
        + _URI_JS_PAYLOADS
        + _URI_DATA_PAYLOADS
        + _IFRAME_PAYLOADS
        + _BASE_PAYLOADS
        + _CUSTOM_ELEMENT_PAYLOADS
        + _SHADOW_DOM_PAYLOADS
        + _SLOT_USE_PAYLOADS
    )
    for p in all_lists:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_inject_payload_new_param() -> None:
    result = _inject_payload(_TARGET, "p", "<script>alert(1)</script>")
    assert "p=" in result
    assert "script" in result


def test_inject_payload_preserves_existing() -> None:
    url = f"{_TARGET}?foo=bar"
    result = _inject_payload(url, "p", "1")
    assert "foo=bar" in result
    assert "p=1" in result


def test_inject_payload_special_chars() -> None:
    result = _inject_payload(_TARGET, "p", "<img src=x onerror=alert(1)>")
    assert "p=" in result


def test_check_xss_reflection_true() -> None:
    body = "<div><script>alert(1)</script></div>"
    assert _check_xss_reflection(body, "<script>alert(1)</script>") is True


def test_check_xss_reflection_case_insensitive() -> None:
    body = "<SCRIPT>alert(1)</SCRIPT>"
    assert _check_xss_reflection(body, "<script>alert(1)</script>") is True


def test_check_xss_reflection_false() -> None:
    body = "<div>safe content</div>"
    assert _check_xss_reflection(body, "<script>alert(1)</script>") is False


def test_attempt_dataclass_frozen() -> None:
    a = XSSVectorAttempt(
        technique="test",
        category="media_events",
        context="test_ctx",
        payload="p",
        method="GET",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=110,
        status_changed=False,
        size_changed=True,
        vulnerable=True,
        details="test",
        error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False  # type: ignore[reportAttributeAccessIssue]


def test_attempt_dataclass_slots() -> None:
    a = XSSVectorAttempt(
        technique="test",
        category="media_events",
        context="test_ctx",
        payload="p",
        method="GET",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=110,
        status_changed=False,
        size_changed=True,
        vulnerable=True,
        details="test",
        error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = XSSVectorResult(
        target=_TARGET,
        tls=True,
        baseline_status=200,
        baseline_size=100,
        attempts=[],
        vulnerable_techniques=[],
        blocked_techniques=[],
        issues=[],
        overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"  # type: ignore[reportAttributeAccessIssue]


def test_result_dataclass_slots() -> None:
    r = XSSVectorResult(
        target=_TARGET,
        tls=True,
        baseline_status=200,
        baseline_size=100,
        attempts=[],
        vulnerable_techniques=[],
        blocked_techniques=[],
        issues=[],
        overall_status="safe",
    )
    assert not hasattr(r, "__dict__")


def test_no_duplicate_technique_names_across_categories() -> None:
    all_techniques: list[str] = []
    for techs in _CATEGORY_MAP.values():
        all_techniques.extend(techs)
    assert len(all_techniques) == len(set(all_techniques))


def test_no_duplicate_payload_names_across_lists() -> None:
    all_names: list[str] = []
    for lst in (
        _MEDIA_PAYLOADS,
        _URI_JS_PAYLOADS,
        _URI_DATA_PAYLOADS,
        _IFRAME_PAYLOADS,
        _BASE_PAYLOADS,
        _CUSTOM_ELEMENT_PAYLOADS,
        _SHADOW_DOM_PAYLOADS,
        _SLOT_USE_PAYLOADS,
    ):
        all_names.extend(p[0] for p in lst)
    assert len(all_names) == len(set(all_names))


def test_all_payloads_have_indicators() -> None:
    all_lists = (
        _MEDIA_PAYLOADS
        + _URI_JS_PAYLOADS
        + _URI_DATA_PAYLOADS
        + _IFRAME_PAYLOADS
        + _BASE_PAYLOADS
        + _CUSTOM_ELEMENT_PAYLOADS
        + _SHADOW_DOM_PAYLOADS
        + _SLOT_USE_PAYLOADS
    )
    for p in all_lists:
        assert len(p[3]) >= 1, f"Payload {p[0]} must have at least 1 indicator"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_attempt(
    technique: str = "video_source_onerror",
    category: str = "media_events",
    context: str = "video_source",
    payload: str = "<video><source onerror=alert(1)></video>",
    vulnerable: bool = False,
    error: str = "",
    details: str = "",
    dom_confirmed: bool = False,
    test_url: str | None = None,
) -> XSSVectorAttempt:
    return XSSVectorAttempt(
        technique=technique,
        category=category,
        context=context,
        payload=payload,
        method="GET",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=110,
        status_changed=False,
        size_changed=True,
        vulnerable=vulnerable,
        details=details,
        error=error,
        exploit="<img src=x onerror=alert(1)>" if vulnerable else "",
        tool="XSStrike",
        test_url=test_url or f"{_TARGET}?p={technique}",
        dom_confirmed=dom_confirmed,
    )


def _make_result(
    attempts: list[XSSVectorAttempt] | None = None,
    issues: list[str] | None = None,
    blocked: list[str] | None = None,
    overall_status: str = "safe",
) -> XSSVectorResult:
    return XSSVectorResult(
        target=_TARGET,
        tls=True,
        baseline_status=200,
        baseline_size=100,
        attempts=attempts or [],
        vulnerable_techniques=[a.technique for a in (attempts or []) if a.vulnerable],
        blocked_techniques=blocked or [],
        issues=issues or [],
        overall_status=overall_status,
    )


def _xss_reflect_handler(request: httpx.Request) -> httpx.Response:
    from urllib.parse import parse_qs, urlparse

    params = parse_qs(urlparse(str(request.url)).query)
    val = next((v[0] for k, v in params.items() if k.startswith("_xss_")), None)
    if val is None:
        return httpx.Response(200, text="<html><body>normal page</body></html>")
    decoded = html.unescape(val)
    body = val if decoded == val else f"{val}{decoded}"
    return httpx.Response(200, text=f"<html><body>{body}</body></html>")


# ---------------------------------------------------------------------------
# _test_xss_category
# ---------------------------------------------------------------------------


class TestTestXssCategory:
    @respx.mock
    @pytest.mark.asyncio
    async def test_vulnerable_attempts(self, async_client) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=_xss_reflect_handler
        )
        results = await _test_xss_category(
            async_client, _TARGET, 5.0, 200, 100, _MEDIA_PAYLOADS, "media_events"
        )
        assert len(results) == len(_MEDIA_PAYLOADS)
        vuln = [a for a in results if a.vulnerable]
        assert len(vuln) == len(_MEDIA_PAYLOADS)
        first = vuln[0]
        assert first.category == "media_events"
        assert first.status_test == 200
        assert first.test_url.startswith(_TARGET)
        assert first.exploit == "<img src=x onerror=alert(1)>"
        assert first.tool == "XSStrike"
        assert first.details.startswith("Payload refletido sem encoding")

    @respx.mock
    @pytest.mark.asyncio
    async def test_not_reflected_not_vulnerable(self, async_client) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            return_value=httpx.Response(200, text="<html><body>safe</body></html>")
        )
        results = await _test_xss_category(
            async_client, _TARGET, 5.0, 200, 100, _MEDIA_PAYLOADS, "media_events"
        )
        assert results
        assert all(not a.vulnerable for a in results)
        assert all(not a.error for a in results)

    @respx.mock
    @pytest.mark.asyncio
    async def test_request_error_creates_error_attempt(self, async_client) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=httpx.ConnectError("refused")
        )
        results = await _test_xss_category(
            async_client, _TARGET, 5.0, 200, 100, _MEDIA_PAYLOADS, "media_events"
        )
        assert results
        assert all(a.error for a in results)
        assert all(not a.vulnerable for a in results)


# ---------------------------------------------------------------------------
# _confirm_headless_execution
# ---------------------------------------------------------------------------


class TestConfirmHeadlessExecution:
    @pytest.mark.asyncio
    async def test_no_vulnerable_returns_empty(self) -> None:
        att = _make_attempt(vulnerable=False)
        with patch(
            "mytools.core.headless.confirm_js_execution", new_callable=AsyncMock
        ) as mock:
            result = await _confirm_headless_execution(
                _TARGET, [att], timeout=5.0, proxy=None
            )
        assert result == set()
        mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_confirms_only_true_urls(self) -> None:
        att1 = _make_attempt(technique="a", vulnerable=True, test_url=f"{_TARGET}?a=1")
        att2 = _make_attempt(technique="b", vulnerable=True, test_url=f"{_TARGET}?b=1")

        async def fake_confirm(url: str, *, timeout: float, proxy: str | None) -> bool:
            return "b=1" in url

        with patch(
            "mytools.core.headless.confirm_js_execution",
            new_callable=AsyncMock,
            side_effect=fake_confirm,
        ) as mock:
            result = await _confirm_headless_execution(
                _TARGET, [att1, att2], timeout=5.0, proxy=None
            )
        assert result == {f"{_TARGET}?b=1"}
        assert mock.call_count == 2

    @pytest.mark.asyncio
    async def test_exception_skips_url(self) -> None:
        att = _make_attempt(vulnerable=True)

        async def fake_confirm(url: str, *, timeout: float, proxy: str | None) -> bool:
            raise RuntimeError("boom")

        with patch(
            "mytools.core.headless.confirm_js_execution",
            new_callable=AsyncMock,
            side_effect=fake_confirm,
        ):
            result = await _confirm_headless_execution(
                _TARGET, [att], timeout=5.0, proxy=None
            )
        assert result == set()


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


class TestPrintResults:
    def test_no_vulns(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_results(_make_result())
        out = capsys.readouterr().out
        assert "XSS Vectors" in out
        assert "Nenhuma vulnerabilidade de XSS Vector detectada" in out

    def test_full_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        dup1 = _make_attempt(
            technique="video_source_onerror",
            vulnerable=True,
            details="payload refletido",
            dom_confirmed=True,
        )
        dup2 = _make_attempt(
            technique="video_source_onerror",
            vulnerable=True,
            details="duplicate",
        )
        no_details = _make_attempt(
            technique="a_href_js",
            category="uri_javascript",
            context="a_href",
            vulnerable=True,
        )
        err = _make_attempt(
            technique="object_onerror",
            category="media_events",
            context="object_data",
            vulnerable=False,
            error="Connection refused",
        )
        blocked = _make_attempt(
            technique="embed_onerror",
            category="media_events",
            context="embed_src",
            vulnerable=False,
        )
        result = _make_result(
            attempts=[dup1, dup2, no_details, err, blocked],
            issues=["Observacao qualquer"],
            blocked=["embed_onerror"],
            overall_status="vulnerable",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Vulnerabilidades encontradas" in out
        assert "[media_events] video_source_onerror" in out
        assert "DOM:       confirmado via headless" in out
        assert "Detalhes: payload refletido" in out
        assert "Total: 3 vulneraveis de 5 testes" in out
        assert "Observacoes" in out
        assert "Observacao qualquer" in out

    def test_with_issues_only(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = _make_result(
            attempts=[_make_attempt()],
            issues=["Nenhum teste de XSS Vector executado"],
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Nenhum teste de XSS Vector executado" in out


# ---------------------------------------------------------------------------
# _run_scan_core
# ---------------------------------------------------------------------------


class TestRunScanCore:
    @respx.mock
    @pytest.mark.asyncio
    async def test_invalid_category_returns_zero(self, capsys) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=_xss_reflect_handler
        )
        rc = await _run_scan_core(_TARGET, ["invalid"], 5.0, None)
        assert rc == 0
        out = capsys.readouterr().out
        assert "Nenhuma vulnerabilidade de XSS Vector detectada" in out
        assert "Nenhum teste de XSS Vector executado" in out

    @respx.mock
    @pytest.mark.asyncio
    async def test_baseline_error_returns_one(self, capsys) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=httpx.ConnectError("refused")
        )
        rc = await _run_scan_core(_TARGET, ["media_events"], 5.0, None)
        assert rc == 1
        assert "Erro ao acessar" in capsys.readouterr().out

    @respx.mock
    @pytest.mark.asyncio
    async def test_headless_unavailable_returns_one(self, capsys) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=_xss_reflect_handler
        )
        with patch("mytools.core.headless.browser_available", return_value=False):
            rc = await _run_scan_core(
                _TARGET, ["media_events"], 5.0, None, headless=True
            )
        assert rc == 1
        assert "--headless requer chromium" in capsys.readouterr().out

    @respx.mock
    @pytest.mark.asyncio
    async def test_all_categories_vulnerable_returns_one(self, capsys) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=_xss_reflect_handler
        )
        rc = await _run_scan_core(_TARGET, [], 5.0, None)
        assert rc == 1
        assert "Vulnerabilidades encontradas" in capsys.readouterr().out

    @respx.mock
    @pytest.mark.asyncio
    async def test_safe_scan_returns_zero(self, capsys) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            return_value=httpx.Response(200, text="<html><body>safe</body></html>")
        )
        rc = await _run_scan_core(_TARGET, ["media_events"], 5.0, None)
        assert rc == 0
        assert "Nenhuma vulnerabilidade de XSS Vector detectada" in (
            capsys.readouterr().out
        )

    @respx.mock
    @pytest.mark.asyncio
    async def test_output_file_calls_write_output(self, tmp_path) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=_xss_reflect_handler
        )
        out_file = str(tmp_path / "out.json")
        with patch("mytools.web.xssvectors.write_output") as mock_write:
            rc = await _run_scan_core(_TARGET, ["media_events"], 5.0, out_file)
        assert rc == 1
        mock_write.assert_called_once()

    @respx.mock
    @pytest.mark.asyncio
    async def test_headless_confirm_marks_dom(self, capsys) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=_xss_reflect_handler
        )

        async def fake_confirm(url: str, *, timeout: float, proxy: str | None) -> bool:
            return True

        with (
            patch("mytools.core.headless.browser_available", return_value=True),
            patch(
                "mytools.core.headless.confirm_js_execution",
                new_callable=AsyncMock,
                side_effect=fake_confirm,
            ),
        ):
            rc = await _run_scan_core(
                _TARGET, ["media_events"], 5.0, None, headless=True
            )
        assert rc == 1
        assert "DOM:       confirmado via headless" in capsys.readouterr().out

    @respx.mock
    @pytest.mark.asyncio
    async def test_headless_no_confirmations(self, capsys) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=_xss_reflect_handler
        )

        async def fake_confirm(url: str, *, timeout: float, proxy: str | None) -> bool:
            return False

        with (
            patch("mytools.core.headless.browser_available", return_value=True),
            patch(
                "mytools.core.headless.confirm_js_execution",
                new_callable=AsyncMock,
                side_effect=fake_confirm,
            ),
        ):
            rc = await _run_scan_core(
                _TARGET, ["media_events"], 5.0, None, headless=True
            )
        assert rc == 1
        assert "DOM:       confirmado via headless" not in capsys.readouterr().out

    @respx.mock
    @pytest.mark.asyncio
    async def test_scanner_run_scan_delegates(self, capsys) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=_xss_reflect_handler
        )
        rc = await scanner.run_scan(
            target=_TARGET, categories=["media_events"], timeout=5.0
        )
        assert rc == 1


# ---------------------------------------------------------------------------
# Scanner: build_parser / print_results / example / help
# ---------------------------------------------------------------------------


def test_build_parser_categories_and_headless() -> None:
    parser = build_parser()
    args = parser.parse_args(["https://example.com"])
    assert args.url == "https://example.com"
    assert args.category == "all"
    assert args.headless is False
    args2 = parser.parse_args(["https://example.com", "-c", "slot_use", "--headless"])
    assert args2.category == "slot_use"
    assert args2.headless is True
    with pytest.raises(SystemExit):
        parser.parse_args(["https://example.com", "-c", "invalid"])


def test_scanner_print_results(capsys: pytest.CaptureFixture[str]) -> None:
    result = _make_result(
        attempts=[_make_attempt(vulnerable=True, dom_confirmed=True)],
        overall_status="vulnerable",
    )
    scanner.print_results(result)
    assert "DOM:       confirmado via headless" in capsys.readouterr().out


def test_scanner_example() -> None:
    assert "-c uri_javascript" in scanner._example()


def test_scanner_help() -> None:
    assert "Uso:" in scanner._help()


# ---------------------------------------------------------------------------
# banner_art / __main__ guard
# ---------------------------------------------------------------------------


def test_banner_art_runs(capsys: pytest.CaptureFixture[str]) -> None:
    from mytools.web.xssvectors import XSSVectorScanner

    XSSVectorScanner.__dict__["banner_fn"]()
    assert "xssvectors" in capsys.readouterr().out


def test_banner_art_is_module_function() -> None:
    from mytools.web.xssvectors import banner_art

    assert callable(banner_art)


def test_main_guard() -> None:
    with (
        patch("mytools.core.base.run_main_loop", side_effect=SystemExit(0)),
        patch("sys.argv", ["mytools-xssvectors"]),
        pytest.raises(SystemExit),
    ):
        runpy.run_module("mytools.web.xssvectors", run_name="__main__")
