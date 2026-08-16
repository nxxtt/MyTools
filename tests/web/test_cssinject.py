#!/usr/bin/env python3
"""Testes unitarios do modulo CSS Injection."""

from __future__ import annotations

import runpy
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mytools.web.cssinject import (
    _ATTRIBUTE_LEAK_PAYLOADS,
    _CATEGORY_MAP,
    _CSP_BYPASS_PAYLOADS,
    _DATA_EXTRACTION_PAYLOADS,
    _INJECTION_PAYLOADS,
    _SELECTOR_ABUSE_PAYLOADS,
    _TOKEN_EXFIL_PAYLOADS,
    CSSInjectAttempt,
    CSSInjectResult,
    _check_csp_css,
    _check_css_reflection,
    _confirm_headless_css,
    _detect_css_contexts,
    _inject_payload,
    _run_scan_core,
    _test_css_category,
    build_parser,
    print_results,
    scanner,
)

_TARGET = "https://example.com/page"


def test_category_map_has_six_categories() -> None:
    assert len(_CATEGORY_MAP) == 6


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {
        "injection_points",
        "data_extraction",
        "attribute_leak",
        "selector_abuse",
        "token_exfil",
        "csp_bypass",
    }


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 38


def test_injection_payloads_count() -> None:
    assert len(_INJECTION_PAYLOADS) == 6


def test_data_extraction_payloads_count() -> None:
    assert len(_DATA_EXTRACTION_PAYLOADS) == 7


def test_attribute_leak_payloads_count() -> None:
    assert len(_ATTRIBUTE_LEAK_PAYLOADS) == 6


def test_selector_abuse_payloads_count() -> None:
    assert len(_SELECTOR_ABUSE_PAYLOADS) == 6


def test_token_exfil_payloads_count() -> None:
    assert len(_TOKEN_EXFIL_PAYLOADS) == 6


def test_csp_bypass_payloads_count() -> None:
    assert len(_CSP_BYPASS_PAYLOADS) == 7


def test_all_payloads_have_four_elements() -> None:
    all_lists = (
        _INJECTION_PAYLOADS
        + _DATA_EXTRACTION_PAYLOADS
        + _ATTRIBUTE_LEAK_PAYLOADS
        + _SELECTOR_ABUSE_PAYLOADS
        + _TOKEN_EXFIL_PAYLOADS
        + _CSP_BYPASS_PAYLOADS
    )
    for p in all_lists:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_inject_payload_new_param() -> None:
    result = _inject_payload(_TARGET, "p", "body{color:red}")
    assert "p=" in result
    assert "color" in result


def test_inject_payload_preserves_existing() -> None:
    url = f"{_TARGET}?foo=bar"
    result = _inject_payload(url, "p", "1")
    assert "foo=bar" in result
    assert "p=1" in result


def test_inject_payload_special_css() -> None:
    result = _inject_payload(_TARGET, "p", "body{background:url(http://evil.com/)}")
    assert "p=" in result


def test_check_css_reflection_true() -> None:
    body = "<div>body{color:red}</div>"
    assert _check_css_reflection(body, "body{color:red}") is True


def test_check_css_reflection_case_insensitive() -> None:
    body = "<STYLE>BODY{COLOR:RED}</STYLE>"
    assert _check_css_reflection(body, "body{color:red}") is True


def test_check_css_reflection_false() -> None:
    body = "<div>safe content</div>"
    assert _check_css_reflection(body, "body{color:red}") is False


def test_detect_css_contexts_style_tag() -> None:
    ctxs = _detect_css_contexts("<style>body{color:red}</style>")
    assert "style_tag" in ctxs


def test_detect_css_contexts_style_attr() -> None:
    ctxs = _detect_css_contexts('<div style="color:red">')
    assert "style_attr" in ctxs


def test_detect_css_contexts_link_css() -> None:
    ctxs = _detect_css_contexts('<link rel="stylesheet" href="style.css">')
    assert "link_css" in ctxs


def test_detect_css_contexts_none() -> None:
    ctxs = _detect_css_contexts("<div>safe</div>")
    assert ctxs == []


def test_check_csp_css_with_style_src() -> None:
    headers = {"Content-Security-Policy": "style-src 'self'"}
    result = _check_csp_css(headers)
    assert result["has_csp"] is True
    assert result["has_style_src"] is True
    assert result["css_blocked"] is True


def test_check_csp_css_with_unsafe_inline() -> None:
    headers = {"Content-Security-Policy": "style-src 'self' 'unsafe-inline'"}
    result = _check_csp_css(headers)
    assert result["css_blocked"] is False


def test_check_csp_css_no_csp() -> None:
    headers = {"X-Custom": "value"}
    result = _check_csp_css(headers)
    assert result["has_csp"] is False
    assert result["css_blocked"] is False


def test_check_csp_css_default_src_only() -> None:
    headers = {"Content-Security-Policy": "default-src 'self'"}
    result = _check_csp_css(headers)
    assert result["has_default_src"] is True
    assert result["css_blocked"] is True


def test_attempt_dataclass_frozen() -> None:
    a = CSSInjectAttempt(
        technique="test",
        category="injection_points",
        context="test_ctx",
        payload="p",
        method="GET",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=110,
        status_changed=False,
        size_changed=True,
        csp_blocks_css=False,
        vulnerable=True,
        details="test",
        error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False  # type: ignore[reportAttributeAccessIssue]


def test_attempt_dataclass_slots() -> None:
    a = CSSInjectAttempt(
        technique="test",
        category="injection_points",
        context="test_ctx",
        payload="p",
        method="GET",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=110,
        status_changed=False,
        size_changed=True,
        csp_blocks_css=False,
        vulnerable=True,
        details="test",
        error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = CSSInjectResult(
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
    r = CSSInjectResult(
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
        _INJECTION_PAYLOADS,
        _DATA_EXTRACTION_PAYLOADS,
        _ATTRIBUTE_LEAK_PAYLOADS,
        _SELECTOR_ABUSE_PAYLOADS,
        _TOKEN_EXFIL_PAYLOADS,
        _CSP_BYPASS_PAYLOADS,
    ):
        all_names.extend(p[0] for p in lst)
    assert len(all_names) == len(set(all_names))


def test_all_payloads_have_indicators() -> None:
    all_lists = (
        _INJECTION_PAYLOADS
        + _DATA_EXTRACTION_PAYLOADS
        + _ATTRIBUTE_LEAK_PAYLOADS
        + _SELECTOR_ABUSE_PAYLOADS
        + _TOKEN_EXFIL_PAYLOADS
        + _CSP_BYPASS_PAYLOADS
    )
    for p in all_lists:
        assert len(p[3]) >= 1, f"Payload {p[0]} must have at least 1 indicator"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_attempt(
    technique: str = "style_tag_inject",
    category: str = "injection_points",
    context: str = "style_tag",
    payload: str = "body{background:red}",
    vulnerable: bool = False,
    error: str = "",
    details: str = "",
    dom_confirmed: bool = False,
    test_url: str | None = None,
) -> CSSInjectAttempt:
    return CSSInjectAttempt(
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
        csp_blocks_css=False,
        vulnerable=vulnerable,
        details=details,
        error=error,
        exploit="css_exfiltration_payload" if vulnerable else "",
        tool="XSStrike",
        test_url=test_url or f"{_TARGET}?p={technique}",
        dom_confirmed=dom_confirmed,
    )


def _make_result(
    attempts: list[CSSInjectAttempt] | None = None,
    issues: list[str] | None = None,
    blocked: list[str] | None = None,
    overall_status: str = "safe",
) -> CSSInjectResult:
    return CSSInjectResult(
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


def _css_reflect_handler(request: httpx.Request) -> httpx.Response:
    from urllib.parse import parse_qs, urlparse

    params = parse_qs(urlparse(str(request.url)).query)
    css = next((v[0] for k, v in params.items() if k.startswith("_css_")), None)
    if css is None:
        return httpx.Response(200, text="<html><body>normal page</body></html>")
    return httpx.Response(200, text=f"<html><style>{css}</style></html>")


# ---------------------------------------------------------------------------
# _test_css_category
# ---------------------------------------------------------------------------


class TestTestCssCategory:
    @respx.mock
    @pytest.mark.asyncio
    async def test_vulnerable_attempts(self, async_client) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=_css_reflect_handler
        )
        results = await _test_css_category(
            async_client,
            _TARGET,
            5.0,
            200,
            100,
            _INJECTION_PAYLOADS,
            "injection_points",
        )
        assert len(results) == len(_INJECTION_PAYLOADS)
        vuln = [a for a in results if a.vulnerable]
        assert len(vuln) == len(_INJECTION_PAYLOADS)
        first = vuln[0]
        assert first.category == "injection_points"
        assert first.status_test == 200
        assert first.test_url.startswith(_TARGET)
        assert first.exploit == "css_exfiltration_payload"
        assert first.tool == "XSStrike"
        assert first.details.startswith("CSS refletido em contexto:")

    @respx.mock
    @pytest.mark.asyncio
    async def test_reflected_without_context_and_csp(self, async_client) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            from urllib.parse import parse_qs, urlparse

            params = parse_qs(urlparse(str(request.url)).query)
            css = next((v[0] for k, v in params.items() if k.startswith("_css_")), None)
            return httpx.Response(
                200,
                text=f"<html><div>{css or ''}</div></html>",
                headers={"Content-Security-Policy": "style-src 'self'"},
            )

        respx.route(url__regex=r"https://example\.com/.*").mock(side_effect=handler)
        results = await _test_css_category(
            async_client,
            _TARGET,
            5.0,
            200,
            100,
            _DATA_EXTRACTION_PAYLOADS,
            "data_extraction",
        )
        assert results
        first = results[0]
        assert first.vulnerable is False
        assert first.category == "data_extraction"
        assert first.csp_blocks_css is True
        assert "Payload refletido (contexto CSS nao detectado)" in first.details
        assert "[CSP bloqueia style-src]" in first.details

    @respx.mock
    @pytest.mark.asyncio
    async def test_request_error_creates_error_attempt(self, async_client) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=httpx.ConnectError("refused")
        )
        results = await _test_css_category(
            async_client,
            _TARGET,
            5.0,
            200,
            100,
            _INJECTION_PAYLOADS,
            "injection_points",
        )
        assert results
        assert all(a.error for a in results)
        assert all(not a.vulnerable for a in results)
        assert all(a.status_test == 0 for a in results)


# ---------------------------------------------------------------------------
# _confirm_headless_css
# ---------------------------------------------------------------------------


class TestConfirmHeadlessCss:
    @pytest.mark.asyncio
    async def test_no_candidates_returns_unchanged(self) -> None:
        att = _make_attempt(vulnerable=False)
        with patch("mytools.core.headless.evaluate", new_callable=AsyncMock) as mock:
            result = await _confirm_headless_css(
                _TARGET, [att], timeout=5.0, proxy=None
            )
        assert result == [att]
        mock.assert_not_called()

    @pytest.mark.asyncio
    async def test_baseline_error_returns_unchanged(self) -> None:
        att = _make_attempt(
            vulnerable=True, payload="body{background:url(http://evil.com/)}"
        )
        with patch(
            "mytools.core.headless.evaluate",
            new_callable=AsyncMock,
            side_effect=RuntimeError("boom"),
        ):
            result = await _confirm_headless_css(
                _TARGET, [att], timeout=5.0, proxy=None
            )
        assert result == [att]

    @pytest.mark.asyncio
    async def test_confirmed_marks_dom_confirmed(self) -> None:
        att = _make_attempt(
            vulnerable=True,
            payload="body{background:url(http://evil.com/)}",
            details="base",
        )

        async def fake_eval(
            url: str, script: str, *, timeout: float, proxy: str | None
        ) -> str:
            if url == _TARGET:
                return "normal page"
            return "rule: body{background:url(http://evil.com/)}"

        with patch(
            "mytools.core.headless.evaluate",
            new_callable=AsyncMock,
            side_effect=fake_eval,
        ) as mock:
            result = await _confirm_headless_css(
                _TARGET, [att], timeout=5.0, proxy=None
            )
        assert mock.call_count == 2
        confirmed = result[0]
        assert confirmed.dom_confirmed is True
        assert "[confirmado via headless]" in confirmed.details

    @pytest.mark.asyncio
    async def test_partial_error_skips_url(self) -> None:
        att1 = _make_attempt(
            technique="a",
            vulnerable=True,
            payload="body{background:url(http://evil.com/)}",
            test_url=f"{_TARGET}?a=1",
        )
        att2 = _make_attempt(
            technique="b",
            vulnerable=True,
            payload="body{background:url(http://evil.com/)}",
            test_url=f"{_TARGET}?b=1",
        )

        async def fake_eval(
            url: str, script: str, *, timeout: float, proxy: str | None
        ) -> str:
            if url == _TARGET:
                return "normal page"
            if "a=1" in url:
                raise RuntimeError("boom")
            return "evil.com applied"

        with patch(
            "mytools.core.headless.evaluate",
            new_callable=AsyncMock,
            side_effect=fake_eval,
        ):
            result = await _confirm_headless_css(
                _TARGET, [att1, att2], timeout=5.0, proxy=None
            )
        by_url = {a.test_url: a for a in result}
        assert by_url[f"{_TARGET}?a=1"].dom_confirmed is False
        assert by_url[f"{_TARGET}?b=1"].dom_confirmed is True

    @pytest.mark.asyncio
    async def test_non_string_values_not_confirmed(self) -> None:
        att = _make_attempt(
            vulnerable=True, payload="body{background:url(http://evil.com/)}"
        )

        async def fake_eval(
            url: str, script: str, *, timeout: float, proxy: str | None
        ) -> dict[str, int]:
            return {"a": 1}

        with patch(
            "mytools.core.headless.evaluate",
            new_callable=AsyncMock,
            side_effect=fake_eval,
        ):
            result = await _confirm_headless_css(
                _TARGET, [att], timeout=5.0, proxy=None
            )
        assert result[0].dom_confirmed is False
        assert "[confirmado via headless]" not in result[0].details


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


class TestPrintResults:
    def test_no_vulns(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_results(_make_result())
        out = capsys.readouterr().out
        assert "CSS Injection" in out
        assert "Nenhuma vulnerabilidade de CSS Injection detectada" in out

    def test_full_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        dup1 = _make_attempt(
            technique="style_tag_inject",
            vulnerable=True,
            details="css reflected",
            dom_confirmed=True,
        )
        dup2 = _make_attempt(
            technique="style_tag_inject",
            vulnerable=True,
            details="duplicate",
        )
        no_details = _make_attempt(
            technique="content_url",
            category="data_extraction",
            context="content_url",
            vulnerable=True,
        )
        err = _make_attempt(
            technique="background_url",
            category="data_extraction",
            context="background_url",
            vulnerable=False,
            error="Connection refused",
        )
        blocked = _make_attempt(
            technique="cursor_url",
            category="data_extraction",
            context="cursor_url",
            vulnerable=False,
        )
        result = _make_result(
            attempts=[dup1, dup2, no_details, err, blocked],
            issues=["CSP presente no alvo"],
            blocked=["cursor_url"],
            overall_status="vulnerable",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Vulnerabilidades encontradas" in out
        assert "[injection_points] style_tag_inject" in out
        assert "DOM:       confirmado via headless" in out
        assert "Detalhes: css reflected" in out
        assert "Total: 3 vulneraveis de 5 testes" in out
        assert "Observacoes" in out
        assert "CSP presente no alvo" in out

    def test_with_issues_only(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = _make_result(
            attempts=[_make_attempt()],
            issues=["Nenhum teste de CSS Injection executado"],
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Nenhum teste de CSS Injection executado" in out


# ---------------------------------------------------------------------------
# _run_scan_core
# ---------------------------------------------------------------------------


class TestRunScanCore:
    @respx.mock
    @pytest.mark.asyncio
    async def test_invalid_category_returns_zero(self, capsys) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=_css_reflect_handler
        )
        rc = await _run_scan_core(_TARGET, ["invalid"], 5.0, None)
        assert rc == 0
        out = capsys.readouterr().out
        assert "Nenhuma vulnerabilidade de CSS Injection detectada" in out
        assert "Nenhum teste de CSS Injection executado" in out

    @respx.mock
    @pytest.mark.asyncio
    async def test_baseline_error_returns_one(self, capsys) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=httpx.ConnectError("refused")
        )
        rc = await _run_scan_core(_TARGET, ["injection_points"], 5.0, None)
        assert rc == 1

    @respx.mock
    @pytest.mark.asyncio
    async def test_headless_unavailable_returns_one(self, capsys) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=_css_reflect_handler
        )
        with patch("mytools.core.headless.browser_available", return_value=False):
            rc = await _run_scan_core(
                _TARGET, ["injection_points"], 5.0, None, headless=True
            )
        assert rc == 1
        assert "--headless requer chromium" in capsys.readouterr().out

    @respx.mock
    @pytest.mark.asyncio
    async def test_all_categories_vulnerable_returns_one(self, capsys) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=_css_reflect_handler
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
        rc = await _run_scan_core(_TARGET, ["injection_points"], 5.0, None)
        assert rc == 0
        assert "Nenhuma vulnerabilidade de CSS Injection detectada" in (
            capsys.readouterr().out
        )

    @respx.mock
    @pytest.mark.asyncio
    async def test_csp_blocked_adds_issue(self, capsys) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            from urllib.parse import parse_qs, urlparse

            params = parse_qs(urlparse(str(request.url)).query)
            css = next((v[0] for k, v in params.items() if k.startswith("_css_")), None)
            if css is None:
                return httpx.Response(200, text="<html><body>normal</body></html>")
            return httpx.Response(
                200,
                text=f"<html><style>{css}</style></html>",
                headers={"Content-Security-Policy": "style-src 'self'"},
            )

        respx.route(url__regex=r"https://example\.com/.*").mock(side_effect=handler)
        rc = await _run_scan_core(_TARGET, ["injection_points"], 5.0, None)
        assert rc == 1
        assert "bloqueados por CSP" in capsys.readouterr().out

    @respx.mock
    @pytest.mark.asyncio
    async def test_output_file_calls_write_output(self, tmp_path) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=_css_reflect_handler
        )
        out_file = str(tmp_path / "out.json")
        with patch("mytools.web.cssinject.write_output") as mock_write:
            rc = await _run_scan_core(_TARGET, ["injection_points"], 5.0, out_file)
        assert rc == 1
        mock_write.assert_called_once()

    @respx.mock
    @pytest.mark.asyncio
    async def test_headless_confirm_marks_dom(self, capsys) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=_css_reflect_handler
        )

        async def fake_eval(
            url: str, script: str, *, timeout: float, proxy: str | None
        ) -> str:
            return "evil.com applied" if "evil.com" in url else "normal page"

        with (
            patch("mytools.core.headless.browser_available", return_value=True),
            patch(
                "mytools.core.headless.evaluate",
                new_callable=AsyncMock,
                side_effect=fake_eval,
            ),
        ):
            rc = await _run_scan_core(
                _TARGET, ["injection_points"], 5.0, None, headless=True
            )
        assert rc == 1
        assert "DOM:       confirmado via headless" in capsys.readouterr().out

    @respx.mock
    @pytest.mark.asyncio
    async def test_scanner_run_scan_delegates(self, capsys) -> None:
        respx.route(url__regex=r"https://example\.com/.*").mock(
            side_effect=_css_reflect_handler
        )
        rc = await scanner.run_scan(
            target=_TARGET, categories=["injection_points"], timeout=5.0
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
    args2 = parser.parse_args(
        ["https://example.com", "-c", "token_exfil", "--headless"]
    )
    assert args2.category == "token_exfil"
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
    assert "-c data_extraction" in scanner._example()


def test_scanner_help() -> None:
    assert "Uso:" in scanner._help()


# ---------------------------------------------------------------------------
# banner_art / __main__ guard
# ---------------------------------------------------------------------------


def test_banner_art_runs(capsys: pytest.CaptureFixture[str]) -> None:
    from mytools.web.cssinject import CSSInjectScanner

    CSSInjectScanner.__dict__["banner_fn"]()
    assert "cssinject" in capsys.readouterr().out


def test_banner_art_is_module_function() -> None:
    from mytools.web.cssinject import banner_art

    assert callable(banner_art)


def test_main_guard() -> None:
    with (
        patch("mytools.core.base.run_main_loop", side_effect=SystemExit(0)),
        patch("sys.argv", ["mytools-cssinject"]),
        pytest.raises(SystemExit),
    ):
        runpy.run_module("mytools.web.cssinject", run_name="__main__")
