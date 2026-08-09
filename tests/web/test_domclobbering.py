#!/usr/bin/env python3
"""Testes unitarios do modulo de DOM Clobbering."""

from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from mytools.web.domclobbering import (
    _CATEGORY_MAP,
    _DOCUMENT_CLOBBERABLE,
    _FORM_CHILD_PAYLOADS,
    _IMPACT_PAYLOADS,
    _NAMED_ACCESS_PAYLOADS,
    _WINDOW_CLOBBERABLE,
    ClobberAttempt,
    ClobberResult,
    DomclobberingScanner,
    _check_clobber_in_html,
    _confirm_dom_clobber,
    _detect_passive_clobbering,
    _extract_clob_name,
    _inject_payload,
    _run_scan_core,
    _test_form_child,
    _test_impact_chains,
    _test_named_access,
    build_parser,
    print_results,
)


def _attempt(
    *,
    technique: str = "window_anchor_id",
    category: str = "named_access",
    payload: str = '<a id="config" href="javascript:void(0)">',
    target_element: str = "window.config",
    attribute_used: str = "id",
    vulnerable: bool = False,
    details: str = "",
    error: str = "",
    dom_confirmed: bool = False,
) -> ClobberAttempt:
    return ClobberAttempt(
        technique=technique,
        category=category,
        payload=payload,
        target_element=target_element,
        attribute_used=attribute_used,
        method="GET",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=100,
        status_changed=False,
        size_changed=False,
        vulnerable=vulnerable,
        details=details,
        error=error,
        exploit="<a id='x'>",
        tool="XSStrike",
        dom_confirmed=dom_confirmed,
    )


def _reflect_clob_handler(request: httpx.Request) -> httpx.Response:
    params = parse_qs(urlparse(str(request.url)).query)
    for key, values in params.items():
        if key.startswith("_clob_"):
            return httpx.Response(200, text=values[0])
    return httpx.Response(
        200, text='<html><body><a id="config" href="/page"></a></body></html>'
    )


# ─── Category Map ────────────────────────────────────────────────────────────
class TestCategoryMap:
    def test_has_three_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 3

    def test_categories_are_correct(self) -> None:
        expected = {"named_access", "form_child", "impact"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_named_access_has_eight_techniques(self) -> None:
        assert len(_CATEGORY_MAP["named_access"]) == 8

    def test_form_child_has_six_techniques(self) -> None:
        assert len(_CATEGORY_MAP["form_child"]) == 6

    def test_impact_has_six_techniques(self) -> None:
        assert len(_CATEGORY_MAP["impact"]) == 6


# ─── Payload Lists ───────────────────────────────────────────────────────────
class TestPayloadLists:
    def test_named_access_payloads_count(self) -> None:
        assert len(_NAMED_ACCESS_PAYLOADS) == 8

    def test_form_child_payloads_count(self) -> None:
        assert len(_FORM_CHILD_PAYLOADS) == 6

    def test_impact_payloads_count(self) -> None:
        assert len(_IMPACT_PAYLOADS) == 6

    def test_named_access_payloads_have_correct_structure(self) -> None:
        for technique, tmpl, attr, indicators in _NAMED_ACCESS_PAYLOADS:
            assert isinstance(technique, str)
            assert isinstance(tmpl, str)
            assert "{name}" in tmpl
            assert isinstance(attr, str)
            assert isinstance(indicators, list)
            assert len(indicators) > 0

    def test_form_child_payloads_have_correct_structure(self) -> None:
        for technique, tmpl, prop, indicators in _FORM_CHILD_PAYLOADS:
            assert isinstance(technique, str)
            assert isinstance(tmpl, str)
            assert "{name}" in tmpl
            assert isinstance(prop, str)
            assert isinstance(indicators, list)

    def test_impact_payloads_have_correct_structure(self) -> None:
        for technique, tmpl, sink, indicators in _IMPACT_PAYLOADS:
            assert isinstance(technique, str)
            assert isinstance(tmpl, str)
            assert "{name}" in tmpl
            assert isinstance(sink, str)
            assert isinstance(indicators, list)


# ─── Clobberable Sets ───────────────────────────────────────────────────────
class TestClobberableSets:
    def test_window_clobberable_not_empty(self) -> None:
        assert len(_WINDOW_CLOBBERABLE) > 0

    def test_document_clobberable_not_empty(self) -> None:
        assert len(_DOCUMENT_CLOBBERABLE) > 0

    def test_window_contains_location(self) -> None:
        assert "location" in _WINDOW_CLOBBERABLE

    def test_window_contains_self(self) -> None:
        assert "self" in _WINDOW_CLOBBERABLE

    def test_document_contains_forms(self) -> None:
        assert "forms" in _DOCUMENT_CLOBBERABLE

    def test_document_contains_cookie(self) -> None:
        assert "cookie" in _DOCUMENT_CLOBBERABLE


# ─── Inject Payload ──────────────────────────────────────────────────────────
class TestInjectPayload:
    def test_inject_simple(self) -> None:
        result = _inject_payload("https://target.com", "q", "test")
        assert "q=test" in result

    def test_inject_preserves_existing_params(self) -> None:
        result = _inject_payload("https://target.com?a=1", "q", "test")
        assert "a=1" in result
        assert "q=test" in result

    def test_inject_encodes_html(self) -> None:
        result = _inject_payload("https://target.com", "q", '<a id="x">')
        assert "%3C" in result

    def test_inject_preserves_path(self) -> None:
        result = _inject_payload("https://target.com/page", "q", "test")
        assert result.startswith("https://target.com/page")


# ─── Check Clobber in HTML ──────────────────────────────────────────────────
class TestCheckClobberInHTML:
    def test_detects_reflected_payload(self) -> None:
        html = '<html><body><a id="config" href="javascript:void(0)"></a></body></html>'
        payload = '<a id="config" href="javascript:void(0)">'
        assert _check_clobber_in_html(html, payload) is True

    def test_no_reflection(self) -> None:
        html = "<html><body>Hello world</body></html>"
        payload = '<a id="config" href="javascript:void(0)">'
        assert _check_clobber_in_html(html, payload) is False

    def test_case_insensitive(self) -> None:
        html = '<A ID="Config" href="javascript:void(0)">'
        payload = '<a id="config" href="javascript:void(0)">'
        assert _check_clobber_in_html(html, payload) is True


# ─── Detect Passive Clobbering ───────────────────────────────────────────────
class TestDetectPassiveClobbering:
    def test_no_clobbering(self) -> None:
        html = "<html><body>Hello world</body></html>"
        result = _detect_passive_clobbering(html)
        assert result == []

    def test_detects_window_anchor_id(self) -> None:
        html = '<html><body><a id="config" href="/page"></a></body></html>'
        result = _detect_passive_clobbering(html)
        assert len(result) > 0
        assert any("window.config" in r[2] for r in result)

    def test_detects_window_div_id(self) -> None:
        html = '<html><body><div id="settings"></div></body></html>'
        result = _detect_passive_clobbering(html)
        assert len(result) > 0
        assert any("window.settings" in r[2] for r in result)

    def test_detects_document_forms(self) -> None:
        html = '<html><body><form name="forms"></form></body></html>'
        result = _detect_passive_clobbering(html)
        assert len(result) > 0
        assert any("document.forms" in r[2] for r in result)

    def test_ignores_non_clobberable_names(self) -> None:
        html = '<html><body><a id="myLink" href="/page"></a></body></html>'
        result = _detect_passive_clobbering(html)
        assert result == []

    def test_deduplicates(self) -> None:
        html = '<html><body><a id="config" href="/p1"></a><a id="config" href="/p2"></a></body></html>'
        result = _detect_passive_clobbering(html)
        config_results = [r for r in result if r[2] == "window.config"]
        assert len(config_results) == 1

    def test_multiple_clobberable_elements(self) -> None:
        html = """
        <html><body>
        <a id="config" href="/p1"></a>
        <div id="settings"></div>
        <form name="document"></form>
        </body></html>
        """
        result = _detect_passive_clobbering(html)
        assert len(result) >= 2


# ─── Named Access Tests ─────────────────────────────────────────────────────
class TestNamedAccess:
    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        client = AsyncMock()
        client.request = AsyncMock(side_effect=httpx.RequestError("Connection refused"))
        from mytools.web.domclobbering import _test_named_access

        result = await _test_named_access(client, "https://target.com", 10.0)
        assert len(result) > 0
        assert any(a.error for a in result)

    @pytest.mark.asyncio
    @patch("mytools.web.domclobbering.fetch", new_callable=AsyncMock)
    async def test_reflected_payload(self, mock_fetch: AsyncMock) -> None:
        mock_fetch.return_value = (
            200,
            {},
            b'<a id="config" href="javascript:void(0)">',
            {},
        )
        client = AsyncMock()
        from mytools.web.domclobbering import _test_named_access

        result = await _test_named_access(client, "https://target.com?q=test", 10.0)
        assert len(result) > 0


# ─── Form Child Tests ────────────────────────────────────────────────────────
class TestFormChild:
    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        client = AsyncMock()
        client.request = AsyncMock(side_effect=httpx.RequestError("Connection refused"))
        from mytools.web.domclobbering import _test_form_child

        result = await _test_form_child(client, "https://target.com", 10.0)
        assert len(result) > 0
        assert any(a.error for a in result)


# ─── Impact Tests ────────────────────────────────────────────────────────────
class TestImpact:
    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        client = AsyncMock()
        client.request = AsyncMock(side_effect=httpx.RequestError("Connection refused"))
        from mytools.web.domclobbering import _test_impact_chains

        result = await _test_impact_chains(client, "https://target.com", 10.0)
        assert len(result) > 0
        assert any(a.error for a in result)


# ─── Dataclasses ─────────────────────────────────────────────────────────────
class TestDataclasses:
    def test_clobber_attempt_frozen(self) -> None:
        from mytools.web.domclobbering import ClobberAttempt

        a = ClobberAttempt(
            technique="t",
            category="c",
            payload="p",
            target_element="e",
            attribute_used="a",
            method="GET",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=100,
            status_changed=False,
            size_changed=False,
            vulnerable=False,
            details="",
            error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "new"  # type: ignore[misc]

    def test_clobber_attempt_slots(self) -> None:
        from mytools.web.domclobbering import ClobberAttempt

        a = ClobberAttempt(
            technique="t",
            category="c",
            payload="p",
            target_element="e",
            attribute_used="a",
            method="GET",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=100,
            status_changed=False,
            size_changed=False,
            vulnerable=False,
            details="",
            error="",
        )
        assert not hasattr(a, "__dict__")

    def test_clobber_result_frozen(self) -> None:
        from mytools.web.domclobbering import ClobberResult

        r = ClobberResult(
            target="t",
            tls=True,
            baseline_status=200,
            baseline_size=100,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="unknown",
        )
        with pytest.raises(AttributeError):
            r.target = "new"  # type: ignore[misc]


# ─── Parser ──────────────────────────────────────────────────────────────────
@pytest.mark.smoke
class TestBuildParser:
    def test_has_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.url == "https://test.com"

    def test_has_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "-c", "named_access"])
        assert args.category == "named_access"

    def test_default_category_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.category == "all"

    def test_all_categories(self) -> None:
        parser = build_parser()
        for cat in ["all", "named_access", "form_child", "impact"]:
            args = parser.parse_args(["https://test.com", "-c", cat])
            assert args.category == cat


# ─── Extract Clob Name ────────────────────────────────────────────────────────
class TestExtractClobName:
    def test_from_payload(self) -> None:
        a = _attempt(payload='<a id="config" href="/x">')
        assert _extract_clob_name(a) == "config"

    def test_fallback_to_target_element(self) -> None:
        a = _attempt(payload="no id or name here", target_element="window.location")
        assert _extract_clob_name(a) == "location"


# ─── Confirm Dom Clobber ─────────────────────────────────────────────────────
class TestConfirmDomClobber:
    @pytest.mark.asyncio
    async def test_confirms_urls(self) -> None:
        a1 = _attempt(payload='<a id="config" href="/x">', vulnerable=True)
        empty = _attempt(payload="", target_element="")
        passive = _attempt(
            technique="passive_clobber_detected",
            category="named_access",
            payload="<a>",
            target_element="window.config",
            vulnerable=True,
        )
        dup = _attempt(payload='<a id="config" href="/x">', vulnerable=True)
        mock_evaluate = AsyncMock(return_value=True)
        with patch("mytools.core.headless.evaluate", mock_evaluate):
            result = await _confirm_dom_clobber(
                "https://example.com", [a1, empty, passive, dup], timeout=10, proxy=None
            )
        assert result == {
            "https://example.com?_clob_config=%3Ca+id%3D%22config%22+href%3D%22%2Fx%22%3E": True,
            "https://example.com": True,
        }
        assert mock_evaluate.call_count == 2

    @pytest.mark.asyncio
    async def test_evaluate_error_returns_false(self) -> None:
        a1 = _attempt(payload='<a id="config" href="/x">', vulnerable=True)
        passive = _attempt(
            technique="passive_clobber_detected",
            category="named_access",
            payload="<a>",
            target_element="window.config",
            vulnerable=True,
        )
        mock_evaluate = AsyncMock(side_effect=RuntimeError("boom"))
        with patch("mytools.core.headless.evaluate", mock_evaluate):
            result = await _confirm_dom_clobber(
                "https://example.com", [a1, passive], timeout=10, proxy=None
            )
        assert result == {
            "https://example.com?_clob_config=%3Ca+id%3D%22config%22+href%3D%22%2Fx%22%3E": False,
            "https://example.com": False,
        }


# ─── Helper Test Branches ────────────────────────────────────────────────────
class TestHelperBranches:
    @pytest.mark.asyncio
    @respx.mock
    async def test_named_access_status_changed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "_clob_" in str(request.url):
                return httpx.Response(404, text="<html>not found</html>")
            return httpx.Response(200, text="<html>base</html>")

        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient() as client:
            result = await _test_named_access(client, "https://example.com", 10.0)
        assert any(a.status_changed for a in result)
        assert any("Status mudou" in a.details for a in result)

    @pytest.mark.asyncio
    @respx.mock
    async def test_named_access_size_changed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "_clob_" in str(request.url):
                return httpx.Response(200, text="A" * 100)
            return httpx.Response(200, text="base")

        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient() as client:
            result = await _test_named_access(client, "https://example.com", 10.0)
        assert any(a.size_changed for a in result)
        assert any("Tamanho mudou" in a.details for a in result)

    @pytest.mark.asyncio
    @respx.mock
    async def test_named_access_inner_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "_clob_" in str(request.url):
                raise httpx.ConnectError("boom")
            return httpx.Response(200, text="<html>base</html>")

        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient() as client:
            result = await _test_named_access(client, "https://example.com", 10.0)
        assert result
        assert all(a.error for a in result)

    @pytest.mark.asyncio
    @respx.mock
    async def test_form_child_reflected(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            params = parse_qs(urlparse(str(request.url)).query)
            for key, values in params.items():
                if key.startswith("_clob_"):
                    return httpx.Response(200, text=values[0])
            return httpx.Response(200, text="<html>base</html>")

        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient() as client:
            result = await _test_form_child(client, "https://example.com", 10.0)
        assert result
        assert any(a.vulnerable for a in result)

    @pytest.mark.asyncio
    @respx.mock
    async def test_form_child_inner_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "_clob_" in str(request.url):
                raise httpx.ConnectError("boom")
            return httpx.Response(200, text="<html>base</html>")

        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient() as client:
            result = await _test_form_child(client, "https://example.com", 10.0)
        assert result
        assert all(a.error for a in result)

    @pytest.mark.asyncio
    @respx.mock
    async def test_form_child_status_changed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "_clob_" in str(request.url):
                return httpx.Response(404, text="<html>not found</html>")
            return httpx.Response(200, text="<html>base</html>")

        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient() as client:
            result = await _test_form_child(client, "https://example.com", 10.0)
        assert any(a.status_changed for a in result)
        assert any("Status mudou" in a.details for a in result)

    @pytest.mark.asyncio
    @respx.mock
    async def test_form_child_size_changed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "_clob_" in str(request.url):
                return httpx.Response(200, text="A" * 100)
            return httpx.Response(200, text="base")

        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient() as client:
            result = await _test_form_child(client, "https://example.com", 10.0)
        assert any(a.size_changed for a in result)
        assert any("Tamanho mudou" in a.details for a in result)

    @pytest.mark.asyncio
    @respx.mock
    async def test_impact_reflected(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            params = parse_qs(urlparse(str(request.url)).query)
            for key, values in params.items():
                if key.startswith("_clob_"):
                    return httpx.Response(200, text=values[0])
            return httpx.Response(200, text="<html>base</html>")

        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient() as client:
            result = await _test_impact_chains(client, "https://example.com", 10.0)
        assert result
        assert any(a.vulnerable for a in result)

    @pytest.mark.asyncio
    @respx.mock
    async def test_impact_status_changed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "_clob_" in str(request.url):
                return httpx.Response(404, text="<html>not found</html>")
            return httpx.Response(200, text="<html>base</html>")

        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient() as client:
            result = await _test_impact_chains(client, "https://example.com", 10.0)
        assert any(a.status_changed for a in result)
        assert any("Status mudou" in a.details for a in result)

    @pytest.mark.asyncio
    @respx.mock
    async def test_impact_size_changed(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "_clob_" in str(request.url):
                return httpx.Response(200, text="A" * 100)
            return httpx.Response(200, text="base")

        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient() as client:
            result = await _test_impact_chains(client, "https://example.com", 10.0)
        assert any(a.size_changed for a in result)
        assert any("Tamanho mudou" in a.details for a in result)

    @pytest.mark.asyncio
    @respx.mock
    async def test_impact_inner_error(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "_clob_" in str(request.url):
                raise httpx.ConnectError("boom")
            return httpx.Response(200, text="<html>base</html>")

        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient() as client:
            result = await _test_impact_chains(client, "https://example.com", 10.0)
        assert result
        assert all(a.error for a in result)


# ─── Print Results ───────────────────────────────────────────────────────────
class TestPrintResults:
    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a1 = _attempt(
            vulnerable=True,
            details="Payload refletido no HTML",
            dom_confirmed=True,
        )
        a2 = _attempt(
            vulnerable=True,
            target_element="window.settings",
        )
        a3 = _attempt(vulnerable=False)
        a4 = _attempt(vulnerable=False, error="boom")
        result = ClobberResult(
            target="https://example.com",
            tls=True,
            baseline_status=200,
            baseline_size=100,
            attempts=[a1, a1, a2, a3, a4],
            vulnerable_techniques=["window_anchor_id"],
            blocked_techniques=["window_anchor_id"],
            issues=["1 padroes de clobbering detectados passivamente"],
            overall_status="vulnerable",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "DOM:       confirmado via headless" in out
        assert "Payload refletido no HTML" in out
        assert "Observacoes" in out
        assert "Total:" in out
        assert "Exploit:" in out

    def test_safe(self, capsys: pytest.CaptureFixture[str]) -> None:
        a3 = _attempt(vulnerable=False)
        a4 = _attempt(vulnerable=False, error="boom")
        result = ClobberResult(
            target="https://example.com",
            tls=False,
            baseline_status=200,
            baseline_size=100,
            attempts=[a3, a4],
            vulnerable_techniques=[],
            blocked_techniques=["window_anchor_id"],
            issues=[],
            overall_status="safe",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Nenhuma vulnerabilidade de DOM Clobbering detectada" in out
        assert "Erros:" in out


# ─── Run Scan Core ───────────────────────────────────────────────────────────
class TestRunScanCore:
    @pytest.mark.asyncio
    @respx.mock
    async def test_safe_all_categories(self) -> None:
        respx.route(method="GET", url__startswith="https://example.com").mock(
            return_value=httpx.Response(
                200, text="<html><body>no payload</body></html>"
            )
        )
        result = await _run_scan_core("https://example.com", [], 10, None)
        assert result == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_vulnerable_named_access(self) -> None:
        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=_reflect_clob_handler
        )
        result = await _run_scan_core("https://example.com", ["named_access"], 10, None)
        assert result == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_category(self) -> None:
        respx.route(method="GET", url__startswith="https://example.com").mock(
            return_value=httpx.Response(200, text="<html><body>safe</body></html>")
        )
        result = await _run_scan_core("https://example.com", ["invalid"], 10, None)
        assert result == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_baseline_error(self) -> None:
        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=httpx.ConnectError("boom")
        )
        result = await _run_scan_core("https://example.com", [], 10, None)
        assert result == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_output_file(self, tmp_path: Path) -> None:
        respx.route(method="GET", url__startswith="https://example.com").mock(
            return_value=httpx.Response(200, text="<html><body>safe</body></html>")
        )
        output_file = str(tmp_path / "out.json")
        result = await _run_scan_core(
            "https://example.com", ["invalid"], 10, output_file
        )
        assert result == 0
        assert (tmp_path / "out.json").exists()

    @pytest.mark.asyncio
    @respx.mock
    async def test_headless_browser_unavailable(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with patch("mytools.core.headless.browser_available", return_value=False):
            result = await _run_scan_core(
                "https://example.com", [], 10, None, headless=True
            )
        assert result == 1
        out = capsys.readouterr().out
        assert "Erro: --headless requer chromium" in out

    @pytest.mark.asyncio
    @respx.mock
    async def test_headless_confirmed(self, capsys: pytest.CaptureFixture[str]) -> None:
        respx.route(method="GET", url__startswith="https://example.com").mock(
            return_value=httpx.Response(200, text="<html><body>safe</body></html>")
        )
        normal = _attempt(
            vulnerable=True,
            details="Payload refletido no HTML",
        )
        empty = _attempt(payload="", target_element="")
        with (
            patch("mytools.core.headless.browser_available", return_value=True),
            patch(
                "mytools.core.headless.evaluate",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch(
                "mytools.web.domclobbering._test_named_access",
                new_callable=AsyncMock,
                return_value=[normal, empty],
            ),
        ):
            result = await _run_scan_core(
                "https://example.com", ["named_access"], 10, None, headless=True
            )
        assert result == 1
        out = capsys.readouterr().out
        assert "confirmado via headless" in out

    @pytest.mark.asyncio
    @respx.mock
    async def test_headless_evaluate_error(self) -> None:
        respx.route(method="GET", url__startswith="https://example.com").mock(
            return_value=httpx.Response(200, text="<html><body>safe</body></html>")
        )
        normal = _attempt(vulnerable=True, details="Payload refletido no HTML")
        with (
            patch("mytools.core.headless.browser_available", return_value=True),
            patch(
                "mytools.core.headless.evaluate",
                new_callable=AsyncMock,
                side_effect=RuntimeError("boom"),
            ),
            patch(
                "mytools.web.domclobbering._test_named_access",
                new_callable=AsyncMock,
                return_value=[normal],
            ),
        ):
            result = await _run_scan_core(
                "https://example.com", ["named_access"], 10, None, headless=True
            )
        assert result == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_headless_partial_confirmation(self) -> None:
        """Um attempt sem confirmacao headless ainda e reportado (sem replace)."""
        respx.route(method="GET", url__startswith="https://example.com").mock(
            return_value=httpx.Response(200, text="<html><body>safe</body></html>")
        )
        normal = _attempt(vulnerable=True, details="Payload refletido no HTML")
        empty = _attempt(payload="", target_element="")
        with (
            patch("mytools.core.headless.browser_available", return_value=True),
            patch(
                "mytools.web.domclobbering._confirm_dom_clobber",
                new_callable=AsyncMock,
                return_value={"https://example.com": True},
            ),
            patch(
                "mytools.web.domclobbering._test_named_access",
                new_callable=AsyncMock,
                return_value=[normal, empty],
            ),
        ):
            result = await _run_scan_core(
                "https://example.com", ["named_access"], 10, None, headless=True
            )
        assert result == 1


# ─── Scanner Class ───────────────────────────────────────────────────────────
class TestScannerClass:
    @pytest.mark.asyncio
    async def test_run_scan(self) -> None:
        with patch(
            "mytools.web.domclobbering._run_scan_core",
            new_callable=AsyncMock,
            return_value=1,
        ) as mock_core:
            result = await DomclobberingScanner().run_scan(
                target="https://example.com",
                categories=[],
                timeout=10,
                output_file=None,
            )
        assert result == 1
        mock_core.assert_called_once()

    def test_print_results(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = ClobberResult(
            target="t",
            tls=True,
            baseline_status=200,
            baseline_size=10,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="unknown",
        )
        DomclobberingScanner().print_results(result)
        out = capsys.readouterr().out
        assert "DOM Clobbering" in out

    def test_example(self) -> None:
        assert "named_access" in DomclobberingScanner()._example()

    def test_help(self) -> None:
        assert "headless" in DomclobberingScanner()._help()


# ─── Banner / Main Guard ─────────────────────────────────────────────────────
class TestBannerArt:
    def test_runs(self, capsys: pytest.CaptureFixture[str]) -> None:
        DomclobberingScanner.__dict__["banner_fn"]()
        out = capsys.readouterr().out
        assert "domclobbering" in out


class TestMainGuard:
    def test_guard_runs(self) -> None:
        import runpy

        with (
            patch("mytools.core.base.run_main_loop", side_effect=SystemExit(0)),
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.web.domclobbering", run_name="__main__")
