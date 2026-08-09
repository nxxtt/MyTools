#!/usr/bin/env python3
"""Testes unitarios do modulo Mutation XSS."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch
from urllib.parse import parse_qs, urlparse

import httpx
import pytest
import respx

from mytools.web.mxss import (
    _ALL_PAYLOADS,
    _CATEGORY_MAP,
    _COMMENT_PAYLOADS,
    _ENCODING_PAYLOADS,
    _ENTITY_PAYLOADS,
    _MATHML_PAYLOADS,
    _NAMESPACE_PAYLOADS,
    _RAWTEXT_PAYLOADS,
    _TEMPLATE_PAYLOADS,
    MXScanner,
    MXSSAttempt,
    MXSSResult,
    _check_mxss_reflection,
    _confirm_headless_active_urls,
    _detect_entity_decoding,
    _detect_namespace_contexts,
    _inject_payload,
    _run_scan_core,
    _test_mxss_category,
    build_parser,
    print_results,
)

_TARGET = "https://example.com/page"


def _mxss_attempt(
    *,
    technique: str = "entity_script_basic",
    category: str = "entity_decode",
    context: str = "entity_decode",
    vulnerable: bool = False,
    entities_decoded: bool = False,
    namespace_contexts: list[str] | None = None,
    details: str = "",
    error: str = "",
    dom_confirmed: bool = False,
    test_url: str = "",
) -> MXSSAttempt:
    return MXSSAttempt(
        technique=technique,
        category=category,
        context=context,
        payload="p",
        method="GET",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=100,
        status_changed=False,
        size_changed=False,
        entities_decoded=entities_decoded,
        decoded_reflected=False,
        namespace_contexts=namespace_contexts or [],
        vulnerable=vulnerable,
        details=details,
        error=error,
        exploit="mutation_xss_payload",
        tool="XSStrike",
        test_url=test_url,
        dom_confirmed=dom_confirmed,
    )


def _reflect_mxss_handler(request: httpx.Request) -> httpx.Response:
    params = parse_qs(urlparse(str(request.url)).query)
    for key, values in params.items():
        if key.startswith("_mxss_"):
            return httpx.Response(200, text=values[0])
    return httpx.Response(200, text="<html><body>safe</body></html>")


def _active_side_effect(url: str, *args: object, **kwargs: object) -> int:
    return 1 if url == "https://example.com" else 5


def test_category_map_has_seven_categories() -> None:
    assert len(_CATEGORY_MAP) == 7


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {
        "entity_decode",
        "namespace_switch",
        "mathml_inject",
        "rawtext_abuse",
        "comment_parse",
        "template_deprecated",
        "encoding_tricks",
    }


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 51


def test_entity_payloads_count() -> None:
    assert len(_ENTITY_PAYLOADS) == 8


def test_namespace_payloads_count() -> None:
    assert len(_NAMESPACE_PAYLOADS) == 8


def test_mathml_payloads_count() -> None:
    assert len(_MATHML_PAYLOADS) == 8


def test_rawtext_payloads_count() -> None:
    assert len(_RAWTEXT_PAYLOADS) == 9


def test_comment_payloads_count() -> None:
    assert len(_COMMENT_PAYLOADS) == 7


def test_template_payloads_count() -> None:
    assert len(_TEMPLATE_PAYLOADS) == 5


def test_encoding_payloads_count() -> None:
    assert len(_ENCODING_PAYLOADS) == 6


def test_all_payloads_have_four_elements() -> None:
    all_lists = (
        _ENTITY_PAYLOADS
        + _NAMESPACE_PAYLOADS
        + _MATHML_PAYLOADS
        + _RAWTEXT_PAYLOADS
        + _COMMENT_PAYLOADS
        + _TEMPLATE_PAYLOADS
        + _ENCODING_PAYLOADS
    )
    for p in all_lists:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_all_category_map_keys_match_payload_lists() -> None:
    expected = {
        "entity_decode",
        "namespace_switch",
        "mathml_inject",
        "rawtext_abuse",
        "comment_parse",
        "template_deprecated",
        "encoding_tricks",
    }
    assert _CATEGORY_MAP.keys() == expected


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


def test_check_mxss_reflection_true() -> None:
    body = "<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>"
    assert _check_mxss_reflection(body, "&lt;script&gt;alert(1)&lt;/script&gt;") is True


def test_check_mxss_reflection_case_insensitive() -> None:
    body = "<SCRIPT>alert(1)</SCRIPT>"
    assert _check_mxss_reflection(body, "<script>alert(1)</script>") is True


def test_check_mxss_reflection_false() -> None:
    body = "<div>safe content</div>"
    assert _check_mxss_reflection(body, "<script>alert(1)</script>") is False


def test_detect_entity_decoding_decoded() -> None:
    payload = "&lt;script&gt;alert(1)&lt;/script&gt;"
    result = _detect_entity_decoding("<script>alert(1)</script>", payload)
    assert result["entities_decoded"] is True
    assert result["decoded_reflected"] is True


def test_detect_entity_decoding_no_decoding() -> None:
    payload = "<script>alert(1)</script>"
    result = _detect_entity_decoding(payload, payload)
    assert result["entities_decoded"] is False
    assert result["decoded_reflected"] is True


def test_detect_namespace_contexts_svg() -> None:
    ctxs = _detect_namespace_contexts(
        "<svg><foreignObject><div></div></foreignObject></svg>"
    )
    assert "svg" in ctxs
    assert "svg_foreignobject" in ctxs


def test_detect_namespace_contexts_mathml() -> None:
    ctxs = _detect_namespace_contexts(
        '<math><annotation-xml encoding="text/html"></annotation-xml></math>'
    )
    assert "mathml" in ctxs
    assert "mathml_annotation_xml" in ctxs


def test_detect_namespace_contexts_none() -> None:
    ctxs = _detect_namespace_contexts("<div>safe</div>")
    assert ctxs == []


def test_detect_namespace_contexts_template() -> None:
    ctxs = _detect_namespace_contexts("<template></template>")
    assert "template" in ctxs


def test_detect_namespace_contexts_xmp() -> None:
    ctxs = _detect_namespace_contexts("<xmp>data</xmp>")
    assert "xmp_rawtext" in ctxs


def test_attempt_dataclass_frozen() -> None:
    a = MXSSAttempt(
        technique="test",
        category="entity_decode",
        context="test_ctx",
        payload="p",
        method="GET",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=110,
        status_changed=False,
        size_changed=True,
        entities_decoded=True,
        decoded_reflected=True,
        namespace_contexts=["svg"],
        vulnerable=True,
        details="test",
        error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False  # type: ignore[reportAttributeAccessIssue]


def test_attempt_dataclass_slots() -> None:
    a = MXSSAttempt(
        technique="test",
        category="entity_decode",
        context="test_ctx",
        payload="p",
        method="GET",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=110,
        status_changed=False,
        size_changed=True,
        entities_decoded=True,
        decoded_reflected=True,
        namespace_contexts=["svg"],
        vulnerable=True,
        details="test",
        error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = MXSSResult(
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
    r = MXSSResult(
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
        _ENTITY_PAYLOADS,
        _NAMESPACE_PAYLOADS,
        _MATHML_PAYLOADS,
        _RAWTEXT_PAYLOADS,
        _COMMENT_PAYLOADS,
        _TEMPLATE_PAYLOADS,
        _ENCODING_PAYLOADS,
    ):
        all_names.extend(p[0] for p in lst)
    assert len(all_names) == len(set(all_names))


def test_all_payloads_have_indicators() -> None:
    all_lists = (
        _ENTITY_PAYLOADS
        + _NAMESPACE_PAYLOADS
        + _MATHML_PAYLOADS
        + _RAWTEXT_PAYLOADS
        + _COMMENT_PAYLOADS
        + _TEMPLATE_PAYLOADS
        + _ENCODING_PAYLOADS
    )
    for p in all_lists:
        assert len(p[3]) >= 1, f"Payload {p[0]} must have at least 1 indicator"


def test_detect_namespace_contexts_extra_markers() -> None:
    ctxs = _detect_namespace_contexts(
        "<template></template><xmp>x</xmp><listing>l</listing>"
    )
    assert "template" in ctxs
    assert "xmp_rawtext" in ctxs
    assert "listing_rawtext" in ctxs


def test_all_payload_lists_registered() -> None:
    assert set(_ALL_PAYLOADS) == set(_CATEGORY_MAP)


# ─── Confirm Headless Active URLs ────────────────────────────────────────────
class TestConfirmHeadlessActiveUrls:
    @pytest.mark.asyncio
    async def test_confirms_active_urls(self) -> None:
        mock_evaluate = AsyncMock(side_effect=[1, 7])
        with patch("mytools.core.headless.evaluate", mock_evaluate):
            result = await _confirm_headless_active_urls(
                "https://example.com",
                ["https://example.com?a=1"],
                timeout=10,
                proxy=None,
            )
        assert result == {"https://example.com?a=1"}

    @pytest.mark.asyncio
    async def test_not_confirmed_when_count_lower(self) -> None:
        mock_evaluate = AsyncMock(side_effect=[9, 3])
        with patch("mytools.core.headless.evaluate", mock_evaluate):
            result = await _confirm_headless_active_urls(
                "https://example.com",
                ["https://example.com?a=1"],
                timeout=10,
                proxy=None,
            )
        assert result == set()

    @pytest.mark.asyncio
    async def test_baseline_error_returns_empty(self) -> None:
        mock_evaluate = AsyncMock(side_effect=RuntimeError("boom"))
        with patch("mytools.core.headless.evaluate", mock_evaluate):
            result = await _confirm_headless_active_urls(
                "https://example.com",
                ["https://example.com?a=1"],
                timeout=10,
                proxy=None,
            )
        assert result == set()

    @pytest.mark.asyncio
    async def test_url_error_continues(self) -> None:
        mock_evaluate = AsyncMock(side_effect=[1, RuntimeError("boom"), 5])
        with patch("mytools.core.headless.evaluate", mock_evaluate):
            result = await _confirm_headless_active_urls(
                "https://example.com",
                ["https://example.com?a=1", "https://example.com?b=2"],
                timeout=10,
                proxy=None,
            )
        assert result == {"https://example.com?b=2"}


# ─── Test MXSS Category ──────────────────────────────────────────────────────
class TestTestMxssCategory:
    @pytest.mark.asyncio
    @respx.mock
    async def test_reflected_entity_payloads(self) -> None:
        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=_reflect_mxss_handler
        )
        async with httpx.AsyncClient() as client:
            results = await _test_mxss_category(
                client,
                "https://example.com",
                10,
                200,
                4,
                _ENTITY_PAYLOADS,
                "entity_decode",
            )
        assert results
        assert any(a.vulnerable for a in results)
        assert any("Payload refletido" in a.details for a in results)

    @pytest.mark.asyncio
    @respx.mock
    async def test_namespace_contexts_detected(self) -> None:
        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=_reflect_mxss_handler
        )
        async with httpx.AsyncClient() as client:
            results = await _test_mxss_category(
                client,
                "https://example.com",
                10,
                200,
                4,
                _NAMESPACE_PAYLOADS,
                "namespace_switch",
            )
        assert any(a.namespace_contexts for a in results)
        assert any("contexts:" in a.details for a in results)

    @pytest.mark.asyncio
    @respx.mock
    async def test_decoded_reflected_details(self) -> None:
        import html as html_mod

        def handler(request: httpx.Request) -> httpx.Response:
            params = parse_qs(urlparse(str(request.url)).query)
            for key, values in params.items():
                if key.startswith("_mxss_"):
                    return httpx.Response(200, text=html_mod.unescape(values[0]))
            return httpx.Response(200, text="<html><body>safe</body></html>")

        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient() as client:
            results = await _test_mxss_category(
                client,
                "https://example.com",
                10,
                200,
                4,
                _ENTITY_PAYLOADS,
                "entity_decode",
            )
        assert any(a.decoded_reflected for a in results)
        assert any("Entidades decodificadas" in a.details for a in results)

    @pytest.mark.asyncio
    @respx.mock
    async def test_error_handled(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if "_mxss_" in str(request.url):
                raise httpx.ConnectError("boom")
            return httpx.Response(200, text="<html>base</html>")

        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=handler
        )
        async with httpx.AsyncClient() as client:
            results = await _test_mxss_category(
                client,
                "https://example.com",
                10,
                200,
                4,
                _ENTITY_PAYLOADS,
                "entity_decode",
            )
        assert results
        assert all(a.error for a in results)


# ─── Print Results ───────────────────────────────────────────────────────────
class TestPrintResults:
    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        a1 = _mxss_attempt(
            technique="entity_script_basic",
            category="entity_decode",
            context="entity_decode",
            vulnerable=True,
            entities_decoded=True,
            namespace_contexts=["svg"],
            details="Entidades decodificadas",
            dom_confirmed=True,
        )
        a2 = _mxss_attempt(
            technique="svg_script_direct",
            category="namespace_switch",
            context="svg_script",
            vulnerable=True,
        )
        a3 = _mxss_attempt(vulnerable=False)
        a4 = _mxss_attempt(vulnerable=False, error="boom")
        result = MXSSResult(
            target=_TARGET,
            tls=True,
            baseline_status=200,
            baseline_size=100,
            attempts=[a1, a1, a2, a3, a4],
            vulnerable_techniques=["entity_script_basic"],
            blocked_techniques=["entity_script_basic"],
            issues=["obs"],
            overall_status="vulnerable",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "DOM:       confirmado via headless" in out
        assert "Entidades: decodificadas" in out
        assert "Namespaces: svg" in out
        assert "Observacoes" in out
        assert "Total:" in out

    def test_safe(self, capsys: pytest.CaptureFixture[str]) -> None:
        a3 = _mxss_attempt(vulnerable=False)
        a4 = _mxss_attempt(vulnerable=False, error="boom")
        result = MXSSResult(
            target=_TARGET,
            tls=False,
            baseline_status=200,
            baseline_size=100,
            attempts=[a3, a4],
            vulnerable_techniques=[],
            blocked_techniques=["entity_script_basic"],
            issues=[],
            overall_status="safe",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Nenhuma vulnerabilidade de Mutation XSS detectada" in out
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
    async def test_vulnerable_entity(self) -> None:
        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=_reflect_mxss_handler
        )
        result = await _run_scan_core(
            "https://example.com", ["entity_decode"], 10, None
        )
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
        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=_reflect_mxss_handler
        )
        with patch("mytools.core.headless.browser_available", return_value=False):
            result = await _run_scan_core(
                "https://example.com", ["entity_decode"], 10, None, headless=True
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
        attempt = _mxss_attempt(
            technique="entity_script_basic",
            category="entity_decode",
            context="entity_decode",
            vulnerable=True,
            test_url="https://example.com?_mxss_entity_script_basic=%26lt%3Bscript%26gt%3B",
        )
        with (
            patch("mytools.core.headless.browser_available", return_value=True),
            patch(
                "mytools.core.headless.evaluate",
                new_callable=AsyncMock,
                side_effect=_active_side_effect,
            ),
            patch(
                "mytools.web.mxss._test_mxss_category",
                new_callable=AsyncMock,
                return_value=[attempt],
            ),
        ):
            result = await _run_scan_core(
                "https://example.com", ["entity_decode"], 10, None, headless=True
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
        attempt = _mxss_attempt(
            technique="entity_script_basic",
            category="entity_decode",
            context="entity_decode",
            vulnerable=True,
            details="x",
            test_url="https://example.com?y=1",
        )
        with (
            patch("mytools.core.headless.browser_available", return_value=True),
            patch(
                "mytools.core.headless.evaluate",
                new_callable=AsyncMock,
                side_effect=RuntimeError("boom"),
            ),
            patch(
                "mytools.web.mxss._test_mxss_category",
                new_callable=AsyncMock,
                return_value=[attempt],
            ),
        ):
            result = await _run_scan_core(
                "https://example.com", ["entity_decode"], 10, None, headless=True
            )
        assert result == 1


# ─── Parser / Scanner Class ──────────────────────────────────────────────────
class TestBuildParser:
    def test_has_url(self) -> None:
        args = build_parser().parse_args(["https://test.com"])
        assert args.url == "https://test.com"

    def test_default_category_all(self) -> None:
        args = build_parser().parse_args(["https://test.com"])
        assert args.category == "all"

    def test_category_choices(self) -> None:
        parser = build_parser()
        for cat in _CATEGORY_MAP:
            args = parser.parse_args(["https://test.com", "-c", cat])
            assert args.category == cat


class TestScannerClass:
    @pytest.mark.asyncio
    async def test_run_scan(self) -> None:
        with patch(
            "mytools.web.mxss._run_scan_core",
            new_callable=AsyncMock,
            return_value=0,
        ) as mock_core:
            result = await MXScanner().run_scan(
                target="https://example.com",
                categories=[],
                timeout=10,
                output_file=None,
            )
        assert result == 0
        mock_core.assert_called_once()

    def test_print_results(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = MXSSResult(
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
        MXScanner().print_results(result)
        out = capsys.readouterr().out
        assert "Mutation XSS" in out

    def test_example(self) -> None:
        assert "entity_decode" in MXScanner()._example()

    def test_help(self) -> None:
        assert "headless" in MXScanner()._help()


# ─── Banner / Main Guard ─────────────────────────────────────────────────────
class TestBannerArt:
    def test_runs(self, capsys: pytest.CaptureFixture[str]) -> None:
        MXScanner.__dict__["banner_fn"]()
        out = capsys.readouterr().out
        assert "mxss" in out


class TestMainGuard:
    def test_guard_runs(self) -> None:
        import runpy

        with (
            patch("mytools.core.base.run_main_loop", side_effect=SystemExit(0)),
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.web.mxss", run_name="__main__")
