#!/usr/bin/env python3
"""Testes unitarios do modulo de DOM Clobbering."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.domclobbering import (
    _CATEGORY_MAP,
    _DOCUMENT_CLOBBERABLE,
    _FORM_CHILD_PAYLOADS,
    _IMPACT_PAYLOADS,
    _NAMED_ACCESS_PAYLOADS,
    _WINDOW_CLOBBERABLE,
    _check_clobber_in_html,
    _detect_passive_clobbering,
    _inject_payload,
    build_parser,
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
        html = '<html><body>Hello world</body></html>'
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
        html = '''
        <html><body>
        <a id="config" href="/p1"></a>
        <div id="settings"></div>
        <form name="document"></form>
        </body></html>
        '''
        result = _detect_passive_clobbering(html)
        assert len(result) >= 2


# ─── Named Access Tests ─────────────────────────────────────────────────────
class TestNamedAccess:
    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=Exception("Connection refused"))
        from mytools.web.domclobbering import _test_named_access
        result = await _test_named_access(client, "https://target.com", 10.0)
        assert len(result) > 0
        assert any(a.error for a in result)

    @pytest.mark.asyncio
    @patch("mytools.web.domclobbering.fetch")
    async def test_reflected_payload(self, mock_fetch: MagicMock) -> None:
        mock_fetch.return_value = (200, {}, b'<a id="config" href="javascript:void(0)">', {})
        client = AsyncMock()
        from mytools.web.domclobbering import _test_named_access
        result = await _test_named_access(client, "https://target.com?q=test", 10.0)
        assert len(result) > 0


# ─── Form Child Tests ────────────────────────────────────────────────────────
class TestFormChild:
    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=Exception("Connection refused"))
        from mytools.web.domclobbering import _test_form_child
        result = await _test_form_child(client, "https://target.com", 10.0)
        assert len(result) > 0
        assert any(a.error for a in result)


# ─── Impact Tests ────────────────────────────────────────────────────────────
class TestImpact:
    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=Exception("Connection refused"))
        from mytools.web.domclobbering import _test_impact_chains
        result = await _test_impact_chains(client, "https://target.com", 10.0)
        assert len(result) > 0
        assert any(a.error for a in result)


# ─── Dataclasses ─────────────────────────────────────────────────────────────
class TestDataclasses:
    def test_clobber_attempt_frozen(self) -> None:
        from mytools.web.domclobbering import ClobberAttempt
        a = ClobberAttempt(
            technique="t", category="c", payload="p", target_element="e",
            attribute_used="a", method="GET", status_baseline=200,
            status_test=200, size_baseline=100, size_test=100,
            status_changed=False, size_changed=False, vulnerable=False,
            details="", error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "new"  # type: ignore[misc]

    def test_clobber_attempt_slots(self) -> None:
        from mytools.web.domclobbering import ClobberAttempt
        a = ClobberAttempt(
            technique="t", category="c", payload="p", target_element="e",
            attribute_used="a", method="GET", status_baseline=200,
            status_test=200, size_baseline=100, size_test=100,
            status_changed=False, size_changed=False, vulnerable=False,
            details="", error="",
        )
        assert not hasattr(a, "__dict__")

    def test_clobber_result_frozen(self) -> None:
        from mytools.web.domclobbering import ClobberResult
        r = ClobberResult(
            target="t", tls=True, baseline_status=200, baseline_size=100,
            attempts=[], vulnerable_techniques=[], blocked_techniques=[],
            issues=[], overall_status="unknown",
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
