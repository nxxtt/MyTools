#!/usr/bin/env python3
"""Testes unitarios do modulo CSS Injection."""
from __future__ import annotations

import pytest

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
    _detect_css_contexts,
    _inject_payload,
)

_TARGET = "https://example.com/page"


def test_category_map_has_six_categories() -> None:
    assert len(_CATEGORY_MAP) == 6


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {
        "injection_points", "data_extraction", "attribute_leak",
        "selector_abuse", "token_exfil", "csp_bypass",
    }


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 36


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
    assert len(_CSP_BYPASS_PAYLOADS) == 5


def test_all_payloads_have_four_elements() -> None:
    all_lists = (
        _INJECTION_PAYLOADS + _DATA_EXTRACTION_PAYLOADS
        + _ATTRIBUTE_LEAK_PAYLOADS + _SELECTOR_ABUSE_PAYLOADS
        + _TOKEN_EXFIL_PAYLOADS + _CSP_BYPASS_PAYLOADS
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
        technique="test", category="injection_points",
        context="test_ctx", payload="p", method="GET",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=110,
        status_changed=False, size_changed=True,
        csp_blocks_css=False, vulnerable=True,
        details="test", error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False


def test_attempt_dataclass_slots() -> None:
    a = CSSInjectAttempt(
        technique="test", category="injection_points",
        context="test_ctx", payload="p", method="GET",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=110,
        status_changed=False, size_changed=True,
        csp_blocks_css=False, vulnerable=True,
        details="test", error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = CSSInjectResult(
        target=_TARGET, tls=True,
        baseline_status=200, baseline_size=100,
        attempts=[], vulnerable_techniques=[],
        blocked_techniques=[], issues=[],
        overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"


def test_result_dataclass_slots() -> None:
    r = CSSInjectResult(
        target=_TARGET, tls=True,
        baseline_status=200, baseline_size=100,
        attempts=[], vulnerable_techniques=[],
        blocked_techniques=[], issues=[],
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
        _INJECTION_PAYLOADS, _DATA_EXTRACTION_PAYLOADS,
        _ATTRIBUTE_LEAK_PAYLOADS, _SELECTOR_ABUSE_PAYLOADS,
        _TOKEN_EXFIL_PAYLOADS, _CSP_BYPASS_PAYLOADS,
    ):
        for p in lst:
            all_names.append(p[0])
    assert len(all_names) == len(set(all_names))


def test_all_payloads_have_indicators() -> None:
    all_lists = (
        _INJECTION_PAYLOADS + _DATA_EXTRACTION_PAYLOADS
        + _ATTRIBUTE_LEAK_PAYLOADS + _SELECTOR_ABUSE_PAYLOADS
        + _TOKEN_EXFIL_PAYLOADS + _CSP_BYPASS_PAYLOADS
    )
    for p in all_lists:
        assert len(p[3]) >= 1, f"Payload {p[0]} must have at least 1 indicator"
