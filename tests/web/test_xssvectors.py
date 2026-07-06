#!/usr/bin/env python3
"""Testes unitarios do modulo XSS Vectors."""
from __future__ import annotations

import pytest

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
    _inject_payload,
)

_TARGET = "https://example.com/page"


def test_category_map_has_eight_categories() -> None:
    assert len(_CATEGORY_MAP) == 8


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {
        "media_events", "uri_javascript", "uri_data",
        "iframe_vectors", "base_redirect", "custom_elements",
        "shadow_dom", "slot_use",
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
        _MEDIA_PAYLOADS + _URI_JS_PAYLOADS + _URI_DATA_PAYLOADS
        + _IFRAME_PAYLOADS + _BASE_PAYLOADS + _CUSTOM_ELEMENT_PAYLOADS
        + _SHADOW_DOM_PAYLOADS + _SLOT_USE_PAYLOADS
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
    body = '<div><script>alert(1)</script></div>'
    assert _check_xss_reflection(body, "<script>alert(1)</script>") is True


def test_check_xss_reflection_case_insensitive() -> None:
    body = '<SCRIPT>alert(1)</SCRIPT>'
    assert _check_xss_reflection(body, "<script>alert(1)</script>") is True


def test_check_xss_reflection_false() -> None:
    body = '<div>safe content</div>'
    assert _check_xss_reflection(body, "<script>alert(1)</script>") is False


def test_attempt_dataclass_frozen() -> None:
    a = XSSVectorAttempt(
        technique="test", category="media_events",
        context="test_ctx", payload="p", method="GET",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=110,
        status_changed=False, size_changed=True,
        vulnerable=True, details="test", error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False


def test_attempt_dataclass_slots() -> None:
    a = XSSVectorAttempt(
        technique="test", category="media_events",
        context="test_ctx", payload="p", method="GET",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=110,
        status_changed=False, size_changed=True,
        vulnerable=True, details="test", error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = XSSVectorResult(
        target=_TARGET, tls=True,
        baseline_status=200, baseline_size=100,
        attempts=[], vulnerable_techniques=[],
        blocked_techniques=[], issues=[],
        overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"


def test_result_dataclass_slots() -> None:
    r = XSSVectorResult(
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
        _MEDIA_PAYLOADS, _URI_JS_PAYLOADS, _URI_DATA_PAYLOADS,
        _IFRAME_PAYLOADS, _BASE_PAYLOADS, _CUSTOM_ELEMENT_PAYLOADS,
        _SHADOW_DOM_PAYLOADS, _SLOT_USE_PAYLOADS,
    ):
        for p in lst:
            all_names.append(p[0])
    assert len(all_names) == len(set(all_names))


def test_all_payloads_have_indicators() -> None:
    all_lists = (
        _MEDIA_PAYLOADS + _URI_JS_PAYLOADS + _URI_DATA_PAYLOADS
        + _IFRAME_PAYLOADS + _BASE_PAYLOADS + _CUSTOM_ELEMENT_PAYLOADS
        + _SHADOW_DOM_PAYLOADS + _SLOT_USE_PAYLOADS
    )
    for p in all_lists:
        assert len(p[3]) >= 1, f"Payload {p[0]} must have at least 1 indicator"
