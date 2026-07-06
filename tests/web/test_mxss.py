#!/usr/bin/env python3
"""Testes unitarios do modulo Mutation XSS."""
from __future__ import annotations

import pytest

from mytools.web.mxss import (
    _CATEGORY_MAP,
    _COMMENT_PAYLOADS,
    _ENCODING_PAYLOADS,
    _ENTITY_PAYLOADS,
    _MATHML_PAYLOADS,
    _NAMESPACE_PAYLOADS,
    _RAWTEXT_PAYLOADS,
    _TEMPLATE_PAYLOADS,
    MXSSAttempt,
    MXSSResult,
    _check_mxss_reflection,
    _detect_entity_decoding,
    _detect_namespace_contexts,
    _inject_payload,
)

_TARGET = "https://example.com/page"


def test_category_map_has_seven_categories() -> None:
    assert len(_CATEGORY_MAP) == 7


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {
        "entity_decode", "namespace_switch", "mathml_inject",
        "rawtext_abuse", "comment_parse", "template_deprecated",
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
        _ENTITY_PAYLOADS + _NAMESPACE_PAYLOADS + _MATHML_PAYLOADS
        + _RAWTEXT_PAYLOADS + _COMMENT_PAYLOADS + _TEMPLATE_PAYLOADS
        + _ENCODING_PAYLOADS
    )
    for p in all_lists:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_all_category_map_keys_match_payload_lists() -> None:
    expected = {
        "entity_decode", "namespace_switch", "mathml_inject",
        "rawtext_abuse", "comment_parse", "template_deprecated",
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
    body = '<div>&lt;script&gt;alert(1)&lt;/script&gt;</div>'
    assert _check_mxss_reflection(body, "&lt;script&gt;alert(1)&lt;/script&gt;") is True


def test_check_mxss_reflection_case_insensitive() -> None:
    body = '<SCRIPT>alert(1)</SCRIPT>'
    assert _check_mxss_reflection(body, "<script>alert(1)</script>") is True


def test_check_mxss_reflection_false() -> None:
    body = '<div>safe content</div>'
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
    ctxs = _detect_namespace_contexts('<svg><foreignObject><div></div></foreignObject></svg>')
    assert "svg" in ctxs
    assert "svg_foreignobject" in ctxs


def test_detect_namespace_contexts_mathml() -> None:
    ctxs = _detect_namespace_contexts('<math><annotation-xml encoding="text/html"></annotation-xml></math>')
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
        technique="test", category="entity_decode",
        context="test_ctx", payload="p", method="GET",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=110,
        status_changed=False, size_changed=True,
        entities_decoded=True, decoded_reflected=True,
        namespace_contexts=["svg"], vulnerable=True,
        details="test", error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False


def test_attempt_dataclass_slots() -> None:
    a = MXSSAttempt(
        technique="test", category="entity_decode",
        context="test_ctx", payload="p", method="GET",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=110,
        status_changed=False, size_changed=True,
        entities_decoded=True, decoded_reflected=True,
        namespace_contexts=["svg"], vulnerable=True,
        details="test", error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = MXSSResult(
        target=_TARGET, tls=True,
        baseline_status=200, baseline_size=100,
        attempts=[], vulnerable_techniques=[],
        blocked_techniques=[], issues=[],
        overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"


def test_result_dataclass_slots() -> None:
    r = MXSSResult(
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
        _ENTITY_PAYLOADS, _NAMESPACE_PAYLOADS, _MATHML_PAYLOADS,
        _RAWTEXT_PAYLOADS, _COMMENT_PAYLOADS, _TEMPLATE_PAYLOADS,
        _ENCODING_PAYLOADS,
    ):
        for p in lst:
            all_names.append(p[0])
    assert len(all_names) == len(set(all_names))


def test_all_payloads_have_indicators() -> None:
    all_lists = (
        _ENTITY_PAYLOADS + _NAMESPACE_PAYLOADS + _MATHML_PAYLOADS
        + _RAWTEXT_PAYLOADS + _COMMENT_PAYLOADS + _TEMPLATE_PAYLOADS
        + _ENCODING_PAYLOADS
    )
    for p in all_lists:
        assert len(p[3]) >= 1, f"Payload {p[0]} must have at least 1 indicator"
