#!/usr/bin/env python3
"""Testes unitarios do modulo Business Logic Attack Detection."""
from __future__ import annotations

import pytest

from mytools.web.businesslogic import (
    _CATEGORY_MAP,
    _NEGATIVE_QTY_PAYLOADS,
    _OVERFLOW_PAYLOADS,
    BizLogicAttempt,
    BizLogicResult,
    _find_checkout_url,
)

_TARGET = "https://example.com/checkout"


def test_category_map_has_three_categories() -> None:
    assert len(_CATEGORY_MAP) == 3


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {
        "integer_overflow", "negative_quantity", "race_condition",
    }


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 15


def test_integer_overflow_techniques_count() -> None:
    assert len(_CATEGORY_MAP["integer_overflow"]) == 5


def test_negative_quantity_techniques_count() -> None:
    assert len(_CATEGORY_MAP["negative_quantity"]) == 5


def test_race_condition_techniques_count() -> None:
    assert len(_CATEGORY_MAP["race_condition"]) == 5


def test_overflow_payloads_count() -> None:
    assert len(_OVERFLOW_PAYLOADS) == 5


def test_negative_qty_payloads_count() -> None:
    assert len(_NEGATIVE_QTY_PAYLOADS) == 5


def test_overflow_payloads_have_four_elements() -> None:
    for p in _OVERFLOW_PAYLOADS:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_negative_qty_payloads_have_four_elements() -> None:
    for p in _NEGATIVE_QTY_PAYLOADS:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_find_checkout_url_with_link() -> None:
    body = '<a href="/checkout">Finalizar compra</a>'
    result = _find_checkout_url("https://example.com", body)
    assert result is not None
    assert "checkout" in result


def test_find_checkout_url_with_action() -> None:
    body = '<form action="/payment/process">'
    result = _find_checkout_url("https://example.com", body)
    assert result is not None


def test_find_checkout_url_not_found() -> None:
    body = '<html><body>Safe page</body></html>'
    result = _find_checkout_url("https://example.com", body)
    assert result is None


def test_attempt_dataclass_frozen() -> None:
    a = BizLogicAttempt(
        technique="test", category="integer_overflow",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=100,
        status_changed=False, size_changed=False,
        vulnerable=True, details="test", error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False


def test_attempt_dataclass_slots() -> None:
    a = BizLogicAttempt(
        technique="test", category="integer_overflow",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=100,
        status_changed=False, size_changed=False,
        vulnerable=True, details="test", error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = BizLogicResult(
        target=_TARGET, tls=True,
        baseline_status=200, baseline_size=100,
        checkout_url=None, attempts=[],
        vulnerable_techniques=[], blocked_techniques=[],
        issues=[], overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"


def test_result_dataclass_slots() -> None:
    r = BizLogicResult(
        target=_TARGET, tls=True,
        baseline_status=200, baseline_size=100,
        checkout_url=None, attempts=[],
        vulnerable_techniques=[], blocked_techniques=[],
        issues=[], overall_status="safe",
    )
    assert not hasattr(r, "__dict__")


def test_no_duplicate_technique_names() -> None:
    all_techniques: list[str] = []
    for techs in _CATEGORY_MAP.values():
        all_techniques.extend(techs)
    assert len(all_techniques) == len(set(all_techniques))


def test_all_techniques_are_strings() -> None:
    for cat, techs in _CATEGORY_MAP.items():
        for t in techs:
            assert isinstance(t, str), f"{cat}/{t} is not a string"
