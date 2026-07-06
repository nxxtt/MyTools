#!/usr/bin/env python3
"""Testes unitarios do modulo Account Abuse Attack Detection."""
from __future__ import annotations

import pytest

from mytools.web.accountabuse import (
    _CATEGORY_MAP,
    _COUPON_PAYLOADS,
    _GIFT_CARD_PAYLOADS,
    _LOYALTY_PAYLOADS,
    _REFUND_PAYLOADS,
    _SUBSCRIPTION_PAYLOADS,
    AccountAttempt,
    AccountResult,
    _find_account_url,
)

_TARGET = "https://example.com/account"


def test_category_map_has_five_categories() -> None:
    assert len(_CATEGORY_MAP) == 5


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {
        "coupon", "loyalty_points", "gift_card", "refund", "subscription",
    }


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 25


def test_coupon_techniques_count() -> None:
    assert len(_CATEGORY_MAP["coupon"]) == 5


def test_loyalty_points_techniques_count() -> None:
    assert len(_CATEGORY_MAP["loyalty_points"]) == 5


def test_gift_card_techniques_count() -> None:
    assert len(_CATEGORY_MAP["gift_card"]) == 5


def test_refund_techniques_count() -> None:
    assert len(_CATEGORY_MAP["refund"]) == 5


def test_subscription_techniques_count() -> None:
    assert len(_CATEGORY_MAP["subscription"]) == 5


def test_coupon_payloads_count() -> None:
    assert len(_COUPON_PAYLOADS) == 5


def test_loyalty_payloads_count() -> None:
    assert len(_LOYALTY_PAYLOADS) == 5


def test_gift_card_payloads_count() -> None:
    assert len(_GIFT_CARD_PAYLOADS) == 5


def test_refund_payloads_count() -> None:
    assert len(_REFUND_PAYLOADS) == 5


def test_subscription_payloads_count() -> None:
    assert len(_SUBSCRIPTION_PAYLOADS) == 5


def test_coupon_payloads_have_four_elements() -> None:
    for p in _COUPON_PAYLOADS:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_loyalty_payloads_have_four_elements() -> None:
    for p in _LOYALTY_PAYLOADS:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_gift_card_payloads_have_four_elements() -> None:
    for p in _GIFT_CARD_PAYLOADS:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_refund_payloads_have_four_elements() -> None:
    for p in _REFUND_PAYLOADS:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_subscription_payloads_have_four_elements() -> None:
    for p in _SUBSCRIPTION_PAYLOADS:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_find_account_url_with_coupon() -> None:
    body = '<a href="/coupon/redeem">Resgatar cupom</a>'
    result = _find_account_url("https://example.com", body)
    assert result is not None
    assert "coupon" in result


def test_find_account_url_with_gift_card() -> None:
    body = '<a href="/gift-card/check">Verificar gift card</a>'
    result = _find_account_url("https://example.com", body)
    assert result is not None
    assert "gift" in result.lower()


def test_find_account_url_with_subscription() -> None:
    body = '<a href="/subscription/manage">Gerenciar assinatura</a>'
    result = _find_account_url("https://example.com", body)
    assert result is not None
    assert "subscription" in result


def test_find_account_url_not_found() -> None:
    body = '<html><body>Safe page</body></html>'
    result = _find_account_url("https://example.com", body)
    assert result is None


def test_attempt_dataclass_frozen() -> None:
    a = AccountAttempt(
        technique="test", category="coupon",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=100,
        status_changed=False, size_changed=False,
        vulnerable=True, details="test", error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False


def test_attempt_dataclass_slots() -> None:
    a = AccountAttempt(
        technique="test", category="coupon",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=100,
        status_changed=False, size_changed=False,
        vulnerable=True, details="test", error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = AccountResult(
        target=_TARGET, tls=True,
        baseline_status=200, baseline_size=100,
        account_url=None, attempts=[],
        vulnerable_techniques=[], blocked_techniques=[],
        issues=[], overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"


def test_result_dataclass_slots() -> None:
    r = AccountResult(
        target=_TARGET, tls=True,
        baseline_status=200, baseline_size=100,
        account_url=None, attempts=[],
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
