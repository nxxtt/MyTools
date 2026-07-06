#!/usr/bin/env python3
"""Testes unitarios do modulo OAuth 2.0 Misconfiguration."""
from __future__ import annotations

import pytest

from mytools.web.oauth import (
    _CATEGORY_MAP,
    _REDIRECT_BYPASS_PAYLOADS,
    _WEAK_SECRETS,
    OAuthAttempt,
    OAuthResult,
    _check_response_indicators,
    _find_authorize_url,
)

_TARGET = "https://example.com/authorize"


def test_category_map_has_five_categories() -> None:
    assert len(_CATEGORY_MAP) == 5


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {
        "misconfig", "scope_escalation", "redirect_uri",
        "pkce_bypass", "refresh_token",
    }


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 27


def test_misconfig_techniques_count() -> None:
    assert len(_CATEGORY_MAP["misconfig"]) == 6


def test_scope_escalation_techniques_count() -> None:
    assert len(_CATEGORY_MAP["scope_escalation"]) == 5


def test_redirect_uri_techniques_count() -> None:
    assert len(_CATEGORY_MAP["redirect_uri"]) == 7


def test_pkce_bypass_techniques_count() -> None:
    assert len(_CATEGORY_MAP["pkce_bypass"]) == 4


def test_refresh_token_techniques_count() -> None:
    assert len(_CATEGORY_MAP["refresh_token"]) == 5


def test_weak_secrets_count() -> None:
    assert len(_WEAK_SECRETS) >= 10


def test_redirect_bypass_payloads_count() -> None:
    assert len(_REDIRECT_BYPASS_PAYLOADS) == 7


def test_redirect_bypass_payloads_have_three_elements() -> None:
    for p in _REDIRECT_BYPASS_PAYLOADS:
        assert len(p) == 3, f"Payload {p[0]} should have 3 elements"


def test_find_authorize_url_with_link() -> None:
    body = '<a href="/oauth/authorize?client_id=123">Login</a>'
    result = _find_authorize_url("https://example.com", body)
    assert result is not None
    assert "authorize" in result


def test_find_authorize_url_with_action() -> None:
    body = '<form action="/auth/login">'
    result = _find_authorize_url("https://example.com", body)
    assert result is not None


def test_find_authorize_url_not_found() -> None:
    body = '<html><body>Safe page</body></html>'
    result = _find_authorize_url("https://example.com", body)
    assert result is None


def test_check_response_indicators_true() -> None:
    body = '<div>You are being redirected to the authorization page</div>'
    assert _check_response_indicators(body, ["redirect", "authorize"]) is True


def test_check_response_indicators_false() -> None:
    body = '<div>Safe content</div>'
    assert _check_response_indicators(body, ["authorize"]) is False


def test_check_response_indicators_case_insensitive() -> None:
    body = '<div>AUTHORIZE Page</div>'
    assert _check_response_indicators(body, ["authorize"]) is True


def test_attempt_dataclass_frozen() -> None:
    a = OAuthAttempt(
        technique="test", category="misconfig",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=100,
        status_changed=False, size_changed=False,
        vulnerable=True, details="test", error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False


def test_attempt_dataclass_slots() -> None:
    a = OAuthAttempt(
        technique="test", category="misconfig",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=100,
        status_changed=False, size_changed=False,
        vulnerable=True, details="test", error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = OAuthResult(
        target=_TARGET, tls=True,
        baseline_status=200, baseline_size=100,
        authorize_url=None, attempts=[],
        vulnerable_techniques=[], blocked_techniques=[],
        issues=[], overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"


def test_result_dataclass_slots() -> None:
    r = OAuthResult(
        target=_TARGET, tls=True,
        baseline_status=200, baseline_size=100,
        authorize_url=None, attempts=[],
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
