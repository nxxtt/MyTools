#!/usr/bin/env python3
"""Testes unitarios do modulo OIDC Attack Detection."""
from __future__ import annotations

import pytest

from mytools.web.oidc import (
    _CATEGORY_MAP,
    OIDCAttempt,
    OIDCResult,
    _extract_well_known_url,
    _parse_json_response,
)

_TARGET = "https://example.com"


def test_category_map_has_two_categories() -> None:
    assert len(_CATEGORY_MAP) == 2


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {"discovery", "token_substitution"}


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 10


def test_discovery_techniques_count() -> None:
    assert len(_CATEGORY_MAP["discovery"]) == 5


def test_token_substitution_techniques_count() -> None:
    assert len(_CATEGORY_MAP["token_substitution"]) == 5


def test_extract_well_known_url_with_path() -> None:
    result = _extract_well_known_url("https://example.com/authorize")
    assert result == "https://example.com"


def test_extract_well_known_url_without_path() -> None:
    result = _extract_well_known_url("https://example.com")
    assert result == "https://example.com"


def test_extract_well_known_url_with_port() -> None:
    result = _extract_well_known_url("https://example.com:8443/auth")
    assert result == "https://example.com:8443"


def test_parse_json_response_valid() -> None:
    data = _parse_json_response('{"issuer": "https://example.com"}')
    assert data is not None
    assert data["issuer"] == "https://example.com"


def test_parse_json_response_invalid() -> None:
    assert _parse_json_response("not json") is None


def test_parse_json_response_array() -> None:
    assert _parse_json_response("[1, 2, 3]") is None


def test_parse_json_response_empty() -> None:
    assert _parse_json_response("") is None


def test_attempt_dataclass_frozen() -> None:
    a = OIDCAttempt(
        technique="test", category="discovery",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=100,
        status_changed=False, size_changed=False,
        vulnerable=True, details="test", error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False


def test_attempt_dataclass_slots() -> None:
    a = OIDCAttempt(
        technique="test", category="discovery",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=100,
        status_changed=False, size_changed=False,
        vulnerable=True, details="test", error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = OIDCResult(
        target=_TARGET, tls=True,
        baseline_status=200, baseline_size=100,
        well_known_url=None, well_known_data=None,
        attempts=[], vulnerable_techniques=[],
        blocked_techniques=[], issues=[],
        overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"


def test_result_dataclass_slots() -> None:
    r = OIDCResult(
        target=_TARGET, tls=True,
        baseline_status=200, baseline_size=100,
        well_known_url=None, well_known_data=None,
        attempts=[], vulnerable_techniques=[],
        blocked_techniques=[], issues=[],
        overall_status="safe",
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
