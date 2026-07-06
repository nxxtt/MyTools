#!/usr/bin/env python3
"""Testes unitarios do modulo JWT Analysis."""
from __future__ import annotations

import time

import jwt
import pytest

from mytools.web.jwtanalysis import (
    _CATEGORY_MAP,
    _COMMON_SECRETS,
    CATEGORY_TESTERS,
    JWTAnalysisAttempt,
    JWTAnalysisResult,
    _decode_jwt_header,
    _decode_jwt_payload,
    _forge_token_hs256,
    _forge_token_none,
    _forge_token_with_header,
    _split_token,
)

_TOKEN_HS256 = jwt.encode({"sub": "1234", "role": "user", "exp": int(time.time()) + 3600}, "secret", algorithm="HS256")
_TOKEN_EXPIRED = jwt.encode({"sub": "1234", "exp": int(time.time()) - 100}, "secret", algorithm="HS256")
_TOKEN_NONE = jwt.encode({"sub": "1234"}, "", algorithm="none")


def test_category_map_has_six_categories() -> None:
    assert len(_CATEGORY_MAP) == 6


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {
        "weak_algorithm", "signature_bypass", "expiration",
        "claims", "header_injection", "replay",
    }


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 27


def test_weak_algorithm_techniques_count() -> None:
    assert len(_CATEGORY_MAP["weak_algorithm"]) == 5


def test_signature_bypass_techniques_count() -> None:
    assert len(_CATEGORY_MAP["signature_bypass"]) == 4


def test_expiration_techniques_count() -> None:
    assert len(_CATEGORY_MAP["expiration"]) == 4


def test_claims_techniques_count() -> None:
    assert len(_CATEGORY_MAP["claims"]) == 5


def test_header_injection_techniques_count() -> None:
    assert len(_CATEGORY_MAP["header_injection"]) == 5


def test_replay_techniques_count() -> None:
    assert len(_CATEGORY_MAP["replay"]) == 4


def test_common_secrets_count() -> None:
    assert len(_COMMON_SECRETS) >= 90


def test_decode_jwt_header_valid() -> None:
    header = _decode_jwt_header(_TOKEN_HS256)
    assert header is not None
    assert header["alg"] == "HS256"
    assert header["typ"] == "JWT"


def test_decode_jwt_header_invalid() -> None:
    assert _decode_jwt_header("not-a-jwt") is None


def test_decode_jwt_payload_valid() -> None:
    payload = _decode_jwt_payload(_TOKEN_HS256)
    assert payload is not None
    assert payload["sub"] == "1234"
    assert payload["role"] == "user"


def test_decode_jwt_payload_expired() -> None:
    payload = _decode_jwt_payload(_TOKEN_EXPIRED)
    assert payload is not None
    assert payload["sub"] == "1234"


def test_decode_jwt_payload_invalid() -> None:
    assert _decode_jwt_payload("not-a-jwt") is None


def test_decode_jwt_payload_none_algorithm() -> None:
    payload = _decode_jwt_payload(_TOKEN_NONE)
    assert payload is not None
    assert payload["sub"] == "1234"


def test_split_token_valid() -> None:
    h, p, s = _split_token(_TOKEN_HS256)
    assert h != ""
    assert p != ""
    assert s != ""


def test_split_token_invalid() -> None:
    h, p, s = _split_token("not-a-jwt")
    assert h == ""
    assert p == ""
    assert s == ""


def test_forge_token_none() -> None:
    token = _forge_token_none({"sub": "admin"})
    header = _decode_jwt_header(token)
    assert header is not None
    assert header["alg"] == "none"


def test_forge_token_hs256() -> None:
    token = _forge_token_hs256({"sub": "admin"}, "secret123")
    payload = _decode_jwt_payload(token)
    assert payload is not None
    assert payload["sub"] == "admin"


def test_forge_token_with_header() -> None:
    token = _forge_token_with_header(
        {"sub": "admin"}, "secret123", {"kid": "../../dev/null"},
    )
    header = _decode_jwt_header(token)
    assert header is not None
    assert header["kid"] == "../../dev/null"


def test_attempt_dataclass_frozen() -> None:
    a = JWTAnalysisAttempt(
        technique="test", category="weak_algorithm",
        vulnerable=True, details="test", error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False


def test_attempt_dataclass_slots() -> None:
    a = JWTAnalysisAttempt(
        technique="test", category="weak_algorithm",
        vulnerable=True, details="test", error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = JWTAnalysisResult(
        target=None, token_valid=True,
        header={"alg": "HS256"}, payload={"sub": "1234"},
        algorithm="HS256",
        attempts=[], vulnerable_techniques=[],
        issues=[], overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"


def test_result_dataclass_slots() -> None:
    r = JWTAnalysisResult(
        target=None, token_valid=True,
        header={"alg": "HS256"}, payload={"sub": "1234"},
        algorithm="HS256",
        attempts=[], vulnerable_techniques=[],
        issues=[], overall_status="safe",
    )
    assert not hasattr(r, "__dict__")


def test_no_duplicate_technique_names() -> None:
    all_techniques: list[str] = []
    for techs in _CATEGORY_MAP.values():
        all_techniques.extend(techs)
    assert len(all_techniques) == len(set(all_techniques))


def test_category_testers_has_six_keys() -> None:
    assert len(CATEGORY_TESTERS) == 6


def test_category_testers_keys_match_map() -> None:
    assert CATEGORY_TESTERS.keys() == _CATEGORY_MAP.keys()


def test_all_techniques_are_strings() -> None:
    for cat, techs in _CATEGORY_MAP.items():
        for t in techs:
            assert isinstance(t, str), f"{cat}/{t} is not a string"
