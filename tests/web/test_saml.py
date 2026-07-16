#!/usr/bin/env python3
"""Testes unitarios do modulo SAML Attack Detection."""
from __future__ import annotations

import base64

import pytest

from mytools.web.saml import (
    _CATEGORY_MAP,
    SAMLAttempt,
    SAMLResult,
    _decode_saml_response,
    _extract_assertion_conditions,
    _extract_assertion_id,
    _extract_in_response_to,
    _extract_response_id,
    _parse_saml_xml,
)

_VALID_SAML_XML = """\
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_resp123" Version="2.0"
                IssueInstant="2026-07-06T12:00:00Z"
                InResponseTo="_req456">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <samlp:Status>
    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
  </samlp:Status>
  <saml:Assertion ID="_assert789" Version="2.0"
                  IssueInstant="2026-07-06T12:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
      </ds:SignedInfo>
      <ds:SignatureValue>sig</ds:SignatureValue>
    </ds:Signature>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-07-06T11:55:00Z" NotOnAfter="2026-07-06T12:05:00Z"/>
    <saml:AuthnStatement AuthnInstant="2026-07-06T12:00:00Z"/>
  </saml:Assertion>
</samlp:Response>"""

_ENCODED_SAML = base64.b64encode(_VALID_SAML_XML.encode()).decode()


def test_category_map_has_two_categories() -> None:
    assert len(_CATEGORY_MAP) == 2


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {"assertion_replay", "xml_signature_wrapping"}


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 10


def test_assertion_replay_techniques_count() -> None:
    assert len(_CATEGORY_MAP["assertion_replay"]) == 5


def test_xml_signature_wrapping_techniques_count() -> None:
    assert len(_CATEGORY_MAP["xml_signature_wrapping"]) == 5


def test_decode_saml_response_valid() -> None:
    result = _decode_saml_response(_ENCODED_SAML)
    assert result is not None
    assert "<samlp:Response" in result


def test_decode_saml_response_invalid() -> None:
    result = _decode_saml_response("not-valid-base64!!!")
    assert result is None


def test_parse_saml_xml_valid() -> None:
    root = _parse_saml_xml(_VALID_SAML_XML)
    assert root is not None
    assert root.tag == "{urn:oasis:names:tc:SAML:2.0:protocol}Response"


def test_parse_saml_xml_invalid() -> None:
    root = _parse_saml_xml("<broken><xml")
    assert root is None


def test_extract_response_id() -> None:
    root = _parse_saml_xml(_VALID_SAML_XML)
    assert root is not None
    rid = _extract_response_id(root)
    assert rid == "_resp123"


def test_extract_assertion_id() -> None:
    root = _parse_saml_xml(_VALID_SAML_XML)
    assert root is not None
    aid = _extract_assertion_id(root)
    assert aid == "_assert789"


def test_extract_in_response_to() -> None:
    root = _parse_saml_xml(_VALID_SAML_XML)
    assert root is not None
    irt = _extract_in_response_to(root)
    assert irt == "_req456"


def test_extract_assertion_conditions() -> None:
    root = _parse_saml_xml(_VALID_SAML_XML)
    assert root is not None
    conds = _extract_assertion_conditions(root)
    assert "NotBefore" in conds
    assert "NotOnAfter" in conds


def test_attempt_dataclass_frozen() -> None:
    a = SAMLAttempt(
        technique="test", category="assertion_replay",
        vulnerable=True, details="test", error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False  # type: ignore[reportAttributeAccessIssue]


def test_attempt_dataclass_slots() -> None:
    a = SAMLAttempt(
        technique="test", category="assertion_replay",
        vulnerable=True, details="test", error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = SAMLResult(
        target=None, xml_valid=True,
        response_id="_resp123", assertion_id="_assert789",
        conditions={}, has_signature=True,
        attempts=[], vulnerable_techniques=[],
        issues=[], overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"  # type: ignore[reportAttributeAccessIssue]


def test_result_dataclass_slots() -> None:
    r = SAMLResult(
        target=None, xml_valid=True,
        response_id="_resp123", assertion_id="_assert789",
        conditions={}, has_signature=True,
        attempts=[], vulnerable_techniques=[],
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
