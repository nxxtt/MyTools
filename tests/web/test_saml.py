#!/usr/bin/env python3
"""Testes unitarios do modulo SAML Attack Detection."""

from __future__ import annotations

import argparse
import base64
import runpy
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

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
    _generate_modified_response,
    _parse_saml_xml,
    _test_assertion_replay_category,
    _test_xml_signature_wrapping_category,
    banner_art,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
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

_SAFE_SAML_XML = """\
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_safe123" Version="2.0"
                IssueInstant="2026-07-06T12:00:00Z"
                InResponseTo="_req456">
  <saml:Issuer>https://idp.example.com</saml:Issuer>
  <saml:Assertion ID="_safe789" Version="2.0"
                  IssueInstant="2026-07-06T12:00:00Z">
    <saml:Issuer>https://idp.example.com</saml:Issuer>
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
    <saml:Conditions NotBefore="2026-07-06T11:55:00Z" NotOnAfter="2026-07-06T12:05:00Z"/>
  </saml:Assertion>
</samlp:Response>"""

_MINIMAL_SAML_XML = """\
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"
                xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
                ID="_min123" Version="2.0">
  <saml:Assertion ID="_min789" Version="2.0">
    <saml:Subject>
      <saml:NameID>user@example.com</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>"""

_ENCODED_SAFE = base64.b64encode(_SAFE_SAML_XML.encode()).decode()

_ENCODED_MINIMAL = base64.b64encode(_MINIMAL_SAML_XML.encode()).decode()


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
        technique="test",
        category="assertion_replay",
        vulnerable=True,
        details="test",
        error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False  # type: ignore[reportAttributeAccessIssue]


def test_attempt_dataclass_slots() -> None:
    a = SAMLAttempt(
        technique="test",
        category="assertion_replay",
        vulnerable=True,
        details="test",
        error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = SAMLResult(
        target=None,
        xml_valid=True,
        response_id="_resp123",
        assertion_id="_assert789",
        conditions={},
        has_signature=True,
        attempts=[],
        vulnerable_techniques=[],
        issues=[],
        overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"  # type: ignore[reportAttributeAccessIssue]


def test_result_dataclass_slots() -> None:
    r = SAMLResult(
        target=None,
        xml_valid=True,
        response_id="_resp123",
        assertion_id="_assert789",
        conditions={},
        has_signature=True,
        attempts=[],
        vulnerable_techniques=[],
        issues=[],
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


def test_extract_response_id_samlp_namespace() -> None:
    root = _parse_saml_xml(
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'samlp:ID="_nsid"/>'
    )
    assert root is not None
    assert _extract_response_id(root) == "_nsid"


def test_extract_response_id_missing() -> None:
    root = _parse_saml_xml(
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>'
    )
    assert root is not None
    assert _extract_response_id(root) == ""


def test_extract_assertion_id_missing() -> None:
    root = _parse_saml_xml(
        '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
        'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><samlp:Status/></samlp:Response>'
    )
    assert root is not None
    assert _extract_assertion_id(root) == ""


def test_extract_conditions_only_notbefore() -> None:
    root = _parse_saml_xml(
        '<r xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        '<saml:Conditions NotBefore="2026-01-01T00:00:00Z"/></r>'
    )
    assert root is not None
    conds = _extract_assertion_conditions(root)
    assert conds == {"NotBefore": "2026-01-01T00:00:00Z"}


def test_extract_conditions_only_notonafter() -> None:
    root = _parse_saml_xml(
        '<r xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
        '<saml:Conditions NotOnAfter="2026-12-31T23:59:59Z"/></r>'
    )
    assert root is not None
    conds = _extract_assertion_conditions(root)
    assert conds == {"NotOnAfter": "2026-12-31T23:59:59Z"}


def test_generate_modified_response_single() -> None:
    result = _generate_modified_response("abc-old-xyz", {"old": "new"})
    assert result == "abc-new-xyz"


def test_generate_modified_response_multiple() -> None:
    result = _generate_modified_response("a=X&b=Y", {"X": "1", "Y": "2"})
    assert result == "a=1&b=2"


def _saml_attempt(
    technique: str,
    *,
    vulnerable: bool = True,
    error: str = "",
    details: str = "detail",
    category: str = "assertion_replay",
) -> SAMLAttempt:
    return SAMLAttempt(
        technique=technique,
        category=category,
        vulnerable=vulnerable,
        details=details,
        error=error,
        exploit="signature_wrapping_payload" if vulnerable else "",
        tool="SAMLRaider",
    )


class TestReplayCategory:
    @pytest.mark.asyncio
    async def test_full_assertion_no_vulns(self) -> None:
        root = _parse_saml_xml(_VALID_SAML_XML)
        assert root is not None
        results = await _test_assertion_replay_category(_VALID_SAML_XML, root, None, 10)
        assert len(results) == 5
        vuln = [r for r in results if r["vulnerable"]]
        assert not vuln

    @pytest.mark.asyncio
    async def test_minimal_assertion_vulnerable(self) -> None:
        root = _parse_saml_xml(_MINIMAL_SAML_XML)
        assert root is not None
        results = await _test_assertion_replay_category(
            _MINIMAL_SAML_XML, root, "https://sp.example.com/acs", 10
        )
        assert len(results) == 5
        assert results[2]["vulnerable"]
        assert results[3]["vulnerable"]
        assert results[4]["vulnerable"]
        assert not results[0]["vulnerable"]


class TestSignatureWrappingCategory:
    @pytest.mark.asyncio
    async def test_with_signature_vulnerable(self) -> None:
        root = _parse_saml_xml(_VALID_SAML_XML)
        assert root is not None
        results = await _test_xml_signature_wrapping_category(
            _VALID_SAML_XML, root, None, 10
        )
        assert len(results) == 5
        assert results[1]["vulnerable"]
        assert results[1]["category"] == "xml_signature_wrapping"

    @pytest.mark.asyncio
    async def test_without_signature_safe(self) -> None:
        root = _parse_saml_xml(_SAFE_SAML_XML)
        assert root is not None
        results = await _test_xml_signature_wrapping_category(
            _SAFE_SAML_XML, root, None, 10
        )
        assert not results[1]["vulnerable"]


class TestPrintResults:
    def test_vulnerable_with_dedupe_and_issues(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = SAMLResult(
            target="https://sp.example.com/acs",
            xml_valid=True,
            response_id="_resp123",
            assertion_id="_assert789",
            conditions={"NotBefore": "x", "NotOnAfter": "y"},
            has_signature=True,
            attempts=[
                _saml_attempt("full_replay", details="replay completo"),
                _saml_attempt("full_replay"),
                _saml_attempt("comment_injection", details=""),
                _saml_attempt("exclusive_c14n", vulnerable=False),
                _saml_attempt("signature_clone", vulnerable=False, error="boom"),
            ],
            vulnerable_techniques=["full_replay", "comment_injection"],
            issues=["Assinatura XML ausente"],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Vulnerabilidades encontradas" in output
        assert "full_replay" in output
        assert "replay completo" in output
        assert "Observacoes" in output
        assert "Erros:" in output

    def test_no_vulns(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = SAMLResult(
            target=None,
            xml_valid=True,
            response_id="",
            assertion_id="",
            conditions={},
            has_signature=False,
            attempts=[_saml_attempt("exclusive_c14n", vulnerable=False)],
            vulnerable_techniques=[],
            issues=[],
            overall_status="safe",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Nenhuma vulnerabilidade SAML detectada" in output
        assert "Seguros:" in output


class TestRunScan:
    @pytest.mark.asyncio
    async def test_invalid_base64_returns_1(self) -> None:
        result = await run_scan("not-valid-base64!!!", None, [], None, 10)
        assert result == 1

    @pytest.mark.asyncio
    async def test_invalid_xml_returns_1(self) -> None:
        encoded = base64.b64encode(b"<broken><xml").decode()
        result = await run_scan(encoded, None, [], None, 10)
        assert result == 1

    @pytest.mark.asyncio
    async def test_vulnerable_full_scan_returns_1(self) -> None:
        result = await run_scan(
            _ENCODED_SAML, "https://sp.example.com/acs", [], None, 10
        )
        assert result == 1

    @pytest.mark.asyncio
    async def test_safe_scan_returns_0(self) -> None:
        result = await run_scan(_ENCODED_SAFE, None, [], None, 10)
        assert result == 0

    @pytest.mark.asyncio
    async def test_minimal_scan_returns_1(self) -> None:
        result = await run_scan(_ENCODED_MINIMAL, None, [], None, 10)
        assert result == 1

    @pytest.mark.asyncio
    async def test_unknown_category_skipped(self) -> None:
        result = await run_scan(_ENCODED_SAFE, None, ["bogus"], None, 10)
        assert result == 0

    @pytest.mark.asyncio
    async def test_tester_exception_appends_error(self) -> None:
        with patch("mytools.web.saml.CATEGORY_TESTERS") as mock_testers:
            mock_testers.get.return_value = AsyncMock(side_effect=RuntimeError("boom"))
            result = await run_scan(_ENCODED_SAFE, None, ["assertion_replay"], None, 10)
            assert result == 0
            mock_testers.get.assert_called_once_with("assertion_replay")

    @pytest.mark.asyncio
    async def test_output_file_writes(self) -> None:
        with patch("mytools.web.saml.write_output") as mock_write:
            result = await run_scan(_ENCODED_SAFE, None, [], "out.json", 10)
            assert result == 0
            mock_write.assert_called_once()


class TestBannerArt:
    def test_banner_art(self) -> None:
        with patch("mytools.web.saml.create_banner") as mock_banner:
            mock_banner.return_value = MagicMock()
            banner_art()
            mock_banner.assert_called_once()


class TestBuildParser:
    def test_has_saml_response(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--saml-response", "ABC"])
        assert args.saml_response == "ABC"

    def test_has_file(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--file", "resp.xml"])
        assert args.file == "resp.xml"

    def test_default_category_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--saml-response", "ABC"])
        assert args.category == "all"

    def test_category_choices(self) -> None:
        parser = build_parser()
        for action in parser._actions:
            if action.dest == "category":
                assert set(action.choices or []) == {
                    "all",
                    "assertion_replay",
                    "xml_signature_wrapping",
                }


class TestRunOnce:
    def test_saml_response_arg(self) -> None:
        args = argparse.Namespace(
            saml_response=_ENCODED_SAML,
            file=None,
            url=None,
            category="all",
            output=None,
            timeout=10,
        )
        with patch(
            "mytools.web.saml.run_scan", new_callable=AsyncMock, return_value=0
        ) as mock_scan:
            result = run_once(args)
            assert result == 0
            assert mock_scan.call_args.kwargs["categories"] == []
            assert mock_scan.call_args.kwargs["saml_response"] == _ENCODED_SAML

    def test_specific_category(self) -> None:
        args = argparse.Namespace(
            saml_response=_ENCODED_SAML,
            file=None,
            url="https://sp/acs",
            category="assertion_replay",
            output=None,
            timeout=5,
        )
        with patch(
            "mytools.web.saml.run_scan", new_callable=AsyncMock, return_value=1
        ) as mock_scan:
            result = run_once(args)
            assert result == 1
            assert mock_scan.call_args.kwargs["categories"] == ["assertion_replay"]

    def test_file_path_reads_first_line(self, tmp_path: Path) -> None:
        f = tmp_path / "resp.xml"
        f.write_text(_ENCODED_SAML + "\n", encoding="utf-8")
        args = argparse.Namespace(
            saml_response=None,
            file=str(f),
            url=None,
            category="all",
            output=None,
            timeout=10,
        )
        with patch(
            "mytools.web.saml.run_scan", new_callable=AsyncMock, return_value=0
        ) as mock_scan:
            result = run_once(args)
            assert result == 0
            assert mock_scan.call_args.kwargs["saml_response"] == _ENCODED_SAML

    def test_file_read_error_returns_1(self) -> None:
        args = argparse.Namespace(
            saml_response=None,
            file="C:/nonexistent/resp.xml",
            url=None,
            category="all",
            output=None,
            timeout=10,
        )
        result = run_once(args)
        assert result == 1

    def test_missing_response_returns_1(self) -> None:
        args = argparse.Namespace(
            saml_response=None,
            file=None,
            url=None,
            category="all",
            output=None,
            timeout=10,
        )
        result = run_once(args)
        assert result == 1


class TestMain:
    def test_main_returns_int(self) -> None:
        with patch("mytools.web.saml.run_main_loop", return_value=0) as mock_loop:
            result = main()
            assert result == 0
            mock_loop.assert_called_once()


class TestMainGuard:
    def test_guard_runs(self) -> None:
        with (
            patch("sys.argv", ["mytools-saml"]),
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("mytools.core.base.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.web.saml", run_name="__main__")
