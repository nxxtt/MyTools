#!/usr/bin/env python3
"""Testes unitarios do modulo de HTTP Method Override."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.methodoverride import (
    _BODY_PAYLOADS,
    _BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    _HEADER_PAYLOADS,
    _PARAM_PAYLOADS,
    _SENSITIVE_PATHS,
    _VERB_PAYLOADS,
    OverrideAttempt,
    OverrideResult,
    _check_override_response,
    _check_response_content,
    _test_baseline,
    _test_body,
    _test_bypass,
    _test_header,
    _test_param,
    _test_verb,
    build_parser,
    print_results,
)


# ─── Category Map ────────────────────────────────────────────────────────────
class TestCategoryMap:
    def test_has_five_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 5

    def test_categories_are_header_param_body_bypass_verb(self) -> None:
        expected = {"header", "param", "body", "bypass", "verb"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_all_categories_have_payloads(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) > 0, f"Categoria {cat} vazia"

    def test_all_categories_have_5_techniques(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) == 5, f"Categoria {cat} tem {len(techs)} tecnicas, esperado 5"


# ─── Payload Lists ───────────────────────────────────────────────────────────
class TestPayloadLists:
    def test_header_payloads_count(self) -> None:
        assert len(_HEADER_PAYLOADS) == 5

    def test_param_payloads_count(self) -> None:
        assert len(_PARAM_PAYLOADS) == 5

    def test_body_payloads_count(self) -> None:
        assert len(_BODY_PAYLOADS) == 5

    def test_bypass_payloads_count(self) -> None:
        assert len(_BYPASS_PAYLOADS) == 5

    def test_verb_payloads_count(self) -> None:
        assert len(_VERB_PAYLOADS) == 5

    def test_sensitive_paths(self) -> None:
        assert len(_SENSITIVE_PATHS) == 10


# ─── Header Payloads ─────────────────────────────────────────────────────────
class TestHeaderPayloads:
    def test_all_have_header_name(self) -> None:
        for _, header_name, _, _ in _HEADER_PAYLOADS:
            assert header_name.startswith("X-")

    def test_all_have_delete_or_put(self) -> None:
        for _, _, value, _ in _HEADER_PAYLOADS:
            assert value in ("DELETE", "PUT")

    def test_all_have_indicators(self) -> None:
        for _, _, _, indicators in _HEADER_PAYLOADS:
            assert len(indicators) > 0


# ─── Param Payloads ──────────────────────────────────────────────────────────
class TestParamPayloads:
    def test_all_have_param_name(self) -> None:
        for _, param_name, _, _, _ in _PARAM_PAYLOADS:
            assert param_name in ("_method", "__method", "method", "override")

    def test_all_have_delete_or_put(self) -> None:
        for _, _, value, _, _ in _PARAM_PAYLOADS:
            assert value in ("DELETE", "PUT")


# ─── Body Payloads ───────────────────────────────────────────────────────────
class TestBodyPayloads:
    def test_all_have_content_type(self) -> None:
        for _, _, _, content_type, _ in _BODY_PAYLOADS:
            assert content_type in ("json", "form", "xml")

    def test_all_have_delete(self) -> None:
        for _, _, value, _, _ in _BODY_PAYLOADS:
            assert value == "DELETE"


# ─── Bypass Payloads ─────────────────────────────────────────────────────────
class TestBypassPayloads:
    def test_all_have_header_name(self) -> None:
        for _, header_name, _, _ in _BYPASS_PAYLOADS:
            assert "Method" in header_name or "method" in header_name.lower()

    def test_all_have_delete(self) -> None:
        for _, _, value, _ in _BYPASS_PAYLOADS:
            assert "DELETE" in value


# ─── Verb Payloads ───────────────────────────────────────────────────────────
class TestVerbPayloads:
    def test_all_have_delete_put_patch_options_trace(self) -> None:
        verbs = {"DELETE", "PUT", "PATCH", "OPTIONS", "TRACE"}
        found: set[str] = set()
        for _, _, value, _ in _VERB_PAYLOADS:
            found.add(value)
        assert found == verbs


# ─── Check Override Response ─────────────────────────────────────────────────
class TestCheckOverrideResponse:
    def test_403_to_200_is_vulnerable(self) -> None:
        assert _check_override_response(b"ok", 200, 403) is True

    def test_401_to_200_is_vulnerable(self) -> None:
        assert _check_override_response(b"ok", 200, 401) is True

    def test_405_to_200_is_vulnerable(self) -> None:
        assert _check_override_response(b"ok", 200, 405) is True

    def test_200_to_200_same_not_vulnerable(self) -> None:
        assert _check_override_response(b"ok", 200, 200) is False

    def test_403_to_403_not_vulnerable(self) -> None:
        assert _check_override_response(b"forbidden", 403, 403) is False

    def test_0_status_not_vulnerable(self) -> None:
        assert _check_override_response(b"", 0, 403) is False

    def test_200_to_201_is_vulnerable(self) -> None:
        assert _check_override_response(b"created", 201, 200) is True

    def test_403_to_204_is_vulnerable(self) -> None:
        assert _check_override_response(b"", 204, 403) is True


# ─── Check Response Content ──────────────────────────────────────────────────
class TestCheckResponseContent:
    def test_match_indicator(self) -> None:
        assert _check_response_content(b"method override detected", ["method"]) is True

    def test_no_match(self) -> None:
        assert _check_response_content(b"not found", ["override"]) is False

    def test_empty_body(self) -> None:
        assert _check_response_content(b"", ["test"]) is False

    def test_case_insensitive(self) -> None:
        assert _check_response_content(b"OVERRIDE", ["override"]) is True

    def test_multiple_indicators(self) -> None:
        assert _check_response_content(b"override applied", ["method", "override"]) is True


# ─── Dataclasses ─────────────────────────────────────────────────────────────
class TestOverrideAttempt:
    def test_frozen(self) -> None:
        a = OverrideAttempt(
            technique="test", category="header", header_name="X-Method",
            header_value="DELETE", method="GET", status_baseline=403,
            status_test=200, size_baseline=100, size_test=200,
            status_changed=True, size_changed=True, vulnerable=True,
            details="test", error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "other"  # type: ignore[misc]

    def test_slots(self) -> None:
        a = OverrideAttempt(
            technique="test", category="header", header_name="X-Method",
            header_value="DELETE", method="GET", status_baseline=403,
            status_test=200, size_baseline=100, size_test=200,
            status_changed=True, size_changed=True, vulnerable=True,
            details="test", error="",
        )
        assert not hasattr(a, "__dict__")


class TestOverrideResult:
    def test_frozen(self) -> None:
        r = OverrideResult(
            target="https://test.com", baseline_status=403,
            baseline_size=100, tls=True, attempts=[],
            vulnerable_techniques=[], blocked_techniques=[],
            issues=[], overall_status="safe",
        )
        with pytest.raises(AttributeError):
            r.target = "other"  # type: ignore[misc]


# ─── Test Baseline ───────────────────────────────────────────────────────────
class TestBaseline:
    @pytest.mark.asyncio
    async def test_baseline_success(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.content = b"forbidden"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        result = await _test_baseline(mock_client, "https://test.com/admin")
        assert result == (403, 9, b"forbidden")

    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("fail"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        result = await _test_baseline(mock_client, "https://test.com/admin")
        assert result == (0, 0, b"")


# ─── Test Header ─────────────────────────────────────────────────────────────
class TestHeader:
    @pytest.mark.asyncio
    async def test_vulnerable_header(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"override applied"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_header(
            mock_client, "https://test.com", (403, 100, b"forbidden"),
        )
        assert len(results) == 20
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) > 0
        assert vuln[0].category == "header"

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_header(
            mock_client, "https://test.com", (403, 100, b"forbidden"),
        )
        assert len(results) == 20
        assert all(r.error for r in results)


# ─── Test Param ──────────────────────────────────────────────────────────────
class TestParam:
    @pytest.mark.asyncio
    async def test_vulnerable_param(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"method override detected"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_param(
            mock_client, "https://test.com", (403, 100, b"forbidden"),
        )
        assert len(results) == 20
        assert all(r.category == "param" for r in results)

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_param(
            mock_client, "https://test.com", (403, 100, b"forbidden"),
        )
        assert len(results) == 20
        assert all(r.error for r in results)


# ─── Test Body ───────────────────────────────────────────────────────────────
class TestBody:
    @pytest.mark.asyncio
    async def test_vulnerable_body(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"override applied"
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_body(
            mock_client, "https://test.com", (403, 100, b"forbidden"),
        )
        assert len(results) == 20
        assert all(r.category == "body" for r in results)

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_body(
            mock_client, "https://test.com", (403, 100, b"forbidden"),
        )
        assert len(results) == 20
        assert all(r.error for r in results)


# ─── Test Bypass ─────────────────────────────────────────────────────────────
class TestBypass:
    @pytest.mark.asyncio
    async def test_vulnerable_bypass(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"override applied"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_bypass(
            mock_client, "https://test.com", (403, 100, b"forbidden"),
        )
        assert len(results) == 20
        assert all(r.category == "bypass" for r in results)


# ─── Test Verb ───────────────────────────────────────────────────────────────
class TestVerb:
    @pytest.mark.asyncio
    async def test_vulnerable_verb(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"deleted"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_verb(
            mock_client, "https://test.com", (403, 100, b"forbidden"),
        )
        assert len(results) == 20
        assert all(r.category == "verb" for r in results)

    @pytest.mark.asyncio
    async def test_verb_method_field(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_verb(
            mock_client, "https://test.com", (200, 100, b"ok"),
        )
        for r in results:
            assert "->" in r.method


# ─── Print Results ───────────────────────────────────────────────────────────
class TestPrintResults:
    def test_vulnerable_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = OverrideResult(
            target="https://test.com", baseline_status=403,
            baseline_size=100, tls=True,
            attempts=[OverrideAttempt(
                technique="x_method_override", category="header",
                header_name="X-HTTP-Method-Override", header_value="DELETE",
                method="GET", status_baseline=403, status_test=200,
                size_baseline=100, size_test=200, status_changed=True,
                size_changed=True, vulnerable=True,
                details="path=/admin", error="",
            )],
            vulnerable_techniques=["x_method_override"],
            blocked_techniques=[], issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Vulnerabilidades detectadas" in output
        assert "x_method_override" in output

    def test_no_vulns_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = OverrideResult(
            target="https://test.com", baseline_status=200,
            baseline_size=100, tls=True, attempts=[],
            vulnerable_techniques=[], blocked_techniques=[],
            issues=[], overall_status="safe",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Nenhuma Method Override detectada" in output

    def test_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = OverrideResult(
            target="https://test.com", baseline_status=200,
            baseline_size=100, tls=True, attempts=[],
            vulnerable_techniques=[], blocked_techniques=[],
            issues=["Nenhum teste retornou resultado claro"],
            overall_status="unknown",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Observacoes" in output


# ─── Build Parser ────────────────────────────────────────────────────────────
@pytest.mark.smoke
class TestBuildParser:
    def test_has_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.url == "https://test.com"

    def test_has_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "-c", "header"])
        assert args.category == "header"

    def test_default_category_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.category == "all"

    def test_all_categories(self) -> None:
        parser = build_parser()
        for cat in ["all", "header", "param", "body", "bypass", "verb"]:
            args = parser.parse_args(["https://test.com", "-c", cat])
            assert args.category == cat


# ─── Run Once ────────────────────────────────────────────────────────────────
class TestRunOnce:
    @patch("mytools.web.methodoverride.run_scan")
    def test_run_once(self, mock_run: MagicMock) -> None:
        mock_run.return_value = 0
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        from mytools.web.methodoverride import run_once
        result = run_once(args)
        assert result == 0
        mock_run.assert_called_once()
