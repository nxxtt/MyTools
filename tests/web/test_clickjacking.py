#!/usr/bin/env python3
"""Testes unitarios do modulo de Clickjacking via Embedded Frames."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.clickjacking import (
    _CATEGORY_MAP,
    ClickjackAttempt,
    ClickjackResult,
    _check_csp_frame_ancestors,
    _check_xframe_options,
    _test_baseline,
    _test_bypass,
    _test_csp,
    _test_legacy,
    _test_meta,
    _test_xframe,
    build_parser,
    print_results,
)


# ─── Category Map ────────────────────────────────────────────────────────────
class TestCategoryMap:
    def test_has_five_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 5

    def test_categories_are_correct(self) -> None:
        expected = {"xframe", "csp", "bypass", "meta", "legacy"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_all_categories_have_5_techniques(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) == 5, f"Categoria {cat} tem {len(techs)} tecnicas"


# ─── Check X-Frame-Options ───────────────────────────────────────────────────
class TestCheckXFrameOptions:
    def test_absent(self) -> None:
        vuln, details = _check_xframe_options({})
        assert vuln is False
        assert "ausente" in details

    def test_deny(self) -> None:
        vuln, details = _check_xframe_options({"x-frame-options": "DENY"})
        assert vuln is True
        assert "deny" in details

    def test_sameorigin(self) -> None:
        vuln, details = _check_xframe_options({"x-frame-options": "SAMEORIGIN"})
        assert vuln is True
        assert "sameorigin" in details

    def test_invalid(self) -> None:
        vuln, details = _check_xframe_options({"x-frame-options": "INVALID"})
        assert vuln is True
        assert "invalido" in details

    def test_case_insensitive(self) -> None:
        vuln, details = _check_xframe_options({"x-frame-options": "deny"})
        assert vuln is True
        assert "deny" in details


# ─── Check CSP Frame Ancestors ───────────────────────────────────────────────
class TestCheckCSPFrameAncestors:
    def test_absent(self) -> None:
        vuln, details = _check_csp_frame_ancestors({})
        assert vuln is False
        assert "ausente" in details

    def test_no_frame_ancestors(self) -> None:
        vuln, details = _check_csp_frame_ancestors({"content-security-policy": "default-src 'self'"})
        assert vuln is False
        assert "sem frame-ancestors" in details

    def test_frame_ancestors_none(self) -> None:
        vuln, details = _check_csp_frame_ancestors(
            {"content-security-policy": "frame-ancestors 'none'"}
        )
        assert vuln is True
        assert "'none'" in details

    def test_frame_ancestors_self(self) -> None:
        vuln, details = _check_csp_frame_ancestors(
            {"content-security-policy": "frame-ancestors 'self'"}
        )
        assert vuln is True
        assert "'self'" in details

    def test_frame_ancestors_wildcard(self) -> None:
        vuln, details = _check_csp_frame_ancestors(
            {"content-security-policy": "frame-ancestors *"}
        )
        assert vuln is True
        assert "wildcard" in details.lower()

    def test_frame_ancestors_configured(self) -> None:
        vuln, details = _check_csp_frame_ancestors(
            {"content-security-policy": "frame-ancestors https://example.com"}
        )
        assert vuln is True
        assert "configurado" in details


# ─── Dataclasses ─────────────────────────────────────────────────────────────
class TestClickjackAttempt:
    def test_frozen(self) -> None:
        a = ClickjackAttempt(
            technique="test", category="xframe", header_tested="X-Frame-Options",
            header_value="DENY", vulnerable=True, details="test", error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "other"  # type: ignore[misc]

    def test_slots(self) -> None:
        a = ClickjackAttempt(
            technique="test", category="xframe", header_tested="X-Frame-Options",
            header_value="DENY", vulnerable=True, details="test", error="",
        )
        assert not hasattr(a, "__dict__")


class TestClickjackResult:
    def test_frozen(self) -> None:
        r = ClickjackResult(
            target="https://test.com", tls=True, attempts=[],
            vulnerable_techniques=[], protected_techniques=[],
            issues=[], overall_status="safe",
        )
        with pytest.raises(AttributeError):
            r.target = "other"  # type: ignore[misc]


# ─── Test Baseline ───────────────────────────────────────────────────────────
class TestBaseline:
    @pytest.mark.asyncio
    async def test_baseline_success(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {"x-frame-options": "DENY"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        status, headers, body = await _test_baseline(mock_client, "https://test.com")
        assert status == 200
        assert "x-frame-options" in headers
        assert body == b"ok"

    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("fail"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        status, headers, body = await _test_baseline(mock_client, "https://test.com")
        assert status == 0
        assert headers == {}
        assert body == b""


# ─── Test XFrame ─────────────────────────────────────────────────────────────
class TestXFrame:
    @pytest.mark.asyncio
    async def test_no_xframe(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_xframe(mock_client, "https://test.com", {})
        assert len(results) == 5
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) > 0

    @pytest.mark.asyncio
    async def test_deny(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {"x-frame-options": "DENY"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_xframe(mock_client, "https://test.com", {})
        assert len(results) == 5
        deny = [r for r in results if r.technique == "xframe_deny"]
        assert len(deny) == 1
        assert deny[0].vulnerable is False


# ─── Test CSP ────────────────────────────────────────────────────────────────
class TestCSP:
    @pytest.mark.asyncio
    async def test_no_csp(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_csp(mock_client, "https://test.com")
        assert len(results) == 5
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) > 0

    @pytest.mark.asyncio
    async def test_csp_frame_ancestors(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {"content-security-policy": "frame-ancestors 'none'"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_csp(mock_client, "https://test.com")
        assert len(results) == 5
        fa = [r for r in results if r.technique == "csp_frame_ancestors"]
        assert len(fa) == 1
        assert fa[0].vulnerable is True


# ─── Test Bypass ─────────────────────────────────────────────────────────────
class TestBypass:
    @pytest.mark.asyncio
    async def test_bypass_no_protection(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"hello"
        mock_resp.headers = {}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_bypass(mock_client, "https://test.com")
        assert len(results) == 5

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_bypass(mock_client, "https://test.com")
        assert len(results) == 5
        errors = [r for r in results if r.error]
        assert len(errors) >= 2


# ─── Test Meta ───────────────────────────────────────────────────────────────
class TestMeta:
    @pytest.mark.asyncio
    async def test_meta_tags(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'<html><head><meta name="referrer" content="no-referrer"></head></html>'
        mock_resp.headers = {}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_meta(mock_client, "https://test.com")
        assert len(results) == 5
        referrer = [r for r in results if r.technique == "meta_referrer"]
        assert len(referrer) == 1
        assert referrer[0].vulnerable is True


# ─── Test Legacy ─────────────────────────────────────────────────────────────
class TestLegacy:
    @pytest.mark.asyncio
    async def test_legacy_no_xframe(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_legacy(mock_client, "https://test.com")
        assert len(results) == 5


# ─── Print Results ───────────────────────────────────────────────────────────
class TestPrintResults:
    def test_vulnerable_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = ClickjackResult(
            target="https://test.com", tls=True,
            attempts=[ClickjackAttempt(
                technique="xframe_absent", category="xframe",
                header_tested="X-Frame-Options", header_value="",
                vulnerable=True, details="X-Frame-Options ausente", error="",
            )],
            vulnerable_techniques=["xframe_absent"],
            protected_techniques=[], issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Vulnerabilidades detectadas" in output
        assert "xframe_absent" in output

    def test_safe_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = ClickjackResult(
            target="https://test.com", tls=True, attempts=[],
            vulnerable_techniques=[], protected_techniques=[],
            issues=[], overall_status="safe",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Nenhum Clickjacking detectado" in output

    def test_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = ClickjackResult(
            target="https://test.com", tls=True, attempts=[],
            vulnerable_techniques=[], protected_techniques=[],
            issues=["Nenhum teste retornou resultado claro"],
            overall_status="unknown",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Observacoes" in output


# ─── Build Parser ────────────────────────────────────────────────────────────
class TestBuildParser:
    def test_has_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.url == "https://test.com"

    def test_has_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "-c", "xframe"])
        assert args.category == "xframe"

    def test_default_category_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.category == "all"

    def test_all_categories(self) -> None:
        parser = build_parser()
        for cat in ["all", "xframe", "csp", "bypass", "meta", "legacy"]:
            args = parser.parse_args(["https://test.com", "-c", cat])
            assert args.category == cat


# ─── Run Once ────────────────────────────────────────────────────────────────
class TestRunOnce:
    @patch("mytools.web.clickjacking.run_scan")
    def test_run_once(self, mock_run: MagicMock) -> None:
        mock_run.return_value = 0
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        from mytools.web.clickjacking import run_once
        result = run_once(args)
        assert result == 0
        mock_run.assert_called_once()
