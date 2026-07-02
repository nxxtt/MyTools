#!/usr/bin/env python3
"""Testes unitarios do modulo de Host Header Injection."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.hostheaderinject import (
    _CATEGORY_MAP,
    _INJECTED_HOST,
    HostInjectAttempt,
    HostInjectResult,
    _test_baseline,
    _test_bypass,
    _test_cache,
    _test_password_reset,
    _test_reflected,
    _test_ssrf,
    build_parser,
    print_results,
)


# ─── Category Map ────────────────────────────────────────────────────────────
class TestCategoryMap:
    def test_has_five_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 5

    def test_categories_are_correct(self) -> None:
        expected = {"reflected", "password_reset", "ssrf", "cache", "bypass"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_all_categories_have_5_techniques(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) == 5, f"Categoria {cat} tem {len(techs)} tecnicas"


# ─── Injected Host ───────────────────────────────────────────────────────────
class TestInjectedHost:
    def test_default_host(self) -> None:
        assert _INJECTED_HOST == "evil.attacker.com"


# ─── Dataclasses ─────────────────────────────────────────────────────────────
class TestHostInjectAttempt:
    def test_frozen(self) -> None:
        a = HostInjectAttempt(
            technique="test", category="reflected", header_name="Host",
            header_value="evil.com", status=200, size=100,
            vulnerable=True, details="test", error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "other"  # type: ignore[misc]

    def test_slots(self) -> None:
        a = HostInjectAttempt(
            technique="test", category="reflected", header_name="Host",
            header_value="evil.com", status=200, size=100,
            vulnerable=True, details="test", error="",
        )
        assert not hasattr(a, "__dict__")


class TestHostInjectResult:
    def test_frozen(self) -> None:
        r = HostInjectResult(
            target="https://test.com", injected_host="evil.com", tls=True,
            attempts=[], vulnerable_techniques=[], blocked_techniques=[],
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
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        status, size, _headers, body = await _test_baseline(mock_client, "https://test.com")
        assert status == 200
        assert size == 2
        assert body == b"ok"

    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("fail"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        status, size, headers, body = await _test_baseline(mock_client, "https://test.com")
        assert status == 0
        assert size == 0
        assert headers == {}
        assert body == b""


# ─── Test Reflected ──────────────────────────────────────────────────────────
class TestReflected:
    @pytest.mark.asyncio
    async def test_vulnerable_reflected(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"host=evil.attacker.com"
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_reflected(mock_client, "https://test.com", "evil.attacker.com")
        assert len(results) == 5
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) > 0

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_reflected(mock_client, "https://test.com", "evil.attacker.com")
        assert len(results) == 5
        assert all(r.error for r in results)


# ─── Test Password Reset ─────────────────────────────────────────────────────
class TestPasswordReset:
    @pytest.mark.asyncio
    async def test_vulnerable_reset(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"reset link: http://evil.attacker.com/reset"
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_password_reset(mock_client, "https://test.com", "evil.attacker.com")
        assert len(results) == 5
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) > 0
        assert all(r.category == "password_reset" for r in results)


# ─── Test SSRF ───────────────────────────────────────────────────────────────
class TestSSRF:
    @pytest.mark.asyncio
    async def test_vulnerable_ssrf(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"internal admin panel"
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_ssrf(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(r.category == "ssrf" for r in results)


# ─── Test Cache ──────────────────────────────────────────────────────────────
class TestCache:
    @pytest.mark.asyncio
    async def test_vulnerable_cache(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"cached page"
        mock_resp.headers = {"x-cache": "HIT", "content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_cache(mock_client, "https://test.com", "evil.attacker.com")
        assert len(results) == 5
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) > 0
        assert all(r.category == "cache" for r in results)


# ─── Test Bypass ─────────────────────────────────────────────────────────────
class TestBypass:
    @pytest.mark.asyncio
    async def test_vulnerable_bypass(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"evil.attacker.com"
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_bypass(
            mock_client, "https://test.com", "test.com", "evil.attacker.com",
        )
        assert len(results) == 5
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) > 0
        assert all(r.category == "bypass" for r in results)


# ─── Print Results ───────────────────────────────────────────────────────────
class TestPrintResults:
    def test_vulnerable_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = HostInjectResult(
            target="https://test.com", injected_host="evil.com", tls=True,
            attempts=[HostInjectAttempt(
                technique="host_reflected", category="reflected",
                header_name="Host", header_value="evil.com",
                status=200, size=100, vulnerable=True,
                details="Host refletido no body", error="",
            )],
            vulnerable_techniques=["host_reflected"],
            blocked_techniques=[], issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Vulnerabilidades detectadas" in output
        assert "host_reflected" in output

    def test_no_vulns_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = HostInjectResult(
            target="https://test.com", injected_host="evil.com", tls=True,
            attempts=[], vulnerable_techniques=[], blocked_techniques=[],
            issues=[], overall_status="safe",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Nenhum Host Header Injection detectado" in output

    def test_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = HostInjectResult(
            target="https://test.com", injected_host="evil.com", tls=True,
            attempts=[], vulnerable_techniques=[], blocked_techniques=[],
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

    def test_has_inject_host(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "--inject-host", "evil.com"])
        assert args.inject_host == "evil.com"

    def test_default_inject_host(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.inject_host == _INJECTED_HOST

    def test_has_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "-c", "reflected"])
        assert args.category == "reflected"

    def test_default_category_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.category == "all"

    def test_all_categories(self) -> None:
        parser = build_parser()
        for cat in ["all", "reflected", "password_reset", "ssrf", "cache", "bypass"]:
            args = parser.parse_args(["https://test.com", "-c", cat])
            assert args.category == cat


# ─── Run Once ────────────────────────────────────────────────────────────────
class TestRunOnce:
    @patch("mytools.web.hostheaderinject.run_scan")
    def test_run_once(self, mock_run: MagicMock) -> None:
        mock_run.return_value = 0
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        from mytools.web.hostheaderinject import run_once
        result = run_once(args)
        assert result == 0
        mock_run.assert_called_once()
