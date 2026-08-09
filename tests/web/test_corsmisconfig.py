#!/usr/bin/env python3
"""Testes unitarios do modulo de CORS Misconfiguration."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.corsmisconfig import (
    _CATEGORY_MAP,
    CORSAttempt,
    CORSResult,
    _check_cors_headers,
    _get_domain_variants,
    _test_bypass,
    _test_credentials,
    _test_null_origin,
    _test_reflected,
    _test_subdomain,
    build_parser,
    print_results,
)


# ─── Category Map ────────────────────────────────────────────────────────────
class TestCategoryMap:
    def test_has_five_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 5

    def test_categories_are_correct(self) -> None:
        expected = {"null_origin", "subdomain", "credentials", "reflected", "bypass"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_all_categories_have_5_techniques(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) == 5, f"Categoria {cat} tem {len(techs)} tecnicas"


# ─── Domain Variants ─────────────────────────────────────────────────────────
class TestDomainVariants:
    def test_generates_variants(self) -> None:
        variants = _get_domain_variants("https://example.com")
        assert len(variants) == 5

    def test_strips_scheme(self) -> None:
        variants = _get_domain_variants("https://example.com")
        for v in variants:
            assert "example.com" in v

    def test_without_scheme(self) -> None:
        variants = _get_domain_variants("example.com")
        assert len(variants) == 5


# ─── Check CORS Headers ──────────────────────────────────────────────────────
class TestCheckCORSHeaders:
    def test_null_origin_accepted(self) -> None:
        vuln, details = _check_cors_headers(
            {"access-control-allow-origin": "null"},
            "null",
        )
        assert vuln is True
        assert "null" in details.lower()

    def test_wildcard_with_credentials(self) -> None:
        vuln, details = _check_cors_headers(
            {
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            },
            "https://evil.com",
        )
        assert vuln is True
        assert "wildcard" in details.lower()

    def test_reflected_origin(self) -> None:
        origin = "https://evil.com"
        vuln, details = _check_cors_headers(
            {"access-control-allow-origin": origin},
            origin,
        )
        assert vuln is True
        assert "refletido" in details.lower()

    def test_no_acao(self) -> None:
        vuln, details = _check_cors_headers({}, "https://evil.com")
        assert vuln is False
        assert details == ""

    def test_acao_not_matching(self) -> None:
        vuln, _details = _check_cors_headers(
            {"access-control-allow-origin": "https://safe.com"},
            "https://evil.com",
        )
        assert vuln is False

    def test_wildcard_without_credentials(self) -> None:
        vuln, _details = _check_cors_headers(
            {"access-control-allow-origin": "*"},
            "https://evil.com",
        )
        assert vuln is False

    def test_subdomain_wildcard(self) -> None:
        vuln, details = _check_cors_headers(
            {"access-control-allow-origin": "*.example.com"},
            "https://evil.com",
        )
        assert vuln is True
        assert "wildcard" in details.lower()


# ─── Dataclasses ─────────────────────────────────────────────────────────────
class TestCORSAttempt:
    def test_frozen(self) -> None:
        a = CORSAttempt(
            technique="test",
            category="null_origin",
            origin="null",
            acao="null",
            acac="true",
            status=200,
            vulnerable=True,
            details="test",
            error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "other"  # type: ignore[misc]

    def test_slots(self) -> None:
        a = CORSAttempt(
            technique="test",
            category="null_origin",
            origin="null",
            acao="null",
            acac="true",
            status=200,
            vulnerable=True,
            details="test",
            error="",
        )
        assert not hasattr(a, "__dict__")


class TestCORSResult:
    def test_frozen(self) -> None:
        r = CORSResult(
            target="https://test.com",
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="safe",
        )
        with pytest.raises(AttributeError):
            r.target = "other"  # type: ignore[misc]


# ─── Test Null Origin ────────────────────────────────────────────────────────
class TestNullOrigin:
    @pytest.mark.asyncio
    async def test_vulnerable_null_origin(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "access-control-allow-origin": "null",
            "access-control-allow-credentials": "true",
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_null_origin(mock_client, "https://test.com")
        assert len(results) == 5
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) > 0
        assert vuln[0].category == "null_origin"

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_null_origin(mock_client, "https://test.com")
        assert len(results) == 5
        assert all(r.error for r in results)


# ─── Test Subdomain ──────────────────────────────────────────────────────────
class TestSubdomain:
    @pytest.mark.asyncio
    async def test_vulnerable_subdomain(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "access-control-allow-origin": "https://evil-example.com",
            "access-control-allow-credentials": "true",
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_subdomain(
            mock_client,
            "https://test.com",
            "https://test.com",
        )
        assert len(results) == 5
        assert all(r.category == "subdomain" for r in results)

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_subdomain(
            mock_client,
            "https://test.com",
            "https://test.com",
        )
        assert len(results) == 5
        assert all(r.error for r in results)


# ─── Test Credentials ────────────────────────────────────────────────────────
class TestCredentials:
    @pytest.mark.asyncio
    async def test_vulnerable_credentials(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        }
        mock_client = AsyncMock()
        mock_client.options = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_credentials(
            mock_client,
            "https://test.com",
            "https://test.com",
        )
        assert len(results) == 5
        assert all(r.category == "credentials" for r in results)

    @pytest.mark.asyncio
    async def test_preflight_checks(self) -> None:
        resp_wild = MagicMock()
        resp_wild.status_code = 200
        resp_wild.headers = {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        }
        resp_origin = MagicMock()
        resp_origin.status_code = 200
        resp_origin.headers = {
            "access-control-allow-origin": "https://safe.com",
            "access-control-allow-credentials": "true",
        }
        mock_client = AsyncMock()
        mock_client.options = AsyncMock(
            side_effect=[resp_wild, resp_wild, resp_origin, resp_origin, resp_origin]
        )
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "mytools.web.corsmisconfig._check_cors_headers", return_value=(False, "")
        ):
            results = await _test_credentials(
                mock_client,
                "https://test.com",
                "https://test.com",
            )
        assert len(results) == 5
        assert all(r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_preflight_no_vulnerability(self) -> None:
        resp_safe = MagicMock()
        resp_safe.status_code = 200
        resp_safe.headers = {
            "access-control-allow-origin": "https://safe.com",
            "access-control-allow-credentials": "false",
        }
        mock_client = AsyncMock()
        mock_client.options = AsyncMock(return_value=resp_safe)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "mytools.web.corsmisconfig._check_cors_headers", return_value=(False, "")
        ):
            results = await _test_credentials(
                mock_client,
                "https://test.com",
                "https://test.com",
            )
        assert len(results) == 5
        assert all(not r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.options = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_credentials(
            mock_client,
            "https://test.com",
            "https://test.com",
        )
        assert len(results) == 5
        assert all(r.error for r in results)


# ─── Test Reflected ──────────────────────────────────────────────────────────
class TestReflected:
    @pytest.mark.asyncio
    async def test_vulnerable_reflected(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "access-control-allow-origin": "https://evil-test.com",
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_reflected(
            mock_client,
            "https://test.com",
            "https://test.com",
        )
        assert len(results) == 5
        assert all(r.category == "reflected" for r in results)

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_reflected(
            mock_client,
            "https://test.com",
            "https://test.com",
        )
        assert len(results) == 5
        assert all(r.error for r in results)


# ─── Test Bypass ─────────────────────────────────────────────────────────────
class TestBypass:
    @pytest.mark.asyncio
    async def test_vulnerable_bypass(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "access-control-allow-origin": "https://evil-test.com",
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_bypass(
            mock_client,
            "https://test.com",
            "https://test.com",
        )
        assert len(results) == 5
        assert all(r.category == "bypass" for r in results)

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_bypass(
            mock_client,
            "https://test.com",
            "https://test.com",
        )
        assert len(results) == 5
        assert all(r.error for r in results)


# ─── Print Results ───────────────────────────────────────────────────────────
class TestPrintResults:
    def test_vulnerable_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CORSResult(
            target="https://test.com",
            tls=True,
            attempts=[
                CORSAttempt(
                    technique="null_origin",
                    category="null_origin",
                    origin="null",
                    acao="null",
                    acac="true",
                    status=200,
                    vulnerable=True,
                    details="Origin null aceito",
                    error="",
                )
            ],
            vulnerable_techniques=["null_origin"],
            blocked_techniques=[],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Vulnerabilidades detectadas" in output
        assert "null_origin" in output

    def test_no_vulns_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CORSResult(
            target="https://test.com",
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="safe",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Nenhuma CORS Misconfiguration detectada" in output

    def test_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CORSResult(
            target="https://test.com",
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=["Nenhum teste retornou resultado claro"],
            overall_status="unknown",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Observacoes" in output

    def test_duplicate_key_and_empty_details(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        def _attempt(technique: str, origin: str, details: str) -> CORSAttempt:
            return CORSAttempt(
                technique=technique,
                category="null_origin",
                origin=origin,
                acao="null",
                acac="true",
                status=200,
                vulnerable=True,
                details=details,
                error="",
            )

        result = CORSResult(
            target="https://test.com",
            tls=True,
            attempts=[
                _attempt("null_origin", "null", "Origin null aceito"),
                _attempt("null_origin", "null", ""),
                _attempt("null_origin_acac", "null", ""),
            ],
            vulnerable_techniques=["null_origin", "null_origin_acac"],
            blocked_techniques=[],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Total" in output
        assert "Detalhes" in output


# ─── Run Scan ────────────────────────────────────────────────────────────────
class TestRunScan:
    def _mock_cm(self, client: AsyncMock) -> MagicMock:
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        return MagicMock(return_value=client)

    @pytest.mark.asyncio
    async def test_vulnerable_all_categories(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "access-control-allow-origin": "*",
            "access-control-allow-credentials": "true",
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.options = AsyncMock(return_value=mock_resp)
        cm = self._mock_cm(mock_client)

        from mytools.web.corsmisconfig import run_scan

        with patch("mytools.web.corsmisconfig.create_async_client", cm):
            result = await run_scan(
                target="https://test.com",
                categories=[],
                timeout=10.0,
                output_file=None,
            )
        assert result == 1

    @pytest.mark.asyncio
    async def test_safe_null_origin(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {
            "access-control-allow-origin": "https://safe.com",
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.options = AsyncMock(return_value=mock_resp)
        cm = self._mock_cm(mock_client)

        from mytools.web.corsmisconfig import run_scan

        with patch("mytools.web.corsmisconfig.create_async_client", cm):
            result = await run_scan(
                target="test.com",
                categories=["null_origin"],
                timeout=10.0,
                output_file=None,
            )
        assert result == 0

    @pytest.mark.asyncio
    async def test_unknown_category_json_output(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("boom"))
        mock_client.options = AsyncMock(side_effect=httpx.RequestError("boom"))
        cm = self._mock_cm(mock_client)

        from mytools.web.corsmisconfig import run_scan

        with (
            patch("mytools.web.corsmisconfig.create_async_client", cm),
            patch("mytools.web.corsmisconfig.print_json") as mock_json,
            patch("mytools.web.corsmisconfig.write_output") as mock_write,
        ):
            result = await run_scan(
                target="test.com",
                categories=["invalid"],
                timeout=10.0,
                output_file="out.json",
                json_output=True,
            )
        assert result == 0
        mock_json.assert_called_once()
        mock_write.assert_called_once()


# ─── Banner Art ──────────────────────────────────────────────────────────────
class TestBannerArt:
    def test_banner_art(self) -> None:
        from mytools.web.corsmisconfig import banner_art

        with patch("mytools.web.corsmisconfig.create_banner") as mock_banner:
            banner_art()
            mock_banner.assert_called_once()


# ─── Build Parser ────────────────────────────────────────────────────────────
@pytest.mark.smoke
class TestBuildParser:
    def test_has_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.url == "https://test.com"

    def test_has_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "-c", "null_origin"])
        assert args.category == "null_origin"

    def test_default_category_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.category == "all"

    def test_all_categories(self) -> None:
        parser = build_parser()
        for cat in [
            "all",
            "null_origin",
            "subdomain",
            "credentials",
            "reflected",
            "bypass",
        ]:
            args = parser.parse_args(["https://test.com", "-c", cat])
            assert args.category == cat


# ─── Run Once ────────────────────────────────────────────────────────────────
class TestRunOnce:
    @patch("mytools.web.corsmisconfig.run_scan")
    def test_run_once(self, mock_run: MagicMock) -> None:
        mock_run.return_value = 0
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        from mytools.web.corsmisconfig import run_once

        result = run_once(args)
        assert result == 0
        mock_run.assert_called_once()

    @patch("mytools.web.corsmisconfig.run_scan")
    def test_run_once_with_category(self, mock_run: MagicMock) -> None:
        mock_run.return_value = 0
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "-c", "null_origin"])
        from mytools.web.corsmisconfig import run_once

        result = run_once(args)
        assert result == 0
        assert mock_run.call_args[1]["categories"] == ["null_origin"]


# ─── Main ────────────────────────────────────────────────────────────────────
class TestMain:
    def test_main(self) -> None:
        from mytools.web.corsmisconfig import main

        with patch(
            "mytools.web.corsmisconfig.run_main_loop", return_value=0
        ) as mock_loop:
            result = main()
            assert result == 0
            mock_loop.assert_called_once()


# ─── Main Guard ──────────────────────────────────────────────────────────────
class TestMainGuard:
    def test_guard_runs(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-cors", "https://test.com"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.corsmisconfig", run_name="__main__")
        assert exc_info.value.code == 0
