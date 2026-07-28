"""Testes do modulo depscanner.py — Dependency Scanner."""
from __future__ import annotations

import httpx
import pytest
import respx

from mytools.web.depscanner import (
    _BACKEND_LIBS,
    _CATEGORY_MAP,
    _FRONTEND_LIBS,
    DepScanAttempt,
    DepScanResult,
    _check_cves,
    _check_outdated,
    _check_url,
    _detect_backend_deps,
    _detect_frontend_deps,
    _parse_manifest_version,
    _parse_version_list,
    _version_in_range,
    build_parser,
    print_results,
    scan_dependency,
)

# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


class TestDepScanAttempt:
    def test_creation(self) -> None:
        a = DepScanAttempt(
            technique="frontend_probe",
            category="frontend_deps",
            library="jQuery",
            version="3.4.1",
            source="script_src",
            severity="",
            details="Detected in HTML source",
            error="",
        )
        assert a.library == "jQuery"
        assert a.version == "3.4.1"

    def test_frozen(self) -> None:
        a = DepScanAttempt(
            technique="t",
            category="c",
            library="lib",
            version="1.0.0",
            source="s",
            severity="",
            details="",
            error="",
        )
        with pytest.raises(AttributeError):
            a.library = "other"  # type: ignore[misc]


class TestDepScanResult:
    def test_creation(self) -> None:
        r = DepScanResult(
            target="https://example.com",
            attempts=[],
            vulnerable_deps=[],
            outdated_deps=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"

    def test_frozen(self) -> None:
        r = DepScanResult(
            target="https://example.com",
            attempts=[],
            vulnerable_deps=[],
            outdated_deps=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "other"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Category map + signatures
# ---------------------------------------------------------------------------


class TestCategoryMap:
    def test_has_four_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 4

    def test_expected_keys(self) -> None:
        expected = {"frontend_deps", "backend_deps", "cve_check", "outdated_check"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_each_has_one_technique(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) == 1, f"{cat} should have 1 technique"


class TestFrontendSignatures:
    def test_has_all_libs(self) -> None:
        assert len(_FRONTEND_LIBS) >= 25

    def test_joomla_has_patterns(self) -> None:
        jquery = _FRONTEND_LIBS.get("jquery", {})
        assert "patterns" in jquery
        assert len(jquery["patterns"]) >= 2

    def test_react_has_sourcemap(self) -> None:
        react = _FRONTEND_LIBS.get("react", {})
        assert react.get("sourcemap") is True

    def test_all_have_cves_key(self) -> None:
        for lib_name, sig in _FRONTEND_LIBS.items():
            assert "cves" in sig, f"{lib_name} missing cves key"
            assert "latest_known" in sig, f"{lib_name} missing latest_known"


class TestBackendSignatures:
    def test_has_all_libs(self) -> None:
        assert len(_BACKEND_LIBS) >= 10

    def test_express_has_headers(self) -> None:
        express = _BACKEND_LIBS.get("express", {})
        assert "headers" in express
        assert any("Express" in h for h in express["headers"])

    def test_laravel_has_cookies(self) -> None:
        laravel = _BACKEND_LIBS.get("laravel", {})
        assert "cookies" in laravel
        assert "laravel_session" in laravel["cookies"]

    def test_all_have_cves_key(self) -> None:
        for lib_name, sig in _BACKEND_LIBS.items():
            assert "cves" in sig, f"{lib_name} missing cves key"
            assert "latest_known" in sig, f"{lib_name} missing latest_known"


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestParseManifestVersion:
    def test_extracts_version(self) -> None:
        body = '"express": "^4.19.2"'
        pat = r'"express":\s*"(\^?\d+\.\d+\.\d+)"'
        assert _parse_manifest_version(body, pat) == "4.19.2"

    def test_no_version(self) -> None:
        body = '"express": "latest"'
        pat = r'"express":\s*"(\^?\d+\.\d+\.\d+)"'
        assert _parse_manifest_version(body, pat) == ""

    def test_strips_range_prefix(self) -> None:
        body = '"laravel/framework": "~11.0.0"'
        pat = r'"laravel/framework":\s*"([~^]?\d+\.\d+\.\d+)"'
        assert _parse_manifest_version(body, pat) == "11.0.0"


class TestParseVersionList:
    def test_standard_version(self) -> None:
        assert _parse_version_list("3.5.0") == [3, 5, 0]

    def test_two_part_version(self) -> None:
        assert _parse_version_list("11.0") == [11, 0]

    def test_version_with_prefix(self) -> None:
        assert _parse_version_list("v2.1.3") == [2, 1, 3]


class TestVersionInRange:
    def test_less_than(self) -> None:
        assert _version_in_range("3.4.1", "<3.5.0") is True

    def test_not_less_than(self) -> None:
        assert _version_in_range("3.5.0", "<3.5.0") is False

    def test_less_equal(self) -> None:
        assert _version_in_range("3.5.0", "<=3.5.0") is True

    def test_greater_equal(self) -> None:
        assert _version_in_range("4.0.0", ">=3.5.0") is True

    def test_equal(self) -> None:
        assert _version_in_range("3.5.0", "==3.5.0") is True

    def test_empty_version(self) -> None:
        assert _version_in_range("", "<3.5.0") is False

    def test_complex_version(self) -> None:
        assert _version_in_range("3.5.1", "<3.5.0") is False


# ---------------------------------------------------------------------------
# Check URL
# ---------------------------------------------------------------------------


class TestCheckUrl:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_status_and_body(self) -> None:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="hello"))
        async with httpx.AsyncClient() as client:
            status, body = await _check_url(client, "https://example.com", "/")
            assert status == 200
            assert body == "hello"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_0_on_fetch_error(self) -> None:
        async def _handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("fail")

        respx.route(method="GET", url="https://example.com/missing").mock(side_effect=_handler)
        async with httpx.AsyncClient() as client:
            status, body = await _check_url(client, "https://example.com", "/missing")
            assert status == 0
            assert body == ""


# ---------------------------------------------------------------------------
# Frontend detection
# ---------------------------------------------------------------------------


class TestDetectFrontendDeps:
    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_jquery(self) -> None:
        html = '<script src="https://cdn.example.com/jquery-3.4.1.min.js"></script>'
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            deps = await _detect_frontend_deps(client, "https://example.com")
            found = [d for d in deps if d.library == "jquery" and d.version]
            assert len(found) == 1
            assert found[0].version == "3.4.1"

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_react(self) -> None:
        html = '<script src="https://cdn.example.com/react@18.2.0/umd/react.production.min.js"></script>'
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            deps = await _detect_frontend_deps(client, "https://example.com")
            found = [d for d in deps if d.library == "react" and d.version]
            assert len(found) == 1
            assert found[0].version == "18.2.0"

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_deps_detected(self) -> None:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="<html></html>"))
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            deps = await _detect_frontend_deps(client, "https://example.com")
            found = [d for d in deps if d.version]
            assert found == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_multi_lib(self) -> None:
        html = """
        <script src="https://cdn.example.com/jquery-3.4.1.min.js"></script>
        <script src="https://cdn.example.com/bootstrap@5.3.0/dist/js/bootstrap.min.js"></script>
        """
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            deps = await _detect_frontend_deps(client, "https://example.com")
            found = [d for d in deps if d.version]
            names = {d.library for d in found}
            assert "jquery" in names
            assert "bootstrap" in names

    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_body(self) -> None:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=""))
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            deps = await _detect_frontend_deps(client, "https://example.com")
            assert deps == []


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------


class TestDetectBackendDeps:
    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_express_header(self) -> None:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(
                200,
                text="hello",
                headers={"X-Powered-By": "Express"},
            ),
        )
        async with httpx.AsyncClient() as client:
            deps = await _detect_backend_deps(client, "https://example.com")
            found = [d for d in deps if d.library == "express"]
            assert len(found) >= 1

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_backend_detected(self) -> None:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="hello"))
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            deps = await _detect_backend_deps(client, "https://example.com")
            found = [d for d in deps if d.version]
            assert found == []


# ---------------------------------------------------------------------------
# CVE check
# ---------------------------------------------------------------------------


class TestCheckCves:
    def test_vulnerable_found(self) -> None:
        deps = [
            DepScanAttempt(
                technique="frontend_probe",
                category="frontend_deps",
                library="jquery",
                version="3.4.1",
                source="script_src",
                severity="",
                details="",
                error="",
            ),
        ]
        results = _check_cves(deps)
        assert len(results) >= 1
        assert results[0].severity in ("medium", "high", "critical", "low")

    def test_clean_version(self) -> None:
        deps = [
            DepScanAttempt(
                technique="frontend_probe",
                category="frontend_deps",
                library="jquery",
                version="3.7.1",
                source="script_src",
                severity="",
                details="",
                error="",
            ),
        ]
        results = _check_cves(deps)
        assert results == []

    def test_multiple_cves(self) -> None:
        deps = [
            DepScanAttempt(
                technique="frontend_probe",
                category="frontend_deps",
                library="lodash",
                version="4.17.15",
                source="script_src",
                severity="",
                details="",
                error="",
            ),
        ]
        results = _check_cves(deps)
        assert len(results) >= 2


# ---------------------------------------------------------------------------
# Outdated check
# ---------------------------------------------------------------------------


class TestCheckOutdated:
    def test_outdated_found(self) -> None:
        deps = [
            DepScanAttempt(
                technique="frontend_probe",
                category="frontend_deps",
                library="jquery",
                version="3.4.1",
                source="script_src",
                severity="",
                details="",
                error="",
            ),
        ]
        results = _check_outdated(deps)
        assert len(results) >= 1
        assert results[0].library == "jquery"

    def test_up_to_date(self) -> None:
        deps = [
            DepScanAttempt(
                technique="frontend_probe",
                category="frontend_deps",
                library="jquery",
                version="3.7.1",
                source="script_src",
                severity="",
                details="",
                error="",
            ),
        ]
        results = _check_outdated(deps)
        assert results == []


# ---------------------------------------------------------------------------
# Scan integration
# ---------------------------------------------------------------------------


class TestScanDependency:
    @respx.mock
    @pytest.mark.asyncio
    async def test_full_scan(self) -> None:
        html = '<script src="https://cdn.example.com/jquery-3.4.1.min.js"></script>'
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text=html))
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        result = await scan_dependency(
            base_url="https://example.com",
            categories=None,
            timeout=5.0,
        )
        assert result.target == "https://example.com"
        assert isinstance(result.attempts, list)

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_deps(self) -> None:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="<html></html>"))
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        result = await scan_dependency(
            base_url="https://example.com",
            categories=None,
            timeout=5.0,
        )
        assert result.overall_status == "secure"

    @respx.mock
    @pytest.mark.asyncio
    async def test_categories_filter(self) -> None:
        respx.get("https://example.com/").mock(return_value=httpx.Response(200, text="<html></html>"))
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        result = await scan_dependency(
            base_url="https://example.com",
            categories=["frontend_deps"],
            timeout=5.0,
        )
        assert result.target == "https://example.com"


# ---------------------------------------------------------------------------
# Build parser
# ---------------------------------------------------------------------------


class TestBuildParser:
    def test_has_url_arg(self) -> None:
        p = build_parser()
        args = p.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_categories_arg(self) -> None:
        p = build_parser()
        args = p.parse_args([
            "https://example.com",
            "-c", "frontend_deps", "cve_check",
        ])
        assert args.categories == ["frontend_deps", "cve_check"]


# ---------------------------------------------------------------------------
# Print results
# ---------------------------------------------------------------------------


class TestPrintResults:
    def test_print_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DepScanResult(
            target="https://example.com",
            attempts=[],
            vulnerable_deps=[],
            outdated_deps=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Dependency Scanner" in output

    def test_print_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DepScanResult(
            target="https://example.com",
            attempts=[],
            vulnerable_deps=["jQuery 3.4.1"],
            outdated_deps=[],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Vulnerable" in output
        assert "jQuery 3.4.1" in output
