"""Testes do modulo depscanner.py — Dependency Scanner."""

from __future__ import annotations

import argparse
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

import mytools.web.depscanner as depscanner_module
from mytools.core.utils import FetchError
from mytools.web.depscanner import (
    _BACKEND_LIBS,
    _CATEGORY_MAP,
    _FRONTEND_LIBS,
    DepScanAttempt,
    DepScanResult,
    _async_run_once,
    _check_cves,
    _check_outdated,
    _check_url,
    _detect_backend_deps,
    _detect_frontend_deps,
    _parse_manifest_version,
    _parse_version_list,
    _try_sourcemap_version,
    _version_in_range,
    build_parser,
    print_results,
    run_once,
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

    def test_greater_than(self) -> None:
        assert _version_in_range("4.0.0", ">3.5.0") is True
        assert _version_in_range("3.5.0", ">3.5.0") is False

    def test_unknown_operator(self) -> None:
        assert _version_in_range("3.5.0", "3.5.0") is False


# ---------------------------------------------------------------------------
# Check URL
# ---------------------------------------------------------------------------


class TestTrySourcemapVersion:
    @respx.mock
    @pytest.mark.asyncio
    async def test_success(self) -> None:
        respx.get("https://example.com/app.js.map").mock(
            return_value=httpx.Response(200, json={"version": "1.2.3"})
        )
        async with httpx.AsyncClient() as client:
            ver = await _try_sourcemap_version(client, "https://example.com", "/app.js")
        assert ver == "1.2.3"

    @respx.mock
    @pytest.mark.asyncio
    async def test_not_found(self) -> None:
        respx.get("https://example.com/app.js.map").mock(
            return_value=httpx.Response(404, text="")
        )
        async with httpx.AsyncClient() as client:
            ver = await _try_sourcemap_version(client, "https://example.com", "/app.js")
        assert ver == ""

    @respx.mock
    @pytest.mark.asyncio
    async def test_invalid_json(self) -> None:
        respx.get("https://example.com/app.js.map").mock(
            return_value=httpx.Response(200, text="not json")
        )
        async with httpx.AsyncClient() as client:
            ver = await _try_sourcemap_version(client, "https://example.com", "/app.js")
        assert ver == ""


class TestCheckUrl:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_status_and_body(self) -> None:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="hello")
        )
        async with httpx.AsyncClient() as client:
            status, body = await _check_url(client, "https://example.com", "/")
            assert status == 200
            assert body == "hello"

    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_0_on_fetch_error(self) -> None:
        async def _handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("fail")

        respx.route(method="GET", url="https://example.com/missing").mock(
            side_effect=_handler
        )
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
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
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
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            deps = await _detect_frontend_deps(client, "https://example.com")
            found = [d for d in deps if d.library == "react" and d.version]
            assert len(found) == 1
            assert found[0].version == "18.2.0"

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_deps_detected(self) -> None:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="<html></html>")
        )
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
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
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
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="")
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            deps = await _detect_frontend_deps(client, "https://example.com")
            assert deps == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_link_tag(self) -> None:
        html = (
            '<link rel="stylesheet" '
            'href="https://cdn.example.com/bulma@1.0.0/css/bulma.min.css">'
        )
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            deps = await _detect_frontend_deps(client, "https://example.com")
            found = [d for d in deps if d.library == "bulma" and d.version]
            assert len(found) == 1
            assert found[0].version == "1.0.0"

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_meta_tag(self) -> None:
        html = (
            '<meta name="description" '
            'content="built via https://cdn.example.com/react@18.2.0">'
        )
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            deps = await _detect_frontend_deps(client, "https://example.com")
            found = [d for d in deps if d.library == "react" and d.version]
            assert len(found) == 1
            assert found[0].version == "18.2.0"

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_react_via_sourcemap(self) -> None:
        class _FakeScriptRE:
            def __init__(self, src: str) -> None:
                self._src = src
                self._calls = 0

            def finditer(self, body: str):
                self._calls += 1
                if self._calls >= 2:
                    yield SimpleNamespace(group=lambda n: self._src)

        src = "https://cdn.example.com/react.production.min.js"
        html = f'<script src="{src}"></script>'
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            with (
                patch.object(depscanner_module, "_SCRIPT_RE", _FakeScriptRE(src)),
                patch(
                    "mytools.web.depscanner._try_sourcemap_version",
                    new_callable=AsyncMock,
                ) as mock_sm,
            ):
                mock_sm.return_value = "18.2.0"
                deps = await _detect_frontend_deps(client, "https://example.com")
            found = [d for d in deps if d.library == "react" and d.version]
            assert len(found) == 1
            assert found[0].version == "18.2.0"
            mock_sm.assert_awaited_once()

    @respx.mock
    @pytest.mark.asyncio
    async def test_sourcemap_no_version(self) -> None:
        class _FakeScriptRE:
            def __init__(self, src: str) -> None:
                self._src = src
                self._calls = 0

            def finditer(self, body: str):
                self._calls += 1
                if self._calls >= 2:
                    yield SimpleNamespace(group=lambda n: self._src)

        src = "https://cdn.example.com/react.production.min.js"
        html = f'<script src="{src}"></script>'
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            with (
                patch.object(depscanner_module, "_SCRIPT_RE", _FakeScriptRE(src)),
                patch(
                    "mytools.web.depscanner._try_sourcemap_version",
                    new_callable=AsyncMock,
                ) as mock_sm,
            ):
                mock_sm.return_value = ""
                deps = await _detect_frontend_deps(client, "https://example.com")
            found = [d for d in deps if d.library == "react" and d.version]
            assert found == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_script_link_and_meta(self) -> None:
        html = (
            '<script src="https://cdn.example.com/jquery-3.4.1.min.js"></script>'
            '<link rel="stylesheet" '
            'href="https://cdn.example.com/bootstrap@5.3.0/dist/css/bootstrap.min.css">'
            '<meta name="description" '
            'content="via https://cdn.example.com/react@18.2.0">'
        )
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            deps = await _detect_frontend_deps(client, "https://example.com")
        names = {d.library for d in deps if d.version}
        assert {"jquery", "bootstrap", "react"} <= names


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
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="hello")
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            deps = await _detect_backend_deps(client, "https://example.com")
            found = [d for d in deps if d.version]
            assert found == []

    @pytest.mark.asyncio
    async def test_fetch_error(self) -> None:
        mock_client = AsyncMock()
        with patch(
            "mytools.web.depscanner.fetch",
            side_effect=FetchError(
                "https://example.com", 3, httpx.ConnectError("boom")
            ),
        ):
            deps = await _detect_backend_deps(mock_client, "https://example.com")
        assert deps == []

    @pytest.mark.asyncio
    async def test_cookies_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=RuntimeError("boom"))
        with (
            patch("mytools.web.depscanner.fetch", return_value=(404, {}, b"", {})),
            patch("mytools.web.depscanner._check_url", return_value=(404, "")),
        ):
            deps = await _detect_backend_deps(mock_client, "https://example.com")
        assert isinstance(deps, list)

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_cookie(self) -> None:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(
                200,
                text="hello",
                headers={"Set-Cookie": "connect.sid=abc"},
            )
        )
        async with httpx.AsyncClient() as client:
            deps = await _detect_backend_deps(client, "https://example.com")
            found = [d for d in deps if d.library == "express"]
            assert len(found) == 1
            assert found[0].details == "Cookie: connect.sid"

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_error_pattern(self) -> None:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="at Layer.handle")
        )
        async with httpx.AsyncClient() as client:
            deps = await _detect_backend_deps(client, "https://example.com")
            found = [d for d in deps if d.library == "express"]
            assert len(found) == 1
            assert found[0].details == "Error page pattern: at Layer.handle"

    @pytest.mark.asyncio
    async def test_detects_manifest(self) -> None:
        backend = dict(depscanner_module._BACKEND_LIBS)
        express = dict(backend["express"])
        express["manifest_key_pattern"] = r'"express":\s*"(\^?\d+\.\d+\.\d+)"'
        backend["express"] = express

        calls = {"package_json": 0}

        async def fake_check_url(
            client: object, base_url: str, path: str
        ) -> tuple[int, str]:
            if path == "/package.json":
                calls["package_json"] += 1
                if calls["package_json"] == 1:
                    return 200, '{"dependencies": {"express": "^4.19.2"}}'
            return 404, ""

        mock_client = AsyncMock()
        with (
            patch.object(depscanner_module, "_BACKEND_LIBS", backend),
            patch("mytools.web.depscanner._check_url", new=fake_check_url),
            patch(
                "mytools.web.depscanner.fetch",
                return_value=(200, {}, b"<html></html>", {}),
            ),
        ):
            deps = await _detect_backend_deps(mock_client, "https://example.com")
        found = [d for d in deps if d.library == "express"]
        assert len(found) == 1
        assert found[0].version == "4.19.2"
        assert found[0].source == "manifest"

    @pytest.mark.asyncio
    async def test_manifest_no_match_branches(self) -> None:
        backend = dict(depscanner_module._BACKEND_LIBS)
        for sig in backend.values():
            if sig.get("manifest_key_pattern"):
                sig["manifest_key_pattern"] = r'"([\d]+\.[\d]+\.[\d]+)"'
        backend["ghostman"] = {
            "headers": [],
            "cookies": [],
            "error_patterns": [],
            "manifest_paths": ["/ghost.json"],
            "manifest_key_pattern": "",
        }

        async def fake_check_url(
            client: object, base_url: str, path: str
        ) -> tuple[int, str]:
            return 200, '{"no_version": true}'

        mock_client = AsyncMock()
        with (
            patch.object(depscanner_module, "_BACKEND_LIBS", backend),
            patch("mytools.web.depscanner._check_url", new=fake_check_url),
            patch(
                "mytools.web.depscanner.fetch",
                return_value=(200, {}, b"<html></html>", {}),
            ),
        ):
            deps = await _detect_backend_deps(mock_client, "https://example.com")
        assert isinstance(deps, list)


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

    def test_skips_lib_without_latest(self, monkeypatch: pytest.MonkeyPatch) -> None:
        backend = dict(depscanner_module._BACKEND_LIBS)
        backend["ghost"] = {"headers": []}
        monkeypatch.setattr(depscanner_module, "_BACKEND_LIBS", backend)
        deps = [
            DepScanAttempt(
                technique="backend_probe",
                category="backend_deps",
                library="ghost",
                version="1.0.0",
                source="header",
                severity="",
                details="",
                error="",
            )
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
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
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
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="<html></html>")
        )
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
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="<html></html>")
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        result = await scan_dependency(
            base_url="https://example.com",
            categories=["frontend_deps"],
            timeout=5.0,
        )
        assert result.target == "https://example.com"

    @respx.mock
    @pytest.mark.asyncio
    async def test_backend_only(self) -> None:
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="<html></html>")
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        result = await scan_dependency(
            base_url="https://example.com",
            categories=["backend_deps"],
            timeout=5.0,
        )
        assert result.target == "https://example.com"
        assert result.overall_status == "secure"

    @respx.mock
    @pytest.mark.asyncio
    async def test_outdated_overall(self) -> None:
        html = '<script src="https://cdn.example.com/jquery-3.4.1.min.js"></script>'
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text=html)
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        result = await scan_dependency(
            base_url="https://example.com",
            categories=["frontend_deps", "outdated_check"],
            timeout=5.0,
        )
        assert result.overall_status == "outdated"
        assert "jquery 3.4.1" in result.outdated_deps


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
        args = p.parse_args(
            [
                "https://example.com",
                "-c",
                "frontend_deps",
                "cve_check",
            ]
        )
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

    def test_print_with_deps(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DepScanResult(
            target="https://example.com",
            attempts=[
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
                DepScanAttempt(
                    technique="backend_probe",
                    category="backend_deps",
                    library="express",
                    version="",
                    source="header",
                    severity="",
                    details="",
                    error="",
                ),
                DepScanAttempt(
                    technique="cve_match",
                    category="cve_check",
                    library="jquery",
                    version="3.4.1",
                    source="script_src",
                    severity="medium",
                    details="CVE-2020-11022",
                    error="",
                ),
            ],
            vulnerable_deps=["jQuery 3.4.1"],
            outdated_deps=["jQuery 3.4.1"],
            overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Outdated dependencies:" in output
        assert "jQuery 3.4.1" in output
        assert "frontend_deps:" in output
        assert "jquery v3.4.1 (script_src)" in output
        assert "backend_deps: no dependencies found" in output
        assert "cve_check:" not in output


# ---------------------------------------------------------------------------
# Async run once / run once / main
# ---------------------------------------------------------------------------


class TestAsyncRunOnce:
    def test_runs_scan(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
        result = DepScanResult(
            target="https://example.com",
            attempts=[],
            vulnerable_deps=[],
            outdated_deps=[],
            overall_status="secure",
        )
        monkeypatch.setattr(
            depscanner_module, "scan_dependency", AsyncMock(return_value=result)
        )
        monkeypatch.setattr(depscanner_module, "init_scanner", lambda args: False)
        monkeypatch.setattr(depscanner_module, "print_results", lambda r: None)
        args = argparse.Namespace(
            url="example.com",
            categories=None,
            timeout=5.0,
            output=str(tmp_path / "out.json"),
        )
        out = _async_run_once(args)
        assert out.overall_status == "secure"
        assert (tmp_path / "out.json").exists()

    def test_runs_scan_with_scheme_no_output(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        result = DepScanResult(
            target="https://example.com",
            attempts=[],
            vulnerable_deps=[],
            outdated_deps=[],
            overall_status="secure",
        )
        monkeypatch.setattr(
            depscanner_module, "scan_dependency", AsyncMock(return_value=result)
        )
        monkeypatch.setattr(depscanner_module, "init_scanner", lambda args: False)
        monkeypatch.setattr(depscanner_module, "print_results", lambda r: None)
        args = argparse.Namespace(
            url="https://example.com",
            categories=["frontend_deps"],
            timeout=5.0,
            output=None,
        )
        out = _async_run_once(args)
        assert out.target == "https://example.com"


class TestRunOnce:
    def test_returns_zero(self, monkeypatch: pytest.MonkeyPatch) -> None:
        result = DepScanResult(
            target="https://example.com",
            attempts=[],
            vulnerable_deps=[],
            outdated_deps=[],
            overall_status="secure",
        )
        monkeypatch.setattr(
            depscanner_module, "_async_run_once", MagicMock(return_value=result)
        )
        args = argparse.Namespace()
        assert run_once(args) == 0


class TestMain:
    def test_runs_loop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            depscanner_module,
            "run_main_loop",
            lambda *args, **kwargs: 42,
        )
        assert depscanner_module.main() == 42

    def test_main_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import runpy

        def _raise() -> int:
            raise SystemExit(0)

        monkeypatch.setattr(depscanner_module, "main", _raise)
        with pytest.raises(SystemExit):
            runpy.run_module("mytools.web.depscanner", run_name="__main__")
