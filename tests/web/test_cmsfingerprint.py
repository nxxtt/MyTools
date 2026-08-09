"""Testes do modulo cmsfingerprint.py — CMS Fingerprinting."""

from __future__ import annotations

import argparse
import json
from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from mytools.web.cmsfingerprint import (
    _CATEGORY_MAP,
    _CMS_SIGNATURES,
    CmsAttempt,
    CmsResult,
    _check_path,
    _detect_cms,
    _detect_joomla_info,
    _detect_wp_plugins,
    _detect_wp_themes,
    _detect_wp_users,
    _detect_wp_version,
    build_parser,
    print_results,
    scan_cms_fingerprint,
)

# ---------------------------------------------------------------------------
# Dataclass tests
# ---------------------------------------------------------------------------


class TestCmsAttempt:
    def test_creation(self) -> None:
        a = CmsAttempt(
            technique="cms_identify",
            category="cms_detect",
            description="CMS detected: wordpress",
            status_code=200,
            vulnerable=True,
            details="CMS: wordpress",
            error="",
        )
        assert a.technique == "cms_identify"
        assert a.vulnerable is True

    def test_frozen(self) -> None:
        a = CmsAttempt(
            technique="t",
            category="c",
            description="d",
            status_code=200,
            vulnerable=False,
            details="",
            error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestCmsResult:
    def test_creation(self) -> None:
        r = CmsResult(
            target="https://example.com",
            cms_detected="wordpress",
            version="6.4",
            attempts=[],
            issues=[],
            overall_status="vulnerable",
        )
        assert r.cms_detected == "wordpress"
        assert r.version == "6.4"

    def test_frozen(self) -> None:
        r = CmsResult(
            target="t",
            cms_detected="",
            version="",
            attempts=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# Category map tests
# ---------------------------------------------------------------------------


class TestCategoryMap:
    def test_has_six_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 6

    def test_categories(self) -> None:
        expected = {
            "cms_detect",
            "wp_version",
            "wp_plugins",
            "wp_themes",
            "wp_users",
            "joomla_info",
        }
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_each_has_one_technique(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) == 1, f"{cat} should have 1 technique"


# ---------------------------------------------------------------------------
# CMS signatures tests
# ---------------------------------------------------------------------------


class TestCmsSignatures:
    def test_has_all_cms(self) -> None:
        expected = {
            "wordpress",
            "joomla",
            "drupal",
            "magento",
            "prestashop",
            "opencart",
        }
        assert set(_CMS_SIGNATURES.keys()) == expected

    def test_wordbook_has_detect_paths(self) -> None:
        assert "detect_paths" in _CMS_SIGNATURES["wordpress"]

    def test_wordpress_has_plugins(self) -> None:
        assert len(_CMS_SIGNATURES["wordpress"]["plugins"]) >= 5

    def test_joomla_has_third_party(self) -> None:
        exts = _CMS_SIGNATURES["joomla"]["third_party_extensions"]
        assert len(exts) >= 3
        # No core extensions
        for ext in exts:
            assert ext not in ("com_content", "com_users", "com_media", "com_banners")


# ---------------------------------------------------------------------------
# HTTP helper tests
# ---------------------------------------------------------------------------


class TestCheckPath:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_status_and_body(self) -> None:
        respx.get("https://example.com/test").mock(
            return_value=httpx.Response(200, text="hello")
        )
        async with httpx.AsyncClient() as client:
            status, body = await _check_path(client, "https://example.com", "/test")
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
            status, body = await _check_path(client, "https://example.com", "/missing")
            assert status == 0
            assert body == ""


# ---------------------------------------------------------------------------
# CMS detection tests
# ---------------------------------------------------------------------------


class TestDetectCms:
    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_wordbook(self) -> None:
        respx.get("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(200, text="login")
        )
        respx.get("https://example.com/wp-admin/").mock(
            return_value=httpx.Response(302, text="redirect")
        )
        async with httpx.AsyncClient() as client:
            cms = await _detect_cms(client, "https://example.com")
            assert cms == "wordpress"

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_cms_detected(self) -> None:
        respx.route(method="GET", url="https://example.com/wp-login.php").mock(
            return_value=httpx.Response(404, text="not found"),
        )
        respx.route(method="GET", url="https://example.com/wp-admin/").mock(
            return_value=httpx.Response(404, text="not found"),
        )
        respx.route(method="GET").mock(
            return_value=httpx.Response(404, text="not found")
        )
        async with httpx.AsyncClient() as client:
            cms = await _detect_cms(client, "https://example.com")
            assert cms == ""


# ---------------------------------------------------------------------------
# WordPress detection tests
# ---------------------------------------------------------------------------


class TestDetectWpVersion:
    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_from_readme(self) -> None:
        respx.get("https://example.com/readme.html").mock(
            return_value=httpx.Response(200, text="<h1>Welcome</h1>Version 6.4.2</p>")
        )
        async with httpx.AsyncClient() as client:
            version, evidence = await _detect_wp_version(client, "https://example.com")
            assert version == "6.4.2"
            assert "readme.html" in evidence

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_from_generator(self) -> None:
        respx.get("https://example.com/readme.html").mock(
            return_value=httpx.Response(404, text="")
        )
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(
                200, text='<meta name="generator" content="WordPress 6.3.1" />'
            )
        )
        async with httpx.AsyncClient() as client:
            version, evidence = await _detect_wp_version(client, "https://example.com")
            assert version == "6.3.1"
            assert "generator" in evidence

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_from_version_php(self) -> None:
        respx.get("https://example.com/readme.html").mock(
            return_value=httpx.Response(200, text="no version here")
        )
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="no generator meta")
        )
        respx.get("https://example.com/wp-includes/version.php").mock(
            return_value=httpx.Response(200, text="$wp_version = '6.2.0';")
        )
        async with httpx.AsyncClient() as client:
            version, evidence = await _detect_wp_version(client, "https://example.com")
            assert version == "6.2.0"
            assert "version.php" in evidence

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_version_found(self) -> None:
        async def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="")

        respx.route(method="GET", url="https://example.com/readme.html").mock(
            side_effect=_handler
        )
        respx.route(method="GET", url="https://example.com/").mock(side_effect=_handler)
        respx.route(
            method="GET", url="https://example.com/wp-includes/version.php"
        ).mock(side_effect=_handler)
        async with httpx.AsyncClient() as client:
            version, _evidence = await _detect_wp_version(client, "https://example.com")
            assert version == ""

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_match_in_version_php(self) -> None:
        respx.get("https://example.com/readme.html").mock(
            return_value=httpx.Response(200, text="no version here")
        )
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="no generator meta")
        )
        respx.get("https://example.com/wp-includes/version.php").mock(
            return_value=httpx.Response(200, text="garbage content")
        )
        async with httpx.AsyncClient() as client:
            version, _evidence = await _detect_wp_version(client, "https://example.com")
            assert version == ""


class TestDetectWpPlugins:
    @respx.mock
    @pytest.mark.asyncio
    async def test_finds_plugins(self) -> None:
        respx.get("https://example.com/wp-content/plugins/akismet/readme.txt").mock(
            return_value=httpx.Response(200, text="=== Akismet ===")
        )
        respx.get("https://example.com/wp-content/plugins/wordfence/readme.txt").mock(
            return_value=httpx.Response(200, text="=== Wordfence ===")
        )
        respx.get("https://example.com/wp-content/plugins/nonexistent/readme.txt").mock(
            return_value=httpx.Response(404, text="")
        )
        async with httpx.AsyncClient() as client:
            plugins = await _detect_wp_plugins(
                client,
                "https://example.com",
                ["akismet", "wordfence", "nonexistent"],
            )
            assert plugins == ["akismet", "wordfence"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_plugins(self) -> None:
        async def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="")

        respx.route(
            method="GET",
            url="https://example.com/wp-content/plugins/akismet/readme.txt",
        ).mock(side_effect=_handler)
        respx.route(
            method="GET",
            url="https://example.com/wp-content/plugins/wordfence/readme.txt",
        ).mock(side_effect=_handler)
        async with httpx.AsyncClient() as client:
            plugins = await _detect_wp_plugins(
                client,
                "https://example.com",
                ["akismet", "wordfence"],
            )
            assert plugins == []


class TestDetectWpThemes:
    @respx.mock
    @pytest.mark.asyncio
    async def test_finds_theme(self) -> None:
        respx.get("https://example.com/wp-content/themes/astra/style.css").mock(
            return_value=httpx.Response(200, text="/* Theme Name: Astra */")
        )
        respx.get("https://example.com/wp-content/themes/nonexistent/style.css").mock(
            return_value=httpx.Response(404, text="")
        )
        async with httpx.AsyncClient() as client:
            themes = await _detect_wp_themes(
                client,
                "https://example.com",
                ["astra", "nonexistent"],
            )
            assert themes == ["astra"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_themes(self) -> None:
        async def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="")

        respx.route(
            method="GET", url="https://example.com/wp-content/themes/astra/style.css"
        ).mock(side_effect=_handler)
        respx.route(
            method="GET",
            url="https://example.com/wp-content/themes/generatepress/style.css",
        ).mock(side_effect=_handler)
        async with httpx.AsyncClient() as client:
            themes = await _detect_wp_themes(
                client,
                "https://example.com",
                ["astra", "generatepress"],
            )
            assert themes == []


class TestDetectWpUsers:
    @respx.mock
    @pytest.mark.asyncio
    async def test_finds_users_via_rest_api(self) -> None:
        respx.get("https://example.com/?author=1").mock(
            return_value=httpx.Response(200, text="")
        )
        respx.get("https://example.com/?author=2").mock(
            return_value=httpx.Response(200, text="")
        )
        respx.get("https://example.com/?author=3").mock(
            return_value=httpx.Response(200, text="")
        )
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(
                200,
                text=json.dumps(
                    [
                        {"name": "admin"},
                        {"name": "editor"},
                    ]
                ),
            )
        )
        async with httpx.AsyncClient() as client:
            users = await _detect_wp_users(client, "https://example.com")
            assert "admin" in users
            assert "editor" in users

    @respx.mock
    @pytest.mark.asyncio
    async def test_finds_users_via_redirect(self) -> None:
        respx.get("https://example.com/?author=1").mock(
            return_value=httpx.Response(301, text="/author/admin")
        )
        respx.get("https://example.com/?author=2").mock(
            return_value=httpx.Response(404, text="")
        )
        respx.get("https://example.com/?author=3").mock(
            return_value=httpx.Response(404, text="")
        )
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(404, text="")
        )
        async with httpx.AsyncClient() as client:
            users = await _detect_wp_users(client, "https://example.com")
            assert users == ["admin"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_redirect_without_author(self) -> None:
        respx.get("https://example.com/?author=1").mock(
            return_value=httpx.Response(301, text="Location: /wp-login.php")
        )
        respx.get("https://example.com/?author=2").mock(
            return_value=httpx.Response(301, text="Location: /wp-login.php")
        )
        respx.get("https://example.com/?author=3").mock(
            return_value=httpx.Response(301, text="Location: /wp-login.php")
        )
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(404, text="")
        )
        async with httpx.AsyncClient() as client:
            users = await _detect_wp_users(client, "https://example.com")
            assert users == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_rest_api_non_list(self) -> None:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(200, text='{"error": "forbidden"}')
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            users = await _detect_wp_users(client, "https://example.com")
            assert users == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_rest_api_entries_missing_name(self) -> None:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(
                200,
                text=json.dumps(
                    [
                        {"name": "admin"},
                        {"id": 5},
                    ]
                ),
            )
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            users = await _detect_wp_users(client, "https://example.com")
            assert users == ["admin"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_rest_api_invalid_json(self) -> None:
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(200, text="not json at all")
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            users = await _detect_wp_users(client, "https://example.com")
            assert users == []


# ---------------------------------------------------------------------------
# Joomla detection tests
# ---------------------------------------------------------------------------


class TestDetectJoomlaInfo:
    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_version(self) -> None:
        respx.get("https://example.com/language/en-GB/en-GB.xml").mock(
            return_value=httpx.Response(200, text="<version>4.3.0</version>")
        )
        respx.get("https://example.com/administrator/manifests/files/joomla.xml").mock(
            return_value=httpx.Response(404, text="")
        )
        respx.get("https://example.com/administrator/components/com_hikashop/").mock(
            return_value=httpx.Response(404, text="")
        )
        async with httpx.AsyncClient() as client:
            version, _extensions = await _detect_joomla_info(
                client,
                "https://example.com",
                ["com_hikashop"],
            )
            assert version == "4.3.0"

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_version(self) -> None:
        async def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="")

        respx.route(
            method="GET", url="https://example.com/language/en-GB/install.xml"
        ).mock(side_effect=_handler)
        respx.route(
            method="GET",
            url="https://example.com/administrator/manifests/files/joomla.xml",
        ).mock(
            side_effect=_handler,
        )
        respx.route(
            method="GET",
            url="https://example.com/administrator/components/com_hikashop/",
        ).mock(
            side_effect=_handler,
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        async with httpx.AsyncClient() as client:
            version, extensions = await _detect_joomla_info(
                client,
                "https://example.com",
                ["com_hikashop"],
            )
            assert version == ""
            assert extensions == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_version_from_manifests(self) -> None:
        respx.get("https://example.com/language/en-GB/en-GB.xml").mock(
            return_value=httpx.Response(200, text="no version tag")
        )
        respx.get("https://example.com/administrator/manifests/files/joomla.xml").mock(
            return_value=httpx.Response(200, text="<version>5.0.0</version>")
        )
        respx.get("https://example.com/administrator/components/com_hikashop/").mock(
            return_value=httpx.Response(404, text="")
        )
        async with httpx.AsyncClient() as client:
            version, extensions = await _detect_joomla_info(
                client,
                "https://example.com",
                ["com_hikashop"],
            )
            assert version == "5.0.0"
            assert extensions == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_detects_extension(self) -> None:
        respx.get("https://example.com/language/en-GB/en-GB.xml").mock(
            return_value=httpx.Response(404, text="")
        )
        respx.get("https://example.com/administrator/manifests/files/joomla.xml").mock(
            return_value=httpx.Response(404, text="")
        )
        respx.get("https://example.com/administrator/components/com_hikashop/").mock(
            return_value=httpx.Response(200, text="")
        )
        async with httpx.AsyncClient() as client:
            version, extensions = await _detect_joomla_info(
                client,
                "https://example.com",
                ["com_hikashop"],
            )
            assert version == ""
            assert extensions == ["com_hikashop"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_manifests_without_version(self) -> None:
        respx.get("https://example.com/language/en-GB/en-GB.xml").mock(
            return_value=httpx.Response(200, text="no version tag")
        )
        respx.get("https://example.com/administrator/manifests/files/joomla.xml").mock(
            return_value=httpx.Response(200, text="no version here either")
        )
        respx.get("https://example.com/administrator/components/com_hikashop/").mock(
            return_value=httpx.Response(404, text="")
        )
        async with httpx.AsyncClient() as client:
            version, extensions = await _detect_joomla_info(
                client,
                "https://example.com",
                ["com_hikashop"],
            )
            assert version == ""
            assert extensions == []


# ---------------------------------------------------------------------------
# Integration test
# ---------------------------------------------------------------------------


class TestScanCmsFingerprint:
    @respx.mock
    @pytest.mark.asyncio
    async def test_wordpress_full_scan(self) -> None:
        # CMS detect
        respx.get("https://example.com/wp-login.php").mock(
            return_value=httpx.Response(200, text="login")
        )
        respx.get("https://example.com/wp-admin/").mock(
            return_value=httpx.Response(302, text="redirect")
        )
        # WP version
        respx.get("https://example.com/readme.html").mock(
            return_value=httpx.Response(200, text="Version 6.4.2")
        )
        # WP plugins
        respx.get("https://example.com/wp-content/plugins/akismet/readme.txt").mock(
            return_value=httpx.Response(200, text="Akismet")
        )
        # WP themes
        respx.get("https://example.com/wp-content/themes/astra/style.css").mock(
            return_value=httpx.Response(200, text="/* Theme Name: Astra */")
        )
        # WP users
        respx.get("https://example.com/?author=1").mock(
            return_value=httpx.Response(200, text="")
        )
        respx.get("https://example.com/wp-json/wp/v2/users").mock(
            return_value=httpx.Response(200, text=json.dumps([{"name": "admin"}]))
        )
        # Fallback for all other routes (must be LAST)
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))

        result = await scan_cms_fingerprint(
            base_url="https://example.com",
            categories=None,
            timeout=5.0,
            plugin_limit=5,
            theme_limit=5,
        )
        assert result.cms_detected == "wordpress"
        assert result.overall_status == "vulnerable"

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_cms_secure(self) -> None:
        async def _handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(404, text="")

        respx.route(method="GET", url="https://example.com/wp-login.php").mock(
            side_effect=_handler
        )
        respx.route(method="GET", url="https://example.com/wp-admin/").mock(
            side_effect=_handler
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        result = await scan_cms_fingerprint(
            base_url="https://example.com",
            categories=None,
            timeout=5.0,
            plugin_limit=5,
            theme_limit=5,
        )
        assert result.cms_detected == ""
        assert result.overall_status == "secure"

    @respx.mock
    @pytest.mark.asyncio
    async def test_wp_themes_only(self) -> None:
        respx.get("https://example.com/wp-content/themes/astra/style.css").mock(
            return_value=httpx.Response(200, text="/* Theme Name: Astra */")
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        result = await scan_cms_fingerprint(
            base_url="https://example.com",
            categories=["wp_themes"],
            timeout=5.0,
            plugin_limit=5,
            theme_limit=5,
        )
        assert result.cms_detected == ""
        assert any(a.technique == "wp_theme_probe" for a in result.attempts)

    @respx.mock
    @pytest.mark.asyncio
    async def test_joomla_scan(self) -> None:
        respx.get("https://example.com/language/en-GB/en-GB.xml").mock(
            return_value=httpx.Response(200, text="<version>4.3.0</version>")
        )
        respx.get("https://example.com/administrator/manifests/files/joomla.xml").mock(
            return_value=httpx.Response(404, text="")
        )
        respx.get("https://example.com/administrator/components/com_hikashop/").mock(
            return_value=httpx.Response(200, text="")
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        result = await scan_cms_fingerprint(
            base_url="https://example.com",
            categories=["joomla_info"],
            timeout=5.0,
            plugin_limit=5,
            theme_limit=5,
        )
        assert result.cms_detected == ""
        assert result.version == "4.3.0"
        assert result.overall_status == "vulnerable"

    @respx.mock
    @pytest.mark.asyncio
    async def test_wp_plugins_only(self) -> None:
        respx.get("https://example.com/wp-content/plugins/akismet/readme.txt").mock(
            return_value=httpx.Response(200, text="Akismet")
        )
        respx.route(method="GET").mock(return_value=httpx.Response(404, text=""))
        result = await scan_cms_fingerprint(
            base_url="https://example.com",
            categories=["wp_plugins"],
            timeout=5.0,
            plugin_limit=5,
            theme_limit=5,
        )
        assert result.cms_detected == ""
        assert any(a.technique == "wp_plugin_probe" for a in result.attempts)


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------


class TestBuildParser:
    def test_has_url_arg(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["https://example.com", "-c", "cms_detect", "wp_version"]
        )
        assert args.categories == ["cms_detect", "wp_version"]

    def test_plugin_limit(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--plugin-limit", "20"])
        assert args.plugin_limit == 20

    def test_theme_limit(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--theme-limit", "15"])
        assert args.theme_limit == 15


# ---------------------------------------------------------------------------
# Print results tests
# ---------------------------------------------------------------------------


class TestPrintResults:
    def test_print_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CmsResult(
            target="https://example.com",
            cms_detected="",
            version="",
            attempts=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "not detected" in output

    def test_print_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        attempt = CmsAttempt(
            technique="wp_plugin_probe",
            category="wp_plugins",
            description="2 plugin(s) found",
            status_code=200,
            vulnerable=True,
            details="akismet, wordfence",
            error="",
        )
        result = CmsResult(
            target="https://example.com",
            cms_detected="wordpress",
            version="6.4",
            attempts=[attempt],
            issues=["CMS detected: wordpress"],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "wordpress" in output
        assert "akismet" in output

    def test_print_no_findings_in_category(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        attempt = CmsAttempt(
            technique="cms_identify",
            category="cms_detect",
            description="No CMS detected",
            status_code=0,
            vulnerable=False,
            details="",
            error="",
        )
        result = CmsResult(
            target="https://example.com",
            cms_detected="",
            version="",
            attempts=[attempt],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "no findings" in output


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------


class TestAsyncRunOnce:
    @patch("mytools.web.cmsfingerprint.scan_cms_fingerprint")
    def test_async_run_once(
        self,
        mock_scan: MagicMock,
        base_ns: argparse.Namespace,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from mytools.web.cmsfingerprint import _async_run_once

        mock_scan.return_value = CmsResult(
            target="https://example.com",
            cms_detected="",
            version="",
            attempts=[],
            issues=[],
            overall_status="secure",
        )
        args = base_ns
        args.url = "example.com"
        result = _async_run_once(args)
        assert result is not None
        assert mock_scan.call_args[1]["base_url"] == "https://example.com"

    @patch("mytools.web.cmsfingerprint.write_output")
    @patch("mytools.web.cmsfingerprint.scan_cms_fingerprint")
    def test_async_run_once_with_output(
        self,
        mock_scan: MagicMock,
        mock_write: MagicMock,
        base_ns: argparse.Namespace,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        from mytools.web.cmsfingerprint import _async_run_once

        mock_scan.return_value = CmsResult(
            target="https://example.com",
            cms_detected="",
            version="",
            attempts=[],
            issues=[],
            overall_status="secure",
        )
        args = base_ns
        args.url = "https://example.com"
        args.output = "out.json"
        _async_run_once(args)
        mock_write.assert_called_once()


class TestRunOnce:
    @patch("mytools.web.cmsfingerprint._async_run_once")
    def test_run_once(self, mock_async: MagicMock) -> None:
        from mytools.web.cmsfingerprint import run_once

        mock_async.return_value = CmsResult(
            target="https://example.com",
            cms_detected="",
            version="",
            attempts=[],
            issues=[],
            overall_status="secure",
        )
        result = run_once(MagicMock())
        assert result == 0
        mock_async.assert_called_once()


class TestMain:
    def test_main(self) -> None:
        from mytools.web.cmsfingerprint import main

        with patch(
            "mytools.web.cmsfingerprint.run_main_loop", return_value=0
        ) as mock_loop:
            result = main()
            assert result == 0
            mock_loop.assert_called_once()


class TestMainGuard:
    def test_guard_runs(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-cmsfp", "https://example.com"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.cmsfingerprint", run_name="__main__")
        assert exc_info.value.code == 0
