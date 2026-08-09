import re
import runpy
from unittest.mock import patch

import pytest
import respx

from mytools.web.techfingerprint import (
    TechFingerprint,
    _detect_body_techs,
    _detect_cookie_techs,
    _detect_css_versions,
    _detect_header_versions,
    _detect_meta_generators,
    _detect_script_versions,
    _scan_url,
    build_parser,
    fingerprint,
    main,
    run_once,
)

# _detect_header_versions


class TestDetectHeaderVersions:
    def test_apache_version(self):
        blob = "Server: Apache/2.4.57 (Ubuntu)"
        results = _detect_header_versions(blob, {"server": "Apache/2.4.57 (Ubuntu)"})
        assert len(results) >= 1
        assert any(r.name == "Apache" and r.version == "2.4.57" for r in results)

    def test_nginx_version(self):
        blob = "Server: nginx/1.25.4"
        results = _detect_header_versions(blob, {"server": "nginx/1.25.4"})
        assert any(r.name == "Nginx" and r.version == "1.25.4" for r in results)

    def test_php_version(self):
        blob = "X-Powered-By: PHP/8.2.4"
        results = _detect_header_versions(blob, {"x-powered-by": "PHP/8.2.4"})
        assert any(r.name == "PHP" and r.version == "8.2.4" for r in results)

    def test_iis_version(self):
        blob = "Server: Microsoft-IIS/10.0"
        results = _detect_header_versions(blob, {"server": "Microsoft-IIS/10.0"})
        assert any(r.name == "IIS" and r.version == "10.0" for r in results)

    def test_litespeed_version(self):
        blob = "Server: LiteSpeed/1.8.1"
        results = _detect_header_versions(blob, {"server": "LiteSpeed/1.8.1"})
        assert any(r.name == "LiteSpeed" and r.version == "1.8.1" for r in results)

    def test_express_version(self):
        blob = "X-Powered-By: Express/4.18.2"
        results = _detect_header_versions(blob, {"x-powered-by": "Express/4.18.2"})
        assert any(r.name == "Express" and r.version == "4.18.2" for r in results)

    def test_aspnet_version(self):
        blob = "X-AspNet-Version: 4.0.30319"
        results = _detect_header_versions(blob, {"x-aspnet-version": "4.0.30319"})
        assert any(r.name == "ASP.NET" and r.version == "4.0.30319" for r in results)

    def test_aspnetmvc_version(self):
        blob = "X-AspNetMvc-Version: 5.2"
        results = _detect_header_versions(blob, {"x-aspnetmvc-version": "5.2"})
        assert any(r.name == "ASP.NET" and r.version == "5.2" for r in results)

    def test_no_match(self):
        blob = "Server: Apache"
        results = _detect_header_versions(blob, {"server": "Apache"})
        assert results == []

    def test_empty_blob(self):
        results = _detect_header_versions("", {})
        assert results == []

    def test_duplicate_tech_dedup(self):
        class _DupHeaderPatterns:
            def items(self):
                yield "Apache", [re.compile(r"Apache/([\d.]+)", re.IGNORECASE)]
                yield "Apache", [re.compile(r"Apache/([\d.]+)", re.IGNORECASE)]

        with patch(
            "mytools.web.techfingerprint.HEADER_VERSION_PATTERNS",
            _DupHeaderPatterns(),
        ):
            results = _detect_header_versions(
                "Server: Apache/2.4.57", {"server": "Apache/2.4.57"}
            )
        assert len(results) == 1
        assert results[0].name == "Apache"


# _detect_meta_generators


class TestDetectMetaGenerators:
    def test_wordpress(self):
        body = '<meta name="generator" content="WordPress 6.4.2" />'
        results = _detect_meta_generators(body)
        assert len(results) == 1
        assert results[0].name == "WordPress"
        assert results[0].version == "6.4.2"
        assert results[0].source == "meta"
        assert results[0].confidence == "high"

    def test_joomla(self):
        body = '<meta name="generator" content="Joomla! 4.4.1" />'
        results = _detect_meta_generators(body)
        assert any(r.name == "Joomla" and r.version == "4.4.1" for r in results)

    def test_drupal(self):
        body = '<meta name="generator" content="Drupal 10.2.0" />'
        results = _detect_meta_generators(body)
        assert any(r.name == "Drupal" and r.version == "10.2.0" for r in results)

    def test_ghost(self):
        body = '<meta name="generator" content="Ghost 5.76.0" />'
        results = _detect_meta_generators(body)
        assert any(r.name == "Ghost" and r.version == "5.76.0" for r in results)

    def test_hugo(self):
        body = '<meta name="generator" content="Hugo 0.121.1" />'
        results = _detect_meta_generators(body)
        assert any(r.name == "Hugo" and r.version == "0.121.1" for r in results)

    def test_squarespace(self):
        body = '<meta name="generator" content="Squarespace" />'
        results = _detect_meta_generators(body)
        assert any(r.name == "Squarespace" for r in results)

    def test_no_generator(self):
        body = "<html><head><title>Test</title></head></html>"
        results = _detect_meta_generators(body)
        assert results == []


# _detect_script_versions


class TestDetectScriptVersions:
    def test_jquery_cdn(self):
        body = '<script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>'
        results = _detect_script_versions(body)
        assert any(r.name == "jQuery" and r.version == "3.7.1" for r in results)

    def test_bootstrap_js(self):
        body = '<script src="/js/bootstrap.5.3.2.min.js"></script>'
        results = _detect_script_versions(body)
        assert any(r.name == "Bootstrap" and r.version == "5.3.2" for r in results)

    def test_react_cdn(self):
        body = '<script src="https://unpkg.com/react@18.2.0/umd/react.production.min.js"></script>'
        results = _detect_script_versions(body)
        assert any(r.name == "React" and r.version == "18.2.0" for r in results)

    def test_vue_cdn(self):
        body = '<script src="https://cdn.jsdelivr.net/npm/vue@3.3.8/dist/vue.global.prod.js"></script>'
        results = _detect_script_versions(body)
        assert any(r.name == "Vue.js" and r.version == "3.3.8" for r in results)

    def test_angular_ng_version(self):
        body = '<app-root ng-version="17.0.5"></app-root>'
        results = _detect_script_versions(body)
        assert any(r.name == "Angular" and r.version == "17.0.5" for r in results)

    def test_lodash(self):
        body = '<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>'
        results = _detect_script_versions(body)
        assert any(r.name == "Lodash" and r.version == "4.17.21" for r in results)

    def test_no_script(self):
        body = "<html><body>No scripts here</body></html>"
        results = _detect_script_versions(body)
        assert results == []

    def test_duplicate_script_dedup(self):
        body = (
            '<script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>'
            '<script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>'
        )
        results = _detect_script_versions(body)
        assert len(results) == 1
        assert results[0].name == "jQuery"


# _detect_css_versions


class TestDetectCssVersions:
    def test_bootstrap_css(self):
        body = '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" />'
        results = _detect_css_versions(body)
        assert any(r.name == "Bootstrap" and r.version == "5.3.2" for r in results)

    def test_font_awesome_css(self):
        body = '<link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" rel="stylesheet" />'
        results = _detect_css_versions(body)
        assert any(r.name == "Font Awesome" and r.version == "6.5.1" for r in results)

    def test_bulma(self):
        body = '<link href="https://cdn.jsdelivr.net/npm/bulma@0.9.4/css/bulma.min.css" rel="stylesheet" />'
        results = _detect_css_versions(body)
        assert any(r.name == "Bulma" and r.version == "0.9.4" for r in results)

    def test_no_css(self):
        body = "<html><body>No CSS links</body></html>"
        results = _detect_css_versions(body)
        assert results == []

    def test_duplicate_css_dedup(self):
        body = (
            '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" />'
            '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" />'
        )
        results = _detect_css_versions(body)
        assert len(results) == 1
        assert results[0].name == "Bootstrap"


# _detect_cookie_techs


class TestDetectCookieTechs:
    def test_php_session(self):
        results = _detect_cookie_techs(["PHPSESSID=abc123"])
        assert len(results) == 1
        assert results[0].name == "PHP"
        assert results[0].source == "cookie"

    def test_java_session(self):
        results = _detect_cookie_techs(["JSESSIONID=xyz789"])
        assert any(r.name == "Java" for r in results)

    def test_aspnet_session(self):
        results = _detect_cookie_techs(["ASP.NET_SessionId=abc"])
        assert any(r.name == "ASP.NET" for r in results)

    def test_laravel(self):
        results = _detect_cookie_techs(["laravel_session=abc123def"])
        assert any(r.name == "Laravel" for r in results)

    def test_rails(self):
        results = _detect_cookie_techs(["_rails_session=abc123"])
        assert any(r.name == "Ruby on Rails" for r in results)

    def test_django(self):
        results = _detect_cookie_techs(["csrftoken=abc123"])
        assert any(r.name == "Django" for r in results)

    def test_wordpress_cookie(self):
        results = _detect_cookie_techs(["wordpress_logged_in_abc123=xyz"])
        assert any(r.name == "WordPress" for r in results)

    def test_cloudflare(self):
        results = _detect_cookie_techs(["__cf_bm=abc123"])
        assert any(r.name == "Cloudflare" for r in results)

    def test_no_match(self):
        results = _detect_cookie_techs(["random_cookie=value"])
        assert results == []

    def test_multiple_cookies(self):
        cookies = ["PHPSESSID=abc", "XSRF-TOKEN=xyz", "csrftoken=123"]
        results = _detect_cookie_techs(cookies)
        names = {r.name for r in results}
        assert "PHP" in names
        assert "Laravel" in names
        assert "Django" in names


# _detect_body_techs


class TestDetectBodyTechs:
    def test_angular_ng_version(self):
        body = '<app-root ng-version="17.0.5"></app-root>'
        results = _detect_body_techs(body)
        assert any(r.name == "Angular" and r.version == "17.0.5" for r in results)

    def test_react_data_reactroot(self):
        body = "<div data-reactroot></div>"
        results = _detect_body_techs(body)
        assert any(r.name == "React" for r in results)

    def test_vue_data_v(self):
        body = "<div data-v-12345678></div>"
        results = _detect_body_techs(body)
        assert any(r.name == "Vue.js" for r in results)

    def test_wordpress_body(self):
        body = '<link href="https://example.com/wp-content/themes/style.css">'
        results = _detect_body_techs(body)
        assert any(r.name == "WordPress" for r in results)

    def test_nextjs(self):
        body = '<script id="__NEXT_DATA__" type="application/json"></script>'
        results = _detect_body_techs(body)
        assert any(r.name == "Next.js" for r in results)

    def test_nuxtjs(self):
        body = "<script>window.__NUXT__={}</script>"
        results = _detect_body_techs(body)
        assert any(r.name == "Nuxt.js" for r in results)

    def test_shopify(self):
        body = (
            '<script src="https://cdn.shopify.com/s/files/1/0001/script.js"></script>'
        )
        results = _detect_body_techs(body)
        assert any(r.name == "Shopify" for r in results)

    def test_django(self):
        body = '<input type="hidden" name="csrfmiddlewaretoken" value="abc123">'
        results = _detect_body_techs(body)
        assert any(r.name == "Django" for r in results)

    def test_no_match(self):
        body = "<html><body>Plain HTML</body></html>"
        results = _detect_body_techs(body)
        assert results == []


# fingerprint (integration)


class TestFingerprint:
    def test_wordpress_stack(self):
        headers = {"Server": "Apache/2.4.57", "X-Powered-By": "PHP/8.2.4"}
        body = '<meta name="generator" content="WordPress 6.4.2" /><link href="/wp-content/themes/style.css" />'
        cookies = ["PHPSESSID=abc123"]
        results = fingerprint("https://example.com", headers, body, cookies)
        names = {r.name for r in results}
        assert "WordPress" in names
        assert "PHP" in names

    def test_empty_response(self):
        results = fingerprint("https://example.com", {}, "", [])
        assert results == []

    def test_dedup_high_priority(self):
        headers = {"X-Powered-By": "PHP/8.2.4"}
        body = '<meta name="generator" content="WordPress 6.4.2" />'
        cookies = ["PHPSESSID=abc"]
        results = fingerprint("https://test.com", headers, body, cookies)
        php_results = [r for r in results if r.name == "PHP"]
        assert len(php_results) == 1

    def test_sorted_by_category(self):
        headers = {"Server": "nginx/1.25.4", "X-Powered-By": "PHP/8.2.4"}
        body = '<meta name="generator" content="WordPress 6.4.2" />'
        cookies = ["PHPSESSID=abc"]
        results = fingerprint("https://test.com", headers, body, cookies)
        categories = [r.category for r in results]
        assert categories == sorted(categories)

    def test_multiple_sources(self):
        headers = {"Server": "Apache/2.4.57"}
        body = '<script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>'
        cookies = ["PHPSESSID=abc", "__cf_bm=xyz"]
        results = fingerprint("https://test.com", headers, body, cookies)
        names = {r.name for r in results}
        assert len(names) >= 2

    def test_dedup_replace_higher_confidence(self):
        low = TechFingerprint(
            name="TestTech",
            version="",
            source="cookie",
            confidence="low",
            evidence="x",
        )
        high = TechFingerprint(
            name="TestTech",
            version="1.0",
            source="body",
            confidence="high",
            evidence="y",
        )
        with (
            patch(
                "mytools.web.techfingerprint._detect_header_versions",
                return_value=[],
            ),
            patch(
                "mytools.web.techfingerprint._detect_meta_generators",
                return_value=[],
            ),
            patch(
                "mytools.web.techfingerprint._detect_script_versions",
                return_value=[],
            ),
            patch(
                "mytools.web.techfingerprint._detect_css_versions",
                return_value=[],
            ),
            patch(
                "mytools.web.techfingerprint._detect_cookie_techs",
                return_value=[low],
            ),
            patch(
                "mytools.web.techfingerprint._detect_body_techs",
                return_value=[high],
            ),
        ):
            results = fingerprint("https://test.com", {}, "", [])
        assert len(results) == 1
        assert results[0].confidence == "high"
        assert results[0].version == "1.0"

    def test_dedup_keeps_first_on_tie(self):
        first = TechFingerprint(
            name="TestTech",
            version="1.0",
            source="script",
            confidence="high",
            evidence="a",
        )
        second = TechFingerprint(
            name="TestTech",
            version="2.0",
            source="body",
            confidence="high",
            evidence="b",
        )
        with (
            patch(
                "mytools.web.techfingerprint._detect_header_versions",
                return_value=[],
            ),
            patch(
                "mytools.web.techfingerprint._detect_meta_generators",
                return_value=[],
            ),
            patch(
                "mytools.web.techfingerprint._detect_script_versions",
                return_value=[first],
            ),
            patch(
                "mytools.web.techfingerprint._detect_css_versions",
                return_value=[],
            ),
            patch(
                "mytools.web.techfingerprint._detect_cookie_techs",
                return_value=[],
            ),
            patch(
                "mytools.web.techfingerprint._detect_body_techs",
                return_value=[second],
            ),
        ):
            results = fingerprint("https://test.com", {}, "", [])
        assert len(results) == 1
        assert results[0].version == "1.0"


# _scan_url (async)


class TestScanUrl:
    @pytest.mark.asyncio
    @respx.mock
    async def test_scan_url_success(self):
        respx.get("https://example.com").mock(
            return_value=respx.MockResponse(
                200,
                headers={"Server": "nginx/1.25.4", "X-Powered-By": "PHP/8.2.4"},
                text='<html><meta name="generator" content="WordPress 6.4.2" /></html>',
            ),
        )
        results = _scan_url("https://example.com", 10.0)
        assert isinstance(results, list)
        assert len(results) > 0
        names = {r.name for r in results}
        assert "WordPress" in names or "PHP" in names or "Nginx" in names

    @pytest.mark.asyncio
    @respx.mock
    async def test_scan_url_with_cookies(self):
        respx.get("https://example.com").mock(
            return_value=respx.MockResponse(
                200,
                headers={
                    "Server": "nginx/1.25.4",
                    "Set-Cookie": "PHPSESSID=abc123; Path=/",
                },
                text="<html><body>Hello</body></html>",
            ),
        )
        results = _scan_url("https://example.com", 10.0)
        names = {r.name for r in results}
        assert "PHP" in names

    @pytest.mark.asyncio
    @respx.mock
    async def test_scan_url_full_stack(self):
        respx.get("https://example.com").mock(
            return_value=respx.MockResponse(
                200,
                headers={
                    "Server": "Apache/2.4.57",
                    "X-Powered-By": "PHP/8.2.4",
                    "Set-Cookie": "__cf_bm=abc123; Path=/",
                },
                text=(
                    '<meta name="generator" content="WordPress 6.4.2" />'
                    '<script src="https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.min.js"></script>'
                    '<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet" />'
                ),
            ),
        )
        results = _scan_url("https://example.com", 10.0)
        names = {r.name for r in results}
        assert "WordPress" in names
        assert "PHP" in names
        assert "Apache" in names


# build_parser


@pytest.mark.smoke
class TestBuildParser:
    def test_has_urls(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.urls == ["https://example.com"]

    def test_has_list(self):
        parser = build_parser()
        args = parser.parse_args(["-l", "urls.txt"])
        assert args.url_list == "urls.txt"

    def test_has_output(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-o", "out.json"])
        assert args.output == "out.json"

    def test_has_timeout(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-t", "15"])
        assert args.timeout == 15.0

    def test_has_user_agent(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-A", "CustomAgent/1.0"])
        assert args.user_agent == "CustomAgent/1.0"


# run_once


class TestRunOnce:
    def test_no_urls_returns_1(self):
        args = build_parser().parse_args([])
        args.urls = []
        args.url_list = None
        result = run_once(args)
        assert result == 1

    def test_dry_run_returns_0(self):
        args = build_parser().parse_args(["https://example.com", "--dry-run"])
        args.urls = ["https://example.com"]
        result = run_once(args)
        assert result == 0

    @patch("mytools.web.techfingerprint._scan_url")
    def test_scan_calls_correctly(self, mock_scan):
        mock_scan.return_value = [
            TechFingerprint(
                name="Nginx",
                version="1.25.4",
                source="header",
                confidence="high",
                evidence="Server: nginx/1.25.4",
                category="server",
            ),
        ]
        args = build_parser().parse_args(["https://example.com"])
        args.urls = ["https://example.com"]
        result = run_once(args)
        assert result == 0
        mock_scan.assert_called_once()

    @patch("mytools.web.techfingerprint._scan_url")
    def test_scan_returns_error_for_fetch(self, mock_scan):
        from mytools.core.utils import FetchError

        mock_scan.side_effect = FetchError(
            "https://example.com", 3, Exception("timeout")
        )
        args = build_parser().parse_args(["https://example.com"])
        args.urls = ["https://example.com"]
        result = run_once(args)
        assert result == 0

    @patch("mytools.web.techfingerprint._scan_url")
    def test_scan_empty_results(self, mock_scan):
        mock_scan.return_value = []
        args = build_parser().parse_args(["https://example.com"])
        args.urls = ["https://example.com"]
        result = run_once(args)
        assert result == 0

    @patch("mytools.web.techfingerprint._scan_url")
    def test_url_list_loading(self, mock_scan, tmp_path):
        url_file = tmp_path / "urls.txt"
        url_file.write_text("https://example.com\n# comment\n\nhttps://test.com\n")
        mock_scan.return_value = []
        args = build_parser().parse_args(["-l", str(url_file)])
        result = run_once(args)
        assert result == 0
        assert mock_scan.call_count == 2

    def test_url_list_not_found(self):
        args = build_parser().parse_args(["-l", "nonexistent.txt"])
        args.url_list = "nonexistent.txt"
        result = run_once(args)
        assert result == 1

    @patch("mytools.web.techfingerprint._scan_url")
    def test_unexpected_exception(self, mock_scan):
        mock_scan.side_effect = ValueError("boom")
        args = build_parser().parse_args(["https://example.com"])
        args.urls = ["https://example.com"]
        result = run_once(args)
        assert result == 0

    @patch("mytools.web.techfingerprint._scan_url")
    def test_write_output(self, mock_scan, tmp_path):
        mock_scan.return_value = [
            TechFingerprint(
                name="Nginx",
                version="1.25.4",
                source="header",
                confidence="high",
                evidence="Server: nginx/1.25.4",
                category="server",
            ),
        ]
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(["https://example.com", "-o", str(out_file)])
        args.urls = ["https://example.com"]
        result = run_once(args)
        assert result == 0
        assert out_file.exists()


# main


class TestMain:
    def test_main_with_url(self):
        with (
            patch("sys.argv", ["mytools-techfp", "https://example.com"]),
            patch("mytools.web.techfingerprint.run_once", return_value=0),
        ):
            assert main() == 0

    def test_main_no_url_uses_loop(self):
        with (
            patch("sys.argv", ["mytools-techfp"]),
            patch("mytools.web.techfingerprint.run_main_loop", return_value=0),
        ):
            assert main() == 0

    def test_main_entrypoint_guard(self):
        with (
            patch("sys.argv", ["mytools-techfp"]),
            patch("builtins.input", side_effect=EOFError("exit")),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.web.techfingerprint", run_name="__main__")
