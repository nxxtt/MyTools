import argparse
import asyncio
import json
from dataclasses import asdict
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mytools.core.utils import (
    RateLimiter,
    normalize_url,
    parse_auth,
    parse_extra_headers,
)
from mytools.network.dirscanner import (
    DEFAULT_PATHS,
    DEFAULT_STATUSES,
    Finding,
    _async_run_once,
    _generate_case_variations,
    _generate_unicode_variations,
    _run_single,
    _to_circled,
    _to_fullwidth,
    build_parser,
    load_paths,
    matches_filter,
    parse_extensions,
    parse_range,
    parse_statuses,
    print_dir_table,
    run_once,
    scan_path,
    scan_target,
)


class TestNormalizeBaseUrl:
    def test_adds_http_scheme(self):
        assert (
            normalize_url(
                "example.com", default_scheme="http", ensure_trailing_slash=True
            )
            == "http://example.com/"
        )

    def test_keeps_https(self):
        assert (
            normalize_url(
                "https://example.com", default_scheme="http", ensure_trailing_slash=True
            )
            == "https://example.com/"
        )

    def test_strips_trailing_slash_then_adds(self):
        assert (
            normalize_url(
                "https://example.com/",
                default_scheme="http",
                ensure_trailing_slash=True,
            )
            == "https://example.com/"
        )

    def test_preserves_path(self):
        assert (
            normalize_url(
                "https://example.com/app",
                default_scheme="http",
                ensure_trailing_slash=True,
            )
            == "https://example.com/app/"
        )

    def test_invalid_scheme_raises(self):
        with pytest.raises(ValueError):
            normalize_url(
                "ftp://example.com", default_scheme="http", ensure_trailing_slash=True
            )

    def test_empty_netloc_raises(self):
        with pytest.raises(ValueError):
            normalize_url("http://", default_scheme="http", ensure_trailing_slash=True)


class TestParseStatuses:
    def test_default(self):
        assert parse_statuses("default") == DEFAULT_STATUSES

    def test_all(self):
        result = parse_statuses("all")
        assert result == set(range(100, 600))

    def test_single(self):
        assert parse_statuses("200") == {200}

    def test_comma_separated(self):
        assert parse_statuses("200,403") == {200, 403}

    def test_range(self):
        assert parse_statuses("200-202") == {200, 201, 202}

    def test_reversed_range(self):
        assert parse_statuses("202-200") == {200, 201, 202}

    def test_invalid_status_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_statuses("99")

    def test_non_numeric_raises(self):
        with pytest.raises(argparse.ArgumentTypeError, match="abc"):
            parse_statuses("abc")

    def test_non_numeric_in_range_raises(self):
        with pytest.raises(argparse.ArgumentTypeError, match="abc-200"):
            parse_statuses("abc-200")

    def test_trailing_comma(self):
        assert parse_statuses("200,403,") == {200, 403}

    def test_whitespace_parts(self):
        assert parse_statuses(" 200 , 403 ") == {200, 403}

    def test_overlapping_ranges(self):
        result = parse_statuses("200-202,201-203")
        assert result == {200, 201, 202, 203}


class TestParseExtensions:
    def test_simple(self):
        assert parse_extensions("php,txt") == ["php", "txt"]

    def test_with_dots(self):
        assert parse_extensions(".php,.bak") == ["php", "bak"]

    def test_empty(self):
        assert parse_extensions("") == []

    def test_whitespace(self):
        assert parse_extensions(" php , txt ") == ["php", "txt"]

    def test_empty_components_skipped(self):
        assert parse_extensions("php,.,txt") == ["php", "txt"]
        assert parse_extensions("php,,txt") == ["php", "txt"]


class TestParseRange:
    def test_valid_range(self):
        assert parse_range("100-5000") == (100, 5000)

    def test_reversed_range(self):
        assert parse_range("5000-100") == (100, 5000)

    def test_empty_returns_none(self):
        assert parse_range("") is None

    def test_none_returns_none(self):
        assert parse_range(None) is None

    def test_invalid_format_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_range("abc")

    def test_non_numeric_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_range("abc-200")


class TestParseAuth:
    def test_valid_auth(self):
        result = parse_auth("admin:secret")
        assert "Authorization" in result
        assert result["Authorization"].startswith("Basic ")

    def test_password_with_colon(self):
        result = parse_auth("user:pass:word")
        assert "Authorization" in result

    def test_no_colon_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_auth("nocolon")


class TestParseExtraHeaders:
    def test_single_header(self):
        result = parse_extra_headers(["X-Token: abc123"])
        assert result == {"X-Token": "abc123"}

    def test_multiple_headers(self):
        result = parse_extra_headers(["X-Token: abc", "X-Custom: xyz"])
        assert len(result) == 2
        assert result["X-Token"] == "abc"
        assert result["X-Custom"] == "xyz"

    def test_no_colon_raises(self):
        with pytest.raises(ValueError):
            parse_extra_headers(["InvalidHeader"])


class TestMatchesFilter:
    def test_no_filter_passes(self):
        f = Finding(
            url="http://x.com/a", path="/a", status=200, size=100, words=10, title=""
        )
        assert matches_filter(f, None, None) is True

    def test_size_within_range(self):
        f = Finding(
            url="http://x.com/a", path="/a", status=200, size=500, words=10, title=""
        )
        assert matches_filter(f, (100, 1000), None) is True

    def test_size_outside_range(self):
        f = Finding(
            url="http://x.com/a", path="/a", status=200, size=50, words=10, title=""
        )
        assert matches_filter(f, (100, 1000), None) is False

    def test_words_within_range(self):
        f = Finding(
            url="http://x.com/a", path="/a", status=200, size=100, words=50, title=""
        )
        assert matches_filter(f, None, (10, 100)) is True

    def test_words_outside_range(self):
        f = Finding(
            url="http://x.com/a", path="/a", status=200, size=100, words=5, title=""
        )
        assert matches_filter(f, None, (10, 100)) is False

    def test_both_filters(self):
        f = Finding(
            url="http://x.com/a", path="/a", status=200, size=500, words=50, title=""
        )
        assert matches_filter(f, (100, 1000), (10, 100)) is True
        assert matches_filter(f, (100, 1000), (60, 100)) is False


class TestLoadPaths:
    def test_default_paths_no_extensions(self):
        paths = load_paths(None, [])
        assert len(paths) > 0
        assert "admin" in paths
        assert "robots.txt" in paths

    def test_default_paths_with_extensions(self):
        paths = load_paths(None, ["php", "txt"])
        assert "admin" in paths
        assert "admin.php" in paths
        assert "admin.txt" in paths

    def test_default_paths_deduplicates(self):
        paths = load_paths(None, [])
        assert len(paths) == len(set(paths))

    def test_custom_wordlist(self, tmp_path):
        wordlist = tmp_path / "wordlist.txt"
        wordlist.write_text("admin\nlogin\n# comment\n\ntest\n")
        paths = load_paths(str(wordlist), [])
        assert "admin" in paths
        assert "login" in paths
        assert "test" in paths
        assert "# comment" not in paths

    def test_extensions_not_applied_to_dotted_files(self):
        paths = load_paths(None, ["php"])
        assert ".env" in paths
        assert ".env.php" not in paths

    def test_sorted_output(self):
        paths = load_paths(None, [])
        assert paths == sorted(paths)

    def test_missing_wordlist_raises(self):
        with pytest.raises(ValueError, match="arquivo nao encontrado"):
            load_paths("/nonexistent/wordlist.txt", [])

    def test_absolute_urls_ignored(self, tmp_path, caplog):
        wordlist = tmp_path / "w.txt"
        wordlist.write_text("http://evil.com/x\nhttps://evil.com/y\nadmin\n")
        with caplog.at_level("WARNING", logger="mytools.dirscanner"):
            paths = load_paths(str(wordlist), [])
        assert "admin" in paths
        assert any("URL absoluta ignorada" in r.message for r in caplog.records)

    def test_blank_lines_skipped(self, tmp_path):
        wordlist = tmp_path / "w.txt"
        wordlist.write_text("admin\n\n   \nlogin\n")
        paths = load_paths(str(wordlist), [])
        assert "admin" in paths
        assert "login" in paths

    def test_slash_only_lines_skipped(self, tmp_path):
        wordlist = tmp_path / "w.txt"
        wordlist.write_text("/\n///\nadmin\n")
        paths = load_paths(str(wordlist), [])
        assert "admin" in paths
        assert "/" not in paths

    def test_case_variation_with_extensions(self, tmp_path):
        wordlist = tmp_path / "w.txt"
        wordlist.write_text("admin\n")
        paths = load_paths(str(wordlist), ["php", "bak"], case_variation=True)
        assert "Admin.php" in paths
        assert "ADMIN.bak" in paths

    def test_case_variation_without_extensions(self, tmp_path):
        wordlist = tmp_path / "w.txt"
        wordlist.write_text("admin\n")
        paths = load_paths(str(wordlist), [], case_variation=True)
        assert "Admin" in paths
        assert "ADMIN" in paths
        assert not any(".php" in p for p in paths)

    def test_empty_wordlist_raises(self, tmp_path):
        wordlist = tmp_path / "w.txt"
        wordlist.write_text("# comment only\n\n")
        with pytest.raises(ValueError, match="nenhum path valido"):
            load_paths(str(wordlist), [])

    def test_urls_only_wordlist_raises(self, tmp_path):
        wordlist = tmp_path / "w.txt"
        wordlist.write_text("http://evil.com/x\n")
        with pytest.raises(ValueError, match="nenhum path valido"):
            load_paths(str(wordlist), [])


class TestToCircled:
    def test_lowercase(self):
        assert _to_circled("admin") == "ⓐⓓⓜⓘⓝ"

    def test_uppercase(self):
        assert _to_circled("ADMIN") == "ⒶⒹⓂⒾⓃ"

    def test_mixed(self):
        assert _to_circled("Admin") == "Ⓐⓓⓜⓘⓝ"

    def test_non_alpha(self):
        assert _to_circled("admin123") == "ⓐⓓⓜⓘⓝ123"

    def test_empty(self):
        assert _to_circled("") == ""

    def test_special_chars(self):
        assert _to_circled("a.b") == "ⓐ.ⓑ"


class TestToFullwidth:
    def test_lowercase(self):
        assert _to_fullwidth("admin") == "ａｄｍｉｎ"

    def test_uppercase(self):
        assert _to_fullwidth("ADMIN") == "ＡＤＭＩＮ"

    def test_mixed(self):
        assert _to_fullwidth("Admin") == "Ａｄｍｉｎ"

    def test_non_ascii(self):
        assert _to_fullwidth("admin123") == "ａｄｍｉｎ１２３"

    def test_empty(self):
        assert _to_fullwidth("") == ""

    def test_special_chars(self):
        assert _to_fullwidth("a.b") == "ａ．ｂ"

    def test_non_ascii_char_preserved(self):
        assert _to_fullwidth("café") == "ｃａｆé"


class TestGenerateCaseVariations:
    def test_admin(self):
        variations = _generate_case_variations("admin")
        assert "Admin" in variations
        assert "ADMIN" in variations
        assert "admin" not in variations

    def test_with_extension(self):
        variations = _generate_case_variations("admin.php")
        assert all(v.endswith(".php") for v in variations)

    def test_deduplication(self):
        variations = _generate_case_variations("Admin")
        assert len(variations) == len(set(variations))

    def test_uppercase_path(self):
        variations = _generate_case_variations("ADMIN")
        assert "ADMIN" not in variations


class TestGenerateUnicodeVariations:
    def test_admin(self):
        variations = _generate_unicode_variations("admin")
        assert len(variations) > 0
        assert any("ⓐ" in v for v in variations)
        assert any("ａ" in v for v in variations)

    def test_with_extension(self):
        variations = _generate_unicode_variations("admin.php")
        assert all(v.endswith(".php") for v in variations)

    def test_no_duplicate_original(self):
        variations = _generate_unicode_variations("admin")
        assert "admin" not in variations

    def test_deduplication(self):
        variations = _generate_unicode_variations("test")
        assert len(variations) == len(set(variations))


class TestLoadPathsWithUnicodeNorm:
    def test_unicode_norm_adds_variations(self):
        paths = load_paths(None, [], unicode_norm=True)
        assert any("ａ" in p for p in paths)
        assert any("ⓐ" in p for p in paths)

    def test_unicode_norm_with_extensions(self):
        paths = load_paths(None, ["php"], unicode_norm=True)
        assert any("ａ" in p and p.endswith(".php") for p in paths)

    def test_unicode_norm_false_no_changes(self):
        paths_normal = load_paths(None, [])
        paths_unicode = load_paths(None, [], unicode_norm=False)
        assert paths_normal == paths_unicode


class TestDefaultPaths:
    def test_not_empty(self):
        assert len(DEFAULT_PATHS) > 0

    def test_has_common_paths(self):
        assert "admin" in DEFAULT_PATHS
        assert "robots.txt" in DEFAULT_PATHS
        assert ".env" in DEFAULT_PATHS


class TestDefaultStatuses:
    def test_has_200(self):
        assert 200 in DEFAULT_STATUSES

    def test_has_403(self):
        assert 403 in DEFAULT_STATUSES


class TestFindingDataclass:
    def test_creation(self):
        f = Finding(
            url="http://x.com/a", path="/a", status=200, size=100, words=5, title="T"
        )
        assert f.status == 200
        assert f.location == ""
        assert f.method == "GET"

    def test_frozen(self):
        f = Finding(
            url="http://x.com/a", path="/a", status=200, size=100, words=5, title="T"
        )
        with pytest.raises(AttributeError):
            f.status = 404  # type: ignore[reportAttributeAccessIssue]

    def test_custom_method(self):
        f = Finding(
            url="http://x.com/a",
            path="/a",
            status=200,
            size=100,
            words=5,
            title="T",
            method="POST",
        )
        assert f.method == "POST"


class TestScanPath:
    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_finding_on_match(self, async_client):
        respx.get("http://example.com/admin").mock(
            return_value=httpx.Response(
                200,
                content=b"<title>Admin</title>",
                headers={"Content-Type": "text/html"},
            )
        )
        client = async_client
        limiter = RateLimiter()
        result = await scan_path(
            client, limiter, "http://example.com/", "admin", 5.0, {200}
        )
        assert result is not None
        assert result.status == 200
        assert result.path == "/admin"

    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_none_on_status_mismatch(self, async_client):
        respx.get("http://example.com/admin").mock(
            return_value=httpx.Response(404, text="not found")
        )
        client = async_client
        limiter = RateLimiter()
        result = await scan_path(
            client, limiter, "http://example.com/", "admin", 5.0, {200}
        )
        assert result is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_returns_none_on_connection_error(self, async_client):
        respx.get("http://example.com/admin").mock(
            side_effect=httpx.ConnectError("refused")
        )
        client = async_client
        limiter = RateLimiter()
        result = await scan_path(
            client, limiter, "http://example.com/", "admin", 5.0, {200}
        )
        assert result is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_custom_method(self, async_client):
        respx.post("http://example.com/api").mock(
            return_value=httpx.Response(200, json={"ok": True})
        )
        client = async_client
        limiter = RateLimiter()
        result = await scan_path(
            client, limiter, "http://example.com/", "api", 5.0, {200}, method="POST"
        )
        assert result is not None
        assert result.method == "POST"


@pytest.mark.smoke
class TestBuildParser:
    def test_returns_argparse(self):
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_has_url_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.url == "http://example.com"

    def test_has_extensions_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "-x", "php,txt"])
        assert args.extensions == ["php", "txt"]

    def test_default_concurrency(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.concurrency == 40

    def test_has_proxy_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--proxy", "http://proxy:8080"])
        assert args.proxy == "http://proxy:8080"

    def test_has_delay_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--delay", "10"])
        assert args.delay == 10.0

    def test_has_method_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "-M", "POST"])
        assert args.method == "POST"

    def test_default_method_is_get(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.method == "GET"

    def test_has_auth_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--auth", "admin:secret"])
        assert args.auth is not None
        assert "Authorization" in args.auth

    def test_has_cookie_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--cookie", "session=abc"])
        assert args.cookie == "session=abc"

    def test_has_header_argument(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "http://example.com",
                "--header",
                "X-Token: abc",
                "--header",
                "X-Custom: xyz",
            ]
        )
        assert args.header == ["X-Token: abc", "X-Custom: xyz"]

    def test_has_filter_size_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--filter-size", "100-5000"])
        assert args.filter_size == (100, 5000)

    def test_has_filter_words_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--filter-words", "10-100"])
        assert args.filter_words == (10, 100)

    def test_has_verbose_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "-v"])
        assert args.verbose is True

    def test_default_verbose_false(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.verbose is False

    def test_has_log_file_argument(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--log-file", "scan.log"])
        assert args.log_file == "scan.log"


class TestScanPathEdgeCases:
    @respx.mock
    @pytest.mark.asyncio
    async def test_connection_refused_returns_none(self, async_client):
        respx.get("https://example.com/secret").mock(
            side_effect=httpx.ConnectError("refused")
        )
        rl = RateLimiter(0)
        result = await scan_path(
            async_client, rl, "https://example.com/", "/secret", 1.0, {200, 301}
        )
        assert result is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout_returns_none(self, async_client):
        def handler(request):
            raise httpx.TimeoutException("timeout")

        respx.get("https://example.com/slow").mock(side_effect=handler)
        rl = RateLimiter(0)
        result = await scan_path(
            async_client, rl, "https://example.com/", "/slow", 0.1, {200}
        )
        assert result is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_path_probes_root(self, async_client):
        respx.get("https://example.com/").mock(
            return_value=httpx.Response(200, text="root")
        )
        rl = RateLimiter(0)
        result = await scan_path(
            async_client, rl, "https://example.com", "", 1.0, {200}
        )
        assert result is None or result.path == "/"

    @respx.mock
    @pytest.mark.asyncio
    async def test_403_returns_finding_when_in_statuses(self, async_client):
        respx.get("https://example.com/admin").mock(
            return_value=httpx.Response(403, text="forbidden")
        )
        rl = RateLimiter(0)
        result = await scan_path(
            async_client, rl, "https://example.com/", "/admin", 1.0, {200, 403}
        )
        assert result is not None
        assert result.status == 403

    @respx.mock
    @pytest.mark.asyncio
    async def test_large_body_handled(self, async_client):
        body = "x" * 500_000
        respx.get("https://example.com/big").mock(
            return_value=httpx.Response(200, text=body)
        )
        rl = RateLimiter(0)
        result = await scan_path(
            async_client, rl, "https://example.com/", "/big", 5.0, {200}
        )
        assert result is not None
        assert result.size >= 500_000


class TestDryRun:
    def test_dry_run_flag_exists_in_parser(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--dry-run"])
        assert args.dry_run is True

    def test_dry_run_default_false(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.dry_run is False

    def test_dry_run_returns_zero(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--dry-run"])
        result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_dry_run_outputs_info(self, caplog):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--dry-run"])
        with caplog.at_level("WARNING", logger="mytools.dirscanner"):
            asyncio.run(_async_run_once(args))
        assert any("Nenhuma requisicao" in r.message for r in caplog.records)


class TestMain:
    @patch("mytools.core.utils.run_interactive_shell")
    def test_no_target_shells_interactive(self, mock_shell):
        mock_shell.return_value = 0
        from mytools.network.dirscanner import main

        args = argparse.Namespace(
            url=None,
            target_list=None,
            quiet=False,
            output=None,
            verbose=False,
            color=None,
            log_file=None,
            timeout=5.0,
            concurrency=40,
            method="GET",
            status=frozenset({200, 301, 403}),
            wordlist=None,
            extensions=[],
            filter_size=None,
            filter_words=None,
            output_dir=None,
            retries=3,
            dry_run=False,
            verify=False,
        )
        with patch(
            "mytools.network.dirscanner.argparse.ArgumentParser.parse_args",
            return_value=args,
        ):
            result = main()
            assert result == 0
            mock_shell.assert_called_once()

    def test_quiet_without_output_returns_1(self):
        from mytools.network.dirscanner import main

        args = argparse.Namespace(
            url="http://example.com",
            target_list=None,
            quiet=True,
            output=None,
            verbose=False,
            color=None,
            log_file=None,
            timeout=5.0,
            concurrency=40,
            method="GET",
            status=frozenset({200, 301, 403}),
            wordlist=None,
            extensions=[],
            filter_size=None,
            filter_words=None,
            output_dir=None,
            retries=3,
            dry_run=False,
            verify=False,
        )
        with patch(
            "mytools.network.dirscanner.argparse.ArgumentParser.parse_args",
            return_value=args,
        ):
            result = main()
            assert result == 1

    @patch("mytools.network.dirscanner.run_once")
    def test_valid_url_calls_run_once(self, mock_run_once):
        mock_run_once.return_value = 0
        from mytools.network.dirscanner import main

        args = argparse.Namespace(
            url="http://example.com",
            target_list=None,
            quiet=False,
            output=None,
            verbose=False,
            color=None,
            log_file=None,
            timeout=5.0,
            concurrency=40,
            method="GET",
            status=frozenset({200, 301, 403}),
            wordlist=None,
            extensions=[],
            filter_size=None,
            filter_words=None,
            output_dir=None,
            retries=3,
            dry_run=False,
            verify=False,
        )
        with patch(
            "mytools.network.dirscanner.argparse.ArgumentParser.parse_args",
            return_value=args,
        ):
            result = main()
            assert result == 0
            mock_run_once.assert_called_once()

    @patch("mytools.network.dirscanner.run_once")
    def test_exception_returns_1(self, mock_run_once):
        mock_run_once.side_effect = RuntimeError("fail")
        from mytools.network.dirscanner import main

        args = argparse.Namespace(
            url="http://example.com",
            target_list=None,
            quiet=False,
            output=None,
            verbose=False,
            color=None,
            log_file=None,
            timeout=5.0,
            concurrency=40,
            method="GET",
            status=frozenset({200, 301, 403}),
            wordlist=None,
            extensions=[],
            filter_size=None,
            filter_words=None,
            output_dir=None,
            retries=3,
            dry_run=False,
            verify=False,
        )
        with patch(
            "mytools.network.dirscanner.argparse.ArgumentParser.parse_args",
            return_value=args,
        ):
            result = main()
            assert result == 1


class TestScanTarget:
    def _finding(self, url, path, status, size, words, title="", location=""):
        return Finding(
            url=url,
            path=path,
            status=status,
            size=size,
            words=words,
            title=title,
            location=location,
        )

    @pytest.mark.asyncio
    async def test_scan_target_full(self):
        client = AsyncMock()
        client.headers = {}
        f1 = self._finding(
            "http://x.com/admin", "/admin", 200, 100, 5, "Admin", "http://x.com/"
        )
        f2 = self._finding("http://x.com/backup", "/backup", 403, 10, 0)
        f3 = self._finding("http://x.com/spa", "/spa", 200, 100, 5, "SPA")
        with (
            patch(
                "mytools.network.dirscanner.create_async_client", return_value=client
            ),
            patch(
                "mytools.network.dirscanner.scan_path",
                new=AsyncMock(side_effect=[f1, f2, f3]),
            ),
            patch("mytools.network.dirscanner.detect_spa_fallback", return_value=[0]),
        ):
            result = await scan_target(
                base_url="http://x.com/",
                paths=["admin", "backup", "spa"],
                timeout=5.0,
                concurrency=2,
                statuses={200, 403},
                user_agent="UA",
                auth_headers={"Authorization": "Bearer x"},
                extra_headers={"X-Test": "1"},
                size_range=(0, 50),
                words_range=None,
                retries=2,
            )
        # f1 skipped by SPA, f3 filtered by size, f2 remains
        assert result == [f2]

    @pytest.mark.asyncio
    async def test_scan_target_none_results_skipped(self):
        client = AsyncMock()
        f1 = self._finding("http://x.com/ok", "/ok", 200, 10, 1)
        with (
            patch(
                "mytools.network.dirscanner.create_async_client", return_value=client
            ),
            patch(
                "mytools.network.dirscanner.scan_path",
                new=AsyncMock(side_effect=[None, f1]),
            ),
            patch("mytools.network.dirscanner.detect_spa_fallback", return_value=[]),
        ):
            result = await scan_target(
                base_url="http://x.com/",
                paths=["gone", "ok"],
                timeout=5.0,
                concurrency=1,
                statuses={200},
                user_agent="UA",
                retries=1,
            )
        assert result == [f1]

    @pytest.mark.asyncio
    async def test_scan_target_no_spa(self):
        client = AsyncMock()
        f1 = self._finding(
            "http://x.com/admin", "/admin", 200, 100, 5, "Admin", "http://x.com/loc"
        )
        with (
            patch(
                "mytools.network.dirscanner.create_async_client", return_value=client
            ),
            patch(
                "mytools.network.dirscanner.scan_path",
                new=AsyncMock(return_value=f1),
            ),
            patch("mytools.network.dirscanner.detect_spa_fallback", return_value=[]),
        ):
            result = await scan_target(
                base_url="http://x.com/",
                paths=["admin"],
                timeout=5.0,
                concurrency=1,
                statuses={200},
                user_agent="UA",
                retries=1,
            )
        assert result == [f1]
        client.aclose.assert_awaited_once()


class TestPrintDirTable:
    def test_empty_findings(self, capsys):
        print_dir_table([])
        assert "Nenhum diretorio" in capsys.readouterr().out

    def test_with_findings(self, capsys):
        f = Finding(
            url="http://x.com/admin",
            path="/admin",
            status=200,
            size=100,
            words=5,
            title="Admin",
            location="http://x.com/login",
        )
        print_dir_table([f])
        out = capsys.readouterr().out
        assert "/admin" in out
        assert "200" in out


class TestRunSingle:
    @pytest.mark.asyncio
    async def test_json_output_no_table(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["--json", "http://example.com"])
        finding = Finding(
            url="http://example.com/admin",
            path="/admin",
            status=200,
            size=100,
            words=5,
            title="",
        )
        with patch(
            "mytools.network.dirscanner.scan_target",
            new=AsyncMock(return_value=[finding]),
        ):
            result = await _run_single("http://example.com", args)
        assert result == [finding]
        assert capsys.readouterr().out == ""

    @pytest.mark.asyncio
    async def test_table_output_not_quiet(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        finding = Finding(
            url="http://example.com/admin",
            path="/admin",
            status=200,
            size=100,
            words=5,
            title="Admin",
        )
        with patch(
            "mytools.network.dirscanner.scan_target",
            new=AsyncMock(return_value=[finding]),
        ):
            result = await _run_single("http://example.com", args)
        assert result == [finding]
        assert "/admin" in capsys.readouterr().out

    @pytest.mark.asyncio
    async def test_quiet_no_output(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["--quiet", "http://example.com"])
        finding = Finding(
            url="http://example.com/admin",
            path="/admin",
            status=200,
            size=100,
            words=5,
            title="",
        )
        with patch(
            "mytools.network.dirscanner.scan_target",
            new=AsyncMock(return_value=[finding]),
        ):
            result = await _run_single("http://example.com", args, quiet=True)
        assert result == [finding]
        assert capsys.readouterr().out == ""


class TestAsyncRunOnceMore:
    def test_concurrency_zero_raises(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--concurrency", "0"])
        with pytest.raises(ValueError, match="concorrencia"):
            asyncio.run(_async_run_once(args))

    @pytest.mark.asyncio
    async def test_output_dir_writes(self, tmp_path):
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "--output-dir", str(tmp_path)])
        finding = Finding(
            url="http://example.com/admin",
            path="/admin",
            status=200,
            size=100,
            words=5,
            title="",
        )
        with (
            patch(
                "mytools.network.dirscanner._run_single",
                new=AsyncMock(return_value=[finding]),
            ),
            patch("mytools.network.dirscanner.write_output") as mock_write,
        ):
            result = await _async_run_once(args)
        assert result == 0
        assert mock_write.call_count == 1

    @pytest.mark.asyncio
    async def test_output_file_writes(self, tmp_path):
        out = tmp_path / "out.json"
        parser = build_parser()
        args = parser.parse_args(["http://example.com", "-o", str(out)])
        finding = Finding(
            url="http://example.com/admin",
            path="/admin",
            status=200,
            size=100,
            words=5,
            title="",
        )
        with (
            patch(
                "mytools.network.dirscanner._run_single",
                new=AsyncMock(return_value=[finding]),
            ),
            patch("mytools.network.dirscanner.write_output") as mock_write,
        ):
            result = await _async_run_once(args)
        assert result == 0
        assert mock_write.call_count == 1

    @pytest.mark.asyncio
    async def test_json_output_all(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["--json", "http://example.com"])
        finding = Finding(
            url="http://example.com/admin",
            path="/admin",
            status=200,
            size=100,
            words=5,
            title="",
        )
        with patch(
            "mytools.network.dirscanner._run_single",
            new=AsyncMock(return_value=[finding]),
        ):
            result = await _async_run_once(args)
        assert result == 0
        assert "admin" in capsys.readouterr().out


class TestRunOnce:
    def test_calls_safe_asyncio_run(self):
        args = argparse.Namespace()
        with patch(
            "mytools.network.dirscanner._async_run_once",
            new=AsyncMock(return_value=0),
        ):
            assert run_once(args) == 0


class TestDirScannerMainGuard:
    def test_main_guard(self):
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-dir"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.network.dirscanner", run_name="__main__")
        assert exc_info.value.code == 0


# ── Flags comuns (add_common_args) ───────────────────────────────────────────


@pytest.mark.smoke
class TestCommonFlags:
    def test_has_json(self):
        args = build_parser().parse_args(["--json", "http://x.com"])
        assert args.json_output is True

    def test_has_quiet(self):
        args = build_parser().parse_args(["--quiet", "http://x.com"])
        assert args.quiet is True

    def test_has_theme(self):
        args = build_parser().parse_args(["--theme", "solarized", "http://x.com"])
        assert args.theme == "solarized"

    def test_has_random_delay(self):
        args = build_parser().parse_args(["--random-delay", "http://x.com"])
        assert args.random_delay is True


# ── Saida --json ─────────────────────────────────────────────────────────────


class TestJsonOutput:
    def test_json_output_is_valid(self, capsys):
        finding = Finding(
            url="http://x.com/admin",
            path="/admin",
            status=200,
            size=1234,
            words=100,
            title="Admin",
        )
        args = build_parser().parse_args(["--json", "-q", "http://x.com"])
        with patch(
            "mytools.network.dirscanner.scan_target",
            new=AsyncMock(return_value=[finding]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        captured = capsys.readouterr().out
        decoder = json.JSONDecoder()
        data, _ = decoder.raw_decode(captured)
        assert isinstance(data, list)
        assert data[0]["path"] == "/admin"
        assert json.loads(captured) == data

    def test_json_with_output_writes_file(self, capsys, tmp_path):
        finding = Finding(
            url="http://x.com/admin",
            path="/admin",
            status=200,
            size=1234,
            words=100,
            title="Admin",
        )
        out = tmp_path / "out.json"
        args = build_parser().parse_args(
            ["--json", "-q", "-o", str(out), "http://x.com"]
        )
        with patch(
            "mytools.network.dirscanner.scan_target",
            new=AsyncMock(return_value=[finding]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        assert out.exists()
        assert json.loads(out.read_text()) == [asdict(finding)]
        assert json.loads(capsys.readouterr().out) == json.loads(out.read_text())
