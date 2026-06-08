from __future__ import annotations

import argparse
import os

from dirscanner import (
    DEFAULT_PATHS,
    DEFAULT_STATUSES,
    Finding,
    build_parser,
    load_paths,
    normalize_base_url,
    parse_extensions,
    parse_statuses,
)


class TestNormalizeBaseUrl:
    def test_adds_http_scheme(self):
        assert normalize_base_url("example.com") == "http://example.com/"

    def test_keeps_https(self):
        assert normalize_base_url("https://example.com") == "https://example.com/"

    def test_strips_trailing_slash_then_adds(self):
        assert normalize_base_url("https://example.com/") == "https://example.com/"

    def test_preserves_path(self):
        assert normalize_base_url("https://example.com/app") == "https://example.com/app/"

    def test_invalid_scheme_raises(self):
        try:
            normalize_base_url("ftp://example.com")
            assert False, "Should have raised"
        except ValueError:
            pass

    def test_empty_netloc_raises(self):
        try:
            normalize_base_url("http://")
            assert False, "Should have raised"
        except ValueError:
            pass


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
        try:
            parse_statuses("99")
            assert False, "Should have raised"
        except argparse.ArgumentTypeError:
            pass


class TestParseExtensions:
    def test_simple(self):
        assert parse_extensions("php,txt") == ["php", "txt"]

    def test_with_dots(self):
        assert parse_extensions(".php,.bak") == ["php", "bak"]

    def test_empty(self):
        assert parse_extensions("") == []

    def test_whitespace(self):
        assert parse_extensions(" php , txt ") == ["php", "txt"]


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
        f = Finding(url="http://x.com/a", path="/a", status=200, size=100, words=5, title="T")
        assert f.status == 200
        assert f.location == ""

    def test_frozen(self):
        f = Finding(url="http://x.com/a", path="/a", status=200, size=100, words=5, title="T")
        try:
            f.status = 404
            assert False, "Should be frozen"
        except AttributeError:
            pass


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

    def test_default_threads(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.threads == 40
