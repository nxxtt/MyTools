import argparse
import asyncio
import json
import runpy
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mytools.core.utils import RateLimiter
from mytools.web.sourcemapdiscovery import (
    DEFAULT_SCRIPT_PATHS,
    SourceMapInfo,
    _async_run_once,
    _fetch_page,
    _load_paths_from_args,
    _probe_map,
    build_map_urls,
    build_parser,
    extract_script_urls,
    main,
    parse_source_map,
    print_results,
    print_sources_detail,
    run_once,
    scan_sourcemaps,
)


class TestSourceMapInfo:
    def test_frozen(self):
        info = SourceMapInfo(url="http://x.com/app.js.map", status=200)
        with pytest.raises(AttributeError):
            info.url = "nope"  # type: ignore[reportAttributeAccessIssue]

    def test_defaults(self):
        info = SourceMapInfo(url="http://x.com/app.js.map")
        assert info.js_url == ""
        assert info.status == 0
        assert info.raw_size == 0
        assert info.sources == []
        assert info.sources_count == 0
        assert info.names_count == 0

    def test_all_fields(self):
        info = SourceMapInfo(
            url="http://x.com/app.js.map",
            js_url="http://x.com/app.js",
            status=200,
            raw_size=1024,
            sources=["src/app.ts", "src/utils.ts"],
            sources_count=2,
            names_count=10,
        )
        assert info.js_url == "http://x.com/app.js"
        assert info.sources_count == 2
        assert info.names_count == 10


class TestExtractScriptUrls:
    def test_single_script(self):
        html = '<script src="/static/js/app.js"></script>'
        urls = extract_script_urls(html, "http://example.com/")
        assert urls == ["http://example.com/static/js/app.js"]

    def test_multiple_scripts(self):
        html = '<script src="/js/vendor.js"></script><script src="/js/app.js"></script>'
        urls = extract_script_urls(html, "http://example.com/")
        assert len(urls) == 2
        assert "vendor" in urls[0]
        assert "app" in urls[1]

    def test_inline_script_ignored(self):
        html = '<script>console.log("hello")</script>'
        urls = extract_script_urls(html, "http://example.com/")
        assert urls == []

    def test_query_string_preserved(self):
        html = '<script src="/js/app.js?v=123"></script>'
        urls = extract_script_urls(html, "http://example.com/")
        assert len(urls) == 1
        assert "app.js" in urls[0]

    def test_empty_html(self):
        urls = extract_script_urls("", "http://example.com/")
        assert urls == []

    def test_aspas_simples(self):
        html = "<script src='/js/app.js'></script>"
        urls = extract_script_urls(html, "http://example.com/")
        assert len(urls) == 1

    def test_dedup(self):
        html = '<script src="/js/app.js"></script><script src="/js/app.js"></script>'
        urls = extract_script_urls(html, "http://example.com/")
        assert len(urls) == 1

    def test_absolute_url(self):
        html = '<script src="https://cdn.example.com/lib.js"></script>'
        urls = extract_script_urls(html, "http://example.com/")
        assert urls == ["https://cdn.example.com/lib.js"]

    def test_relative_path(self):
        html = '<script src="js/app.js"></script>'
        urls = extract_script_urls(html, "http://example.com/")
        assert urls == ["http://example.com/js/app.js"]

    def test_hash_not_captured(self):
        html = '<script src="/js/app.js#main"></script>'
        urls = extract_script_urls(html, "http://example.com/")
        assert urls == []


class TestBuildMapUrls:
    def test_basic_js(self):
        urls = build_map_urls("http://x.com/app.js")
        assert "http://x.com/app.js.map" in urls
        assert "http://x.com/app.js.map" in urls
        assert "http://x.com/app.map" in urls

    def test_min_js(self):
        urls = build_map_urls("http://x.com/app.min.js")
        assert len(urls) == 3
        assert urls[0].endswith(".js.map")

    def test_with_query(self):
        urls = build_map_urls("http://x.com/app.js?v=123")
        assert len(urls) == 3
        assert "v=123" not in urls[0]

    def test_non_js_returns_empty(self):
        urls = build_map_urls("http://x.com/style.css")
        assert urls == []

    def test_multiple_candidates(self):
        urls = build_map_urls("http://x.com/static/js/bundle.js")
        assert len(urls) == 3

    def test_query_base_not_js_returns_empty(self):
        urls = build_map_urls("http://x.com/a?b.js?c")
        assert urls == []


class TestParseSourceMap:
    def test_valid_sourcemap(self):
        data = json.dumps(
            {
                "version": 3,
                "file": "app.js",
                "sources": ["src/app.ts", "src/utils.ts"],
                "names": ["App", "Utils", "render"],
                "mappings": "AAAA;CCCC",
            }
        ).encode()
        result = parse_source_map(data)
        assert result is not None
        assert result.sources_count == 2
        assert result.names_count == 3
        assert result.raw_size == len(data)

    def test_empty_sources(self):
        data = json.dumps({"version": 3, "mappings": ""}).encode()
        result = parse_source_map(data)
        assert result is not None
        assert result.sources_count == 0

    def test_invalid_json(self):
        result = parse_source_map(b"not json at all")
        assert result is None

    def test_empty_content(self):
        result = parse_source_map(b"")
        assert result is None

    def test_not_a_dict(self):
        result = parse_source_map(json.dumps([1, 2, 3]).encode())
        assert result is None

    def test_no_sources_no_mappings(self):
        result = parse_source_map(json.dumps({"version": 3}).encode())
        assert result is None

    def test_non_string_sources_filtered(self):
        data = json.dumps(
            {
                "sources": ["a.ts", 123, None, "b.ts"],
                "mappings": "AAAA",
            }
        ).encode()
        result = parse_source_map(data)
        assert result is not None
        assert result.sources_count == 2

    def test_whitespace_only(self):
        result = parse_source_map(b"   \n  ")
        assert result is None

    def test_large_sourcemap(self):
        sources = [f"src/file{i}.ts" for i in range(100)]
        data = json.dumps(
            {
                "sources": sources,
                "names": [f"name{i}" for i in range(50)],
                "mappings": "A" * 1000,
            }
        ).encode()
        result = parse_source_map(data)
        assert result is not None
        assert result.sources_count == 100
        assert result.names_count == 50


class TestDefaultScriptPaths:
    def test_paths_are_strings(self):
        assert all(isinstance(p, str) for p in DEFAULT_SCRIPT_PATHS)

    def test_common_paths_present(self):
        assert "app.js" in DEFAULT_SCRIPT_PATHS
        assert "main.js" in DEFAULT_SCRIPT_PATHS
        assert "bundle.js" in DEFAULT_SCRIPT_PATHS

    def test_minimum_count(self):
        assert len(DEFAULT_SCRIPT_PATHS) >= 15

    def test_all_end_with_js(self):
        for p in DEFAULT_SCRIPT_PATHS:
            assert p.endswith(".js"), f"Path {p} should end with .js"


class TestLoadPaths:
    def test_default_returns_empty(self):
        args = argparse.Namespace(paths=0)
        result = _load_paths_from_args(args)
        assert result == []

    def test_limited(self):
        args = argparse.Namespace(paths=5)
        result = _load_paths_from_args(args)
        assert len(result) == 5

    def test_all(self):
        args = argparse.Namespace(paths=len(DEFAULT_SCRIPT_PATHS))
        result = _load_paths_from_args(args)
        assert len(result) == len(DEFAULT_SCRIPT_PATHS)

    def test_exceeds_max(self):
        args = argparse.Namespace(paths=999)
        result = _load_paths_from_args(args)
        assert len(result) == len(DEFAULT_SCRIPT_PATHS)


@pytest.mark.smoke
class TestBuildParser:
    def test_has_url(self):
        parser = build_parser()
        args = parser.parse_args(["http://example.com"])
        assert args.url == "http://example.com"

    def test_has_list(self):
        parser = build_parser()
        args = parser.parse_args(["-l", "urls.txt"])
        assert args.target_list == "urls.txt"

    def test_has_concurrency(self):
        parser = build_parser()
        args = parser.parse_args(["--concurrency", "50", "http://x.com"])
        assert args.concurrency == 50

    def test_default_concurrency(self):
        parser = build_parser()
        args = parser.parse_args(["http://x.com"])
        assert args.concurrency == 30

    def test_no_scan_scripts(self):
        parser = build_parser()
        args = parser.parse_args(["--no-scan-scripts", "http://x.com"])
        assert args.no_scan_scripts is True

    def test_no_scan_scripts_default(self):
        parser = build_parser()
        args = parser.parse_args(["http://x.com"])
        assert args.no_scan_scripts is False

    def test_has_sources_flag(self):
        parser = build_parser()
        args = parser.parse_args(["--sources", "http://x.com"])
        assert args.show_sources is True

    def test_has_timeout(self):
        parser = build_parser()
        args = parser.parse_args(["-t", "15", "http://x.com"])
        assert args.timeout == 15

    def test_has_output(self):
        parser = build_parser()
        args = parser.parse_args(["-o", "out.json", "http://x.com"])
        assert args.output == "out.json"

    def test_has_proxy(self):
        parser = build_parser()
        args = parser.parse_args(["--proxy", "http://p:8080", "http://x.com"])
        assert args.proxy == "http://p:8080"

    def test_has_user_agent(self):
        parser = build_parser()
        args = parser.parse_args(["-A", "Bot/1.0", "http://x.com"])
        assert args.user_agent == "Bot/1.0"

    def test_has_dry_run(self):
        parser = build_parser()
        args = parser.parse_args(["--dry-run", "http://x.com"])
        assert args.dry_run is True

    def test_has_retries(self):
        parser = build_parser()
        args = parser.parse_args(["--retries", "5", "http://x.com"])
        assert args.retries == 5

    def test_has_delay(self):
        parser = build_parser()
        args = parser.parse_args(["--delay", "2", "http://x.com"])
        assert args.delay == 2

    def test_has_cookie(self):
        parser = build_parser()
        args = parser.parse_args(["--cookie", "session=abc", "http://x.com"])
        assert args.cookie == "session=abc"

    def test_has_header(self):
        parser = build_parser()
        args = parser.parse_args(["--header", "X-Custom: yes", "http://x.com"])
        assert args.header == ["X-Custom: yes"]

    def test_has_paths_arg(self):
        parser = build_parser()
        args = parser.parse_args(["--paths", "10", "http://x.com"])
        assert args.paths == 10

    def test_default_paths(self):
        parser = build_parser()
        args = parser.parse_args(["http://x.com"])
        assert args.paths == 0


# ── Flags comuns (add_common_args) ───────────────────────────────────────────


@pytest.mark.smoke
class TestCommonFlags:
    def test_has_json(self):
        parser = build_parser()
        args = parser.parse_args(["--json", "http://x.com"])
        assert args.json_output is True

    def test_has_quiet(self):
        parser = build_parser()
        args = parser.parse_args(["--quiet", "http://x.com"])
        assert args.quiet is True

    def test_has_theme(self):
        parser = build_parser()
        args = parser.parse_args(["--theme", "solarized", "http://x.com"])
        assert args.theme == "solarized"

    def test_has_random_delay(self):
        parser = build_parser()
        args = parser.parse_args(["--random-delay", "http://x.com"])
        assert args.random_delay is True


# ── Saida --json ─────────────────────────────────────────────────────────────


class TestJsonOutput:
    def test_json_output_is_valid(self, capsys):
        info = SourceMapInfo(url="http://x.com/app.js.map", status=200)
        args = build_parser().parse_args(["--json", "-q", "http://x.com"])
        with patch(
            "mytools.web.sourcemapdiscovery.scan_sourcemaps",
            new=AsyncMock(return_value=[info]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        decoder = json.JSONDecoder()
        data, _ = decoder.raw_decode(capsys.readouterr().out)
        assert isinstance(data, list)
        assert data[0]["url"] == "http://x.com/app.js.map"


# ── _probe_map ───────────────────────────────────────────────────────────────


class TestProbeMap:
    @pytest.mark.asyncio
    @respx.mock
    async def test_found(self, async_client):
        respx.get("http://x.com/app.js.map").mock(
            return_value=httpx.Response(
                200,
                json={
                    "version": 3,
                    "sources": ["src/a.ts"],
                    "names": ["A"],
                    "mappings": "AAAA",
                },
                headers={"content-type": "application/json"},
            )
        )
        info = await _probe_map(
            async_client,
            RateLimiter(0),
            "http://x.com/app.js.map",
            "http://x.com/app.js",
            5.0,
            retries=1,
        )
        assert info is not None
        assert info.url == "http://x.com/app.js.map"
        assert info.js_url == "http://x.com/app.js"
        assert info.sources_count == 1
        assert info.names_count == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_error_returns_none(self, async_client):
        respx.get("http://x.com/app.js.map").mock(
            side_effect=httpx.ConnectError("refused")
        )
        info = await _probe_map(
            async_client,
            RateLimiter(0),
            "http://x.com/app.js.map",
            "http://x.com/app.js",
            5.0,
            retries=1,
        )
        assert info is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_bad_status_returns_none(self, async_client):
        respx.get("http://x.com/app.js.map").mock(
            return_value=httpx.Response(404, text="")
        )
        info = await _probe_map(
            async_client,
            RateLimiter(0),
            "http://x.com/app.js.map",
            "http://x.com/app.js",
            5.0,
            retries=1,
        )
        assert info is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_content_returns_none(self, async_client):
        respx.get("http://x.com/app.js.map").mock(
            return_value=httpx.Response(200, text="not a map")
        )
        info = await _probe_map(
            async_client,
            RateLimiter(0),
            "http://x.com/app.js.map",
            "http://x.com/app.js",
            5.0,
            retries=1,
        )
        assert info is None


# ── _fetch_page ──────────────────────────────────────────────────────────────


class TestFetchPage:
    @pytest.mark.asyncio
    @respx.mock
    async def test_html(self, async_client):
        respx.get("http://x.com/").mock(
            return_value=httpx.Response(
                200,
                text="<html><body>hi</body></html>",
                headers={"content-type": "text/html"},
            )
        )
        body = await _fetch_page(
            async_client, RateLimiter(0), "http://x.com/", 5.0, retries=1
        )
        assert "<html>" in body

    @pytest.mark.asyncio
    @respx.mock
    async def test_error_returns_empty(self, async_client):
        respx.get("http://x.com/").mock(side_effect=httpx.ConnectError("refused"))
        body = await _fetch_page(
            async_client, RateLimiter(0), "http://x.com/", 5.0, retries=1
        )
        assert body == ""

    @pytest.mark.asyncio
    @respx.mock
    async def test_non_html_returns_empty(self, async_client):
        respx.get("http://x.com/app.js").mock(
            return_value=httpx.Response(
                200, text="var a=1;", headers={"content-type": "application/javascript"}
            )
        )
        body = await _fetch_page(
            async_client, RateLimiter(0), "http://x.com/app.js", 5.0, retries=1
        )
        assert body == ""


# ── scan_sourcemaps ──────────────────────────────────────────────────────────


class TestScanSourcemaps:
    @pytest.mark.asyncio
    async def test_found(self, capsys):
        info = SourceMapInfo(
            url="http://x.com/app.js.map",
            js_url="http://x.com/app.js",
            status=200,
            sources=["src/a.ts"],
            sources_count=1,
        )
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.sourcemapdiscovery.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.sourcemapdiscovery._fetch_page",
                new_callable=AsyncMock,
                return_value='<script src="/app.js"></script>',
            ),
            patch(
                "mytools.web.sourcemapdiscovery._probe_map",
                new_callable=AsyncMock,
                return_value=info,
            ),
        ):
            result = await scan_sourcemaps(
                "http://x.com", 5.0, 2, "UA", scan_scripts=True, custom_paths=["app.js"]
            )
        assert result
        assert all(isinstance(r, SourceMapInfo) for r in result)
        out = capsys.readouterr().out
        assert "Source maps encontrados" in out

    @pytest.mark.asyncio
    async def test_no_html_uses_else_branch(self, capsys):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.sourcemapdiscovery.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.sourcemapdiscovery._fetch_page",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mytools.web.sourcemapdiscovery._probe_map",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            result = await scan_sourcemaps(
                "http://x.com", 5.0, 2, "UA", scan_scripts=True, custom_paths=["app.js"]
            )
        assert result == []
        out = capsys.readouterr().out
        assert "Nao foi possivel buscar" in out

    @pytest.mark.asyncio
    async def test_no_candidates(self, capsys):
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.sourcemapdiscovery.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.sourcemapdiscovery._fetch_page",
                new_callable=AsyncMock,
                return_value="",
            ),
            patch(
                "mytools.web.sourcemapdiscovery._probe_map",
                new_callable=AsyncMock,
                return_value=None,
            ),
        ):
            result = await scan_sourcemaps(
                "http://x.com",
                5.0,
                2,
                "UA",
                scan_scripts=False,
                custom_paths=["style.css"],
            )
        assert result == []
        out = capsys.readouterr().out
        assert "Nenhum candidato" in out


# ── print_results / print_sources_detail ─────────────────────────────────────


class TestPrintResults:
    def test_empty(self, capsys):
        print_results([])
        assert "Nenhum source map" in capsys.readouterr().out

    def test_with_maps(self, capsys):
        info = SourceMapInfo(
            url="http://x.com/app.js.map",
            js_url="http://x.com/app.js",
            status=200,
            raw_size=1024,
            sources_count=2,
            names_count=3,
        )
        print_results([info])
        out = capsys.readouterr().out
        assert "Source Maps Encontrados" in out
        assert "app.js.map" in out


class TestPrintSourcesDetail:
    def test_with_sources(self, capsys):
        info = SourceMapInfo(
            url="http://x.com/app.js.map",
            sources=[f"src/file{i}.ts" for i in range(35)],
        )
        print_sources_detail([info])
        out = capsys.readouterr().out
        assert "Sources:" in out
        assert "+5 mais" in out

    def test_empty_sources_skipped(self, capsys):
        info = SourceMapInfo(url="http://x.com/app.js.map")
        print_sources_detail([info])
        capsys.readouterr()


# ── _async_run_once / run_once / main ────────────────────────────────────────


class TestAsyncRunOnceExtra:
    def test_dry_run(self, capsys):
        args = build_parser().parse_args(["--dry-run", "http://x.com"])
        result = asyncio.run(_async_run_once(args))
        assert result == 0
        assert "DRY-RUN" in capsys.readouterr().out

    def test_show_sources(self, capsys):
        info = SourceMapInfo(
            url="http://x.com/app.js.map", sources=["src/a.ts"], sources_count=1
        )
        args = build_parser().parse_args(["--sources", "http://x.com"])
        with patch(
            "mytools.web.sourcemapdiscovery.scan_sourcemaps",
            new=AsyncMock(return_value=[info]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        out = capsys.readouterr().out
        assert "Sources:" in out

    def test_output_without_sources(self, capsys):
        info = SourceMapInfo(
            url="http://x.com/app.js.map", sources=["src/a.ts"], sources_count=1
        )
        args = build_parser().parse_args(["http://x.com"])
        with patch(
            "mytools.web.sourcemapdiscovery.scan_sourcemaps",
            new=AsyncMock(return_value=[info]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        out = capsys.readouterr().out
        assert "Source Maps Encontrados" in out
        assert "Sources:" not in out

    def test_output_dir_and_output_file(self, tmp_path):
        info = SourceMapInfo(url="http://x.com/app.js.map", status=200)
        out_dir = tmp_path / "out"
        out_dir.mkdir()
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(
            ["--output-dir", str(out_dir), "-o", str(out_file), "-q", "http://x.com"]
        )
        with patch(
            "mytools.web.sourcemapdiscovery.scan_sourcemaps",
            new=AsyncMock(return_value=[info]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        assert (out_dir / "x.com.json").exists()
        assert out_file.exists()


class TestRunOnce:
    def test_run_once(self):
        args = build_parser().parse_args(["-q", "-o", "out.json", "http://x.com"])
        with patch(
            "mytools.web.sourcemapdiscovery._async_run_once",
            new=AsyncMock(return_value=0),
        ):
            assert run_once(args) == 0


class TestMainEntry:
    def test_main(self):
        with patch("mytools.web.sourcemapdiscovery.run_main_loop", return_value=0):
            assert main() == 0

    def test_main_guard(self):
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.sourcemapdiscovery", run_name="__main__")
        assert exc_info.value.code == 0
