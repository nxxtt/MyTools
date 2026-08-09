#!/usr/bin/env python3
"""Testes unitarios do modulo de Google Dorking."""

import asyncio
import json
import runpy
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mytools.osint.googledorking import (
    ALL_CATEGORIES,
    FILETYPE_DORKS,
    DorkQuery,
    _async_run_once,
    _build_ddg_url,
    _build_full_query,
    _build_google_url,
    _parse_ddg_results,
    add_custom_dorks,
    build_parser,
    generate_dorks,
    main,
    print_results,
    run_once,
    scan_dorks,
    search_ddg,
)

# ── Dataclass ────────────────────────────────────────────────────────────────


class TestDorkQuery:
    def test_frozen(self):
        q = DorkQuery(
            category="x", dork="y", full_query="z", google_url="a", ddg_url="b"
        )
        with pytest.raises(AttributeError):
            q.dork = "w"  # type: ignore[misc]

    def test_defaults(self):
        q = DorkQuery(
            category="x", dork="y", full_query="z", google_url="a", ddg_url="b"
        )
        assert q.results == []

    def test_all_fields(self):
        q = DorkQuery(
            category="filetype",
            dork="filetype:pdf",
            full_query="site:ex.com filetype:pdf",
            google_url="https://google.com/search?q=site%3Aex.com+filetype%3Apdf",
            ddg_url="https://html.duckduckgo.com/html/?q=site%3Aex.com+filetype%3Apdf",
            results=[{"title": "t", "url": "u", "snippet": "s"}],
        )
        assert q.category == "filetype"
        assert len(q.results) == 1


# ── _build_full_query ────────────────────────────────────────────────────────


class TestBuildFullQuery:
    def test_with_domain_placeholder(self):
        assert _build_full_query("site:*.{domain}", "ex.com") == "site:*.ex.com"

    def test_without_domain_placeholder(self):
        assert _build_full_query("filetype:pdf", "ex.com") == "site:ex.com filetype:pdf"

    def test_complex_dork(self):
        result = _build_full_query('intitle:"index of"', "ex.com")
        assert result == 'site:ex.com intitle:"index of"'


# ── _build_google_url ────────────────────────────────────────────────────────


class TestBuildGoogleUrl:
    def test_basic_query(self):
        url = _build_google_url("site:ex.com filetype:pdf")
        assert url.startswith("https://www.google.com/search?q=")
        assert "site%3Aex.com" in url

    def test_url_encoding(self):
        url = _build_google_url('site:ex.com intitle:"index of"')
        assert "%22" in url


# ── _build_ddg_url ───────────────────────────────────────────────────────────


class TestBuildDdgUrl:
    def test_basic_query(self):
        url = _build_ddg_url("site:ex.com filetype:pdf")
        assert url.startswith("https://html.duckduckgo.com/html/?q=")
        assert "site%3Aex.com" in url


# ── generate_dorks ───────────────────────────────────────────────────────────


class TestGenerateDorks:
    def test_all_categories(self):
        dorks = generate_dorks("ex.com")
        assert len(dorks) > 30

    def test_specific_category(self):
        dorks = generate_dorks("ex.com", categories=["filetype"])
        assert len(dorks) == len(FILETYPE_DORKS)
        assert all(q.category == "filetype" for q in dorks)

    def test_domain_in_query(self):
        dorks = generate_dorks("ex.com", categories=["filetype"])
        for q in dorks:
            assert "ex.com" in q.full_query

    def test_subdomain_placeholder(self):
        dorks = generate_dorks("ex.com", categories=["subdomain"])
        for q in dorks:
            assert "ex.com" in q.full_query
            assert "{domain}" not in q.full_query

    def test_google_url_populated(self):
        dorks = generate_dorks("ex.com", categories=["filetype"])
        for q in dorks:
            assert q.google_url.startswith("https://www.google.com/search?q=")

    def test_ddg_url_populated(self):
        dorks = generate_dorks("ex.com", categories=["filetype"])
        for q in dorks:
            assert q.ddg_url.startswith("https://html.duckduckgo.com/html/?q=")

    def test_custom_category_empty(self):
        dorks = generate_dorks("ex.com", categories=["custom"])
        assert dorks == []

    def test_multiple_categories(self):
        dorks = generate_dorks("ex.com", categories=["filetype", "login"])
        cats = {q.category for q in dorks}
        assert cats == {"filetype", "login"}

    def test_all_constants_populated(self):
        for cat, dorks in ALL_CATEGORIES.items():
            assert len(dorks) > 0, f"Categoria {cat} vazia"


# ── add_custom_dorks ─────────────────────────────────────────────────────────


class TestAddCustomDorks:
    def test_adds_custom(self):
        queries = generate_dorks("ex.com", categories=["filetype"])
        result = add_custom_dorks("ex.com", ["inurl:api v1"], queries)
        custom = [q for q in result if q.category == "custom"]
        assert len(custom) == 1
        assert "inurl:api v1" in custom[0].dork

    def test_empty_custom(self):
        queries = generate_dorks("ex.com", categories=["filetype"])
        result = add_custom_dorks("ex.com", [], queries)
        assert len(result) == len(queries)

    def test_multiple_custom(self):
        queries = generate_dorks("ex.com", categories=["filetype"])
        result = add_custom_dorks("ex.com", ["inurl:api", "inurl:admin"], queries)
        custom = [q for q in result if q.category == "custom"]
        assert len(custom) == 2


# ── _parse_ddg_results ───────────────────────────────────────────────────────


class TestParseDdgResults:
    def test_empty_html(self):
        assert _parse_ddg_results("") == []

    def test_no_results(self):
        html = "<html><body><p>No results</p></body></html>"
        assert _parse_ddg_results(html) == []

    def test_with_results(self):
        html = """
        <div class="result">
            <a class="result__a" href="http://example.com">Title</a>
            <a class="result__snippet" href="http://duckduckgo.com">Snippet text</a>
            <a class="result__url" href="http://example.com">example.com</a>
        </div>
        """
        results = _parse_ddg_results(html)
        assert len(results) == 1
        assert results[0]["title"] == "Title"
        assert results[0]["snippet"] == "Snippet text"
        assert results[0]["url"] == "example.com"

    def test_multiple_results(self):
        html = """
        <div class="result">
            <a class="result__a" href="http://a.com">A</a>
            <a class="result__snippet" href="#">S1</a>
            <a class="result__url" href="http://a.com">a.com</a>
        </div>
        <div class="result">
            <a class="result__a" href="http://b.com">B</a>
            <a class="result__snippet" href="#">S2</a>
            <a class="result__url" href="http://b.com">b.com</a>
        </div>
        """
        results = _parse_ddg_results(html)
        assert len(results) == 2

    def test_partial_fields(self):
        html = """
        <div class="result">
            <a class="result__a" href="http://x.com">X</a>
        </div>
        """
        results = _parse_ddg_results(html)
        assert len(results) == 1
        assert results[0]["title"] == "X"
        assert results[0]["url"] == ""

    def test_empty_title_and_url(self):
        html = """
        <div class="result">
            <a class="result__snippet" href="#">Only snippet</a>
        </div>
        """
        results = _parse_ddg_results(html)
        assert results == []


# ── print_results ─────────────────────────────────────────────────────────────


class TestPrintResults:
    def test_empty(self, capsys):
        print_results([])
        out = capsys.readouterr().out
        assert "Nenhuma" in out

    def test_with_results(self, capsys):
        queries = [
            DorkQuery(
                category="filetype",
                dork="filetype:pdf",
                full_query="site:ex.com filetype:pdf",
                google_url="https://google.com/search?q=x",
                ddg_url="https://ddg.com/x",
            ),
        ]
        print_results(queries)
        out = capsys.readouterr().out
        assert "filetype:pdf" in out

    def test_with_search_results(self, capsys):
        queries = [
            DorkQuery(
                category="filetype",
                dork="filetype:pdf",
                full_query="site:ex.com filetype:pdf",
                google_url="https://google.com/search?q=x",
                ddg_url="https://ddg.com/x",
                results=[{"title": "T", "url": "http://x.com", "snippet": "S"}],
            ),
        ]
        print_results(queries)
        out = capsys.readouterr().out
        assert "Resultados encontrados" in out


# ── search_ddg (mock) ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_search_ddg_success():
    from mytools.core.utils import RateLimiter

    html = """
    <div class="result">
        <a class="result__a" href="http://a.com">Title</a>
        <a class="result__snippet" href="#">Snippet</a>
        <a class="result__url" href="http://a.com">a.com</a>
    </div>
    """
    with respx.mock:
        respx.route(method="GET", url__startswith="https://html.duckduckgo.com/").mock(
            return_value=httpx.Response(200, text=html),
        )
        rate_limiter = RateLimiter(0)
        client = httpx.AsyncClient()
        results = await search_ddg(
            client, "site:ex.com filetype:pdf", 5.0, rate_limiter, max_results=5
        )
        await client.aclose()
        assert len(results) == 1
        assert results[0]["title"] == "Title"


@pytest.mark.asyncio
async def test_search_ddg_error():
    from mytools.core.utils import RateLimiter

    with respx.mock:
        respx.route(method="GET", url__startswith="https://html.duckduckgo.com/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        rate_limiter = RateLimiter(0)
        client = httpx.AsyncClient()
        results = await search_ddg(client, "test", 5.0, rate_limiter)
        await client.aclose()
        assert results == []


@pytest.mark.asyncio
async def test_search_ddg_non_200():
    from mytools.core.utils import RateLimiter

    with respx.mock:
        respx.route(method="GET", url__startswith="https://html.duckduckgo.com/").mock(
            return_value=httpx.Response(500),
        )
        rate_limiter = RateLimiter(0)
        client = httpx.AsyncClient()
        results = await search_ddg(client, "test", 5.0, rate_limiter)
        await client.aclose()
        assert results == []


# ── build_parser ──────────────────────────────────────────────────────────────


@pytest.mark.smoke
class TestBuildParser:
    def test_has_domain(self):
        args = build_parser().parse_args(["ex.com"])
        assert args.domain == "ex.com"

    def test_has_list(self):
        args = build_parser().parse_args(["-l", "domains.txt"])
        assert args.target_list == "domains.txt"

    def test_has_category(self):
        args = build_parser().parse_args(["-c", "filetype"])
        assert args.category == "filetype"

    def test_has_search(self):
        args = build_parser().parse_args(["--search"])
        assert args.do_search is True

    def test_has_custom_dork(self):
        args = build_parser().parse_args(["--custom-dork", "inurl:api"])
        assert args.custom_dorks == ["inurl:api"]

    def test_has_multiple_custom_dorks(self):
        args = build_parser().parse_args(["--custom-dork", "a", "--custom-dork", "b"])
        assert args.custom_dorks == ["a", "b"]

    def test_default_category(self):
        args = build_parser().parse_args([])
        assert args.category == "all"


# ── scan_dorks (mock) ────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_dorks_no_search():
    queries = await scan_dorks("ex.com", do_search=False)
    assert len(queries) > 30
    for q in queries:
        assert "ex.com" in q.full_query


@pytest.mark.asyncio
async def test_scan_dorks_with_search():
    html = """
    <div class="result">
        <a class="result__a" href="http://a.com">Title</a>
        <a class="result__snippet" href="#">Snippet</a>
        <a class="result__url" href="http://a.com">a.com</a>
    </div>
    """
    with respx.mock:
        respx.route(method="GET", url__startswith="https://html.duckduckgo.com/").mock(
            return_value=httpx.Response(200, text=html),
        )
        queries = await scan_dorks(
            "ex.com",
            categories=["filetype"],
            do_search=True,
            max_results=2,
        )
        assert len(queries) == len(FILETYPE_DORKS)
        has_results = any(q.results for q in queries)
        assert has_results


@pytest.mark.asyncio
async def test_scan_dorks_custom_dorks():
    queries = await scan_dorks(
        "ex.com",
        categories=["filetype"],
        custom_dorks=["inurl:secret"],
        do_search=False,
    )
    custom = [q for q in queries if q.category == "custom"]
    assert len(custom) == 1
    assert "inurl:secret" in custom[0].dork


# ── Flags comuns (add_common_args) ───────────────────────────────────────────


@pytest.mark.smoke
class TestCommonFlags:
    def test_has_json(self):
        args = build_parser().parse_args(["--json", "ex.com"])
        assert args.json_output is True

    def test_has_quiet(self):
        args = build_parser().parse_args(["--quiet", "ex.com"])
        assert args.quiet is True

    def test_has_theme(self):
        args = build_parser().parse_args(["--theme", "solarized", "ex.com"])
        assert args.theme == "solarized"

    def test_has_random_delay(self):
        args = build_parser().parse_args(["--random-delay", "ex.com"])
        assert args.random_delay is True


# ── Saida --json ─────────────────────────────────────────────────────────────


class TestJsonOutput:
    def test_json_output_is_valid(self, capsys):
        query = DorkQuery(
            category="filetype",
            dork="filetype:pdf",
            full_query="site:ex.com filetype:pdf",
            google_url="https://google.com/",
            ddg_url="https://ddg.co/",
            results=[],
        )
        args = build_parser().parse_args(["--json", "-q", "ex.com"])
        with patch(
            "mytools.osint.googledorking.scan_dorks",
            new=AsyncMock(return_value=[query]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        data = json.loads(capsys.readouterr().out)
        assert isinstance(data, list)
        assert data[0]["dork"] == "filetype:pdf"


# ── Saida --output-dir ───────────────────────────────────────────────────────


class TestOutputDir:
    def test_creates_file(self, tmp_path):
        query = DorkQuery(
            category="filetype",
            dork="filetype:pdf",
            full_query="site:ex.com filetype:pdf",
            google_url="https://google.com/",
            ddg_url="https://ddg.co/",
            results=[],
        )
        args = build_parser().parse_args(
            ["--output-dir", str(tmp_path), "-q", "ex.com"]
        )
        with patch(
            "mytools.osint.googledorking.scan_dorks",
            new=AsyncMock(return_value=[query]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        out_file = tmp_path / "ex.com.json"
        assert out_file.exists()
        data = json.loads(out_file.read_text(encoding="utf-8"))
        assert data[0]["dork"] == "filetype:pdf"


# ── print_results quiet / edge paths ─────────────────────────────────────────


class TestPrintResultsEdges:
    def test_quiet(self, capsys) -> None:
        print_results([], quiet=True)
        out = capsys.readouterr().out
        assert out == ""

    def test_mixed_results(self, capsys) -> None:
        queries = [
            DorkQuery(
                category="filetype",
                dork="filetype:pdf",
                full_query="site:ex.com filetype:pdf",
                google_url="https://google.com/search?q=x",
                ddg_url="https://ddg.com/x",
                results=[{"title": "T", "url": "http://x.com", "snippet": "S"}],
            ),
            DorkQuery(
                category="filetype",
                dork="filetype:sql",
                full_query="site:ex.com filetype:sql",
                google_url="https://google.com/search?q=y",
                ddg_url="https://ddg.com/y",
            ),
        ]
        print_results(queries)
        out = capsys.readouterr().out
        assert "Resultados encontrados" in out
        assert "filetype:sql" in out


# ── run_once / _async_run_once / main ────────────────────────────────────────


class TestRunOnce:
    def test_run_once(self) -> None:
        args = build_parser().parse_args(["ex.com"])
        with (
            patch(
                "mytools.osint.googledorking._async_run_once",
                new_callable=MagicMock,
                return_value=0,
            ),
            patch(
                "mytools.osint.googledorking.safe_asyncio_run",
                new_callable=MagicMock,
                return_value=0,
            ) as mock_safe,
        ):
            result = run_once(args)
            assert result == 0
        mock_safe.assert_called_once()


class TestAsyncRunOnce:
    def test_dry_run(self) -> None:
        args = build_parser().parse_args(["ex.com", "--dry-run"])
        result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_no_target(self) -> None:
        args = build_parser().parse_args([])
        result = asyncio.run(_async_run_once(args))
        assert result == 1

    def test_file_not_found(self) -> None:
        args = build_parser().parse_args(["-l", "missing.txt"])
        with patch(
            "mytools.osint.googledorking.read_target_lines",
            side_effect=FileNotFoundError,
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 1

    def test_no_results_warning(self) -> None:
        args = build_parser().parse_args(["ex.com"])
        with patch(
            "mytools.osint.googledorking.scan_dorks",
            new=AsyncMock(return_value=[]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_print_results_path(self) -> None:
        query = DorkQuery(
            category="filetype",
            dork="filetype:pdf",
            full_query="site:ex.com filetype:pdf",
            google_url="https://google.com/",
            ddg_url="https://ddg.co/",
        )
        args = build_parser().parse_args(["ex.com"])
        with patch(
            "mytools.osint.googledorking.scan_dorks",
            new=AsyncMock(return_value=[query]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_output_flag(self, tmp_path) -> None:
        query = DorkQuery(
            category="filetype",
            dork="filetype:pdf",
            full_query="site:ex.com filetype:pdf",
            google_url="https://google.com/",
            ddg_url="https://ddg.co/",
        )
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(["ex.com", "-o", str(out_file)])
        with (
            patch(
                "mytools.osint.googledorking.scan_dorks",
                new=AsyncMock(return_value=[query]),
            ),
            patch("mytools.osint.googledorking.write_output") as mock_write,
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        mock_write.assert_called_once()


class TestMain:
    def test_main(self) -> None:
        with patch(
            "mytools.osint.googledorking.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-dork", "ex.com"]),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.osint.googledorking", run_name="__main__")
