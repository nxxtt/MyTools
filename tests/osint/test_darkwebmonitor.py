#!/usr/bin/env python3
"""Testes unitarios do modulo de Dark Web Monitoring."""

import asyncio
import runpy
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mytools.core.utils import RateLimiter
from mytools.osint.darkwebmonitor import (
    DarkWebMention,
    _async_run_once,
    _classify_severity,
    _dedup_mentions,
    _query_ahmia,
    _query_darksearch,
    _query_intelx,
    banner,
    build_parser,
    main,
    print_results,
    run_once,
    scan_darkweb,
)


class TestDarkWebMention:
    """Testes do dataclass DarkWebMention."""

    def test_frozen(self) -> None:
        r = DarkWebMention(
            source="a",
            url="b",
            title="c",
            snippet="d",
            date_seen="e",
            domain="f",
            severity="g",
        )
        with pytest.raises(AttributeError):
            r.source = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(DarkWebMention, "__slots__")


class TestClassifySeverity:
    """Testes da funcao _classify_severity."""

    def test_critical(self) -> None:
        assert _classify_severity("password dump leaked") == "critical"

    def test_high(self) -> None:
        assert _classify_severity("exploit attack method") == "high"

    def test_medium(self) -> None:
        assert _classify_severity("forum discussion about") == "medium"

    def test_low(self) -> None:
        assert _classify_severity("mention reference link") == "low"

    def test_info(self) -> None:
        assert _classify_severity("random unrelated text") == "info"

    def test_case_insensitive(self) -> None:
        assert _classify_severity("PASSWORD leaked") == "critical"


class TestDedupMentions:
    """Testes da funcao _dedup_mentions."""

    def test_dedup(self) -> None:
        r1 = DarkWebMention(
            source="a",
            url="b",
            title="c",
            snippet="d",
            date_seen="e",
            domain="f",
            severity="g",
        )
        r2 = DarkWebMention(
            source="a",
            url="b",
            title="c",
            snippet="d",
            date_seen="e",
            domain="f",
            severity="g",
        )
        result = _dedup_mentions([r1, r2])
        assert len(result) == 1

    def test_different_sources(self) -> None:
        r1 = DarkWebMention(
            source="a",
            url="b",
            title="c",
            snippet="d",
            date_seen="e",
            domain="f",
            severity="g",
        )
        r2 = DarkWebMention(
            source="x",
            url="b",
            title="c",
            snippet="d",
            date_seen="e",
            domain="f",
            severity="g",
        )
        result = _dedup_mentions([r1, r2])
        assert len(result) == 2

    def test_empty(self) -> None:
        assert _dedup_mentions([]) == []


class TestParser:
    """Testes do build_parser."""

    def test_basic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_source(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["example.com", "--source", "ahmia", "--source", "darksearch"]
        )
        assert args.sources == ["ahmia", "darksearch"]

    def test_intelx_key(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--intelx-key", "test123"])
        assert args.intelx_key == "test123"

    def test_max_results(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--max-results", "50"])
        assert args.max_results == 50

    def test_list_file(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-l", "domains.txt"])
        assert args.target_list == "domains.txt"


class TestPrintResults:
    """Testes da funcao print_results."""

    def test_empty(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_results([])
        out = capsys.readouterr().out
        assert "Nenhuma mencao" in out

    def test_with_data(self, capsys: pytest.CaptureFixture[str]) -> None:
        mentions = [
            DarkWebMention(
                source="ahmia",
                url="http://example.onion",
                title="test mention",
                snippet="password dump",
                date_seen="2025-01-01T00:00:00",
                domain="example.com",
                severity="critical",
            ),
        ]
        print_results(mentions)
        out = capsys.readouterr().out
        assert "1 mencao" in out
        assert "ahmia" in out
        assert "CRITICAL" in out


class TestScanDarkweb:
    """Testes da funcao scan_darkweb com mocks HTTP."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_ahmia(self) -> None:
        html = '<div class="result"><h3><a href="http://test.onion">test password dump</a></h3></div>'
        respx.get("https://ahmia.fi/search/").mock(
            return_value=httpx.Response(200, text=html),
        )

        mentions = await scan_darkweb(
            domain="example.com",
            sources=["ahmia"],
            api_keys={},
            max_results=5,
        )
        assert any(m.source == "ahmia" for m in mentions)

    @pytest.mark.asyncio
    @respx.mock
    async def test_darksearch(self) -> None:
        api_response = {
            "data": [
                {
                    "title": "example.com password leak",
                    "description": "password dump found",
                    "link": "http://example.onion/page",
                    "date": "2025-01-01",
                },
            ],
        }
        respx.get("https://darksearch.io/api/search").mock(
            return_value=httpx.Response(200, json=api_response),
        )

        mentions = await scan_darkweb(
            domain="example.com",
            sources=["darksearch"],
            api_keys={},
            max_results=5,
        )
        assert any(m.source == "darksearch" for m in mentions)

    @pytest.mark.asyncio
    @respx.mock
    async def test_intelx_no_key(self) -> None:
        mentions = await scan_darkweb(
            domain="example.com",
            sources=["intelx"],
            api_keys={},
            max_results=5,
        )
        assert mentions == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_empty_results(self) -> None:
        respx.get("https://ahmia.fi/search/").mock(
            return_value=httpx.Response(200, text=""),
        )
        respx.get("https://darksearch.io/api/search").mock(
            return_value=httpx.Response(200, json={"data": []}),
        )

        mentions = await scan_darkweb(
            domain="example.com",
            sources=["ahmia", "darksearch"],
            api_keys={},
            max_results=5,
        )
        assert mentions == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_unknown_source(self) -> None:
        mentions = await scan_darkweb(
            domain="example.com",
            sources=["unknown_source"],
            api_keys={},
            max_results=5,
        )
        assert mentions == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_dedup_across_sources(self) -> None:
        html = '<div class="result"><h3><a href="http://test.onion">example password</a></h3></div>'
        respx.get("https://ahmia.fi/search/").mock(
            return_value=httpx.Response(200, text=html),
        )
        api_response = {
            "data": [
                {
                    "title": "example password",
                    "description": "found",
                    "link": "http://test.onion/page",
                    "date": "2025-01-01",
                },
            ],
        }
        respx.get("https://darksearch.io/api/search").mock(
            return_value=httpx.Response(200, json=api_response),
        )

        mentions = await scan_darkweb(
            domain="example.com",
            sources=["ahmia", "darksearch"],
            api_keys={},
            max_results=5,
        )
        assert len(mentions) == 2


# ── Edge/error paths de _query_ahmia ─────────────────────────────────────────


class TestQueryAhmiaEdges:
    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_error(self) -> None:
        respx.get(url__startswith="https://ahmia.fi/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        mentions = await _query_ahmia(client, "example.com", 5.0, rl)
        await client.aclose()
        assert mentions == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_non_200(self) -> None:
        respx.get(url__startswith="https://ahmia.fi/").mock(
            return_value=httpx.Response(500),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        mentions = await _query_ahmia(client, "example.com", 5.0, rl)
        await client.aclose()
        assert mentions == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_empty_title(self) -> None:
        html = '<h3><a href="http://x.onion"></a></h3>'
        respx.get(url__startswith="https://ahmia.fi/").mock(
            return_value=httpx.Response(200, text=html),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        mentions = await _query_ahmia(client, "example.com", 5.0, rl)
        await client.aclose()
        assert mentions == []


# ── Edge/error paths de _query_darksearch ────────────────────────────────────


class TestQueryDarksearchEdges:
    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_error(self) -> None:
        respx.get(url__startswith="https://darksearch.io/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        mentions = await _query_darksearch(client, "example.com", 5.0, rl)
        await client.aclose()
        assert mentions == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_non_200(self) -> None:
        respx.get(url__startswith="https://darksearch.io/").mock(
            return_value=httpx.Response(500),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        mentions = await _query_darksearch(client, "example.com", 5.0, rl)
        await client.aclose()
        assert mentions == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_missing_link(self) -> None:
        api_response = {
            "data": [
                {
                    "title": "example.com password leak",
                    "description": "password dump",
                    "date": "2025-01-01",
                },
            ],
        }
        respx.get(url__startswith="https://darksearch.io/").mock(
            return_value=httpx.Response(200, json=api_response),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        mentions = await _query_darksearch(client, "example.com", 5.0, rl)
        await client.aclose()
        assert mentions == []


# ── _query_intelx ────────────────────────────────────────────────────────────


class TestQueryIntelx:
    @pytest.mark.asyncio
    @respx.mock
    async def test_success(self) -> None:
        respx.post("https://2.intelx.io/intelligent/search").mock(
            return_value=httpx.Response(200, json={"id": "abc123"}),
        )
        respx.get("https://2.intelx.io/intelligent/search/result?id=abc123&x=20").mock(
            return_value=httpx.Response(
                200,
                json={
                    "records": [
                        {
                            "name": "password dump for example.com",
                            "selector_value": "test@example.com",
                            "bucket": "pastes",
                        },
                    ]
                },
            ),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        mentions = await _query_intelx(client, "example.com", 5.0, rl, "key123")
        await client.aclose()
        assert len(mentions) == 1
        assert mentions[0].source == "intelx"
        assert mentions[0].severity == "critical"

    @pytest.mark.asyncio
    @respx.mock
    async def test_no_key(self) -> None:
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        mentions = await _query_intelx(client, "example.com", 5.0, rl, "")
        await client.aclose()
        assert mentions == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_error(self) -> None:
        respx.post("https://2.intelx.io/intelligent/search").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        mentions = await _query_intelx(client, "example.com", 5.0, rl, "key123")
        await client.aclose()
        assert mentions == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_non_200(self) -> None:
        respx.post("https://2.intelx.io/intelligent/search").mock(
            return_value=httpx.Response(500),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        mentions = await _query_intelx(client, "example.com", 5.0, rl, "key123")
        await client.aclose()
        assert mentions == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_json(self) -> None:
        respx.post("https://2.intelx.io/intelligent/search").mock(
            return_value=httpx.Response(200, text="<not json>"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        mentions = await _query_intelx(client, "example.com", 5.0, rl, "key123")
        await client.aclose()
        assert mentions == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_no_search_id(self) -> None:
        respx.post("https://2.intelx.io/intelligent/search").mock(
            return_value=httpx.Response(200, json={"id": ""}),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        mentions = await _query_intelx(client, "example.com", 5.0, rl, "key123")
        await client.aclose()
        assert mentions == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_result_fetch_error(self) -> None:
        respx.post("https://2.intelx.io/intelligent/search").mock(
            return_value=httpx.Response(200, json={"id": "abc123"}),
        )
        respx.get(url__startswith="https://2.intelx.io/intelligent/search/result").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        mentions = await _query_intelx(client, "example.com", 5.0, rl, "key123")
        await client.aclose()
        assert mentions == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_result_non_200(self) -> None:
        respx.post("https://2.intelx.io/intelligent/search").mock(
            return_value=httpx.Response(200, json={"id": "abc123"}),
        )
        respx.get(url__startswith="https://2.intelx.io/intelligent/search/result").mock(
            return_value=httpx.Response(500),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        mentions = await _query_intelx(client, "example.com", 5.0, rl, "key123")
        await client.aclose()
        assert mentions == []


# ── Banner / run_once / _async_run_once / main ───────────────────────────────


class TestBanner:
    def test_banner(self) -> None:
        with patch("mytools.osint.darkwebmonitor.create_banner") as mock_create:
            mock_create.return_value = MagicMock()
            banner()
        mock_create.assert_called_once()


class TestRunOnce:
    def test_run_once(self) -> None:
        args = build_parser().parse_args(["example.com"])
        with (
            patch(
                "mytools.osint.darkwebmonitor._async_run_once",
                new_callable=MagicMock,
                return_value=0,
            ),
            patch(
                "mytools.osint.darkwebmonitor.safe_asyncio_run",
                new_callable=MagicMock,
                return_value=0,
            ) as mock_safe,
        ):
            result = run_once(args)
            assert result == 0
        mock_safe.assert_called_once()


class TestAsyncRunOnce:
    def test_no_target(self) -> None:
        args = build_parser().parse_args([])
        result = asyncio.run(_async_run_once(args))
        assert result == 1

    def test_file_not_found(self) -> None:
        args = build_parser().parse_args(["-l", "definitely_missing_12345.txt"])
        result = asyncio.run(_async_run_once(args))
        assert result == 1

    def test_dry_run(self) -> None:
        args = build_parser().parse_args(["example.com", "--dry-run"])
        result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_domain_from_file(self, tmp_path) -> None:
        domain_file = tmp_path / "domains.txt"
        domain_file.write_text("example.com\nother.com\n\n", encoding="utf-8")
        args = build_parser().parse_args(["-l", str(domain_file)])
        with patch(
            "mytools.osint.darkwebmonitor.scan_darkweb",
            new=AsyncMock(return_value=[]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_intelx_without_key(self) -> None:
        args = build_parser().parse_args(["example.com", "--source", "intelx"])
        with patch(
            "mytools.osint.darkwebmonitor.scan_darkweb",
            new=AsyncMock(return_value=[]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_with_output(self, tmp_path) -> None:
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(["example.com", "-o", str(out_file)])
        with (
            patch(
                "mytools.osint.darkwebmonitor.scan_darkweb",
                new=AsyncMock(return_value=[]),
            ),
            patch("mytools.osint.darkwebmonitor.write_output") as mock_write,
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        mock_write.assert_called_once()

    def test_quiet_skips_print(self, tmp_path) -> None:
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(["example.com", "-q", "-o", str(out_file)])
        with (
            patch(
                "mytools.osint.darkwebmonitor.scan_darkweb",
                new=AsyncMock(return_value=[]),
            ),
            patch("mytools.osint.darkwebmonitor.print_results") as mock_print,
            patch("mytools.osint.darkwebmonitor.write_output") as mock_write,
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        mock_print.assert_not_called()
        mock_write.assert_called_once()


class TestMain:
    def test_main(self) -> None:
        with patch(
            "mytools.osint.darkwebmonitor.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-darkwebmonitor", "example.com"]),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.osint.darkwebmonitor", run_name="__main__")
