#!/usr/bin/env python3
"""Testes unitarios do modulo de Paste/Leak Monitoring."""

import asyncio
import runpy
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mytools.core.utils import RateLimiter
from mytools.osint.pasteleak import (
    LeakRecord,
    _async_run_once,
    _contains_domain,
    _dedup_leaks,
    _mask_secret,
    _query_github_code,
    _query_github_gists,
    _query_gitlab_snippets,
    _query_pastebin_rss,
    _scan_content,
    banner,
    build_parser,
    main,
    print_results,
    run_once,
    scan_leaks,
)


class TestLeakRecord:
    """Testes do dataclass LeakRecord."""

    def test_frozen(self) -> None:
        r = LeakRecord(
            source="a",
            url="b",
            filename="c",
            matched_pattern="d",
            matched_text="e",
            found_at="f",
        )
        with pytest.raises(AttributeError):
            r.source = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(LeakRecord, "__slots__")


class TestMaskSecret:
    """Testes da funcao _mask_secret."""

    def test_short(self) -> None:
        assert _mask_secret("abc") == "ab***"

    def test_medium(self) -> None:
        assert _mask_secret("abcdefgh") == "ab***"

    def test_long(self) -> None:
        assert _mask_secret("AKIAIOSFODNN7EXAMPLE") == "AKIA***MPLE"


class TestScanContent:
    """Testes da funcao _scan_content."""

    def test_aws_key(self) -> None:
        leaks = _scan_content("key=AKIAIOSFODNN7EXAMPLE", "test", "http://x", "f.txt")
        assert len(leaks) >= 1
        assert any(leak.matched_pattern == "aws_key" for leak in leaks)

    def test_github_token(self) -> None:
        leaks = _scan_content(
            "token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234",
            "test",
            "http://x",
            "f.txt",
        )
        assert any(leak.matched_pattern == "github_token" for leak in leaks)

    def test_slack_token(self) -> None:
        fake_slack = "xoxb-" + "1" * 10 + "-" + "2" * 12 + "-" + "a" * 32
        leaks = _scan_content(fake_slack, "test", "http://x", "f.txt")
        assert any(leak.matched_pattern == "slack_token" for leak in leaks)

    def test_stripe_key(self) -> None:
        fake_stripe = "sk_live_" + "a" * 24
        leaks = _scan_content(fake_stripe, "test", "http://x", "f.txt")
        assert any(leak.matched_pattern == "stripe_key" for leak in leaks)

    def test_private_key(self) -> None:
        leaks = _scan_content(
            "-----BEGIN RSA PRIVATE KEY-----", "test", "http://x", "f.txt"
        )
        assert any(leak.matched_pattern == "private_key" for leak in leaks)

    def test_password_assign(self) -> None:
        leaks = _scan_content('password="supersecret123"', "test", "http://x", "f.txt")
        assert any(leak.matched_pattern == "password_assign" for leak in leaks)

    def test_api_key_assign(self) -> None:
        leaks = _scan_content("api_key: abcdefghijklmnop", "test", "http://x", "f.txt")
        assert any(leak.matched_pattern == "api_key_assign" for leak in leaks)

    def test_secret_assign(self) -> None:
        leaks = _scan_content("secret=mysupersecretvalue", "test", "http://x", "f.txt")
        assert any(leak.matched_pattern == "secret_assign" for leak in leaks)

    def test_token_assign(self) -> None:
        leaks = _scan_content(
            "auth_token=abc123def456ghi789", "test", "http://x", "f.txt"
        )
        assert any(leak.matched_pattern == "token_assign" for leak in leaks)

    def test_connection_string(self) -> None:
        leaks = _scan_content(
            "DATABASE_URL=postgres://user:pass@host/db", "test", "http://x", "f.txt"
        )
        assert any(leak.matched_pattern == "connection_string" for leak in leaks)

    def test_no_match(self) -> None:
        leaks = _scan_content("nothing interesting here", "test", "http://x", "f.txt")
        assert leaks == []

    def test_multiple(self) -> None:
        content = "AKIAIOSFODNN7EXAMPLE\npassword=secret123"
        leaks = _scan_content(content, "test", "http://x", "f.txt")
        patterns = {leak.matched_pattern for leak in leaks}
        assert "aws_key" in patterns
        assert "password_assign" in patterns


class TestDedupLeaks:
    """Testes da funcao _dedup_leaks."""

    def test_dedup(self) -> None:
        r1 = LeakRecord(
            source="a",
            url="b",
            filename="c",
            matched_pattern="d",
            matched_text="e",
            found_at="f",
        )
        r2 = LeakRecord(
            source="a",
            url="b",
            filename="c",
            matched_pattern="d",
            matched_text="e",
            found_at="f",
        )
        result = _dedup_leaks([r1, r2])
        assert len(result) == 1

    def test_different_sources(self) -> None:
        r1 = LeakRecord(
            source="a",
            url="b",
            filename="c",
            matched_pattern="d",
            matched_text="e",
            found_at="f",
        )
        r2 = LeakRecord(
            source="x",
            url="b",
            filename="c",
            matched_pattern="d",
            matched_text="e",
            found_at="f",
        )
        result = _dedup_leaks([r1, r2])
        assert len(result) == 2

    def test_empty(self) -> None:
        assert _dedup_leaks([]) == []


class TestContainsDomain:
    """Testes da funcao _contains_domain."""

    def test_match(self) -> None:
        assert _contains_domain("config for example.com", "example.com")

    def test_case_insensitive(self) -> None:
        assert _contains_domain("EXAMPLE.COM config", "example.com")

    def test_no_match(self) -> None:
        assert not _contains_domain("nothing here", "example.com")


class TestParser:
    """Testes do build_parser."""

    def test_basic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com"])
        assert args.domain == "example.com"

    def test_source(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            ["example.com", "--source", "github_gists", "--source", "pastebin_rss"]
        )
        assert args.sources == ["github_gists", "pastebin_rss"]

    def test_github_token(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["example.com", "--github-token", "ghp_xxx"])
        assert args.github_token == "ghp_xxx"

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
        assert "Nenhum leak" in out

    def test_with_data(self, capsys: pytest.CaptureFixture[str]) -> None:
        leaks = [
            LeakRecord(
                source="github_gists",
                url="http://gist.github.com/123",
                filename="config.py",
                matched_pattern="password_assign",
                matched_text="pass***",
                found_at="2025-01-01T00:00:00",
            ),
        ]
        print_results(leaks)
        out = capsys.readouterr().out
        assert "1 leak" in out
        assert "github_gists" in out
        assert "password_assign" in out


class TestScanLeaks:
    """Testes da funcao scan_leaks com mocks HTTP."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_github_gists(self) -> None:
        gist_list = [
            {
                "description": "config for example.com",
                "html_url": "http://gist.github.com/123",
                "files": {
                    "config.py": {
                        "raw_url": "http://gist.githubusercontent.com/123/raw"
                    }
                },
            },
        ]
        respx.get("https://api.github.com/gists/public").mock(
            return_value=httpx.Response(200, json=gist_list),
        )
        respx.get("http://gist.githubusercontent.com/123/raw").mock(
            return_value=httpx.Response(200, text='password="secret123"'),
        )

        leaks = await scan_leaks(
            domain="example.com",
            sources=["github_gists"],
            api_keys={},
            max_results=5,
        )
        assert any(leak.source == "github_gists" for leak in leaks)

    @pytest.mark.asyncio
    @respx.mock
    async def test_gitlab_snippets(self) -> None:
        snippet_list = [
            {
                "title": "test.py",
                "web_url": "https://gitlab.com/snippets/123",
                "files": {
                    "test.py": {"raw_url": "https://gitlab.com/snippets/123/raw"}
                },
            },
        ]
        respx.get("https://gitlab.com/api/v4/snippets/public").mock(
            return_value=httpx.Response(200, json=snippet_list),
        )
        respx.get("https://gitlab.com/snippets/123/raw").mock(
            return_value=httpx.Response(200, text="AKIAIOSFODNN7EXAMPLE"),
        )

        leaks = await scan_leaks(
            domain="example.com",
            sources=["gitlab_snippets"],
            api_keys={},
            max_results=5,
        )
        assert any(leak.source == "gitlab_snippets" for leak in leaks)

    @pytest.mark.asyncio
    @respx.mock
    async def test_pastebin_rss(self) -> None:
        rss_xml = """<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
  <entry>
    <title>paste1</title>
    <link href="https://pastebin.com/abc123"/>
  </entry>
</feed>"""
        respx.get("https://pastebin.com/feed.php").mock(
            return_value=httpx.Response(200, text=rss_xml),
        )
        respx.get("https://pastebin.com/abc123").mock(
            return_value=httpx.Response(200, text="api_key=abcdefgh12345678"),
        )

        leaks = await scan_leaks(
            domain="example.com",
            sources=["pastebin_rss"],
            api_keys={},
            max_results=5,
        )
        assert any(leak.source == "pastebin_rss" for leak in leaks)

    @pytest.mark.asyncio
    @respx.mock
    async def test_github_code_no_token(self) -> None:
        leaks = await scan_leaks(
            domain="example.com",
            sources=["github_code"],
            api_keys={},
            max_results=5,
        )
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_unknown_source(self) -> None:
        leaks = await scan_leaks(
            domain="example.com",
            sources=["unknown_source"],
            api_keys={},
            max_results=5,
        )
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_github_code_with_token(self) -> None:
        code_result = {
            "items": [
                {
                    "repository": {"full_name": "user/repo"},
                    "path": "config.py",
                    "html_url": "https://github.com/user/repo/blob/main/config.py",
                    "download_url": "https://raw.githubusercontent.com/user/repo/main/config.py",
                },
            ],
        }
        respx.get("https://api.github.com/search/code").mock(
            return_value=httpx.Response(200, json=code_result),
        )
        respx.get("https://raw.githubusercontent.com/user/repo/main/config.py").mock(
            return_value=httpx.Response(200, text='password="test123"'),
        )

        leaks = await scan_leaks(
            domain="example.com",
            sources=["github_code"],
            api_keys={"github_token": "ghp_test123"},
            max_results=5,
        )
        assert any(leak.source == "github_code" for leak in leaks)

    @pytest.mark.asyncio
    @respx.mock
    async def test_empty_results(self) -> None:
        respx.get("https://api.github.com/gists/public").mock(
            return_value=httpx.Response(200, json=[]),
        )
        respx.get("https://gitlab.com/api/v4/snippets/public").mock(
            return_value=httpx.Response(200, json=[]),
        )

        leaks = await scan_leaks(
            domain="example.com",
            sources=["github_gists", "gitlab_snippets"],
            api_keys={},
            max_results=5,
        )
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_dedup_across_sources(self) -> None:
        gist_list = [
            {
                "description": "config for example.com",
                "html_url": "http://gist.github.com/123",
                "files": {
                    "config.py": {
                        "raw_url": "http://gist.githubusercontent.com/123/raw"
                    }
                },
            },
        ]
        respx.get("https://api.github.com/gists/public").mock(
            return_value=httpx.Response(200, json=gist_list),
        )
        respx.get("http://gist.githubusercontent.com/123/raw").mock(
            return_value=httpx.Response(200, text="AKIAIOSFODNN7EXAMPLE"),
        )
        snippet_list = [
            {
                "title": "test.py",
                "web_url": "https://gitlab.com/snippets/456",
                "files": {
                    "test.py": {"raw_url": "https://gitlab.com/snippets/456/raw"}
                },
            },
        ]
        respx.get("https://gitlab.com/api/v4/snippets/public").mock(
            return_value=httpx.Response(200, json=snippet_list),
        )
        respx.get("https://gitlab.com/snippets/456/raw").mock(
            return_value=httpx.Response(200, text="AKIAIOSFODNN7EXAMPLE"),
        )

        leaks = await scan_leaks(
            domain="example.com",
            sources=["github_gists", "gitlab_snippets"],
            api_keys={},
            max_results=5,
        )
        aws_leaks = [leak for leak in leaks if leak.matched_pattern == "aws_key"]
        assert len(aws_leaks) == 2


# ── Edge/error paths de _query_github_gists ──────────────────────────────────


class TestQueryGithubGistsEdges:
    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_error(self) -> None:
        respx.get(url__startswith="https://api.github.com/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_github_gists(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_non_200(self) -> None:
        respx.get(url__startswith="https://api.github.com/").mock(
            return_value=httpx.Response(500),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_github_gists(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_json(self) -> None:
        respx.get(url__startswith="https://api.github.com/").mock(
            return_value=httpx.Response(200, text="<not json>"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_github_gists(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_raw_fetch_error(self) -> None:
        gist_list = [
            {
                "description": "config for example.com",
                "html_url": "http://gist.github.com/1",
                "files": {"c.py": {"raw_url": "http://raw.gist/1"}},
            },
        ]
        respx.get(url__startswith="https://api.github.com/gists/public").mock(
            return_value=httpx.Response(200, json=gist_list),
        )
        respx.get("http://raw.gist/1").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_github_gists(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_max_results_break(self) -> None:
        gist_list = [
            {
                "description": "config for example.com",
                "html_url": "http://gist.github.com/1",
                "files": {"c.py": {"raw_url": "http://raw.gist/1"}},
            },
            {
                "description": "other",
                "html_url": "http://gist.github.com/2",
                "files": {"d.py": {"raw_url": "http://raw.gist/2"}},
            },
        ]
        respx.get("https://api.github.com/gists/public?per_page=1").mock(
            return_value=httpx.Response(200, json=gist_list),
        )
        respx.get("http://raw.gist/1").mock(
            return_value=httpx.Response(200, text="password=secret123"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_github_gists(client, "example.com", 5.0, rl, max_results=1)
        await client.aclose()
        assert len(leaks) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_description_not_matching(self) -> None:
        gist_list = [
            {
                "description": "unrelated content",
                "html_url": "http://gist.github.com/1",
                "files": {"c.py": {"raw_url": "http://raw.gist/1"}},
            },
        ]
        respx.get(url__startswith="https://api.github.com/gists/public").mock(
            return_value=httpx.Response(200, json=gist_list),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_github_gists(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_file_without_raw_url(self) -> None:
        gist_list = [
            {
                "description": "config for example.com",
                "html_url": "http://gist.github.com/1",
                "files": {"c.py": {}},
            },
        ]
        respx.get(url__startswith="https://api.github.com/gists/public").mock(
            return_value=httpx.Response(200, json=gist_list),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_github_gists(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_raw_non_200(self) -> None:
        gist_list = [
            {
                "description": "config for example.com",
                "html_url": "http://gist.github.com/1",
                "files": {"c.py": {"raw_url": "http://raw.gist/1"}},
            },
        ]
        respx.get(url__startswith="https://api.github.com/gists/public").mock(
            return_value=httpx.Response(200, json=gist_list),
        )
        respx.get("http://raw.gist/1").mock(return_value=httpx.Response(500))
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_github_gists(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []


# ── Edge/error paths de _query_pastebin_rss ──────────────────────────────────


class TestQueryPastebinRssEdges:
    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_error(self) -> None:
        respx.get(url__startswith="https://pastebin.com/feed.php").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_pastebin_rss(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_non_200(self) -> None:
        respx.get(url__startswith="https://pastebin.com/feed.php").mock(
            return_value=httpx.Response(500),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_pastebin_rss(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_xml(self) -> None:
        respx.get(url__startswith="https://pastebin.com/feed.php").mock(
            return_value=httpx.Response(200, text="not xml at all"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_pastebin_rss(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_entry_without_link(self) -> None:
        rss_xml = (
            '<?xml version="1.0"?><feed><entry><title>no link</title></entry></feed>'
        )
        respx.get(url__startswith="https://pastebin.com/feed.php").mock(
            return_value=httpx.Response(200, text=rss_xml),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_pastebin_rss(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_raw_fetch_error(self) -> None:
        rss_xml = """<?xml version="1.0"?>
<feed>
  <entry>
    <title>p1</title>
    <link href="https://pastebin.com/raw/xyz"/>
  </entry>
</feed>"""
        respx.get(url__startswith="https://pastebin.com/feed.php").mock(
            return_value=httpx.Response(200, text=rss_xml),
        )
        respx.get("https://pastebin.com/raw/xyz").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_pastebin_rss(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_max_results_break(self) -> None:
        rss_xml = """<?xml version="1.0"?>
<feed>
  <entry>
    <title>p1</title>
    <link href="https://pastebin.com/raw/abc"/>
  </entry>
  <entry>
    <title>p2</title>
    <link href="https://pastebin.com/raw/def"/>
  </entry>
</feed>"""
        respx.get(url__startswith="https://pastebin.com/feed.php").mock(
            return_value=httpx.Response(200, text=rss_xml),
        )
        respx.get("https://pastebin.com/raw/abc").mock(
            return_value=httpx.Response(200, text="password=secret123"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_pastebin_rss(client, "example.com", 5.0, rl, max_results=1)
        await client.aclose()
        assert len(leaks) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_raw_non_200(self) -> None:
        rss_xml = """<?xml version="1.0"?>
<feed>
  <entry>
    <title>p1</title>
    <link href="https://pastebin.com/raw/xyz"/>
  </entry>
</feed>"""
        respx.get(url__startswith="https://pastebin.com/feed.php").mock(
            return_value=httpx.Response(200, text=rss_xml),
        )
        respx.get("https://pastebin.com/raw/xyz").mock(return_value=httpx.Response(500))
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_pastebin_rss(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []


# ── Edge/error paths de _query_gitlab_snippets ───────────────────────────────


class TestQueryGitlabEdges:
    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_error(self) -> None:
        respx.get(url__startswith="https://gitlab.com/api/v4/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_gitlab_snippets(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_non_200(self) -> None:
        respx.get(url__startswith="https://gitlab.com/api/v4/").mock(
            return_value=httpx.Response(500),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_gitlab_snippets(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_raw_fetch_error(self) -> None:
        snippets = [
            {
                "web_url": "https://gitlab.com/snippets/1",
                "files": {"c.py": {"raw_url": "https://gitlab.com/snippets/1/raw"}},
            },
        ]
        respx.get(url__startswith="https://gitlab.com/api/v4/snippets/public").mock(
            return_value=httpx.Response(200, json=snippets),
        )
        respx.get("https://gitlab.com/snippets/1/raw").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_gitlab_snippets(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_max_results_break(self) -> None:
        snippets = [
            {
                "web_url": "https://gitlab.com/snippets/1",
                "files": {"c.py": {"raw_url": "https://gitlab.com/snippets/1/raw"}},
            },
            {
                "web_url": "https://gitlab.com/snippets/2",
                "files": {"d.py": {"raw_url": "https://gitlab.com/snippets/2/raw"}},
            },
        ]
        respx.get("https://gitlab.com/api/v4/snippets/public?per_page=1").mock(
            return_value=httpx.Response(200, json=snippets),
        )
        respx.get("https://gitlab.com/snippets/1/raw").mock(
            return_value=httpx.Response(200, text="password=secret123"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_gitlab_snippets(
            client, "example.com", 5.0, rl, max_results=1
        )
        await client.aclose()
        assert len(leaks) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_file_without_raw_url(self) -> None:
        snippets = [
            {
                "web_url": "https://gitlab.com/snippets/1",
                "files": {"c.py": {}},
            },
        ]
        respx.get(url__startswith="https://gitlab.com/api/v4/snippets/public").mock(
            return_value=httpx.Response(200, json=snippets),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_gitlab_snippets(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_raw_non_200(self) -> None:
        snippets = [
            {
                "web_url": "https://gitlab.com/snippets/1",
                "files": {"c.py": {"raw_url": "https://gitlab.com/snippets/1/raw"}},
            },
        ]
        respx.get(url__startswith="https://gitlab.com/api/v4/snippets/public").mock(
            return_value=httpx.Response(200, json=snippets),
        )
        respx.get("https://gitlab.com/snippets/1/raw").mock(
            return_value=httpx.Response(500)
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_gitlab_snippets(client, "example.com", 5.0, rl)
        await client.aclose()
        assert leaks == []


# ── Edge/error paths de _query_github_code ───────────────────────────────────


class TestQueryGithubCodeEdges:
    @pytest.mark.asyncio
    @respx.mock
    async def test_fetch_error(self) -> None:
        respx.get(url__startswith="https://api.github.com/search/code").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_github_code(client, "example.com", 5.0, rl, "ghp_test", 5)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_non_200(self) -> None:
        respx.get(url__startswith="https://api.github.com/search/code").mock(
            return_value=httpx.Response(500),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_github_code(client, "example.com", 5.0, rl, "ghp_test", 5)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_json(self) -> None:
        respx.get(url__startswith="https://api.github.com/search/code").mock(
            return_value=httpx.Response(200, text="<not json>"),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_github_code(client, "example.com", 5.0, rl, "ghp_test", 5)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_raw_fetch_error(self) -> None:
        items = [
            {
                "path": "config.py",
                "html_url": "https://github.com/user/repo/blob/main/config.py",
                "download_url": "https://raw.githubusercontent.com/user/repo/main/config.py",
            },
        ]
        respx.get(url__startswith="https://api.github.com/search/code").mock(
            return_value=httpx.Response(200, json={"items": items}),
        )
        respx.get("https://raw.githubusercontent.com/user/repo/main/config.py").mock(
            side_effect=httpx.ConnectError("refused")
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_github_code(client, "example.com", 5.0, rl, "ghp_test", 5)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_max_results_break(self) -> None:
        items = [
            {
                "path": "config.py",
                "html_url": "https://github.com/user/repo/blob/main/config.py",
                "download_url": "https://raw.githubusercontent.com/user/repo/main/config.py",
            },
            {
                "path": "x.py",
                "html_url": "https://github.com/user/repo/blob/main/x.py",
                "download_url": "https://raw.githubusercontent.com/user/repo/main/x.py",
            },
        ]
        respx.get(url__startswith="https://api.github.com/search/code").mock(
            return_value=httpx.Response(200, json={"items": items}),
        )
        respx.get("https://raw.githubusercontent.com/user/repo/main/config.py").mock(
            return_value=httpx.Response(200, text="password=secret123")
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_github_code(client, "example.com", 5.0, rl, "ghp_test", 1)
        await client.aclose()
        assert len(leaks) >= 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_item_without_download_url(self) -> None:
        items = [
            {
                "path": "config.py",
                "html_url": "https://github.com/user/repo/blob/main/config.py",
            },
        ]
        respx.get(url__startswith="https://api.github.com/search/code").mock(
            return_value=httpx.Response(200, json={"items": items}),
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_github_code(client, "example.com", 5.0, rl, "ghp_test", 5)
        await client.aclose()
        assert leaks == []

    @pytest.mark.asyncio
    @respx.mock
    async def test_download_non_200(self) -> None:
        items = [
            {
                "path": "config.py",
                "html_url": "https://github.com/user/repo/blob/main/config.py",
                "download_url": "https://raw.githubusercontent.com/user/repo/main/config.py",
            },
        ]
        respx.get(url__startswith="https://api.github.com/search/code").mock(
            return_value=httpx.Response(200, json={"items": items}),
        )
        respx.get("https://raw.githubusercontent.com/user/repo/main/config.py").mock(
            return_value=httpx.Response(500)
        )
        client = httpx.AsyncClient()
        rl = RateLimiter(0)
        leaks = await _query_github_code(client, "example.com", 5.0, rl, "ghp_test", 5)
        await client.aclose()
        assert leaks == []


# ── Banner / run_once / _async_run_once / main ───────────────────────────────


class TestBanner:
    def test_banner(self) -> None:
        with patch("mytools.osint.pasteleak.create_banner") as mock_create:
            mock_create.return_value = MagicMock()
            banner()
        mock_create.assert_called_once()


class TestRunOnce:
    def test_run_once(self) -> None:
        args = build_parser().parse_args(["example.com"])
        with (
            patch(
                "mytools.osint.pasteleak._async_run_once",
                new_callable=MagicMock,
                return_value=0,
            ),
            patch(
                "mytools.osint.pasteleak.safe_asyncio_run",
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
            "mytools.osint.pasteleak.scan_leaks",
            new=AsyncMock(return_value=[]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_github_code_without_token(self) -> None:
        args = build_parser().parse_args(["example.com", "--source", "github_code"])
        with patch(
            "mytools.osint.pasteleak.scan_leaks",
            new=AsyncMock(return_value=[]),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_with_output(self, tmp_path) -> None:
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(["example.com", "-o", str(out_file)])
        with (
            patch(
                "mytools.osint.pasteleak.scan_leaks",
                new=AsyncMock(return_value=[]),
            ),
            patch("mytools.osint.pasteleak.write_output") as mock_write,
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        mock_write.assert_called_once()

    def test_quiet_skips_print(self, tmp_path) -> None:
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(["example.com", "-q", "-o", str(out_file)])
        with (
            patch(
                "mytools.osint.pasteleak.scan_leaks",
                new=AsyncMock(return_value=[]),
            ),
            patch("mytools.osint.pasteleak.print_results") as mock_print,
            patch("mytools.osint.pasteleak.write_output") as mock_write,
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        mock_print.assert_not_called()
        mock_write.assert_called_once()


class TestMain:
    def test_main(self) -> None:
        with patch(
            "mytools.osint.pasteleak.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-pasteleak", "example.com"]),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.osint.pasteleak", run_name="__main__")
