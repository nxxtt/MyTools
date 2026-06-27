#!/usr/bin/env python3
"""Testes unitarios do modulo de Paste/Leak Monitoring."""
import httpx
import pytest
import respx

from pasteleak import (
    LeakRecord,
    _contains_domain,
    _dedup_leaks,
    _mask_secret,
    _scan_content,
    build_parser,
    print_results,
    scan_leaks,
)


class TestLeakRecord:
    """Testes do dataclass LeakRecord."""

    def test_frozen(self) -> None:
        r = LeakRecord(source="a", url="b", filename="c", matched_pattern="d", matched_text="e", found_at="f")
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
        leaks = _scan_content("token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234", "test", "http://x", "f.txt")
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
        leaks = _scan_content("-----BEGIN RSA PRIVATE KEY-----", "test", "http://x", "f.txt")
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
        leaks = _scan_content("auth_token=abc123def456ghi789", "test", "http://x", "f.txt")
        assert any(leak.matched_pattern == "token_assign" for leak in leaks)

    def test_connection_string(self) -> None:
        leaks = _scan_content("DATABASE_URL=postgres://user:pass@host/db", "test", "http://x", "f.txt")
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
        r1 = LeakRecord(source="a", url="b", filename="c", matched_pattern="d", matched_text="e", found_at="f")
        r2 = LeakRecord(source="a", url="b", filename="c", matched_pattern="d", matched_text="e", found_at="f")
        result = _dedup_leaks([r1, r2])
        assert len(result) == 1

    def test_different_sources(self) -> None:
        r1 = LeakRecord(source="a", url="b", filename="c", matched_pattern="d", matched_text="e", found_at="f")
        r2 = LeakRecord(source="x", url="b", filename="c", matched_pattern="d", matched_text="e", found_at="f")
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
        args = parser.parse_args(["example.com", "--source", "github_gists", "--source", "pastebin_rss"])
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
                "files": {"config.py": {"raw_url": "http://gist.githubusercontent.com/123/raw"}},
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
                "files": {"test.py": {"raw_url": "https://gitlab.com/snippets/123/raw"}},
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
                "files": {"config.py": {"raw_url": "http://gist.githubusercontent.com/123/raw"}},
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
                "files": {"test.py": {"raw_url": "https://gitlab.com/snippets/456/raw"}},
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
