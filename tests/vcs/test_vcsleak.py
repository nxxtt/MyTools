import argparse
import asyncio
import json
from dataclasses import asdict
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mytools.vcs.vcsleak import (
    ALL_PATHS,
    GIT_PATHS,
    HG_PATHS,
    SVN_PATHS,
    VCSLeak,
    _async_run_once,
    _classify_path,
    _load_paths_from_args,
    _validate_content,
    build_parser,
    main,
    print_results,
    run_once,
    scan_vcs,
)


class TestVCSLeak:
    def test_frozen(self):
        leak = VCSLeak(vcs_type="git", url="http://x.com/.git/HEAD", path=".git/HEAD")
        with pytest.raises(AttributeError):
            leak.vcs_type = "hg"  # type: ignore[reportAttributeAccessIssue]

    def test_defaults(self):
        leak = VCSLeak(vcs_type="git", url="http://x.com/.git/HEAD", path=".git/HEAD")
        assert leak.status == 0
        assert leak.detail == ""
        assert leak.raw_size == 0

    def test_all_fields(self):
        leak = VCSLeak(
            vcs_type="git",
            url="http://x.com/.git/HEAD",
            path=".git/HEAD",
            status=200,
            detail="ref: refs/heads/main",
            raw_size=20,
        )
        assert leak.vcs_type == "git"
        assert leak.detail == "ref: refs/heads/main"


class TestClassifyPath:
    def test_git(self):
        assert _classify_path(".git/HEAD") == "git"
        assert _classify_path(".git/config") == "git"
        assert _classify_path(".gitignore") == "git"

    def test_svn(self):
        assert _classify_path(".svn/entries") == "svn"
        assert _classify_path(".svn/wc.db") == "svn"

    def test_hg(self):
        assert _classify_path(".hg/store/00manifest.i") == "hg"
        assert _classify_path(".hgignore") == "hg"

    def test_unknown(self):
        assert _classify_path("robots.txt") == "unknown"


class TestValidateContent:
    def test_git_head_valid(self):
        content = b"ref: refs/heads/main\n"
        ok, detail = _validate_content(".git/HEAD", content)
        assert ok is True
        assert "ref: refs/heads/main" in detail

    def test_git_head_invalid(self):
        content = b"not a git ref"
        ok, _ = _validate_content(".git/HEAD", content)
        assert ok is False

    def test_git_config_valid(self):
        content = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true"
        ok, detail = _validate_content(".git/config", content)
        assert ok is True
        assert "[core]" in detail

    def test_git_config_remote(self):
        content = b'[remote "origin"]\n\turl = https://github.com/x/y.git'
        ok, detail = _validate_content(".git/config", content)
        assert ok is True
        assert "[remote" in detail

    def test_git_config_empty(self):
        content = b"empty file"
        ok, _ = _validate_content(".git/config", content)
        assert ok is False

    def test_git_index_valid(self):
        content = b"DIRC" + b"\x00" * 100
        ok, detail = _validate_content(".git/index", content)
        assert ok is True
        assert "Git index" in detail

    def test_git_index_invalid(self):
        content = b"not an index"
        ok, _ = _validate_content(".git/index", content)
        assert ok is False

    def test_git_commit_msg(self):
        content = b"# Please enter the commit message"
        ok, _ = _validate_content(".git/COMMIT_EDITMSG", content)
        assert ok is True

    def test_git_packed_refs(self):
        content = b"abc123def456abc123def456abc123def456abc1 refs/heads/main\n"
        ok, _ = _validate_content(".git/packed-refs", content)
        assert ok is True

    def test_git_logs_head(self):
        content = b"abc123def456abc123def456abc123def456abc1 def456abc123def456abc123def456abc123def456abc1 Author <x@x.com> 1234567890 +0000\tcommit message\n"
        ok, _ = _validate_content(".git/logs/HEAD", content)
        assert ok is True

    def test_git_fallback(self):
        content = b"some git content here"
        ok, detail = _validate_content(".git/description", content)
        assert ok is True
        assert "some git content" in detail

    def test_svn_wc_db_valid(self):
        content = b"SQLite format 3" + b"\x00" * 100
        ok, detail = _validate_content(".svn/wc.db", content)
        assert ok is True
        assert "SQLite" in detail

    def test_svn_wc_db_invalid(self):
        content = b"not sqlite"
        ok, _ = _validate_content(".svn/wc.db", content)
        assert ok is False

    def test_svn_entries_valid(self):
        content = b"12\n\ndir\nhttps://svn.example.com/repo\n"
        ok, _ = _validate_content(".svn/entries", content)
        assert ok is True

    def test_hg_manifest_valid(self):
        content = b"abc123def456abc123def456abc123def456abc1 644 path/to/file\n"
        ok, _ = _validate_content(".hg/store/00manifest.i", content)
        assert ok is True

    def test_hg_dirstate_valid(self):
        content = (
            b"n   644   abc123def456abc123def456abc123def456abc1   path/file.txt\n"
        )
        ok, _ = _validate_content(".hg/dirstate", content)
        assert ok is True

    def test_empty_content(self):
        ok, detail = _validate_content(".git/HEAD", b"")
        assert ok is False
        assert detail == ""

    def test_unknown_path(self):
        content = b"some content"
        ok, _ = _validate_content("robots.txt", content)
        assert ok is False

    def test_git_refs_no_validator(self):
        ok, _ = _validate_content(".git/refs/heads/main", b"anything")
        assert ok is False

    def test_svn_entries_no_match(self):
        ok, _ = _validate_content(".svn/entries", b"garbage data")
        assert ok is False

    def test_svn_no_validator(self):
        ok, _ = _validate_content(".svn/all-wcprops", b"x")
        assert ok is False

    def test_hg_manifest_no_match(self):
        ok, _ = _validate_content(".hg/store/00manifest.i", b"garbage")
        assert ok is False

    def test_hg_no_validator(self):
        ok, _ = _validate_content(".hg/branch", b"x")
        assert ok is False

    def test_git_description_default(self):
        content = (
            b"Unnamed repository; edit this file 'description' to name the repository."
        )
        ok, _ = _validate_content(".git/description", content)
        assert ok is False


class TestPathConstants:
    def test_all_paths_are_strings(self):
        assert all(isinstance(p, str) for p in ALL_PATHS)

    def test_git_paths_have_git_prefix(self):
        assert all(p.startswith(".git") for p in GIT_PATHS)

    def test_svn_paths_have_svn_prefix(self):
        assert all(p.startswith(".svn") for p in SVN_PATHS)

    def test_hg_paths_have_hg_prefix(self):
        assert all(p.startswith(".hg") for p in HG_PATHS)

    def test_git_has_head(self):
        assert ".git/HEAD" in GIT_PATHS

    def test_svn_has_entries(self):
        assert ".svn/entries" in SVN_PATHS

    def test_hg_has_manifest(self):
        assert ".hg/store/00manifest.i" in HG_PATHS

    def test_minimum_count(self):
        assert len(ALL_PATHS) >= 20

    def test_minimum_git(self):
        assert len(GIT_PATHS) >= 8

    def test_minimum_svn(self):
        assert len(SVN_PATHS) >= 3

    def test_minimum_hg(self):
        assert len(HG_PATHS) >= 3


class TestLoadPaths:
    def test_default_returns_none(self):
        args = argparse.Namespace(git_only=False, svn_only=False, hg_only=False)
        result = _load_paths_from_args(args)
        assert result is None

    def test_git_only(self):
        args = argparse.Namespace(git_only=True, svn_only=False, hg_only=False)
        result = _load_paths_from_args(args)
        assert result == GIT_PATHS

    def test_svn_only(self):
        args = argparse.Namespace(git_only=False, svn_only=True, hg_only=False)
        result = _load_paths_from_args(args)
        assert result == SVN_PATHS

    def test_hg_only(self):
        args = argparse.Namespace(git_only=False, svn_only=False, hg_only=True)
        result = _load_paths_from_args(args)
        assert result == HG_PATHS

    def test_git_takes_priority(self):
        args = argparse.Namespace(git_only=True, svn_only=True, hg_only=True)
        result = _load_paths_from_args(args)
        assert result == GIT_PATHS


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

    def test_git_only(self):
        parser = build_parser()
        args = parser.parse_args(["--git-only", "http://x.com"])
        assert args.git_only is True

    def test_svn_only(self):
        parser = build_parser()
        args = parser.parse_args(["--svn-only", "http://x.com"])
        assert args.svn_only is True

    def test_hg_only(self):
        parser = build_parser()
        args = parser.parse_args(["--hg-only", "http://x.com"])
        assert args.hg_only is True

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


# ── scan_vcs (mock HTTP) ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_scan_vcs_no_results():
    with respx.mock:
        respx.route(method="HEAD", url__startswith="http://x.com/").mock(
            return_value=httpx.Response(404),
        )
        respx.route(method="GET", url__startswith="http://x.com/").mock(
            return_value=httpx.Response(404),
        )
        leaks = await scan_vcs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert leaks == []


@pytest.mark.asyncio
async def test_scan_vcs_finds_git_head():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.git/HEAD").mock(
            return_value=httpx.Response(200, headers={"content-length": "20"}),
        )
        respx.route(method="GET", url="http://x.com/.git/HEAD").mock(
            return_value=httpx.Response(200, content=b"ref: refs/heads/main\n"),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_vcs(
            base_url="http://x.com",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert any(leak.path == ".git/HEAD" for leak in leaks)
        head = next(leak for leak in leaks if leak.path == ".git/HEAD")
        assert head.exploit == "git clone http://x.com/"
        assert head.tool == "git"


@pytest.mark.asyncio
async def test_scan_vcs_finds_svn_wc_db():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.svn/wc.db").mock(
            return_value=httpx.Response(200),
        )
        respx.route(method="GET", url="http://x.com/.svn/wc.db").mock(
            return_value=httpx.Response(200, content=b"SQLite format 3" + b"\x00" * 50),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_vcs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert any(leak.path == ".svn/wc.db" for leak in leaks)
        svn = next(leak for leak in leaks if leak.path == ".svn/wc.db")
        assert svn.exploit == "svn checkout http://x.com/"
        assert svn.tool == "svn"


@pytest.mark.asyncio
async def test_scan_vcs_finds_hg_manifest():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.hg/store/00manifest.i").mock(
            return_value=httpx.Response(200),
        )
        respx.route(method="GET", url="http://x.com/.hg/store/00manifest.i").mock(
            return_value=httpx.Response(
                200, content=b"abc123def456abc123def456abc123def456abc1 644 path\n"
            ),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_vcs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert any(leak.path == ".hg/store/00manifest.i" for leak in leaks)
        hg = next(leak for leak in leaks if leak.path == ".hg/store/00manifest.i")
        assert hg.exploit == "hg clone http://x.com/"
        assert hg.tool == "hg"


@pytest.mark.asyncio
async def test_scan_vcs_head_405_then_get():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.git/HEAD").mock(
            return_value=httpx.Response(405),
        )
        respx.route(method="GET", url="http://x.com/.git/HEAD").mock(
            return_value=httpx.Response(200, content=b"ref: refs/heads/main\n"),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_vcs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert any(leak.path == ".git/HEAD" for leak in leaks)


@pytest.mark.asyncio
async def test_scan_vcs_head_fetch_error():
    with respx.mock:
        respx.route(method="HEAD", url__startswith="http://x.com/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        respx.route(method="GET", url__startswith="http://x.com/").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        leaks = await scan_vcs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert leaks == []


@pytest.mark.asyncio
async def test_scan_vcs_get_fetch_error():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.git/HEAD").mock(
            return_value=httpx.Response(200),
        )
        respx.route(method="GET", url="http://x.com/.git/HEAD").mock(
            side_effect=httpx.ConnectError("refused"),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_vcs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert leaks == []


@pytest.mark.asyncio
async def test_scan_vcs_get_non_200():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.git/HEAD").mock(
            return_value=httpx.Response(200),
        )
        respx.route(method="GET", url="http://x.com/.git/HEAD").mock(
            return_value=httpx.Response(404),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_vcs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert leaks == []


@pytest.mark.asyncio
async def test_scan_vcs_oversized():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.git/HEAD").mock(
            return_value=httpx.Response(200),
        )
        respx.route(method="GET", url="http://x.com/.git/HEAD").mock(
            return_value=httpx.Response(200, content=b"x" * (5 * 1024 * 1024 + 1)),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_vcs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert leaks == []


@pytest.mark.asyncio
async def test_scan_vcs_head_oversized_content_length():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.git/HEAD").mock(
            return_value=httpx.Response(
                200, headers={"content-length": str(5 * 1024 * 1024 + 1)}
            ),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_vcs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert leaks == []


@pytest.mark.asyncio
async def test_scan_vcs_head_invalid_content_length():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.git/HEAD").mock(
            return_value=httpx.Response(
                200, headers={"content-length": "not-a-number"}
            ),
        )
        respx.route(method="GET", url="http://x.com/.git/HEAD").mock(
            return_value=httpx.Response(200, content=b"ref: refs/heads/main\n"),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_vcs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert any(leak.path == ".git/HEAD" for leak in leaks)


@pytest.mark.asyncio
async def test_scan_vcs_invalid_content():
    with respx.mock:
        respx.route(method="HEAD", url="http://x.com/.git/HEAD").mock(
            return_value=httpx.Response(200),
        )
        respx.route(method="GET", url="http://x.com/.git/HEAD").mock(
            return_value=httpx.Response(200, content=b"not a ref"),
        )
        respx.route(method="HEAD").mock(return_value=httpx.Response(404))
        respx.route(method="GET").mock(return_value=httpx.Response(404))
        leaks = await scan_vcs(
            base_url="http://x.com/",
            timeout=5.0,
            concurrency=5,
            user_agent="test/1.0",
        )
        assert leaks == []


# ── print_results ─────────────────────────────────────────────────────────────


class TestPrintResults:
    def test_empty(self, capsys):
        print_results([])
        out = capsys.readouterr().out
        assert "Nenhum" in out

    def test_with_results(self, capsys):
        leaks = [
            VCSLeak(
                vcs_type="git",
                url="http://x.com/.git/HEAD",
                path=".git/HEAD",
                status=200,
                detail="ref: refs/heads/main",
                raw_size=20,
            ),
        ]
        print_results(leaks)
        out = capsys.readouterr().out
        assert ".git/HEAD" in out

    def test_with_exploit(self, capsys):
        leak = VCSLeak(
            vcs_type="git",
            url="http://x.com/.git/HEAD",
            path=".git/HEAD",
            status=200,
            detail="ref: refs/heads/main",
            raw_size=20,
            exploit="git clone http://x.com/.git",
            tool="git",
        )
        print_results([leak])
        out = capsys.readouterr().out
        assert "Exploits" in out


class TestAsyncRunOnce:
    def _args(self):
        args = build_parser().parse_args(["http://x.com"])
        args.dry_run = False
        args.json_output = False
        args.output = None
        args.output_dir = None
        return args

    def test_dry_run(self):
        args = self._args()
        args.dry_run = True
        with (
            patch("mytools.vcs.vcsleak.init_scanner", return_value=False),
            patch(
                "mytools.vcs.vcsleak.resolve_target_urls",
                return_value=["http://x.com/"],
            ),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_timeout_zero(self):
        args = self._args()
        args.timeout = 0
        with (
            patch("mytools.vcs.vcsleak.init_scanner", return_value=False),
            patch(
                "mytools.vcs.vcsleak.resolve_target_urls",
                return_value=["http://x.com/"],
            ),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 1

    def test_prints_results_when_not_quiet(self, capsys):
        args = self._args()
        with (
            patch("mytools.vcs.vcsleak.init_scanner", return_value=False),
            patch(
                "mytools.vcs.vcsleak.resolve_target_urls",
                return_value=["http://x.com/"],
            ),
            patch(
                "mytools.vcs.vcsleak.scan_vcs",
                new=AsyncMock(return_value=[]),
            ),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_json_output(self, capsys):
        args = self._args()
        args.json_output = True
        leak = VCSLeak(
            vcs_type="git",
            url="http://x.com/.git/HEAD",
            path=".git/HEAD",
            status=200,
            detail="ref: refs/heads/main",
        )
        with (
            patch("mytools.vcs.vcsleak.init_scanner", return_value=True),
            patch(
                "mytools.vcs.vcsleak.resolve_target_urls",
                return_value=["http://x.com/"],
            ),
            patch(
                "mytools.vcs.vcsleak.scan_vcs",
                new=AsyncMock(return_value=[leak]),
            ),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        captured = capsys.readouterr().out
        data = json.loads(captured)
        assert data == [asdict(leak)]

    def test_json_multiple_urls(self, capsys):
        args = self._args()
        args.json_output = True
        leak = VCSLeak(
            vcs_type="git",
            url="http://x.com/.git/HEAD",
            path=".git/HEAD",
            status=200,
            detail="ref: refs/heads/main",
        )
        with (
            patch("mytools.vcs.vcsleak.init_scanner", return_value=True),
            patch(
                "mytools.vcs.vcsleak.resolve_target_urls",
                return_value=["http://x.com/", "http://y.com/"],
            ),
            patch(
                "mytools.vcs.vcsleak.scan_vcs",
                new=AsyncMock(side_effect=[[leak], []]),
            ),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        captured = capsys.readouterr().out
        assert json.loads(captured) == [asdict(leak)]

    def test_json_with_output_writes_file(self, tmp_path, capsys):
        args = self._args()
        args.json_output = True
        args.output = str(tmp_path / "out.json")
        leak = VCSLeak(
            vcs_type="git",
            url="http://x.com/.git/HEAD",
            path=".git/HEAD",
            status=200,
            detail="ref: refs/heads/main",
        )
        with (
            patch("mytools.vcs.vcsleak.init_scanner", return_value=True),
            patch(
                "mytools.vcs.vcsleak.resolve_target_urls",
                return_value=["http://x.com/"],
            ),
            patch(
                "mytools.vcs.vcsleak.scan_vcs",
                new=AsyncMock(return_value=[leak]),
            ),
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        out_file = tmp_path / "out.json"
        assert out_file.exists()
        assert json.loads(out_file.read_text()) == [asdict(leak)]
        assert json.loads(capsys.readouterr().out) == [asdict(leak)]

    def test_output_dir(self, tmp_path):
        args = self._args()
        args.output_dir = str(tmp_path)
        with (
            patch("mytools.vcs.vcsleak.init_scanner", return_value=True),
            patch(
                "mytools.vcs.vcsleak.resolve_target_urls",
                return_value=["http://x.com/"],
            ),
            patch(
                "mytools.vcs.vcsleak.scan_vcs",
                new=AsyncMock(return_value=[]),
            ),
            patch("mytools.vcs.vcsleak.write_output") as mock_write,
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        mock_write.assert_called_once()

    def test_output_file(self, tmp_path):
        args = self._args()
        args.output = str(tmp_path / "out.json")
        with (
            patch("mytools.vcs.vcsleak.init_scanner", return_value=True),
            patch(
                "mytools.vcs.vcsleak.resolve_target_urls",
                return_value=["http://x.com/"],
            ),
            patch(
                "mytools.vcs.vcsleak.scan_vcs",
                new=AsyncMock(return_value=[]),
            ),
            patch("mytools.vcs.vcsleak.write_output") as mock_write,
        ):
            result = asyncio.run(_async_run_once(args))
        assert result == 0
        mock_write.assert_called_once()


# ── run_once / main / __main__ guard ─────────────────────────────────────────


class TestRunOnceAndMain:
    def test_run_once(self):
        args = argparse.Namespace()
        with patch(
            "mytools.vcs.vcsleak._async_run_once",
            new_callable=AsyncMock,
            return_value=0,
        ):
            assert run_once(args) == 0

    def test_main(self):
        with patch("mytools.vcs.vcsleak.run_main_loop", return_value=0) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()

    def test_main_guard(self):
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-vcsleak"]),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.vcs.vcsleak", run_name="__main__")
