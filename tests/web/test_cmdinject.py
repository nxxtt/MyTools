import argparse
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.cmdinject import (
    CmdInjectAttempt,
    CmdInjectResult,
    _check_content,
    _check_timing,
    _find_cmd_params,
    _make_inject_url,
    build_parser,
    main,
    print_results,
    run_scan,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# _check_content
# ---------------------------------------------------------------------------


class TestCheckContent:
    def test_uid(self) -> None:
        body = b"<html>uid=33(www-data) gid=33(www-data)</html>"
        detected, ctype = _check_content(body)
        assert detected is True
        assert ctype == "uid"

    def test_whoami(self) -> None:
        body = b"www-data"
        detected, ctype = _check_content(body)
        assert detected is True
        assert ctype == "whoami"

    def test_uname(self) -> None:
        body = b"Linux target 5.4.0 #1 SMP x86_64 GNU/Linux"
        detected, ctype = _check_content(body)
        assert detected is True
        assert ctype == "uname"

    def test_windows(self) -> None:
        body = b"Microsoft Windows [Version 10.0.19041]"
        detected, ctype = _check_content(body)
        assert detected is True
        assert ctype == "windows"

    def test_error(self) -> None:
        body = b"sh: 1: id: not found"
        detected, ctype = _check_content(body)
        assert detected is True
        assert ctype == "error"

    def test_none(self) -> None:
        body = b"<html>normal page</html>"
        detected, ctype = _check_content(body)
        assert detected is False
        assert ctype == "none"


# ---------------------------------------------------------------------------
# _check_timing
# ---------------------------------------------------------------------------


class TestCheckTiming:
    def test_slow(self) -> None:
        assert _check_timing(0.5, 5.0) is True

    def test_normal(self) -> None:
        assert _check_timing(0.5, 0.6) is False

    def test_fast_baseline(self) -> None:
        assert _check_timing(0.01, 0.1) is False

    def test_just_over_threshold(self) -> None:
        assert _check_timing(0.5, 1.1) is True


# ---------------------------------------------------------------------------
# _find_cmd_params
# ---------------------------------------------------------------------------


class TestFindCmdParams:
    def test_finds_cmd(self) -> None:
        params = _find_cmd_params("https://target.com/?cmd=ls")
        assert "cmd" in params

    def test_finds_exec(self) -> None:
        params = _find_cmd_params("https://target.com/?exec=id")
        assert "exec" in params

    def test_no_params(self) -> None:
        params = _find_cmd_params("https://target.com/")
        assert params == []

    def test_unknown_param(self) -> None:
        params = _find_cmd_params("https://target.com/?foo=bar")
        assert params == []


# ---------------------------------------------------------------------------
# _make_inject_url
# ---------------------------------------------------------------------------


class TestMakeInjectURL:
    def test_basic(self) -> None:
        url = _make_inject_url("https://target.com/?cmd=ls", "cmd", "; id")
        assert "; id" in url or "%3B" in url
        assert "cmd=" in url

    def test_preserves_other_params(self) -> None:
        url = _make_inject_url("https://target.com/?cmd=ls&page=1", "cmd", "| id")
        assert "page=1" in url


# ---------------------------------------------------------------------------
# build_parser
# ---------------------------------------------------------------------------


class TestBuildParser:
    @pytest.mark.smoke
    def test_returns_parser(self) -> None:
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_accepts_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com"])
        assert args.url == "https://target.com"

    def test_default_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com"])
        assert args.category == "all"

    def test_os_command_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com", "-c", "os_command"])
        assert args.category == "os_command"

    def test_blind_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com", "-c", "blind"])
        assert args.category == "blind"

    def test_bypass_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com", "-c", "bypass"])
        assert args.category == "bypass"

    def test_invalid_category(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["https://target.com", "-c", "invalid"])


# ---------------------------------------------------------------------------
# run_scan (async mock)
# ---------------------------------------------------------------------------


class TestRunScan:
    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        with patch(
            "mytools.web.cmdinject._test_baseline", return_value=(0, 0, b"", 0.0)
        ):
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            with patch(
                "mytools.web.cmdinject.create_async_client", return_value=mock_client
            ):
                result = await run_scan("https://target.com/?cmd=ls")
                assert result.overall_status == "error"

    @pytest.mark.asyncio
    async def test_scan_returns_result(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "mytools.web.cmdinject.create_async_client", return_value=mock_client
        ):
            result = await run_scan("https://target.com/?cmd=ls", category="os_command")
            assert isinstance(result, CmdInjectResult)
            assert result.baseline_status == 200

    @pytest.mark.asyncio
    async def test_invalid_category(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"OK"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "mytools.web.cmdinject.create_async_client", return_value=mock_client
        ):
            result = await run_scan(
                "https://target.com/?cmd=ls", category="nonexistent"
            )
            assert result.overall_status == "error"
            assert "desconhecida" in result.issues[0]


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


class TestPrintResults:
    def test_secure_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CmdInjectResult(
            target="https://target.com",
            baseline_status=200,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "COMMAND" in captured.out.upper()
        assert "SECURE" in captured.out

    def test_vulnerable_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        attempt = CmdInjectAttempt(
            technique="semicolon",
            category="os_command",
            injection_point="param:cmd",
            url="https://target.com/?cmd=%3B+id",
            payload="; id",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=500,
            time_baseline=0.1,
            time_test=0.15,
            content_match=True,
            content_type="uid",
            timing_match=False,
            vulnerable=True,
            details="Content: uid",
            error="",
            exploit="curl 'https://target.com/?cmd=%3B+id'",
            tool="curl",
        )
        result = CmdInjectResult(
            target="https://target.com",
            baseline_status=200,
            tls=True,
            attempts=[attempt],
            vulnerable_techniques=["semicolon"],
            blocked_techniques=[],
            issues=["1 tecnicas de command injection vulneraveis"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "VULNERAVEL" in captured.out
        assert "semicolon" in captured.out


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


class TestCmdInjectAttempt:
    def test_frozen(self) -> None:
        attempt = CmdInjectAttempt(
            technique="test",
            category="os_command",
            injection_point="param:cmd",
            url="https://x.com",
            payload="test",
            status_baseline=200,
            status_test=200,
            size_baseline=0,
            size_test=0,
            time_baseline=0.1,
            time_test=0.1,
            content_match=False,
            content_type="none",
            timing_match=False,
            vulnerable=False,
            details="",
            error="",
        )
        with pytest.raises(AttributeError):
            attempt.technique = "changed"  # type: ignore[misc]


class TestCmdInjectResult:
    def test_frozen(self) -> None:
        result = CmdInjectResult(
            target="https://x.com",
            baseline_status=200,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            result.target = "changed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# main
# ---------------------------------------------------------------------------


class TestMain:
    def test_main_no_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("sys.argv", ["mytools-cmd"])
        monkeypatch.setattr("builtins.input", lambda _: "exit")
        result = main()
        assert result == 0
