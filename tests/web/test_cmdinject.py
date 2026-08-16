import argparse
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import mytools.web.cmdinject as cmdinject_module
from mytools.web.cmdinject import (
    CmdInjectAttempt,
    CmdInjectResult,
    _check_content,
    _check_timing,
    _find_cmd_params,
    _make_inject_url,
    _test_baseline,
    _test_blind,
    _test_bypass,
    _test_os_command,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)

pytestmark = pytest.mark.integration


class _FakeMonotonic:
    def __init__(self, step: float = 2.0) -> None:
        self._value = 0.0
        self._step = step

    def monotonic(self) -> float:
        self._value += self._step
        return self._value


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

    def test_ampersand_payload_is_encoded(self) -> None:
        url = _make_inject_url("https://target.com/?cmd=ls", "cmd", "&& id")
        assert "cmd=%26%26+id" in url
        assert "&&" not in url


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

    @pytest.mark.asyncio
    async def test_no_scheme(self) -> None:
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
            result = await run_scan("target.com/?cmd=ls", category="os_command")
            assert result.target == "http://target.com/?cmd=ls"

    @pytest.mark.asyncio
    async def test_no_params_defaults_cmd(self) -> None:
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
            result = await run_scan("https://target.com/", category="os_command")
            assert isinstance(result, CmdInjectResult)
            assert result.baseline_status == 200

    @pytest.mark.asyncio
    async def test_scan_all_categories(self) -> None:
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
            result = await run_scan("https://target.com/?cmd=ls", category="all")
            assert result.overall_status == "secure"

    @pytest.mark.asyncio
    async def test_vulnerable_scan(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"uid=33 www-data"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch(
                "mytools.web.cmdinject.create_async_client", return_value=mock_client
            ),
            patch(
                "mytools.web.cmdinject.verify_positive", new_callable=AsyncMock
            ) as mock_verify,
        ):
            mock_verify.return_value = (True, "www-data")
            result = await run_scan("https://target.com/?cmd=ls", category="os_command")
        assert result.vulnerable_techniques
        assert result.overall_status == "vulnerable"
        assert any("vulneraveis" in i for i in result.issues)

    @pytest.mark.asyncio
    async def test_task_exception_is_skipped(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch(
                "mytools.web.cmdinject.create_async_client", return_value=mock_client
            ),
            patch(
                "mytools.web.cmdinject._test_os_command",
                new_callable=AsyncMock,
                side_effect=RuntimeError("boom"),
            ),
        ):
            result = await run_scan("https://target.com/?cmd=ls", category="os_command")
        assert result.overall_status == "secure"
        assert result.attempts == []

    @pytest.mark.asyncio
    async def test_duplicate_technique_across_params(self) -> None:
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
                "https://target.com/?cmd=ls&exec=id", category="os_command"
            )
        assert result.overall_status == "secure"
        assert len(result.attempts) > len(result.vulnerable_techniques)

    @pytest.mark.asyncio
    async def test_blocked_scan(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.content = b"OK"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch(
                "mytools.web.cmdinject.create_async_client", return_value=mock_client
            ),
            patch(
                "mytools.web.cmdinject._test_baseline", new_callable=AsyncMock
            ) as mock_baseline,
        ):
            mock_baseline.return_value = (200, 100, b"", 0.1)
            result = await run_scan("https://target.com/?cmd=ls", category="os_command")
        assert result.blocked_techniques
        assert result.overall_status == "blocked"
        assert any("bloqueadas" in i for i in result.issues)


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

    def test_vulnerable_output_with_timing(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        attempt = CmdInjectAttempt(
            technique="sleep_semicolon",
            category="blind",
            injection_point="param:cmd",
            url="https://target.com/?cmd=%3B+sleep+5",
            payload="; sleep 5",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=100,
            time_baseline=0.1,
            time_test=2.5,
            content_match=False,
            content_type="none",
            timing_match=True,
            vulnerable=True,
            details="Timing: 0.1s->2.5s",
            error="",
            exploit="curl 'https://target.com/?cmd=%3B+sleep+5'",
            tool="curl",
        )
        result = CmdInjectResult(
            target="https://target.com",
            baseline_status=200,
            tls=True,
            attempts=[attempt],
            vulnerable_techniques=["sleep_semicolon"],
            blocked_techniques=[],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "Timing: 0.1s->2.5s" in captured.out

    def test_vulnerable_output_without_matching_attempt(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = CmdInjectResult(
            target="https://target.com",
            baseline_status=200,
            tls=True,
            attempts=[],
            vulnerable_techniques=["semicolon"],
            blocked_techniques=[],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "semicolon" in captured.out

    def test_blocked_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CmdInjectResult(
            target="https://target.com",
            baseline_status=200,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=["semicolon"],
            issues=[],
            overall_status="blocked",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "BLOQUEADO" in captured.out
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

    def test_main_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import runpy

        def _raise(*_args: object, **_kwargs: object) -> int:
            raise SystemExit(0)

        monkeypatch.setattr("mytools.core.utils.run_main_loop", _raise)
        with pytest.raises(SystemExit):
            runpy.run_module("mytools.web.cmdinject", run_name="__main__")


# ---------------------------------------------------------------------------
# _test_baseline
# ---------------------------------------------------------------------------


class TestBaselineFunction:
    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))
        status, size, body, elapsed = await _test_baseline(
            mock_client, "https://target.com/"
        )
        assert status == 0
        assert size == 0
        assert body == b""
        assert elapsed == 0.0


# ---------------------------------------------------------------------------
# _test_os_command
# ---------------------------------------------------------------------------


class TestOsCommandFunction:
    @pytest.mark.asyncio
    async def test_confirmed(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"uid=33 www-data"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        with patch(
            "mytools.web.cmdinject.verify_positive", new_callable=AsyncMock
        ) as mock_verify:
            mock_verify.return_value = (True, "www-data")
            attempts = await _test_os_command(
                mock_client,
                "https://target.com/?cmd=ls",
                ["cmd"],
                (200, 100, b"", 0.1),
            )
        vuln = [a for a in attempts if a.vulnerable]
        assert vuln
        assert any("2nd-order confirmed" in a.details for a in attempts)
        assert vuln[0].exploit != ""

    @pytest.mark.asyncio
    async def test_second_order_failed(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"uid=33 www-data"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        with patch(
            "mytools.web.cmdinject.verify_positive", new_callable=AsyncMock
        ) as mock_verify:
            mock_verify.return_value = (False, "")
            attempts = await _test_os_command(
                mock_client,
                "https://target.com/?cmd=ls",
                ["cmd"],
                (200, 100, b"", 0.1),
            )
        assert any("2nd-order failed" in a.details for a in attempts)
        assert all(not a.vulnerable for a in attempts)

    @pytest.mark.asyncio
    async def test_content_match_no_verify_payload(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"uid=33 www-data"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        with patch("mytools.web.cmdinject.get_verify_payload", return_value=None):
            attempts = await _test_os_command(
                mock_client,
                "https://target.com/?cmd=ls",
                ["cmd"],
                (200, 100, b"", 0.1),
            )
        assert any(a.vulnerable for a in attempts)
        assert all("2nd-order" not in a.details for a in attempts)

    @pytest.mark.asyncio
    async def test_status_changed(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.content = b"<html>error</html>"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        attempts = await _test_os_command(
            mock_client,
            "https://target.com/?cmd=ls",
            ["cmd"],
            (200, 100, b"", 0.1),
        )
        assert any("Status 200->500" in a.details for a in attempts)

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))
        attempts = await _test_os_command(
            mock_client,
            "https://target.com/?cmd=ls",
            ["cmd"],
            (200, 100, b"", 0.1),
        )
        assert len(attempts) == len(
            [
                ("semicolon", "; id"),
                ("pipe", "| id"),
                ("or", "|| id"),
                ("and", "&& id"),
                ("backtick", "`id`"),
                ("dollar", "$(id)"),
                ("whoami", "; whoami"),
                ("uname", "; uname -a"),
            ]
        )
        assert all(a.error for a in attempts)


# ---------------------------------------------------------------------------
# _test_blind
# ---------------------------------------------------------------------------


class TestBlindFunction:
    @pytest.mark.asyncio
    async def test_timing_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cmdinject_module, "time", _FakeMonotonic(2.0))
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        attempts = await _test_blind(
            mock_client,
            "https://target.com/?cmd=ls",
            ["cmd"],
            (200, 100, b"", 0.5),
        )
        assert any(a.timing_match for a in attempts)
        assert any(a.vulnerable for a in attempts)
        assert any("Timing:" in a.details for a in attempts)

    @pytest.mark.asyncio
    async def test_no_delay(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cmdinject_module, "time", _FakeMonotonic(0.0))
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        attempts = await _test_blind(
            mock_client,
            "https://target.com/?cmd=ls",
            ["cmd"],
            (200, 100, b"", 0.5),
        )
        assert all(not a.timing_match for a in attempts)
        assert any("Sem delay" in a.details for a in attempts)

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))
        attempts = await _test_blind(
            mock_client,
            "https://target.com/?cmd=ls",
            ["cmd"],
            (200, 100, b"", 0.5),
        )
        assert len(attempts) == 5
        assert all(a.error for a in attempts)


# ---------------------------------------------------------------------------
# _test_bypass
# ---------------------------------------------------------------------------


class TestBypassFunction:
    @pytest.mark.asyncio
    async def test_confirmed(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"uid=33 www-data"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        with patch(
            "mytools.web.cmdinject.verify_positive", new_callable=AsyncMock
        ) as mock_verify:
            mock_verify.return_value = (True, "www-data")
            attempts = await _test_bypass(
                mock_client,
                "https://target.com/?cmd=ls",
                ["cmd"],
                (200, 100, b"", 0.1),
            )
        assert any(a.vulnerable for a in attempts)
        assert any("2nd-order confirmed" in a.details for a in attempts)

    @pytest.mark.asyncio
    async def test_second_order_failed(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"uid=33 www-data"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        with patch(
            "mytools.web.cmdinject.verify_positive", new_callable=AsyncMock
        ) as mock_verify:
            mock_verify.return_value = (False, "")
            attempts = await _test_bypass(
                mock_client,
                "https://target.com/?cmd=ls",
                ["cmd"],
                (200, 100, b"", 0.1),
            )
        assert any("2nd-order failed" in a.details for a in attempts)
        assert all(not a.vulnerable for a in attempts)

    @pytest.mark.asyncio
    async def test_content_match_no_verify_payload(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"uid=33 www-data"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        with patch("mytools.web.cmdinject.get_verify_payload", return_value=None):
            attempts = await _test_bypass(
                mock_client,
                "https://target.com/?cmd=ls",
                ["cmd"],
                (200, 100, b"", 0.1),
            )
        assert any(a.vulnerable for a in attempts)
        assert all("2nd-order" not in a.details for a in attempts)

    @pytest.mark.asyncio
    async def test_no_match(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        attempts = await _test_bypass(
            mock_client,
            "https://target.com/?cmd=ls",
            ["cmd"],
            (200, 100, b"", 0.1),
        )
        assert all(not a.vulnerable for a in attempts)
        assert any("Sem mudanca" in a.details for a in attempts)

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))
        attempts = await _test_bypass(
            mock_client,
            "https://target.com/?cmd=ls",
            ["cmd"],
            (200, 100, b"", 0.1),
        )
        assert len(attempts) == 5
        assert all(a.error for a in attempts)


# ---------------------------------------------------------------------------
# run_once
# ---------------------------------------------------------------------------


class TestRunOnce:
    def test_secure_returns_0(self, monkeypatch: pytest.MonkeyPatch) -> None:
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
        monkeypatch.setattr(
            cmdinject_module, "run_scan", AsyncMock(return_value=result)
        )
        monkeypatch.setattr(cmdinject_module, "init_scanner", MagicMock())
        mock_print = MagicMock()
        monkeypatch.setattr(cmdinject_module, "print_results", mock_print)
        args = argparse.Namespace(
            url="https://target.com/?cmd=ls",
            category="all",
            timeout=5.0,
            concurrency=5,
            output=None,
            json_output=False,
        )
        assert run_once(args) == 0
        mock_print.assert_called_once_with(result)

    def test_json_output(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = CmdInjectResult(
            target="https://target.com",
            baseline_status=200,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="vulnerable",
        )
        monkeypatch.setattr(
            cmdinject_module, "run_scan", AsyncMock(return_value=result)
        )
        monkeypatch.setattr(cmdinject_module, "init_scanner", MagicMock())
        args = argparse.Namespace(
            url="https://target.com/?cmd=ls",
            category="all",
            timeout=5.0,
            concurrency=5,
            output=None,
            json_output=True,
        )
        assert run_once(args) == 0
        captured = capsys.readouterr()
        assert "vulnerable" in captured.out

    def test_writes_output(self, monkeypatch: pytest.MonkeyPatch, tmp_path) -> None:
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
        monkeypatch.setattr(
            cmdinject_module, "run_scan", AsyncMock(return_value=result)
        )
        monkeypatch.setattr(cmdinject_module, "init_scanner", MagicMock())
        args = argparse.Namespace(
            url="https://target.com/?cmd=ls",
            category="all",
            timeout=5.0,
            concurrency=5,
            output=str(tmp_path / "out.json"),
            json_output=False,
        )
        assert run_once(args) == 0
        assert (tmp_path / "out.json").exists()

    def test_error_returns_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        result = CmdInjectResult(
            target="https://target.com",
            baseline_status=200,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=["Falha"],
            overall_status="error",
        )
        monkeypatch.setattr(
            cmdinject_module, "run_scan", AsyncMock(return_value=result)
        )
        monkeypatch.setattr(cmdinject_module, "init_scanner", MagicMock())
        args = argparse.Namespace(
            url="https://target.com/?cmd=ls",
            category="all",
            timeout=5.0,
            concurrency=5,
            output=None,
            json_output=False,
        )
        assert run_once(args) == 1
