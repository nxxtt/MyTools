import argparse
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

import mytools.web.lfidetect as lfidetect_module
from mytools.web.lfidetect import (
    LFIAttempt,
    LFIFindings,
    _detect_leak,
    _find_lfi_params,
    _make_lfi_url,
    _test_baseline,
    _test_lfi,
    _test_rfi,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# _detect_leak
# ---------------------------------------------------------------------------


class TestDetectLeak:
    def test_passwd(self) -> None:
        body = b"<html>root:x:0:0:root:/root:/bin/bash</html>"
        detected, leak_type = _detect_leak(body)
        assert detected is True
        assert leak_type == "passwd"

    def test_php_source(self) -> None:
        body = b"<?php system($_GET['cmd']); ?>"
        detected, leak_type = _detect_leak(body)
        assert detected is True
        assert leak_type == "php_source"

    def test_base64(self) -> None:
        body = b"PD9waHAgc3lzdGVtKCRfR0VUW2NdKTs="
        detected, leak_type = _detect_leak(body)
        assert detected is True
        assert leak_type == "base64"

    def test_windows(self) -> None:
        body = b"[fonts]\r\nfonst=\r\n[extensions]"
        detected, leak_type = _detect_leak(body)
        assert detected is True
        assert leak_type == "windows"

    def test_proc(self) -> None:
        body = b"PATH=/usr/bin\nHOME=/root\nSHELL=/bin/bash"
        detected, leak_type = _detect_leak(body)
        assert detected is True
        assert leak_type == "proc"

    def test_none(self) -> None:
        body = b"<html>normal page</html>"
        detected, leak_type = _detect_leak(body)
        assert detected is False
        assert leak_type == "none"

    def test_robots_user_agent_caps(self) -> None:
        body = b"User-Agent: *\r\nDisallow: /admin"
        detected, leak_type = _detect_leak(body)
        assert detected is True
        assert leak_type == "robots"

    def test_robots_user_agent_lowercase(self) -> None:
        body = b"user-agent: *\r\nAllow: /public"
        detected, leak_type = _detect_leak(body)
        assert detected is True
        assert leak_type == "robots"

    def test_passwd_case_insensitive(self) -> None:
        body = b"<html>Root:X:0:0:Root:/Root:/Bin/Bash</html>"
        detected, leak_type = _detect_leak(body)
        assert detected is True
        assert leak_type == "passwd"


# ---------------------------------------------------------------------------
# _find_lfi_params
# ---------------------------------------------------------------------------


class TestFindLFIParams:
    def test_finds_file(self) -> None:
        params = _find_lfi_params("https://target.com/?page=home&file=test")
        assert "file" in params

    def test_finds_page(self) -> None:
        params = _find_lfi_params("https://target.com/?page=home")
        assert "page" in params

    def test_finds_include(self) -> None:
        params = _find_lfi_params("https://target.com/?include=header")
        assert "include" in params

    def test_no_params(self) -> None:
        params = _find_lfi_params("https://target.com/")
        assert params == []

    def test_unknown_param(self) -> None:
        params = _find_lfi_params("https://target.com/?foo=bar")
        assert params == []


# ---------------------------------------------------------------------------
# _test_baseline
# ---------------------------------------------------------------------------


class TestBaseline:
    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))
        status, size, body = await _test_baseline(mock_client, "https://target.com")
        assert (status, size, body) == (0, 0, b"")


# ---------------------------------------------------------------------------
# _test_lfi
# ---------------------------------------------------------------------------


def _mock_response(status: int = 200, body: bytes = b"<html></html>") -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.content = body
    return resp


LEAK_BODY = b"root:x:0:0:root:/root:/bin/bash"


class TestLFI:
    @pytest.mark.asyncio
    async def test_leak_confirmed(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(body=LEAK_BODY)
        with patch(
            "mytools.web.lfidetect.verify_positive",
            new_callable=AsyncMock,
            return_value=(True, "\n"),
        ):
            attempts = await _test_lfi(
                mock_client,
                "https://target.com/?page=home",
                ["page"],
                (200, 100, b"<html></html>"),
            )
        vuln = [a for a in attempts if a.vulnerable]
        assert len(vuln) > 0
        assert "2nd-order confirmed" in vuln[0].details
        assert vuln[0].exploit.startswith("curl")
        assert vuln[0].tool == "curl"

    @pytest.mark.asyncio
    async def test_leak_failed_second_order(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(body=LEAK_BODY)
        with patch(
            "mytools.web.lfidetect.verify_positive",
            new_callable=AsyncMock,
            return_value=(False, None),
        ):
            attempts = await _test_lfi(
                mock_client,
                "https://target.com/?page=home",
                ["page"],
                (200, 100, b"<html></html>"),
            )
        assert all(not a.vulnerable for a in attempts)
        assert any("2nd-order failed" in a.details for a in attempts)

    @pytest.mark.asyncio
    async def test_leak_no_verify_payload(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(body=LEAK_BODY)
        with patch("mytools.web.lfidetect.get_verify_payload", return_value=None):
            attempts = await _test_lfi(
                mock_client,
                "https://target.com/?page=home",
                ["page"],
                (200, 100, b"<html></html>"),
            )
        assert all(a.vulnerable for a in attempts)

    @pytest.mark.asyncio
    async def test_status_changed(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(status=500, body=b"error")
        attempts = await _test_lfi(
            mock_client,
            "https://target.com/?page=home",
            ["page"],
            (200, 100, b"<html></html>"),
        )
        assert attempts
        assert attempts[0].details == "Status 200->500"

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))
        attempts = await _test_lfi(
            mock_client,
            "https://target.com/?page=home",
            ["page"],
            (200, 100, b"<html></html>"),
        )
        assert len(attempts) == len(lfidetect_module._LFI_PAYLOADS)
        assert all(a.error for a in attempts)


# ---------------------------------------------------------------------------
# _test_rfi
# ---------------------------------------------------------------------------


class TestRFI:
    @pytest.mark.asyncio
    async def test_no_change(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response()
        attempts = await _test_rfi(
            mock_client,
            "https://target.com/?page=home",
            ["page"],
            (200, 100, b"<html></html>"),
        )
        assert attempts
        assert all(not a.vulnerable for a in attempts)
        assert attempts[0].details == "Sem mudanca"

    @pytest.mark.asyncio
    async def test_status_changed(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(status=500, body=b"error")
        attempts = await _test_rfi(
            mock_client,
            "https://target.com/?page=home",
            ["page"],
            (200, 100, b"<html></html>"),
        )
        assert attempts[0].details == "Status 200->500"
        assert all(not a.vulnerable for a in attempts)

    @pytest.mark.asyncio
    async def test_leak_confirmed(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(body=LEAK_BODY)
        with patch(
            "mytools.web.lfidetect.verify_positive",
            new_callable=AsyncMock,
            return_value=(True, "User-agent"),
        ):
            attempts = await _test_rfi(
                mock_client,
                "https://target.com/?page=home",
                ["page"],
                (200, 100, b"<html></html>"),
            )
        vuln = [a for a in attempts if a.vulnerable]
        assert len(vuln) > 0
        assert "2nd-order confirmed" in vuln[0].details
        assert vuln[0].exploit.startswith("curl")

    @pytest.mark.asyncio
    async def test_leak_failed_second_order(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(body=LEAK_BODY)
        with patch(
            "mytools.web.lfidetect.verify_positive",
            new_callable=AsyncMock,
            return_value=(False, None),
        ):
            attempts = await _test_rfi(
                mock_client,
                "https://target.com/?page=home",
                ["page"],
                (200, 100, b"<html></html>"),
            )
        assert all(not a.vulnerable for a in attempts)
        assert any("2nd-order failed" in a.details for a in attempts)

    @pytest.mark.asyncio
    async def test_leak_no_verify_payload(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(body=LEAK_BODY)
        with patch("mytools.web.lfidetect.get_verify_payload", return_value=None):
            attempts = await _test_rfi(
                mock_client,
                "https://target.com/?page=home",
                ["page"],
                (200, 100, b"<html></html>"),
            )
        assert all(a.vulnerable for a in attempts)

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))
        attempts = await _test_rfi(
            mock_client,
            "https://target.com/?page=home",
            ["page"],
            (200, 100, b"<html></html>"),
        )
        assert len(attempts) == len(lfidetect_module._RFI_PAYLOADS)
        assert all(a.error for a in attempts)

    @pytest.mark.asyncio
    async def test_self_referencing_no_httpbin(self) -> None:
        """Payloads RFI nao devem depender de httpbin.org (outbound)."""
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response()
        attempts = await _test_rfi(
            mock_client,
            "https://target.com/?page=home",
            ["page"],
            (200, 100, b"<html></html>"),
        )
        assert attempts
        assert not any("httpbin.org" in a.url for a in attempts)
        assert not any("httpbin.org" in a.payload for a in attempts)
        assert any("target.com" in a.url for a in attempts)

    @pytest.mark.asyncio
    async def test_robots_leak_detected(self) -> None:
        """robots.txt refletido (User-agent:) e detectado como leak."""
        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            body=b"User-agent: *\r\nDisallow: /admin"
        )
        attempts = await _test_rfi(
            mock_client,
            "https://target.com/?page=home",
            ["page"],
            (200, 100, b"<html></html>"),
        )
        vuln = [a for a in attempts if a.vulnerable and a.body_leak_type == "robots"]
        assert len(vuln) > 0

    @pytest.mark.asyncio
    async def test_verify_payload_self_referencing(self) -> None:
        """Verificacao de segunda ordem tambem substitui httpbin pelo host."""
        captured: dict[str, str] = {}

        async def _verify(
            _client: object, v_url: str, _indicators: object
        ) -> tuple[bool, str]:
            captured["v_url"] = v_url
            return (True, "User-agent")

        mock_client = AsyncMock()
        mock_client.get.return_value = _mock_response(
            body=b"User-Agent: *\r\nDisallow: /"
        )
        with patch("mytools.web.lfidetect.verify_positive", side_effect=_verify):
            attempts = await _test_rfi(
                mock_client,
                "https://target.com/?page=home",
                ["page"],
                (200, 100, b"<html></html>"),
            )
        assert captured["v_url"]
        assert "httpbin.org" not in captured["v_url"]
        assert "target.com" in captured["v_url"]
        assert any("2nd-order confirmed" in a.details for a in attempts)


# ---------------------------------------------------------------------------
# _make_lfi_url
# ---------------------------------------------------------------------------


class TestMakeLFIUrl:
    def test_basic(self) -> None:
        url = _make_lfi_url("https://target.com/?page=home", "file", "test.txt")
        assert "file=test.txt" in url
        assert "page=home" in url

    def test_encodes_payload(self) -> None:
        url = _make_lfi_url("https://target.com/", "file", "../../etc/passwd")
        assert "file=" in url

    def test_ampersand_payload_is_encoded(self) -> None:
        url = _make_lfi_url("https://target.com/?page=home", "file", "a&&b")
        assert "a%26%26b" in url
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

    def test_lfi_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com", "-c", "lfi"])
        assert args.category == "lfi"

    def test_rfi_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://target.com", "-c", "rfi"])
        assert args.category == "rfi"

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
            "mytools.web.lfidetect._test_baseline",
            new_callable=AsyncMock,
            return_value=(0, 0, b""),
        ):
            mock_client = AsyncMock()
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            with patch(
                "mytools.web.lfidetect.create_async_client", return_value=mock_client
            ):
                result = await run_scan("https://target.com/?page=home")
                assert result.overall_status == "error"

    @pytest.mark.asyncio
    async def test_scan_returns_findings(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch(
            "mytools.web.lfidetect.create_async_client", return_value=mock_client
        ):
            result = await run_scan("https://target.com/?page=home", category="lfi")
            assert isinstance(result, LFIFindings)
            assert result.baseline_status == 200

    @pytest.mark.asyncio
    async def test_no_scheme_and_no_params(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.lfidetect.create_async_client", return_value=mock_client
            ),
            patch(
                "mytools.web.lfidetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"<html></html>"),
            ),
            patch(
                "mytools.web.lfidetect._test_lfi",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = await run_scan("target.com", category="lfi")
        assert result.target == "http://target.com"
        assert result.overall_status == "secure"

    @pytest.mark.asyncio
    async def test_rfi_category(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.lfidetect.create_async_client", return_value=mock_client
            ),
            patch(
                "mytools.web.lfidetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"<html></html>"),
            ),
            patch(
                "mytools.web.lfidetect._test_rfi",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = await run_scan("https://target.com/?page=home", category="rfi")
        assert result.overall_status == "secure"

    @pytest.mark.asyncio
    async def test_unknown_category(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.lfidetect.create_async_client", return_value=mock_client
            ),
            patch(
                "mytools.web.lfidetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"<html></html>"),
            ),
        ):
            result = await run_scan("https://target.com/?page=home", category="bogus")
        assert result.overall_status == "error"
        assert any("Categoria desconhecida" in i for i in result.issues)

    @pytest.mark.asyncio
    async def test_results_exception_skipped(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.lfidetect.create_async_client", return_value=mock_client
            ),
            patch(
                "mytools.web.lfidetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"<html></html>"),
            ),
            patch(
                "mytools.web.lfidetect._test_lfi",
                new_callable=AsyncMock,
                side_effect=RuntimeError("boom"),
            ),
        ):
            result = await run_scan("https://target.com/?page=home", category="lfi")
        assert result.overall_status == "secure"

    @pytest.mark.asyncio
    async def test_vulnerable_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        def _attempt(technique: str, vulnerable: bool, status_test: int) -> LFIAttempt:
            return LFIAttempt(
                technique=technique,
                category="lfi",
                injection_point="param:page",
                url="https://target.com/?page=x",
                payload="payload",
                status_baseline=200,
                status_test=status_test,
                size_baseline=100,
                size_test=100,
                body_leak_detected=vulnerable,
                body_leak_type="passwd" if vulnerable else "none",
                vulnerable=vulnerable,
                details="d",
                error="",
                exploit="curl x" if vulnerable else "",
                tool="curl" if vulnerable else "",
            )

        vuln = _attempt("php_filter", True, 200)
        blocked = _attempt("null_byte", False, 500)
        secure = _attempt("path_depth", False, 200)
        with (
            patch(
                "mytools.web.lfidetect.create_async_client", return_value=mock_client
            ),
            patch(
                "mytools.web.lfidetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"<html></html>"),
            ),
            patch(
                "mytools.web.lfidetect._test_lfi",
                new_callable=AsyncMock,
                return_value=[vuln, blocked, secure],
            ),
            patch(
                "mytools.web.lfidetect._test_rfi",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = await run_scan("https://target.com/?page=home", category="all")
        assert result.overall_status == "vulnerable"
        assert result.vulnerable_techniques == ["php_filter"]
        assert result.blocked_techniques == ["null_byte"]
        assert result.issues == [
            "1 tecnicas de file inclusion vulneraveis",
            "1 tecnicas bloqueadas pelo servidor",
        ]


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


class TestPrintResults:
    def test_secure_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = LFIFindings(
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
        assert "LFI/RFI" in captured.out
        assert "SECURE" in captured.out

    def test_vulnerable_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        from mytools.web.lfidetect import LFIAttempt

        attempt = LFIAttempt(
            technique="php_filter",
            category="lfi",
            injection_point="param:page",
            url="https://target.com/?page=php://filter",
            payload="php://filter/convert.base64-encode/resource=index",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=500,
            body_leak_detected=True,
            body_leak_type="base64",
            vulnerable=True,
            details="Leak: base64",
            error="",
            exploit="curl 'https://target.com/?page=php://filter'",
            tool="curl",
        )
        result = LFIFindings(
            target="https://target.com",
            baseline_status=200,
            tls=True,
            attempts=[attempt],
            vulnerable_techniques=["php_filter"],
            blocked_techniques=[],
            issues=["1 tecnicas de file inclusion vulneraveis"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "VULNERAVEL" in captured.out
        assert "php_filter" in captured.out

    def test_blocked_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        attempt = LFIAttempt(
            technique="null_byte",
            category="lfi",
            injection_point="param:page",
            url="https://target.com/?page=x",
            payload="../../etc/passwd%00",
            status_baseline=200,
            status_test=500,
            size_baseline=100,
            size_test=200,
            body_leak_detected=False,
            body_leak_type="none",
            vulnerable=False,
            details="Status 200->500",
            error="",
        )
        result = LFIFindings(
            target="https://target.com",
            baseline_status=200,
            tls=False,
            attempts=[attempt],
            vulnerable_techniques=[],
            blocked_techniques=["null_byte"],
            issues=["1 tecnicas bloqueadas pelo servidor"],
            overall_status="blocked",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "BLOQUEADO" in captured.out
        assert "null_byte" in captured.out
        assert "Observacoes" in captured.out

    def test_vulnerable_without_matching_attempt(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = LFIFindings(
            target="https://target.com",
            baseline_status=200,
            tls=True,
            attempts=[],
            vulnerable_techniques=["php_filter"],
            blocked_techniques=[],
            issues=["1 tecnicas de file inclusion vulneraveis"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "VULNERAVEL" in captured.out
        assert "php_filter" in captured.out


# ---------------------------------------------------------------------------
# LFIAttempt / LFIFindings dataclasses
# ---------------------------------------------------------------------------


class TestLFIAttempt:
    def test_frozen(self) -> None:
        from mytools.web.lfidetect import LFIAttempt

        attempt = LFIAttempt(
            technique="test",
            category="lfi",
            injection_point="param:file",
            url="https://x.com",
            payload="test",
            status_baseline=200,
            status_test=200,
            size_baseline=0,
            size_test=0,
            body_leak_detected=False,
            body_leak_type="none",
            vulnerable=False,
            details="",
            error="",
        )
        with pytest.raises(AttributeError):
            attempt.technique = "changed"  # type: ignore[misc]


class TestLFIFindings:
    def test_frozen(self) -> None:
        result = LFIFindings(
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
        monkeypatch.setattr("sys.argv", ["mytools-lfi"])
        monkeypatch.setattr("builtins.input", lambda _: "exit")
        result = main()
        assert result == 0


class TestMainGuard:
    def test_main_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import runpy

        def _raise(*_args: object, **_kwargs: object) -> int:
            raise SystemExit(0)

        monkeypatch.setattr("mytools.core.utils.run_main_loop", _raise)
        with pytest.raises(SystemExit):
            runpy.run_module("mytools.web.lfidetect", run_name="__main__")


# ---------------------------------------------------------------------------
# run_once
# ---------------------------------------------------------------------------


def _run_once_args(**overrides: object) -> argparse.Namespace:
    defaults: dict[str, object] = {
        "url": "https://target.com/?page=home",
        "category": "all",
        "timeout": 10.0,
        "concurrency": 5,
        "output": None,
        "json_output": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestRunOnce:
    def test_run_once_secure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        result = LFIFindings(
            target="https://target.com",
            baseline_status=200,
            tls=False,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        monkeypatch.setattr(lfidetect_module, "init_scanner", lambda args: None)
        monkeypatch.setattr(
            lfidetect_module, "run_scan", AsyncMock(return_value=result)
        )
        assert run_once(_run_once_args()) == 0

    def test_run_once_json_output(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = LFIFindings(
            target="https://target.com",
            baseline_status=200,
            tls=False,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        monkeypatch.setattr(lfidetect_module, "init_scanner", lambda args: None)
        monkeypatch.setattr(
            lfidetect_module, "run_scan", AsyncMock(return_value=result)
        )
        assert run_once(_run_once_args(json_output=True)) == 0
        captured = capsys.readouterr()
        assert "overall_status" in captured.out
        assert "secure" in captured.out

    def test_run_once_error_returns_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        result = LFIFindings(
            target="https://target.com",
            baseline_status=0,
            tls=False,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=["Falha ao conectar no alvo"],
            overall_status="error",
        )
        monkeypatch.setattr(lfidetect_module, "init_scanner", lambda args: None)
        monkeypatch.setattr(
            lfidetect_module, "run_scan", AsyncMock(return_value=result)
        )
        monkeypatch.setattr(lfidetect_module, "print_results", lambda r: None)
        assert run_once(_run_once_args()) == 1

    def test_run_once_output_file(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        out = str(tmp_path / "out.json")
        result = LFIFindings(
            target="https://target.com",
            baseline_status=200,
            tls=False,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        monkeypatch.setattr(lfidetect_module, "init_scanner", lambda args: None)
        monkeypatch.setattr(
            lfidetect_module, "run_scan", AsyncMock(return_value=result)
        )
        monkeypatch.setattr(lfidetect_module, "print_results", lambda r: None)
        assert run_once(_run_once_args(output=out)) == 0
        assert Path(out).exists()
