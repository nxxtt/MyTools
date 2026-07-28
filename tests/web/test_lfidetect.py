import argparse
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.lfidetect import (
    LFIFindings,
    _detect_leak,
    _find_lfi_params,
    _make_lfi_url,
    build_parser,
    main,
    print_results,
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
