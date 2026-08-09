#!/usr/bin/env python3
"""Testes unitarios do modulo de CRLF Injection."""

import argparse
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mytools.web.crlfinjection import (
    _CRLF_PAYLOADS,
    _ENCODED_PAYLOADS,
    _HEADER_NAMES,
    _SPLIT_PAYLOADS,
    _SPLIT_POINTS,
    CRLFAttempt,
    CRLFResult,
    _check_vulnerability,
    _detect_injected_headers,
    _test_baseline,
    _test_bypass,
    _test_header_crlf,
    _test_param_crlf,
    _test_path_crlf,
    _test_split,
    build_parser,
    main,
    print_crlf_art,
    print_results,
    run_once,
    run_scan,
)


class TestCRIFPayloads:
    """Testes para _CRLF_PAYLOADS."""

    def test_has_header(self) -> None:
        assert any("X-Injected" in p[1] for p in _CRLF_PAYLOADS)

    def test_has_cookie(self) -> None:
        assert any("Set-Cookie" in p[1] for p in _CRLF_PAYLOADS)

    def test_has_host(self) -> None:
        assert any("Host:" in p[1] for p in _CRLF_PAYLOADS)

    def test_has_body(self) -> None:
        assert any("<h1>INJECTED</h1>" in p[1] for p in _CRLF_PAYLOADS)

    def test_count(self) -> None:
        assert len(_CRLF_PAYLOADS) == 8


class TestSplitPayloads:
    """Testes para _SPLIT_PAYLOADS."""

    def test_has_simple(self) -> None:
        assert any("SPLIT" in p[1] for p in _SPLIT_PAYLOADS)

    def test_has_admin(self) -> None:
        assert any("/admin" in p[1] for p in _SPLIT_PAYLOADS)

    def test_count(self) -> None:
        assert len(_SPLIT_PAYLOADS) == 4


class TestEncodedPayloads:
    """Testes para _ENCODED_PAYLOADS."""

    def test_has_percent(self) -> None:
        assert any("%0d%0a" in p[1] for p in _ENCODED_PAYLOADS)

    def test_has_double(self) -> None:
        assert any("%250d" in p[1] for p in _ENCODED_PAYLOADS)

    def test_has_unicode(self) -> None:
        assert any("\u000d" in p[1] for p in _ENCODED_PAYLOADS)

    def test_has_backslash(self) -> None:
        assert any("\\r\\n" in p[1] for p in _ENCODED_PAYLOADS)

    def test_count(self) -> None:
        assert len(_ENCODED_PAYLOADS) == 6


class TestSplitPoints:
    """Testes para _SPLIT_POINTS."""

    def test_has_url(self) -> None:
        assert any(p[0] == "url_path" for p in _SPLIT_POINTS)

    def test_has_param(self) -> None:
        assert any(p[0] == "query_param" for p in _SPLIT_POINTS)

    def test_count(self) -> None:
        assert len(_SPLIT_POINTS) == 4


class TestHeaderNames:
    """Testes para _HEADER_NAMES."""

    def test_has_ua(self) -> None:
        assert "User-Agent" in _HEADER_NAMES

    def test_has_referer(self) -> None:
        assert "Referer" in _HEADER_NAMES

    def test_has_cookie(self) -> None:
        assert "Cookie" in _HEADER_NAMES

    def test_count(self) -> None:
        assert len(_HEADER_NAMES) == 6


class TestDetectInjectedHeaders:
    """Testes para _detect_injected_headers."""

    def test_detects_x_injected(self) -> None:
        body = b"HTTP/1.1 200 OK\r\nX-Injected: test\r\n\r\n"
        result = _detect_injected_headers(body, {})
        assert "x-injected" in result

    def test_detects_set_cookie(self) -> None:
        body = b"Set-Cookie: evil=1\r\n\r\n"
        result = _detect_injected_headers(body, {})
        assert "set-cookie" in result

    def test_detects_in_header(self) -> None:
        body = b"ok"
        headers = {"x-injected": "test"}
        result = _detect_injected_headers(body, headers)
        assert "header:x-injected" in result

    def test_no_injection(self) -> None:
        body = b"<html>ok</html>"
        result = _detect_injected_headers(body, {})
        assert len(result) == 0

    def test_empty_body(self) -> None:
        result = _detect_injected_headers(b"", {})
        assert len(result) == 0


class TestCheckVulnerability:
    """Testes para _check_vulnerability."""

    def test_status_changed(self) -> None:
        assert _check_vulnerability(200, 302, 100, 100, []) is True

    def test_size_changed(self) -> None:
        assert _check_vulnerability(200, 200, 100, 200, []) is True

    def test_has_injection(self) -> None:
        assert _check_vulnerability(200, 200, 100, 100, ["x-injected"]) is True

    def test_no_vulnerability(self) -> None:
        assert _check_vulnerability(200, 200, 100, 100, []) is False

    def test_small_size_change(self) -> None:
        assert _check_vulnerability(200, 200, 100, 110, []) is False


class TestCRLFAttempt:
    """Testes para CRLFAttempt dataclass."""

    def test_creation(self) -> None:
        att = CRLFAttempt(
            technique="test",
            category="param",
            url="https://example.com",
            payload="\r\nX-Injected: test",
            status_baseline=200,
            status_test=302,
            size_baseline=100,
            size_test=0,
            status_changed=True,
            size_changed=True,
            injected_headers=["x-injected"],
            vulnerable=True,
            details="VULN",
            error="",
        )
        assert att.technique == "test"
        assert att.vulnerable is True
        assert att.injected_headers == ["x-injected"]

    def test_frozen(self) -> None:
        att = CRLFAttempt(
            technique="t",
            category="c",
            url="u",
            payload="p",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=100,
            status_changed=False,
            size_changed=False,
            injected_headers=[],
            vulnerable=False,
            details="d",
            error="",
        )
        with pytest.raises(AttributeError):
            att.technique = "new"  # type: ignore[misc]


class TestCRLFResult:
    """Testes para CRLFResult dataclass."""

    def test_creation(self) -> None:
        result = CRLFResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=1000,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert result.target == "https://example.com"
        assert result.overall_status == "secure"


class TestTestBaseline:
    """Testes para _test_baseline."""

    @pytest.mark.asyncio
    async def test_success(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"hello"
        client.get = AsyncMock(return_value=resp)

        status, size, body = await _test_baseline(client, "https://example.com")
        assert status == 200
        assert size == 5
        assert body == b"hello"

    @pytest.mark.asyncio
    async def test_error(self) -> None:
        import httpx

        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        status, size, body = await _test_baseline(client, "https://example.com")
        assert status == 0
        assert size == 0
        assert body == b""


class TestTestParamCRLF:
    """Testes para _test_param_crlf."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        resp.headers = {}
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_param_crlf(
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        assert len(attempts) > 0
        assert all(isinstance(a, CRLFAttempt) for a in attempts)

    @pytest.mark.asyncio
    async def test_error_handled(self) -> None:
        import httpx

        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_param_crlf(
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        assert len(attempts) > 0
        assert any(a.error for a in attempts)


class TestTestHeaderCRLF:
    """Testes para _test_header_crlf."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        resp.headers = {}
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_header_crlf(
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        assert len(attempts) > 0


class TestTestPathCRLF:
    """Testes para _test_path_crlf."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        resp.headers = {}
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_path_crlf(
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        assert len(attempts) > 0


class TestTestSplit:
    """Testes para _test_split."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        resp.headers = {}
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_split(
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        assert len(attempts) == 4


class TestTestBypass:
    """Testes para _test_bypass."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        resp.headers = {}
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_bypass(
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        assert len(attempts) > 0


@pytest.mark.smoke
class TestBuildParser:
    """Testes para build_parser."""

    def test_has_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "param"])
        assert args.category == "param"

    def test_has_concurrency(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--concurrency", "10"])
        assert args.concurrency == 10

    def test_category_choices(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "bypass"])
        assert args.category == "bypass"


class TestPrintResults:
    """Testes para print_results."""

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CRLFResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=1000,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        captured = capsys.readouterr()
        import re

        clean = re.sub(r"\033\[[0-9;]*m", "", captured.out)
        assert "CRLF INJECTION" in clean

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CRLFResult(
            target="https://example.com",
            baseline_status=302,
            baseline_size=0,
            tls=False,
            attempts=[],
            vulnerable_techniques=["crlf_header_ua"],
            blocked_techniques=[],
            issues=["1 tecnicas vulneraveis"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        import re

        clean = re.sub(r"\033\[[0-9;]*m", "", captured.out)
        assert "VULNERAVEIS" in clean or "VULNERAVEL" in clean


class TestMain:
    """Testes para main."""

    def test_no_url(self) -> None:
        with (
            patch("sys.argv", ["mytools-crlfinject"]),
            patch(
                "mytools.web.crlfinjection.run_main_loop", return_value=1
            ) as mock_loop,
        ):
            result = main()
            assert result == 1
            mock_loop.assert_called_once()


# ─── Error Handling Detail Tests ─────────────────────────────────────────────


class TestDetailErrors:
    @pytest.mark.asyncio
    async def test_header_error(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))
        attempts = await _test_header_crlf(
            client, "https://example.com", (200, 100, b"ok")
        )
        assert any(a.error for a in attempts)

    @pytest.mark.asyncio
    async def test_path_error(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))
        attempts = await _test_path_crlf(
            client, "https://example.com", (200, 100, b"ok")
        )
        assert any(a.error for a in attempts)

    @pytest.mark.asyncio
    async def test_split_error(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))
        attempts = await _test_split(client, "https://example.com", (200, 100, b"ok"))
        assert any(a.error for a in attempts)

    @pytest.mark.asyncio
    async def test_bypass_error(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))
        attempts = await _test_bypass(client, "https://example.com", (200, 100, b"ok"))
        assert any(a.error for a in attempts)


# ─── Print Results Detail Tests ──────────────────────────────────────────────


class TestPrintResultsDetail:
    def _attempt(self, *, error: str = "", vulnerable: bool = True) -> CRLFAttempt:
        return CRLFAttempt(
            technique="crlf_header_q",
            category="param",
            url="https://example.com",
            payload="\r\nX-Injected: test",
            status_baseline=200,
            status_test=302,
            size_baseline=100,
            size_test=100,
            status_changed=True,
            size_changed=False,
            injected_headers=["x-injected"],
            vulnerable=vulnerable,
            details="detected",
            error=error,
            exploit="exploit-cmd",
            tool="curl",
        )

    def test_vulnerable_with_attempt(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CRLFResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[self._attempt()],
            vulnerable_techniques=["crlf_header_q"],
            blocked_techniques=[],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "crlf_header_q" in out

    def test_prints_errors(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CRLFResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[self._attempt(error="connection failed")],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Erros" in out
        assert "connection failed" in out


# ─── Print CRLF Art ──────────────────────────────────────────────────────────


class TestPrintCRLFArt:
    def test_print_art(self, capsys: pytest.CaptureFixture[str]) -> None:
        print_crlf_art()
        out = capsys.readouterr().out
        assert "_____" in out


# ─── run_scan Tests ──────────────────────────────────────────────────────────


class TestRunScan:
    def _attempt(self, *, vulnerable: bool = True) -> CRLFAttempt:
        return CRLFAttempt(
            technique="crlf_header_q",
            category="param",
            url="https://example.com",
            payload="\r\nX-Injected: test",
            status_baseline=200,
            status_test=302,
            size_baseline=100,
            size_test=100,
            status_changed=True,
            size_changed=False,
            injected_headers=["x-injected"],
            vulnerable=vulnerable,
            details="detected",
            error="",
        )

    @pytest.mark.asyncio
    async def test_all_categories_secure(self) -> None:
        mock_print = MagicMock()
        with (
            patch(
                "mytools.web.crlfinjection.create_async_client",
                return_value=AsyncMock(),
            ),
            patch(
                "mytools.web.crlfinjection._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"ok"),
            ),
            patch(
                "mytools.web.crlfinjection._test_param_crlf",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.crlfinjection._test_header_crlf",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.crlfinjection._test_path_crlf",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.crlfinjection._test_split",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.crlfinjection._test_bypass",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch("mytools.web.crlfinjection.print_results", mock_print),
        ):
            code = await run_scan("https://example.com", [], 10, 5, None, False)
        assert code == 0
        result = mock_print.call_args[0][0]
        assert result.overall_status == "secure"

    @pytest.mark.asyncio
    async def test_vulnerable_with_issues(self) -> None:
        mock_print = MagicMock()
        with (
            patch(
                "mytools.web.crlfinjection.create_async_client",
                return_value=AsyncMock(),
            ),
            patch(
                "mytools.web.crlfinjection._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"ok"),
            ),
            patch(
                "mytools.web.crlfinjection._test_param_crlf",
                new_callable=AsyncMock,
                return_value=[self._attempt()],
            ),
            patch("mytools.web.crlfinjection.print_results", mock_print),
        ):
            code = await run_scan("https://example.com", ["param"], 10, 5, None, False)
        assert code == 1
        result = mock_print.call_args[0][0]
        assert result.overall_status == "vulnerable"
        assert result.vulnerable_techniques == ["crlf_header_q"]
        assert any("VULN" in i for i in result.issues)
        assert any("INJECTED" in i for i in result.issues)

    @pytest.mark.asyncio
    async def test_blocked_attempt(self) -> None:
        blocked_att = CRLFAttempt(
            technique="crlf_header_q",
            category="param",
            url="https://example.com",
            payload="\r\nX-Injected: test",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=100,
            status_changed=False,
            size_changed=False,
            injected_headers=[],
            vulnerable=False,
            details="no injection",
            error="",
        )
        mock_print = MagicMock()
        with (
            patch(
                "mytools.web.crlfinjection.create_async_client",
                return_value=AsyncMock(),
            ),
            patch(
                "mytools.web.crlfinjection._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"ok"),
            ),
            patch(
                "mytools.web.crlfinjection._test_param_crlf",
                new_callable=AsyncMock,
                return_value=[blocked_att],
            ),
            patch("mytools.web.crlfinjection.print_results", mock_print),
        ):
            code = await run_scan("https://example.com", ["param"], 10, 5, None, False)
        assert code == 0
        result = mock_print.call_args[0][0]
        assert result.overall_status == "secure"
        assert result.blocked_techniques == ["crlf_header_q"]

    @pytest.mark.asyncio
    async def test_baseline_failure(self) -> None:
        with (
            patch(
                "mytools.web.crlfinjection.create_async_client",
                return_value=AsyncMock(),
            ),
            patch(
                "mytools.web.crlfinjection._test_baseline",
                new_callable=AsyncMock,
                return_value=(0, 0, b""),
            ),
        ):
            code = await run_scan("https://example.com", [], 10, 5, None, False)
        assert code == 1

    @pytest.mark.asyncio
    async def test_gather_exception_skipped(self) -> None:
        with (
            patch(
                "mytools.web.crlfinjection.create_async_client",
                return_value=AsyncMock(),
            ),
            patch(
                "mytools.web.crlfinjection._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"ok"),
            ),
            patch(
                "mytools.web.crlfinjection._test_param_crlf",
                new_callable=AsyncMock,
                side_effect=RuntimeError("boom"),
            ),
            patch("mytools.web.crlfinjection.print_results"),
        ):
            code = await run_scan("https://example.com", ["param"], 10, 5, None, False)
        assert code == 0

    @pytest.mark.asyncio
    async def test_invalid_category_skipped(self) -> None:
        mock_print = MagicMock()
        with (
            patch(
                "mytools.web.crlfinjection.create_async_client",
                return_value=AsyncMock(),
            ),
            patch(
                "mytools.web.crlfinjection._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"ok"),
            ),
            patch("mytools.web.crlfinjection.print_results", mock_print),
        ):
            code = await run_scan(
                "https://example.com", ["invalid"], 10, 5, None, False
            )
        assert code == 0
        result = mock_print.call_args[0][0]
        assert result.attempts == []

    @pytest.mark.asyncio
    async def test_output_file(self) -> None:
        client = AsyncMock()
        client.get.return_value = MagicMock(status_code=200, content=b"ok", headers={})
        with (
            patch(
                "mytools.web.crlfinjection.create_async_client",
                return_value=client,
            ),
            patch(
                "mytools.web.crlfinjection._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"ok"),
            ),
            patch("mytools.web.crlfinjection.print_results"),
            patch("mytools.web.crlfinjection.write_output") as mock_write,
        ):
            await run_scan("https://example.com", ["param"], 10, 5, "out.json", False)
        mock_write.assert_called_once()


# ─── run_once Tests ──────────────────────────────────────────────────────────


class TestRunOnce:
    def _ns(self, **overrides: object) -> argparse.Namespace:
        defaults = {
            "url": "https://example.com",
            "category": None,
            "timeout": 10,
            "concurrency": 5,
            "output": None,
            "verbose": False,
        }
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    @patch("mytools.web.crlfinjection.run_scan", return_value=0)
    def test_default(self, mock_run: MagicMock) -> None:
        assert run_once(self._ns()) == 0
        assert mock_run.call_args[1]["categories"] == []
        assert mock_run.call_args[1]["concurrency"] == 5

    @patch("mytools.web.crlfinjection.run_scan", return_value=1)
    def test_with_category(self, mock_run: MagicMock) -> None:
        assert run_once(self._ns(category="param")) == 1
        assert mock_run.call_args[1]["categories"] == ["param"]


# ─── Main Guard ──────────────────────────────────────────────────────────────


class TestMainGuard:
    def test_guard_runs(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.web.crlfinjection", run_name="__main__")
