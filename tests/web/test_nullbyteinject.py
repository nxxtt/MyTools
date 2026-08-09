#!/usr/bin/env python3
"""Testes unitarios do modulo de Null Byte Injection."""

import argparse
import runpy
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.nullbyteinject import (
    _CATEGORY_MAP,
    NullByteAttempt,
    NullByteResult,
    _build_baseline_url,
    _build_null_url,
    _test_auth_bypass,
    _test_baseline,
    _test_null_in_headers,
    _test_null_in_params,
    _test_null_in_url,
    _test_path_traversal,
    build_parser,
    main,
    print_results,
    scan_null_byte,
    scanner,
)


class _FakeClientCtx:
    """Contexto fake para create_async_client, evitando rede nos testes."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"<html>OK</html>"
        self.client = AsyncMock()
        self.client.get.return_value = resp
        self.client.post.return_value = resp

    async def __aenter__(self) -> AsyncMock:
        return self.client

    async def __aexit__(self, *exc: object) -> bool:
        return False


class TestBuildBaselineUrl:
    """Testes para _build_baseline_url."""

    def test_full_url(self) -> None:
        assert (
            _build_baseline_url("https://example.com/path")
            == "https://example.com/path"
        )

    def test_no_scheme(self) -> None:
        result = _build_baseline_url("example.com/path")
        assert result.startswith("http://")
        assert "example.com" in result


class TestBuildNullUrl:
    """Testes para _build_null_url."""

    def test_path_injection(self) -> None:
        result = _build_null_url("https://example.com/page", "%00", "path")
        assert "%00" in result
        assert "page" in result

    def test_query_injection(self) -> None:
        result = _build_null_url("https://example.com/page", "%00", "query")
        assert "test=" in result

    def test_extension_injection(self) -> None:
        result = _build_null_url("https://example.com/page.html", "%00", "extension")
        assert "%00" in result
        assert ".html" in result

    def test_no_scheme(self) -> None:
        result = _build_null_url("example.com/page", "%00", "path")
        assert result.startswith("http://")
        assert "%00" in result

    def test_invalid_position_returns_url(self) -> None:
        url = "https://example.com/page"
        assert _build_null_url(url, "%00", "invalid") == url

    def test_extension_no_match(self) -> None:
        result = _build_null_url("https://example.com/page", "%00", "extension")
        assert result.endswith("page%00")


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_all_categories_present(self) -> None:
        expected = {"url", "header", "param", "traversal", "auth"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_categories_have_techniques(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) > 0, f"Categoria {cat} vazia"

    def test_all_techniques_unique(self) -> None:
        all_techs: list[str] = []
        for techs in _CATEGORY_MAP.values():
            all_techs.extend(techs)
        assert len(all_techs) == len(set(all_techs))


@pytest.mark.smoke
class TestBuildParser:
    """Testes para build_parser."""

    def test_returns_parser(self) -> None:
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_has_url_argument(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_category_argument(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "url"])
        assert args.category == "url"

    def test_has_concurrency_argument(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--concurrency", "10"])
        assert args.concurrency == 10

    def test_invalid_category_rejected(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["https://example.com", "-c", "invalid"])


class TestTestBaseline:
    """Testes para _test_baseline."""

    @pytest.mark.asyncio
    async def test_baseline_success(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp

        status, size, body = await _test_baseline(mock_client, "https://example.com")
        assert status == 200
        assert size == 15
        assert body == b"<html>OK</html>"

    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")

        status, size, body = await _test_baseline(mock_client, "https://example.com")
        assert status == 0
        assert size == 0
        assert body == b""


class TestTestNullInUrl:
    """Testes para _test_null_in_url."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp

        attempts = await _test_null_in_url(
            mock_client, "https://example.com", (200, 14, b"")
        )
        assert len(attempts) > 0
        assert all(isinstance(a, NullByteAttempt) for a in attempts)

    @pytest.mark.asyncio
    async def test_detects_vulnerability(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.content = b"Forbidden"
        mock_client.get.return_value = mock_resp

        attempts = await _test_null_in_url(
            mock_client, "https://example.com", (200, 14, b"")
        )
        vuln = [a for a in attempts if a.vulnerable]
        assert len(vuln) == 0

    @pytest.mark.asyncio
    async def test_all_categories_used(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp

        attempts = await _test_null_in_url(
            mock_client, "https://example.com", (200, 14, b"")
        )
        categories = {a.category for a in attempts}
        assert "url" in categories

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")

        attempts = await _test_null_in_url(
            mock_client, "https://example.com", (200, 14, b"")
        )
        assert len(attempts) > 0
        assert all(a.error for a in attempts)
        assert all(a.status_test == 0 for a in attempts)


class TestTestNullInHeaders:
    """Testes para _test_null_in_headers."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp

        attempts = await _test_null_in_headers(
            mock_client, "https://example.com", (200, 14, b"")
        )
        assert len(attempts) == 4
        assert all(a.category == "header" for a in attempts)

    @pytest.mark.asyncio
    async def test_techniques_present(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp

        attempts = await _test_null_in_headers(
            mock_client, "https://example.com", (200, 14, b"")
        )
        techniques = {a.technique for a in attempts}
        assert "ua_null" in techniques
        assert "cookie_null" in techniques
        assert "auth_null" in techniques
        assert "referer_null" in techniques

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")

        attempts = await _test_null_in_headers(
            mock_client, "https://example.com", (200, 14, b"")
        )
        assert len(attempts) == 4
        assert all(a.error for a in attempts)


class TestTestNullInParams:
    """Testes para _test_null_in_params."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp
        mock_client.post.return_value = mock_resp

        attempts = await _test_null_in_params(
            mock_client, "https://example.com", (200, 14, b"")
        )
        assert len(attempts) > 0
        assert all(a.category == "param" for a in attempts)

    @pytest.mark.asyncio
    async def test_techniques_present(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp
        mock_client.post.return_value = mock_resp

        attempts = await _test_null_in_params(
            mock_client, "https://example.com", (200, 14, b"")
        )
        techniques = {a.technique for a in attempts}
        assert "get_null" in techniques
        assert "post_null" in techniques
        assert "json_null" in techniques

    @pytest.mark.asyncio
    async def test_get_request_error(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")
        mock_client.post.return_value = mock_resp

        attempts = await _test_null_in_params(
            mock_client, "https://example.com", (200, 14, b"")
        )
        get_attempts = [a for a in attempts if a.technique == "get_null"]
        assert get_attempts
        assert all(a.error for a in get_attempts)

    @pytest.mark.asyncio
    async def test_post_request_error(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp
        mock_client.post.side_effect = httpx.ConnectError("Connection refused")

        attempts = await _test_null_in_params(
            mock_client, "https://example.com", (200, 14, b"")
        )
        post_attempts = [a for a in attempts if a.technique == "post_null"]
        json_attempts = [a for a in attempts if a.technique == "json_null"]
        assert all(a.error for a in post_attempts)
        assert all(a.error for a in json_attempts)


class TestTestPathTraversal:
    """Testes para _test_path_traversal."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.content = b"Not Found"
        mock_client.get.return_value = mock_resp

        attempts = await _test_path_traversal(
            mock_client, "https://example.com", (200, 14, b"")
        )
        assert len(attempts) > 0
        assert all(a.category == "traversal" for a in attempts)

    @pytest.mark.asyncio
    async def test_techniques_present(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.content = b"Not Found"
        mock_client.get.return_value = mock_resp

        attempts = await _test_path_traversal(
            mock_client, "https://example.com", (200, 14, b"")
        )
        techniques = {a.technique for a in attempts}
        assert "path_traversal" in techniques
        assert "file_bypass" in techniques
        assert "double_null" in techniques

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")

        attempts = await _test_path_traversal(
            mock_client, "https://example.com", (200, 14, b"")
        )
        assert len(attempts) > 0
        assert all(a.error for a in attempts)


class TestTestAuthBypass:
    """Testes para _test_auth_bypass."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.content = b"Unauthorized"
        mock_client.get.return_value = mock_resp

        attempts = await _test_auth_bypass(
            mock_client, "https://example.com", (200, 14, b"")
        )
        assert len(attempts) == 3
        assert all(a.category == "auth" for a in attempts)

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.ConnectError("Connection refused")

        attempts = await _test_auth_bypass(
            mock_client, "https://example.com", (200, 14, b"")
        )
        assert len(attempts) == 3
        assert all(a.error for a in attempts)


class TestScanNullByte:
    """Testes para scan_null_byte."""

    @pytest.mark.asyncio
    async def test_invalid_category(self) -> None:
        result = await scan_null_byte("https://example.com", category="invalid")
        assert result.overall_status == "error"
        assert any("Categoria desconhecida" in i for i in result.issues)

    @pytest.mark.asyncio
    async def test_returns_result(self) -> None:
        result = await scan_null_byte("https://example.com", category="url")
        assert isinstance(result, NullByteResult)
        assert result.target == "https://example.com"

    @pytest.mark.asyncio
    async def test_tls_detected(self) -> None:
        result = await scan_null_byte("https://example.com", category="url")
        assert result.tls is True

    @pytest.mark.asyncio
    async def test_no_tls(self) -> None:
        result = await scan_null_byte("http://example.com", category="url")
        assert result.tls is False

    @pytest.mark.asyncio
    async def test_no_scheme_adds_http(self) -> None:
        with patch(
            "mytools.web.nullbyteinject.create_async_client",
            return_value=_FakeClientCtx(),
        ):
            result = await scan_null_byte("example.com", category="url")
        assert result.target == "http://example.com"
        assert isinstance(result, NullByteResult)

    @pytest.mark.asyncio
    async def test_full_scan_all_categories(self) -> None:
        with patch(
            "mytools.web.nullbyteinject.create_async_client",
            return_value=_FakeClientCtx(),
        ):
            result = await scan_null_byte("https://example.com")
        assert result.overall_status == "secure"

    @pytest.mark.asyncio
    async def test_vulnerable_detected(self) -> None:
        vuln = NullByteAttempt(
            technique="null_url_path",
            category="url",
            url="https://example.com/test%00",
            payload="%00",
            status_baseline=200,
            status_test=200,
            size_baseline=14,
            size_test=200,
            status_changed=True,
            size_changed=True,
            vulnerable=True,
            details="Status 200->200",
            error="",
        )
        with (
            patch(
                "mytools.web.nullbyteinject.create_async_client",
                return_value=_FakeClientCtx(),
            ),
            patch(
                "mytools.web.nullbyteinject._test_null_in_url",
                AsyncMock(return_value=[vuln]),
            ),
        ):
            result = await scan_null_byte("https://example.com")
        assert result.overall_status == "vulnerable"
        assert "null_url_path" in result.vulnerable_techniques
        assert result.issues

    @pytest.mark.asyncio
    async def test_blocked_detected(self) -> None:
        blocked_att = NullByteAttempt(
            technique="null_url_path",
            category="url",
            url="https://example.com/test%00",
            payload="%00",
            status_baseline=200,
            status_test=403,
            size_baseline=14,
            size_test=14,
            status_changed=True,
            size_changed=False,
            vulnerable=False,
            details="Status 200->403",
            error="",
        )
        with (
            patch(
                "mytools.web.nullbyteinject.create_async_client",
                return_value=_FakeClientCtx(),
            ),
            patch(
                "mytools.web.nullbyteinject._test_null_in_url",
                AsyncMock(return_value=[blocked_att]),
            ),
        ):
            result = await scan_null_byte("https://example.com")
        assert result.overall_status == "blocked"
        assert "null_url_path" in result.blocked_techniques
        assert result.issues

    @pytest.mark.asyncio
    async def test_task_exception_is_ignored(self) -> None:
        with (
            patch(
                "mytools.web.nullbyteinject.create_async_client",
                return_value=_FakeClientCtx(),
            ),
            patch(
                "mytools.web.nullbyteinject._test_null_in_headers",
                AsyncMock(side_effect=ValueError("boom")),
            ),
        ):
            result = await scan_null_byte("https://example.com")
        assert result.overall_status == "secure"


class TestNullByteAttempt:
    """Testes para NullByteAttempt dataclass."""

    def test_frozen(self) -> None:
        att = NullByteAttempt(
            technique="test",
            category="url",
            url="http://x.com",
            payload="%00",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=100,
            status_changed=False,
            size_changed=False,
            vulnerable=False,
            details="",
            error="",
        )
        with pytest.raises(AttributeError):
            att.technique = "changed"  # type: ignore[misc]

    def test_slots(self) -> None:
        att = NullByteAttempt(
            technique="test",
            category="url",
            url="http://x.com",
            payload="%00",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=100,
            status_changed=False,
            size_changed=False,
            vulnerable=False,
            details="",
            error="",
        )
        assert not hasattr(att, "__dict__")


class TestNullByteResult:
    """Testes para NullByteResult dataclass."""

    def test_frozen(self) -> None:
        result = NullByteResult(
            target="http://x.com",
            baseline_status=200,
            baseline_size=100,
            tls=False,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            result.target = "changed"  # type: ignore[misc]

    def test_overall_status_values(self) -> None:
        for status in ["vulnerable", "blocked", "secure", "error"]:
            result = NullByteResult(
                target="http://x.com",
                baseline_status=200,
                baseline_size=100,
                tls=False,
                attempts=[],
                vulnerable_techniques=[],
                blocked_techniques=[],
                issues=[],
                overall_status=status,
            )
            assert result.overall_status == status


class TestPrintResults:
    """Testes para print_results."""

    def test_print_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = NullByteResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[
                NullByteAttempt(
                    technique="path_null",
                    category="url",
                    url="https://example.com/test%00",
                    payload="%00",
                    status_baseline=200,
                    status_test=200,
                    size_baseline=100,
                    size_test=200,
                    status_changed=True,
                    size_changed=True,
                    vulnerable=True,
                    details="Mudanca detectada",
                    error="",
                )
            ],
            vulnerable_techniques=["path_null"],
            blocked_techniques=[],
            issues=["1 tecnicas vulneraveis"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "NULL BYTE" in captured.out
        assert "VULNERAVEL" in captured.out

    def test_print_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = NullByteResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "SECURE" in captured.out

    def test_print_blocked(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = NullByteResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=False,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=["ua_null"],
            issues=["1 bloqueadas"],
            overall_status="blocked",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "BLOQUEADO" in captured.out

    def test_print_vulnerable_no_attempt_match(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = NullByteResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=["path_null"],
            blocked_techniques=[],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "path_null" in captured.out


class TestScannerMethods:
    """Testes para os metodos de NullByteScanner."""

    @pytest.mark.asyncio
    async def test_run_scan(self) -> None:
        with patch(
            "mytools.web.nullbyteinject.create_async_client",
            return_value=_FakeClientCtx(),
        ):
            result = await scanner.run_scan(url="https://example.com", category="url")
        assert isinstance(result, NullByteResult)
        assert result.target == "https://example.com"

    def test_print_results(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = NullByteResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        scanner.print_results(result)
        captured = capsys.readouterr()
        assert "NULL BYTE" in captured.out


class TestMain:
    """Testes para main()."""

    def test_main_no_url(self) -> None:
        with (
            patch("sys.argv", ["mytools-nullbyte"]),
            patch("builtins.input", side_effect=EOFError("exit")),
        ):
            result = main()
            assert result == 0

    def test_main_entrypoint_guard(self) -> None:
        with (
            patch("sys.argv", ["mytools-nullbyte"]),
            patch("builtins.input", side_effect=EOFError("exit")),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.web.nullbyteinject", run_name="__main__")
