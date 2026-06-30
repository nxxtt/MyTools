#!/usr/bin/env python3
"""Testes unitarios do modulo de Double URL Encoding Bypass."""
import argparse
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.doubleurlencode import (
    _CATEGORY_MAP,
    DoubleURLEncodeAttempt,
    DoubleURLEncodeResult,
    _build_double_url,
    _double_encode,
    _test_baseline,
    _test_double_headers,
    _test_double_params,
    _test_double_traversal,
    _test_double_url,
    _test_double_waf,
    _triple_encode,
    build_parser,
    main,
    print_results,
    scan_double_url_encode,
)


class TestDoubleEncode:
    """Testes para _double_encode."""

    def test_slash(self) -> None:
        assert _double_encode("/").lower() == "%252f"

    def test_backslash(self) -> None:
        assert _double_encode("\\").lower() == "%255c"

    def test_single_quote(self) -> None:
        assert _double_encode("'").lower() == "%2527"

    def test_space(self) -> None:
        assert _double_encode(" ").lower() == "%2520"

    def test_angle_bracket(self) -> None:
        assert _double_encode("<").lower() == "%253c"


class TestTripleEncode:
    """Testes para _triple_encode."""

    def test_slash(self) -> None:
        result = _triple_encode("/")
        assert "%2525" in result

    def test_double_is_triple_of_single(self) -> None:
        single = _double_encode("/")
        triple = _triple_encode("/")
        assert len(triple) > len(single)


class TestBuildDoubleUrl:
    """Testes para _build_double_url."""

    def test_path_position(self) -> None:
        result = _build_double_url("https://example.com/page", "/", "%252f", "path")
        assert "%252f" in result
        assert "page" in result

    def test_query_position(self) -> None:
        result = _build_double_url("https://example.com/page", "/", "%252f", "query")
        assert "%252f" in result
        assert "test=" in result

    def test_fragment_position(self) -> None:
        result = _build_double_url("https://example.com/page", "/", "%252f", "fragment")
        assert "%252f" in result
        assert "#" in result

    def test_no_scheme_adds_http(self) -> None:
        result = _build_double_url("example.com/page", "/", "%252f", "path")
        assert result.startswith("http://")


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_all_categories_present(self) -> None:
        expected = {"url", "param", "traversal", "header", "waf"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_categories_have_techniques(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) > 0, f"Categoria {cat} vazia"

    def test_all_techniques_unique(self) -> None:
        all_techs: list[str] = []
        for techs in _CATEGORY_MAP.values():
            all_techs.extend(techs)
        assert len(all_techs) == len(set(all_techs))


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


class TestTestDoubleUrl:
    """Testes para _test_double_url."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp

        attempts = await _test_double_url(mock_client, "https://example.com", (200, 15, b""))
        assert len(attempts) > 0
        assert all(isinstance(a, DoubleURLEncodeAttempt) for a in attempts)

    @pytest.mark.asyncio
    async def test_all_categories_used(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp

        attempts = await _test_double_url(mock_client, "https://example.com", (200, 15, b""))
        categories = {a.category for a in attempts}
        assert "url" in categories


class TestTestDoubleParams:
    """Testes para _test_double_params."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp
        mock_client.post.return_value = mock_resp

        attempts = await _test_double_params(mock_client, "https://example.com", (200, 15, b""))
        assert len(attempts) == 3
        assert all(a.category == "param" for a in attempts)

    @pytest.mark.asyncio
    async def test_techniques_present(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp
        mock_client.post.return_value = mock_resp

        attempts = await _test_double_params(mock_client, "https://example.com", (200, 15, b""))
        techniques = {a.technique for a in attempts}
        assert "double_get" in techniques
        assert "double_post" in techniques
        assert "double_json" in techniques


class TestTestDoubleTraversal:
    """Testes para _test_double_traversal."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.content = b"Not Found"
        mock_client.get.return_value = mock_resp

        attempts = await _test_double_traversal(mock_client, "https://example.com", (200, 15, b""))
        assert len(attempts) > 0
        assert all(a.category == "traversal" for a in attempts)


class TestTestDoubleHeaders:
    """Testes para _test_double_headers."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp

        attempts = await _test_double_headers(mock_client, "https://example.com", (200, 15, b""))
        assert len(attempts) == 3
        assert all(a.category == "header" for a in attempts)


class TestTestDoubleWaf:
    """Testes para _test_double_waf."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html>OK</html>"
        mock_client.get.return_value = mock_resp

        attempts = await _test_double_waf(mock_client, "https://example.com", (200, 15, b""))
        assert len(attempts) == 3
        assert all(a.category == "waf" for a in attempts)


class TestScanDoubleURLEncode:
    """Testes para scan_double_url_encode."""

    @pytest.mark.asyncio
    async def test_invalid_category(self) -> None:
        result = await scan_double_url_encode("https://example.com", category="invalid")
        assert result.overall_status == "error"
        assert any("Categoria desconhecida" in i for i in result.issues)

    @pytest.mark.asyncio
    async def test_returns_result(self) -> None:
        result = await scan_double_url_encode("https://example.com", category="url")
        assert isinstance(result, DoubleURLEncodeResult)
        assert result.target == "https://example.com"

    @pytest.mark.asyncio
    async def test_tls_detected(self) -> None:
        result = await scan_double_url_encode("https://example.com", category="url")
        assert result.tls is True

    @pytest.mark.asyncio
    async def test_no_tls(self) -> None:
        result = await scan_double_url_encode("http://example.com", category="url")
        assert result.tls is False


class TestDoubleURLEncodeAttempt:
    """Testes para DoubleURLEncodeAttempt dataclass."""

    def test_frozen(self) -> None:
        att = DoubleURLEncodeAttempt(
            technique="test", category="url", url="http://x.com",
            payload="%252f", status_baseline=200, status_test=200,
            size_baseline=100, size_test=100, status_changed=False,
            size_changed=False, vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            att.technique = "changed"  # type: ignore[misc]

    def test_slots(self) -> None:
        att = DoubleURLEncodeAttempt(
            technique="test", category="url", url="http://x.com",
            payload="%252f", status_baseline=200, status_test=200,
            size_baseline=100, size_test=100, status_changed=False,
            size_changed=False, vulnerable=False, details="", error="",
        )
        assert not hasattr(att, "__dict__")


class TestDoubleURLEncodeResult:
    """Testes para DoubleURLEncodeResult dataclass."""

    def test_frozen(self) -> None:
        result = DoubleURLEncodeResult(
            target="http://x.com", baseline_status=200, baseline_size=100,
            tls=False, attempts=[], vulnerable_techniques=[],
            blocked_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            result.target = "changed"  # type: ignore[misc]

    def test_overall_status_values(self) -> None:
        for status in ["vulnerable", "blocked", "secure", "error"]:
            result = DoubleURLEncodeResult(
                target="http://x.com", baseline_status=200, baseline_size=100,
                tls=False, attempts=[], vulnerable_techniques=[],
                blocked_techniques=[], issues=[], overall_status=status,
            )
            assert result.overall_status == status


class TestPrintResults:
    """Testes para print_results."""

    def test_print_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = DoubleURLEncodeResult(
            target="https://example.com", baseline_status=200, baseline_size=100,
            tls=True,
            attempts=[DoubleURLEncodeAttempt(
                technique="double_path", category="url", url="https://example.com/test%252f",
                payload="%252f", status_baseline=200, status_test=200,
                size_baseline=100, size_test=200, status_changed=True,
                size_changed=True, vulnerable=True, details="Mudanca detectada", error="",
            )],
            vulnerable_techniques=["double_path"],
            blocked_techniques=[],
            issues=["1 tecnicas vulneraveis"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "DOUBLE URL" in captured.out
        assert "VULNERAVEL" in captured.out

    def test_print_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = DoubleURLEncodeResult(
            target="https://example.com", baseline_status=200, baseline_size=100,
            tls=True, attempts=[], vulnerable_techniques=[],
            blocked_techniques=[], issues=[], overall_status="secure",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "SECURE" in captured.out


class TestMain:
    """Testes para main()."""

    def test_main_no_url(self) -> None:
        with patch("sys.argv", ["mytools-dblurl"]), patch("builtins.input", side_effect=EOFError("exit")):
            result = main()
            assert result == 0
