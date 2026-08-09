#!/usr/bin/env python3
"""Testes unitarios do modulo de BOM Injection."""

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mytools.web.bominjection import (
    _BOM_BYTES,
    _BOM_VARIANTS,
    _CATEGORY_MAP,
    _SENSITIVE_STRINGS,
    BomAttempt,
    BominjectionScanner,
    BomResult,
    _bom_url,
    _test_baseline,
    _test_bom_body,
    _test_bom_headers,
    _test_bom_upload,
    _test_bom_url,
    build_parser,
    main,
    print_results,
    scan_bom_injection,
)


def _attempt(
    *,
    technique: str = "bom_utf8_bom_path",
    category: str = "url",
    vulnerable: bool = False,
    status_changed: bool = False,
    error: str = "",
    exploit: str = "",
    tool: str = "curl",
) -> BomAttempt:
    return BomAttempt(
        technique=technique,
        category=category,
        url="https://example.com",
        payload="utf8_bom=\ufeff",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=100,
        status_changed=status_changed,
        size_changed=False,
        vulnerable=vulnerable,
        details="Sem mudanca",
        error=error,
        exploit=exploit,
        tool=tool,
    )


def _result(status: str) -> BomResult:
    return BomResult(
        target="https://example.com",
        baseline_status=200,
        baseline_size=100,
        tls=True,
        attempts=[],
        vulnerable_techniques=[],
        blocked_techniques=[],
        issues=[],
        overall_status=status,
    )


class TestBomVariants:
    """Testes para _BOM_VARIANTS."""

    def test_has_utf8(self) -> None:
        assert "utf8_bom" in _BOM_VARIANTS
        assert _BOM_VARIANTS["utf8_bom"] == "\ufeff"

    def test_has_utf16_le(self) -> None:
        assert "utf16_le" in _BOM_VARIANTS

    def test_has_utf16_be(self) -> None:
        assert "utf16_be" in _BOM_VARIANTS

    def test_has_utf32_le(self) -> None:
        assert "utf32_le" in _BOM_VARIANTS

    def test_has_utf32_be(self) -> None:
        assert "utf32_be" in _BOM_VARIANTS

    def test_has_utf7(self) -> None:
        assert "utf7_bom" in _BOM_VARIANTS

    def test_count(self) -> None:
        assert len(_BOM_VARIANTS) == 6

    def test_all_are_strings(self) -> None:
        for name, char in _BOM_VARIANTS.items():
            assert isinstance(char, str), f"{name} nao e string"


class TestBomBytes:
    """Testes para _BOM_BYTES."""

    def test_has_all_variants(self) -> None:
        for name in _BOM_VARIANTS:
            assert name in _BOM_BYTES, f"{name} faltando em _BOM_BYTES"

    def test_utf8_bytes(self) -> None:
        assert _BOM_BYTES["utf8_bom"] == b"\xef\xbb\xbf"

    def test_utf16_le_bytes(self) -> None:
        assert _BOM_BYTES["utf16_le"] == b"\xff\xfe"

    def test_utf16_be_bytes(self) -> None:
        assert _BOM_BYTES["utf16_be"] == b"\xfe\xff"

    def test_utf32_le_bytes(self) -> None:
        assert _BOM_BYTES["utf32_le"] == b"\xff\xfe\x00\x00"

    def test_utf32_be_bytes(self) -> None:
        assert _BOM_BYTES["utf32_be"] == b"\x00\x00\xfe\xff"

    def test_utf7_bytes(self) -> None:
        assert _BOM_BYTES["utf7_bom"] == b"+/v8"


class TestBomUrl:
    """Testes para _bom_url."""

    def test_path_position(self) -> None:
        result = _bom_url("https://example.com/admin", "utf8_bom", "\ufeff", "path")
        assert "\ufeff" in result
        assert "admin" in result

    def test_query_position(self) -> None:
        result = _bom_url("https://example.com", "utf8_bom", "\ufeff", "query")
        assert "test=\ufeff" in result

    def test_no_scheme(self) -> None:
        result = _bom_url("example.com/admin", "utf8_bom", "\ufeff", "path")
        assert "\ufeff" in result

    def test_unknown_position(self) -> None:
        result = _bom_url("https://example.com", "utf8_bom", "\ufeff", "unknown")
        assert result == "https://example.com"


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_has_url(self) -> None:
        assert "url" in _CATEGORY_MAP

    def test_has_header(self) -> None:
        assert "header" in _CATEGORY_MAP

    def test_has_body(self) -> None:
        assert "body" in _CATEGORY_MAP

    def test_has_upload(self) -> None:
        assert "upload" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 4


class TestSensitiveStrings:
    """Testes para _SENSITIVE_STRINGS."""

    def test_has_xss(self) -> None:
        assert any("<script>" in s for s in _SENSITIVE_STRINGS)

    def test_has_sqli(self) -> None:
        assert any("OR 1=1" in s for s in _SENSITIVE_STRINGS)

    def test_has_traversal(self) -> None:
        assert any("passwd" in s for s in _SENSITIVE_STRINGS)

    def test_count(self) -> None:
        assert len(_SENSITIVE_STRINGS) >= 5


class TestBomAttempt:
    """Testes para BomAttempt dataclass."""

    def test_creation(self) -> None:
        att = BomAttempt(
            technique="bom_utf8_bom_path",
            category="url",
            url="https://example.com/test",
            payload="utf8_bom=\ufeff",
            status_baseline=200,
            status_test=404,
            size_baseline=1000,
            size_test=500,
            status_changed=True,
            size_changed=True,
            vulnerable=False,
            details="Status 200->404",
            error="",
        )
        assert att.technique == "bom_utf8_bom_path"
        assert att.status_changed is True
        assert att.vulnerable is False

    def test_frozen(self) -> None:
        att = BomAttempt(
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
            vulnerable=False,
            details="d",
            error="",
        )
        with pytest.raises(AttributeError):
            att.technique = "new"  # type: ignore[misc]


class TestBomResult:
    """Testes para BomResult dataclass."""

    def test_creation(self) -> None:
        result = BomResult(
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


class TestTestBomUrl:
    """Testes para _test_bom_url."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 404
        resp.content = b"not found"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_bom_url(
            client,
            "https://example.com/admin",
            (200, 1000, b""),
        )
        assert len(attempts) > 0
        assert all(isinstance(a, BomAttempt) for a in attempts)

    @pytest.mark.asyncio
    async def test_vulnerability_detected(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"admin panel"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_bom_url(
            client,
            "https://example.com/admin",
            (404, 100, b""),
        )
        vulnerable = [a for a in attempts if a.vulnerable]
        assert len(vulnerable) > 0

    @pytest.mark.asyncio
    async def test_error_handled(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_bom_url(
            client,
            "https://example.com/admin",
            (200, 1000, b""),
        )
        assert len(attempts) == 12
        assert all(a.error for a in attempts)


class TestTestBomHeaders:
    """Testes para _test_bom_headers."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_bom_headers(
            client,
            "https://example.com",
            (200, 1000, b""),
        )
        assert len(attempts) == 3

    @pytest.mark.asyncio
    async def test_error_handled(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_bom_headers(
            client,
            "https://example.com",
            (200, 1000, b""),
        )
        assert len(attempts) == 3
        assert all(a.error for a in attempts)


class TestTestBomBody:
    """Testes para _test_bom_body."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.post = AsyncMock(return_value=resp)

        attempts = await _test_bom_body(
            client,
            "https://example.com",
            (200, 1000, b""),
        )
        assert len(attempts) == 3

    @pytest.mark.asyncio
    async def test_error_handled(self) -> None:
        client = AsyncMock()
        client.post = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_bom_body(
            client,
            "https://example.com",
            (200, 1000, b""),
        )
        assert len(attempts) == 3
        assert all(a.error for a in attempts)


class TestTestBomUpload:
    """Testes para _test_bom_upload."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.post = AsyncMock(return_value=resp)

        attempts = await _test_bom_upload(
            client,
            "https://example.com",
            (200, 1000, b""),
        )
        assert len(attempts) == 2

    @pytest.mark.asyncio
    async def test_error_handled(self) -> None:
        client = AsyncMock()
        client.post = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_bom_upload(
            client,
            "https://example.com",
            (200, 1000, b""),
        )
        assert len(attempts) == 2
        assert all(a.error for a in attempts)


@pytest.mark.smoke
class TestBuildParser:
    """Testes para build_parser."""

    def test_has_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "url"])
        assert args.category == "url"

    def test_has_concurrency(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--concurrency", "10"])
        assert args.concurrency == 10

    def test_category_choices(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "upload"])
        assert args.category == "upload"


class TestPrintResults:
    """Testes para print_results."""

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = BomResult(
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
        assert "BOM" in captured.out

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = BomResult(
            target="https://example.com",
            baseline_status=404,
            baseline_size=100,
            tls=False,
            attempts=[],
            vulnerable_techniques=["bom_utf8_bom_path"],
            blocked_techniques=[],
            issues=["1 tecnicas vulneraveis"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "VULNERAVEL" in captured.out

    def test_vulnerable_attempts_and_blocked(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        vuln = _attempt(
            vulnerable=True,
            status_changed=True,
            exploit="\\xef\\xbb\\xbf",
        )
        blocked = _attempt(technique="bom_query", category="url", status_changed=True)
        result = BomResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[vuln, blocked],
            vulnerable_techniques=["bom_utf8_bom_path"],
            blocked_techniques=["bom_query"],
            issues=["1 tecnicas vulneraveis", "1 tecnicas bloqueadas"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "bom_utf8_bom_path" in captured.out
        assert "BLOQUEADO" in captured.out
        assert "bom_query" in captured.out


class TestScanBomInjection:
    @pytest.mark.asyncio
    async def test_secure_all_categories(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.bominjection.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.bominjection._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 1000, b"ok"),
            ),
            patch(
                "mytools.web.bominjection._test_bom_url",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.bominjection._test_bom_headers",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.bominjection._test_bom_body",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.bominjection._test_bom_upload",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = await scan_bom_injection("https://example.com")
        assert result.overall_status == "secure"
        assert result.tls is True

    @pytest.mark.asyncio
    async def test_no_scheme(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.bominjection.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.bominjection._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 1000, b"ok"),
            ),
            patch(
                "mytools.web.bominjection._test_bom_url",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = await scan_bom_injection("example.com", category="url")
        assert result.target == "http://example.com"
        assert result.tls is False

    @pytest.mark.asyncio
    async def test_vulnerable_category(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        vuln = _attempt(vulnerable=True)
        with (
            patch(
                "mytools.web.bominjection.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.bominjection._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 1000, b"ok"),
            ),
            patch(
                "mytools.web.bominjection._test_bom_url",
                new_callable=AsyncMock,
                return_value=[vuln, vuln, _attempt(technique="bom_query")],
            ),
        ):
            result = await scan_bom_injection("https://example.com", category="url")
        assert result.overall_status == "vulnerable"
        assert result.vulnerable_techniques == ["bom_utf8_bom_path"]

    @pytest.mark.asyncio
    async def test_blocked_category(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        blocked_att = _attempt(technique="bom_query", status_changed=True)
        with (
            patch(
                "mytools.web.bominjection.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.bominjection._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 1000, b"ok"),
            ),
            patch(
                "mytools.web.bominjection._test_bom_url",
                new_callable=AsyncMock,
                return_value=[blocked_att],
            ),
        ):
            result = await scan_bom_injection("https://example.com", category="url")
        assert result.overall_status == "blocked"
        assert result.blocked_techniques == ["bom_query"]

    @pytest.mark.asyncio
    async def test_unknown_category(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.bominjection.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.bominjection._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 1000, b"ok"),
            ),
        ):
            result = await scan_bom_injection("https://example.com", category="invalid")
        assert result.overall_status == "error"
        assert any("desconhecida" in i for i in result.issues)

    @pytest.mark.asyncio
    async def test_gather_exception_is_skipped(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.bominjection.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.bominjection._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 1000, b"ok"),
            ),
            patch(
                "mytools.web.bominjection._test_bom_url",
                new_callable=AsyncMock,
                side_effect=RuntimeError("boom"),
            ),
        ):
            result = await scan_bom_injection("https://example.com", category="url")
        assert result.overall_status == "secure"
        assert result.attempts == []


class TestScanner:
    @pytest.mark.asyncio
    async def test_run_scan(self) -> None:
        with patch(
            "mytools.web.bominjection.scan_bom_injection",
            new_callable=AsyncMock,
            return_value=_result("secure"),
        ) as mock_scan:
            result = await BominjectionScanner().run_scan(url="https://example.com")
        assert result.overall_status == "secure"
        mock_scan.assert_called_once()

    def test_print_results(self, capsys: pytest.CaptureFixture[str]) -> None:
        BominjectionScanner().print_results(_result("secure"))
        captured = capsys.readouterr()
        assert "BOM" in captured.out


class TestMainGuard:
    def test_guard_runs(self) -> None:
        import runpy

        with (
            patch("mytools.core.base.run_main_loop", side_effect=SystemExit(0)),
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.web.bominjection", run_name="__main__")


class TestMain:
    """Testes para main."""

    def test_no_url(self) -> None:
        with (
            patch("sys.argv", ["mytools-bominject"]),
            patch("mytools.core.base.run_main_loop", return_value=1) as mock_loop,
        ):
            result = main()
            assert result == 1
            mock_loop.assert_called_once()
