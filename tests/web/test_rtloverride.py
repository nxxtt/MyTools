#!/usr/bin/env python3
"""Testes unitarios do modulo de RTL Override."""

import argparse
from unittest.mock import AsyncMock, patch

import httpx
import pytest

import mytools.web.rtloverride as rtl_module
from mytools.core.utils import FetchError
from mytools.web.rtloverride import (
    _COMBINING_CHARS,
    _RTL_CHARS,
    _ZERO_WIDTH_CHARS,
    RTLAttempt,
    RTLResult,
    _async_run_once,
    _generate_variants,
    _insert_combining,
    _insert_rtl,
    _make_display,
    _test_variant,
    build_parser,
    detect_rtl,
    main,
    print_results,
    run_once,
)


class TestRTLChars:
    """Testes para _RTL_CHARS."""

    def test_has_rlo(self) -> None:
        assert "rlo" in _RTL_CHARS
        assert _RTL_CHARS["rlo"] == "\u202e"

    def test_has_rle(self) -> None:
        assert "rle" in _RTL_CHARS

    def test_all_values_are_rtl(self) -> None:
        for key, char in _RTL_CHARS.items():
            code = ord(char)
            assert code in (0x202E, 0x202B, 0x202D, 0x2066, 0x2067, 0x2068, 0x2069), (
                f"{key} nao e RTL"
            )


class TestInsertRTL:
    """Testes para _insert_rtl."""

    def test_before_domain(self) -> None:
        result = _insert_rtl("https://evil.com/path", "\u202e", "before_domain")
        assert "\u202e" in result
        assert result.startswith("https://")

    def test_in_path(self) -> None:
        result = _insert_rtl("https://evil.com/a/b/c", "\u202e", "in_path")
        assert "\u202e" in result

    def test_before_path(self) -> None:
        result = _insert_rtl("https://evil.com/admin", "\u202e", "before_path")
        assert "\u202e" in result
        assert result.startswith("https://evil.com\u202e")

    def test_in_query(self) -> None:
        result = _insert_rtl("https://evil.com/path?q=test", "\u202e", "in_query")
        assert result.endswith("\u202e")

    def test_unknown_position(self) -> None:
        result = _insert_rtl("https://evil.com/path", "\u202e", "unknown_pos")
        assert result == "https://evil.com/path"


class TestGenerateVariants:
    """Testes para _generate_variants."""

    def test_generates_variants(self) -> None:
        variants = _generate_variants("https://example.com")
        assert len(variants) > 0

    def test_all_variants_different(self) -> None:
        variants = _generate_variants("https://example.com/a/b/c")
        urls = [v[3] for v in variants]
        assert len(urls) == len(set(urls))

    def test_variants_contain_rtl(self) -> None:
        variants = _generate_variants("https://example.com")
        for _label, rtl_char, _position, url in variants:
            assert rtl_char in url


class TestDetectRTL:
    """Testes para detect_rtl."""

    def test_detects_rlo(self) -> None:
        text = "hello\u202eworld"
        found = detect_rtl(text)
        assert len(found) == 1
        assert "RIGHT-TO-LEFT OVERRIDE" in found[0][0]

    def test_detects_multiple(self) -> None:
        text = "\u202e\u202btest"
        found = detect_rtl(text)
        assert len(found) == 2

    def test_no_rtl(self) -> None:
        found = detect_rtl("normal text")
        assert len(found) == 0

    def test_empty(self) -> None:
        found = detect_rtl("")
        assert len(found) == 0


class TestMakeDisplay:
    """Testes para _make_display."""

    def test_removes_rlo(self) -> None:
        result = _make_display("hello\u202eworld")
        assert result == "helloworld"

    def test_removes_all_rtl(self) -> None:
        result = _make_display("a\u202eb\u202bc\u202d")
        assert result == "abc"

    def test_no_rtl_unchanged(self) -> None:
        result = _make_display("normal text")
        assert result == "normal text"


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

    def test_has_mode_argument(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-m", "gen"])
        assert args.mode == "gen"

    def test_default_mode_scan(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.mode == "scan"


class TestRTLAttempt:
    """Testes para RTLAttempt dataclass."""

    def test_frozen(self) -> None:
        att = RTLAttempt(
            technique="rlo",
            label="RTL Override",
            url_display="http://x.com",
            url_real="http://x.com",
            rtl_char="\u202e",
            position="before_domain",
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


class TestRTLResult:
    """Testes para RTLResult dataclass."""

    def test_frozen(self) -> None:
        result = RTLResult(
            target="http://x.com",
            baseline_status=200,
            baseline_size=100,
            tls=False,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="safe",
        )
        with pytest.raises(AttributeError):
            result.target = "changed"  # type: ignore[misc]


class TestPrintResults:
    """Testes para print_results."""

    def test_print_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = RTLResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="blocked",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "BLOQUEADO" in captured.out

    def test_print_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = RTLResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[
                RTLAttempt(
                    technique="rlo",
                    label="RTL Override",
                    url_display="https://example.com",
                    url_real="https://example.com\u202eadmin",
                    rtl_char="\u202e",
                    position="before_domain",
                    status_baseline=200,
                    status_test=200,
                    size_baseline=100,
                    size_test=200,
                    status_changed=False,
                    size_changed=True,
                    vulnerable=True,
                    details="size changed",
                    error="",
                )
            ],
            vulnerable_techniques=["rlo"],
            blocked_techniques=[],
            issues=["1 tecnicas vulneraveis"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "VULNERAVEL" in captured.out

    def test_print_blocked_techniques(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = RTLResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=["rlo", "rle"],
            issues=[],
            overall_status="blocked",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "BLOQUEADO" in captured.out
        assert "rlo" in captured.out
        assert "rle" in captured.out

    def test_print_attempt_statuses(self, capsys: pytest.CaptureFixture[str]) -> None:
        base = {
            "label": "RTL Override",
            "url_display": "https://example.com",
            "url_real": "https://example.com\u202eadmin",
            "rtl_char": "\u202e",
            "position": "before_domain",
            "status_baseline": 200,
            "status_test": 200,
            "size_baseline": 100,
            "size_test": 100,
            "size_changed": False,
            "vulnerable": False,
        }
        different = RTLAttempt(
            **base,
            technique="rlo",
            status_changed=True,
            details="status 200 -> 500",
            error="",
        )
        error = RTLAttempt(
            **base,
            technique="rle",
            status_changed=False,
            details="",
            error="boom",
        )
        safe = RTLAttempt(
            **base,
            technique="lro",
            status_changed=False,
            details="",
            error="",
        )
        result = RTLResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[different, error, safe],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="safe",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "DIFERENTE" in captured.out
        assert "ERRO" in captured.out
        assert "SAFE" in captured.out
        assert "SEGURO" in captured.out

    """Testes para main()."""

    def test_main_no_url(self) -> None:
        with (
            patch("sys.argv", ["mytools-rtlo"]),
            patch("builtins.input", side_effect=EOFError("exit")),
        ):
            result = main()
            assert result == 0

    def test_main_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import runpy

        def _raise(*_args: object, **_kwargs: object) -> int:
            raise SystemExit(0)

        monkeypatch.setattr("mytools.core.utils.run_main_loop", _raise)
        with pytest.raises(SystemExit):
            runpy.run_module("mytools.web.rtloverride", run_name="__main__")


class TestVariantFunction:
    """Testes para _test_variant."""

    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock_client = AsyncMock()
        with patch(
            "mytools.web.rtloverride.fetch", new_callable=AsyncMock
        ) as mock_fetch:
            mock_fetch.side_effect = [
                (200, {}, b"hello", {}),
                (200, {}, b"world", {}),
            ]
            b_status, t_status, b_size, t_size, details = await _test_variant(
                mock_client,
                "https://target.com/\u202epath",
                "https://target.com/path",
                5.0,
            )
        assert b_status == 200
        assert t_status == 200
        assert b_size == 5
        assert t_size == 5
        assert details == ""

    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        mock_client = AsyncMock()
        with patch(
            "mytools.web.rtloverride.fetch", new_callable=AsyncMock
        ) as mock_fetch:
            mock_fetch.side_effect = [
                FetchError("https://target.com", 3, httpx.ConnectError("boom"))
            ]
            result = await _test_variant(
                mock_client,
                "https://target.com/\u202epath",
                "https://target.com/path",
                5.0,
            )
        assert result == (
            0,
            0,
            0,
            0,
            "baseline error: falha ao acessar https://target.com apos 3 tentativa(s): boom",
        )

    @pytest.mark.asyncio
    async def test_test_error(self) -> None:
        mock_client = AsyncMock()
        with patch(
            "mytools.web.rtloverride.fetch", new_callable=AsyncMock
        ) as mock_fetch:
            mock_fetch.side_effect = [
                (200, {}, b"hello", {}),
                FetchError(
                    "https://target.com/\u202epath", 3, httpx.ConnectError("boom")
                ),
            ]
            b_status, t_status, b_size, _t_size, details = await _test_variant(
                mock_client,
                "https://target.com/\u202epath",
                "https://target.com/path",
                5.0,
            )
            assert b_status == 200
            assert t_status == 0
            assert b_size == 5
            assert details.startswith("test error")


class TestAsyncRunOnce:
    """Testes para _async_run_once."""

    def _make_args(self, **overrides: object) -> argparse.Namespace:
        defaults: dict[str, object] = {
            "url": "https://target.com/path",
            "mode": "scan",
            "type": "rtl",
            "user_agent": "ua",
            "timeout": 5.0,
            "techniques": None,
            "output": None,
        }
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    @pytest.mark.asyncio
    async def test_detect_mode_found(self, capsys: pytest.CaptureFixture[str]) -> None:
        args = self._make_args(url="https://target.com/\u202e", mode="detect")
        with patch("mytools.web.rtloverride.init_scanner", return_value=False):
            code = await _async_run_once(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "invisiveis" in captured.out

    @pytest.mark.asyncio
    async def test_detect_mode_clean(self, capsys: pytest.CaptureFixture[str]) -> None:
        args = self._make_args(url="https://target.com", mode="detect")
        with patch("mytools.web.rtloverride.init_scanner", return_value=False):
            code = await _async_run_once(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "Nenhum caractere invisivel" in captured.out

    @pytest.mark.asyncio
    async def test_gen_mode(self, capsys: pytest.CaptureFixture[str]) -> None:
        args = self._make_args(url="https://target.com", mode="gen")
        with patch("mytools.web.rtloverride.init_scanner", return_value=False):
            code = await _async_run_once(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "variante" in captured.out

    @pytest.mark.asyncio
    async def test_scan_mode_vulnerable(
        self, capsys: pytest.CaptureFixture[str], tmp_path
    ) -> None:
        async def fake_fetch(client: object, url: str, timeout: float = 5.0) -> tuple:
            if url == "https://target.com/path":
                return (200, {}, b"x" * 100, {})
            return (200, {}, b"x" * 500, {})

        mock_client = AsyncMock()
        args = self._make_args(
            output=str(tmp_path / "out.json"),
        )
        with (
            patch("mytools.web.rtloverride.init_scanner", return_value=False),
            patch(
                "mytools.web.rtloverride.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.rtloverride.fetch", new_callable=AsyncMock
            ) as mock_fetch,
        ):
            mock_fetch.side_effect = fake_fetch
            code = await _async_run_once(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "VULNERAVEL" in captured.out
        assert (tmp_path / "out.json").exists()
        mock_client.aclose.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_scan_mode_baseline_error(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        async def fake_fetch(client: object, url: str, timeout: float = 5.0) -> tuple:
            raise FetchError(url, 3, httpx.ConnectError("boom"))

        mock_client = AsyncMock()
        args = self._make_args()
        with (
            patch("mytools.web.rtloverride.init_scanner", return_value=False),
            patch(
                "mytools.web.rtloverride.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.rtloverride.fetch", new_callable=AsyncMock
            ) as mock_fetch,
        ):
            mock_fetch.side_effect = fake_fetch
            code = await _async_run_once(args)
        assert code == 1
        captured = capsys.readouterr()
        assert "Erro no baseline" in captured.out

    @pytest.mark.asyncio
    async def test_scan_mode_status_changed_with_filter(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        async def fake_fetch(client: object, url: str, timeout: float = 5.0) -> tuple:
            if url == "https://target.com/path":
                return (200, {}, b"x" * 100, {})
            return (500, {}, b"x" * 100, {})

        mock_client = AsyncMock()
        args = self._make_args(techniques=["rlo"])
        with (
            patch("mytools.web.rtloverride.init_scanner", return_value=False),
            patch(
                "mytools.web.rtloverride.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.rtloverride.fetch", new_callable=AsyncMock
            ) as mock_fetch,
        ):
            mock_fetch.side_effect = fake_fetch
            code = await _async_run_once(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "VULNERAVEL" in captured.out
        assert "status 200 -> 500" in captured.out

    @pytest.mark.asyncio
    async def test_scan_mode_variant_error(self) -> None:
        async def fake_fetch(client: object, url: str, timeout: float = 5.0) -> tuple:
            if url == "https://target.com/path":
                return (200, {}, b"x" * 100, {})
            raise FetchError(url, 3, httpx.ConnectError("boom"))

        mock_client = AsyncMock()
        args = self._make_args(output=None)
        with (
            patch("mytools.web.rtloverride.init_scanner", return_value=False),
            patch(
                "mytools.web.rtloverride.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.rtloverride.fetch", new_callable=AsyncMock
            ) as mock_fetch,
        ):
            mock_fetch.side_effect = fake_fetch
            code = await _async_run_once(args)
        assert code == 0

    @pytest.mark.asyncio
    async def test_scan_mode_blocked_quiet(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        async def fake_fetch(client: object, url: str, timeout: float = 5.0) -> tuple:
            return (200, {}, b"x" * 100, {})

        mock_client = AsyncMock()
        args = self._make_args(output=None)
        with (
            patch("mytools.web.rtloverride.init_scanner", return_value=True),
            patch(
                "mytools.web.rtloverride.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.rtloverride.fetch", new_callable=AsyncMock
            ) as mock_fetch,
        ):
            mock_fetch.side_effect = fake_fetch
            code = await _async_run_once(args)
        assert code == 0
        captured = capsys.readouterr()
        assert "VULNERAVEL" not in captured.out


class TestRunOnce:
    """Testes para run_once."""

    def test_runs_async_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_async = AsyncMock(return_value=0)
        monkeypatch.setattr(rtl_module, "_async_run_once", mock_async)
        args = argparse.Namespace()
        assert run_once(args) == 0
        mock_async.assert_called_once_with(args)


class TestZeroWidthChars:
    """Testes para _ZERO_WIDTH_CHARS."""

    def test_has_zwsp(self) -> None:
        assert "zwsp" in _ZERO_WIDTH_CHARS
        assert _ZERO_WIDTH_CHARS["zwsp"] == "\u200b"

    def test_has_zwnj(self) -> None:
        assert "zwnj" in _ZERO_WIDTH_CHARS

    def test_has_zwj(self) -> None:
        assert "zwj" in _ZERO_WIDTH_CHARS

    def test_has_bom(self) -> None:
        assert "bom" in _ZERO_WIDTH_CHARS
        assert _ZERO_WIDTH_CHARS["bom"] == "\ufeff"


class TestGenerateVariantsZeroWidth:
    """Testes para _generate_variants com zero-width."""

    def test_zero_width_type(self) -> None:
        variants = _generate_variants("https://example.com/a/b", char_type="zero-width")
        assert len(variants) > 0

    def test_zero_width_contains_zwsp(self) -> None:
        variants = _generate_variants("https://example.com/a/b", char_type="zero-width")
        assert any("\u200b" in v[3] for v in variants)

    def test_all_type(self) -> None:
        variants = _generate_variants("https://example.com/a/b", char_type="all")
        assert len(variants) > 10

    def test_all_type_has_both(self) -> None:
        variants = _generate_variants("https://example.com/a/b", char_type="all")
        has_rtl = any("\u202e" in v[3] for v in variants)
        has_zw = any("\u200b" in v[3] for v in variants)
        assert has_rtl and has_zw


class TestDetectRTLZeroWidth:
    """Testes para detect_rtl com zero-width."""

    def test_detects_zwsp(self) -> None:
        found = detect_rtl("hello\u200bworld", char_type="zero-width")
        assert len(found) == 1

    def test_detects_bom(self) -> None:
        found = detect_rtl("test\ufeffdata", char_type="zero-width")
        assert len(found) == 1

    def test_all_type_detects_both(self) -> None:
        found = detect_rtl("\u202e\u200b", char_type="all")
        assert len(found) == 2


class TestMakeDisplayZeroWidth:
    """Testes para _make_display com zero-width."""

    def test_removes_zwsp(self) -> None:
        result = _make_display("hello\u200bworld")
        assert result == "helloworld"

    def test_removes_bom(self) -> None:
        result = _make_display("test\ufeffdata")
        assert result == "testdata"

    def test_removes_mixed(self) -> None:
        result = _make_display("\u202e\u200bhello")
        assert result == "hello"


@pytest.mark.smoke
class TestBuildParserType:
    """Testes para build_parser --type."""

    def test_default_type_rtl(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.type == "rtl"

    def test_type_zero_width(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--type", "zero-width"])
        assert args.type == "zero-width"

    def test_type_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--type", "all"])
        assert args.type == "all"

    def test_type_combining(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--type", "combining"])
        assert args.type == "combining"


class TestCombiningChars:
    """Testes para _COMBINING_CHARS."""

    def test_has_grave(self) -> None:
        assert "grave" in _COMBINING_CHARS
        assert _COMBINING_CHARS["grave"] == "\u0300"

    def test_has_acute(self) -> None:
        assert "acute" in _COMBINING_CHARS
        assert _COMBINING_CHARS["acute"] == "\u0301"

    def test_has_circumflex(self) -> None:
        assert "circumflex" in _COMBINING_CHARS

    def test_has_tilde(self) -> None:
        assert "tilde" in _COMBINING_CHARS


class TestInsertCombining:
    """Testes para _insert_combining."""

    def test_inserts_between_letters(self) -> None:
        result = _insert_combining("https://example.com/admin", "\u0300")
        assert "\u0300" in result

    def test_preserves_non_alpha(self) -> None:
        result = _insert_combining("https://example.com/123", "\u0300")
        assert "\u200b" not in result
        assert "/123" in result

    def test_empty_path(self) -> None:
        result = _insert_combining("https://example.com", "\u0300")
        assert isinstance(result, str)


class TestGenerateVariantsCombining:
    """Testes para _generate_variants com combining."""

    def test_combining_type(self) -> None:
        variants = _generate_variants(
            "https://example.com/admin", char_type="combining"
        )
        assert len(variants) > 0

    def test_combining_inserts_marks(self) -> None:
        variants = _generate_variants(
            "https://example.com/admin", char_type="combining"
        )
        assert any("\u0300" in v[3] for v in variants)

    def test_all_type_includes_combining(self) -> None:
        variants = _generate_variants("https://example.com/admin", char_type="all")
        has_combining = any("\u0300" in v[3] or "\u0301" in v[3] for v in variants)
        assert has_combining


class TestGenerateVariantsEdgeCases:
    """Testes para _generate_variants com entradas incomuns."""

    def test_unknown_char_type_returns_empty(self) -> None:
        variants = _generate_variants("https://example.com", char_type="bogus")
        assert variants == []

    def test_combining_no_alpha_returns_empty(self) -> None:
        variants = _generate_variants(
            "http://1.2.3.4:8080/123/456?789", char_type="combining"
        )
        assert variants == []


class TestDetectRTLCombining:
    """Testes para detect_rtl com combining."""

    def test_detects_grave(self) -> None:
        found = detect_rtl("a\u0300dmin", char_type="combining")
        assert len(found) == 1

    def test_detects_multiple(self) -> None:
        found = detect_rtl("a\u0300d\u0301min", char_type="combining")
        assert len(found) == 2

    def test_all_type_detects_combining(self) -> None:
        found = detect_rtl("\u202ea\u0300", char_type="all")
        assert len(found) == 2
