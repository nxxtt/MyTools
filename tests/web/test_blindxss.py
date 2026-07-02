#!/usr/bin/env python3
"""Testes unitarios do modulo de Blind XSS via callback."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.blindxss import (
    _ATTR_PAYLOADS,
    _BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    _EVENT_PAYLOADS,
    _HEADER_PAYLOADS,
    _INPUT_PAYLOADS,
    _SENSITIVE_PATHS,
    BlindXSSAttempt,
    BlindXSSResult,
    _check_xss_response,
    _generate_callback,
    _test_attr,
    _test_baseline,
    _test_bypass,
    _test_event,
    _test_header,
    _test_input,
    build_parser,
    print_results,
)


# ─── Category Map ────────────────────────────────────────────────────────────
class TestCategoryMap:
    def test_has_five_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 5

    def test_categories_are_correct(self) -> None:
        expected = {"input", "header", "attr", "event", "bypass"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_all_categories_have_payloads(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) > 0, f"Categoria {cat} vazia"

    def test_all_categories_have_5_techniques(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) == 5, f"Categoria {cat} tem {len(techs)} tecnicas"


# ─── Payload Lists ───────────────────────────────────────────────────────────
class TestPayloadLists:
    def test_input_payloads_count(self) -> None:
        assert len(_INPUT_PAYLOADS) == 5

    def test_header_payloads_count(self) -> None:
        assert len(_HEADER_PAYLOADS) == 5

    def test_attr_payloads_count(self) -> None:
        assert len(_ATTR_PAYLOADS) == 5

    def test_event_payloads_count(self) -> None:
        assert len(_EVENT_PAYLOADS) == 5

    def test_bypass_payloads_count(self) -> None:
        assert len(_BYPASS_PAYLOADS) == 5

    def test_sensitive_paths(self) -> None:
        assert len(_SENSITIVE_PATHS) == 10


# ─── Input Payloads ──────────────────────────────────────────────────────────
class TestInputPayloads:
    def test_all_have_callback_placeholder(self) -> None:
        for _, payload, _ in _INPUT_PAYLOADS:
            assert "{{callback}}" in payload

    def test_all_have_xss_tags(self) -> None:
        for _, payload, _ in _INPUT_PAYLOADS:
            assert any(tag in payload.lower() for tag in ["<script", "<img", "<svg", "<iframe", "<details"])


# ─── Header Payloads ─────────────────────────────────────────────────────────
class TestHeaderPayloads:
    def test_all_have_header_name(self) -> None:
        for _, header_name, _, _ in _HEADER_PAYLOADS:
            assert len(header_name) > 0

    def test_all_have_callback_placeholder(self) -> None:
        for _, _, payload, _ in _HEADER_PAYLOADS:
            assert "{{callback}}" in payload


# ─── Attr Payloads ───────────────────────────────────────────────────────────
class TestAttrPayloads:
    def test_all_have_callback_placeholder(self) -> None:
        for _, payload, _ in _ATTR_PAYLOADS:
            assert "{{callback}}" in payload

    def test_all_have_event_handler(self) -> None:
        for _, payload, _ in _ATTR_PAYLOADS:
            assert any(evt in payload for evt in ["onerror", "onfocus", "onmouseover", "onclick", "onload"])


# ─── Event Payloads ──────────────────────────────────────────────────────────
class TestEventPayloads:
    def test_all_have_callback_placeholder(self) -> None:
        for _, payload, _ in _EVENT_PAYLOADS:
            assert "{{callback}}" in payload

    def test_all_have_event_handler(self) -> None:
        for _, payload, _ in _EVENT_PAYLOADS:
            assert any(evt in payload for evt in ["onerror", "onload", "onfocus", "onmouseover", "onstart"])


# ─── Bypass Payloads ─────────────────────────────────────────────────────────
class TestBypassPayloads:
    def test_all_have_callback_placeholder(self) -> None:
        for _, payload, _ in _BYPASS_PAYLOADS:
            assert "{{callback}}" in payload


# ─── Generate Callback ───────────────────────────────────────────────────────
class TestGenerateCallback:
    def test_generates_unique_urls(self) -> None:
        url1 = _generate_callback("https://hook.example.com")
        url2 = _generate_callback("https://hook.example.com")
        assert url1 != url2

    def test_preserves_base_url(self) -> None:
        url = _generate_callback("https://hook.example.com")
        assert url.startswith("https://hook.example.com/xss-callback/")

    def test_strips_trailing_slash(self) -> None:
        url = _generate_callback("https://hook.example.com/")
        assert url.startswith("https://hook.example.com/xss-callback/")


# ─── Check XSS Response ─────────────────────────────────────────────────────
class TestCheckXSSResponse:
    def test_script_in_response(self) -> None:
        assert _check_xss_response(b"<script>alert(1)</script>", 200) is True

    def test_onerror_in_response(self) -> None:
        assert _check_xss_response(b'<img src=x onerror="alert(1)">', 200) is True

    def test_no_xss_indicators(self) -> None:
        assert _check_xss_response(b"hello world", 200) is False

    def test_0_status(self) -> None:
        assert _check_xss_response(b"", 0) is False

    def test_empty_body(self) -> None:
        assert _check_xss_response(b"", 200) is False


# ─── Dataclasses ─────────────────────────────────────────────────────────────
class TestBlindXSSAttempt:
    def test_frozen(self) -> None:
        a = BlindXSSAttempt(
            technique="test", category="input", field="input",
            payload="<script>", callback_url="https://hook.example.com/xss/123",
            method="POST", status_baseline=200, status_test=200,
            size_baseline=100, size_test=200, status_changed=True,
            size_changed=True, vulnerable=True, details="test", error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "other"  # type: ignore[misc]

    def test_slots(self) -> None:
        a = BlindXSSAttempt(
            technique="test", category="input", field="input",
            payload="<script>", callback_url="https://hook.example.com/xss/123",
            method="POST", status_baseline=200, status_test=200,
            size_baseline=100, size_test=200, status_changed=True,
            size_changed=True, vulnerable=True, details="test", error="",
        )
        assert not hasattr(a, "__dict__")


class TestBlindXSSResult:
    def test_frozen(self) -> None:
        r = BlindXSSResult(
            target="https://test.com", webhook_url="https://hook.example.com",
            baseline_status=200, baseline_size=100, tls=True, attempts=[],
            vulnerable_techniques=[], blocked_techniques=[],
            issues=[], overall_status="safe",
        )
        with pytest.raises(AttributeError):
            r.target = "other"  # type: ignore[misc]


# ─── Test Baseline ───────────────────────────────────────────────────────────
class TestBaseline:
    @pytest.mark.asyncio
    async def test_baseline_success(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        result = await _test_baseline(mock_client, "https://test.com/admin")
        assert result == (200, 2, b"ok")

    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("fail"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        result = await _test_baseline(mock_client, "https://test.com/admin")
        assert result == (0, 0, b"")


# ─── Test Input ──────────────────────────────────────────────────────────────
class TestInput:
    @pytest.mark.asyncio
    async def test_vulnerable_input(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<script>echo</script>"
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_input(
            mock_client, "https://test.com", "https://hook.example.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.category == "input" for r in results)

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_input(
            mock_client, "https://test.com", "https://hook.example.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.error for r in results)


# ─── Test Header ─────────────────────────────────────────────────────────────
class TestHeader:
    @pytest.mark.asyncio
    async def test_vulnerable_header(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<script>echo</script>"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_header(
            mock_client, "https://test.com", "https://hook.example.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.category == "header" for r in results)


# ─── Test Attr ───────────────────────────────────────────────────────────────
class TestAttr:
    @pytest.mark.asyncio
    async def test_vulnerable_attr(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"onerror detected"
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_attr(
            mock_client, "https://test.com", "https://hook.example.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.category == "attr" for r in results)


# ─── Test Event ──────────────────────────────────────────────────────────────
class TestEvent:
    @pytest.mark.asyncio
    async def test_vulnerable_event(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"onload detected"
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_event(
            mock_client, "https://test.com", "https://hook.example.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.category == "event" for r in results)


# ─── Test Bypass ─────────────────────────────────────────────────────────────
class TestBypass:
    @pytest.mark.asyncio
    async def test_vulnerable_bypass(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"script detected"
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_bypass(
            mock_client, "https://test.com", "https://hook.example.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.category == "bypass" for r in results)


# ─── Print Results ───────────────────────────────────────────────────────────
class TestPrintResults:
    def test_vulnerable_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = BlindXSSResult(
            target="https://test.com", webhook_url="https://hook.example.com",
            baseline_status=200, baseline_size=100, tls=True,
            attempts=[BlindXSSAttempt(
                technique="script_input", category="input", field="input",
                payload="<script>fetch(...)</script>",
                callback_url="https://hook.example.com/xss/abc123",
                method="POST", status_baseline=200, status_test=200,
                size_baseline=100, size_test=200, status_changed=False,
                size_changed=True, vulnerable=True,
                details="path=/contact", error="",
            )],
            vulnerable_techniques=["script_input"],
            blocked_techniques=[], issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Vulnerabilidades detectadas" in output
        assert "script_input" in output

    def test_no_vulns_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = BlindXSSResult(
            target="https://test.com", webhook_url="https://hook.example.com",
            baseline_status=200, baseline_size=100, tls=True, attempts=[],
            vulnerable_techniques=[], blocked_techniques=[],
            issues=[], overall_status="safe",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Nenhum Blind XSS detectado" in output

    def test_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = BlindXSSResult(
            target="https://test.com", webhook_url="https://hook.example.com",
            baseline_status=200, baseline_size=100, tls=True, attempts=[],
            vulnerable_techniques=[], blocked_techniques=[],
            issues=["Nenhum teste retornou resultado claro"],
            overall_status="unknown",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Observacoes" in output


# ─── Build Parser ────────────────────────────────────────────────────────────
class TestBuildParser:
    def test_has_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "--webhook", "https://hook.example.com"])
        assert args.url == "https://test.com"

    def test_has_webhook(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "--webhook", "https://hook.example.com"])
        assert args.webhook == "https://hook.example.com"

    def test_webhook_required(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["https://test.com"])

    def test_has_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "--webhook", "https://hook.example.com", "-c", "input"])
        assert args.category == "input"

    def test_default_category_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "--webhook", "https://hook.example.com"])
        assert args.category == "all"

    def test_all_categories(self) -> None:
        parser = build_parser()
        for cat in ["all", "input", "header", "attr", "event", "bypass"]:
            args = parser.parse_args(["https://test.com", "--webhook", "https://hook.example.com", "-c", cat])
            assert args.category == cat


# ─── Run Once ────────────────────────────────────────────────────────────────
class TestRunOnce:
    @patch("mytools.web.blindxss.run_scan")
    def test_run_once(self, mock_run: MagicMock) -> None:
        mock_run.return_value = 0
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "--webhook", "https://hook.example.com"])
        from mytools.web.blindxss import run_once
        result = run_once(args)
        assert result == 0
        mock_run.assert_called_once()
