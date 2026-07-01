#!/usr/bin/env python3
"""Testes unitarios do modulo de SSTI Detection."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.sstidetect import (
    _BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    _DETECT_PAYLOADS,
    _EXPLOIT_PAYLOADS,
    _HEADER_NAMES,
    _PARAMS,
    SSTIAttempt,
    SSTIResult,
    _check_exploit,
    _check_response,
    _extract_engine,
    _test_baseline,
    _test_body_ssti,
    _test_bypass,
    _test_exploit,
    _test_header_ssti,
    _test_param_ssti,
    build_parser,
    main,
    print_results,
)


class TestDetectPayloads:
    """Testes para _DETECT_PAYLOADS."""

    def test_has_jinja2_math(self) -> None:
        assert any("jinja2_math" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_jinja2_config(self) -> None:
        assert any("jinja2_config" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_twig_math(self) -> None:
        assert any("twig_math" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_freemarker_math(self) -> None:
        assert any("freemarker_math" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_mako_math(self) -> None:
        assert any("mako_math" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_pebble_math(self) -> None:
        assert any("pebble_math" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_smarty_math(self) -> None:
        assert any("smarty_math" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_erb_math(self) -> None:
        assert any("erb_math" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_velocity_math(self) -> None:
        assert any("velocity_math" in p[0] for p in _DETECT_PAYLOADS)

    def test_count(self) -> None:
        assert len(_DETECT_PAYLOADS) == 15


class TestExploitPayloads:
    """Testes para _EXPLOIT_PAYLOADS."""

    def test_has_jinja2_config(self) -> None:
        assert any("jinja2_config" in p[0] for p in _EXPLOIT_PAYLOADS)

    def test_has_jinja2_os(self) -> None:
        assert any("jinja2_os" in p[0] for p in _EXPLOIT_PAYLOADS)

    def test_has_freemarker_exec(self) -> None:
        assert any("freemarker_exec" in p[0] for p in _EXPLOIT_PAYLOADS)

    def test_has_twig_os(self) -> None:
        assert any("twig_os" in p[0] for p in _EXPLOIT_PAYLOADS)

    def test_count(self) -> None:
        assert len(_EXPLOIT_PAYLOADS) == 6


class TestBypassPayloads:
    """Testes para _BYPASS_PAYLOADS."""

    def test_has_jinja2_space(self) -> None:
        assert any("jinja2_space" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_jinja2_hex(self) -> None:
        assert any("jinja2_hex" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_twig_comment(self) -> None:
        assert any("twig_comment" in p[0] for p in _BYPASS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BYPASS_PAYLOADS) == 11


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_has_detect(self) -> None:
        assert "detect" in _CATEGORY_MAP

    def test_has_exploit(self) -> None:
        assert "exploit" in _CATEGORY_MAP

    def test_has_bypass(self) -> None:
        assert "bypass" in _CATEGORY_MAP

    def test_has_header(self) -> None:
        assert "header" in _CATEGORY_MAP

    def test_has_body(self) -> None:
        assert "body" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 5


class TestHeaderNames:
    """Testes para _HEADER_NAMES."""

    def test_has_ua(self) -> None:
        assert "User-Agent" in _HEADER_NAMES

    def test_has_referer(self) -> None:
        assert "Referer" in _HEADER_NAMES

    def test_count(self) -> None:
        assert len(_HEADER_NAMES) == 6


class TestParams:
    """Testes para _PARAMS."""

    def test_has_name(self) -> None:
        assert "name" in _PARAMS

    def test_has_template(self) -> None:
        assert "template" in _PARAMS

    def test_count(self) -> None:
        assert len(_PARAMS) == 10


class TestExtractEngine:
    """Testes para _extract_engine."""

    def test_jinja2(self) -> None:
        assert _extract_engine("jinja2_math") == "jinja2"

    def test_twig(self) -> None:
        assert _extract_engine("twig_detect") == "twig"

    def test_freemarker(self) -> None:
        assert _extract_engine("freemarker_math") == "freemarker"

    def test_mako(self) -> None:
        assert _extract_engine("mako_math") == "mako"

    def test_unknown(self) -> None:
        assert _extract_engine("other") == "unknown"


class TestCheckResponse:
    """Testes para _check_response."""

    def test_found(self) -> None:
        assert _check_response(b"result: 49", "49") is True

    def test_not_found(self) -> None:
        assert _check_response(b"result: 100", "49") is False

    def test_empty_body(self) -> None:
        assert _check_response(b"", "49") is False

    def test_text_match(self) -> None:
        assert _check_response(b"<html>49</html>", "49") is True

    def test_class_match(self) -> None:
        assert _check_response(b"<class 'str'>", "class") is True

    def test_config_match(self) -> None:
        assert _check_response(b"config items: SECRET_KEY", "SECRET") is True


class TestCheckExploit:
    """Testes para _check_exploit."""

    def test_found(self) -> None:
        found, indicator = _check_exploit(b"uid=33(www-data)", ["uid=", "gid="])
        assert found is True
        assert indicator == "uid="

    def test_not_found(self) -> None:
        found, indicator = _check_exploit(b"error", ["uid=", "gid="])
        assert found is False
        assert indicator == ""

    def test_empty_body(self) -> None:
        found, _ = _check_exploit(b"", ["uid="])
        assert found is False


class TestSSTIAttempt:
    """Testes para SSTIAttempt dataclass."""

    def test_creation(self) -> None:
        att = SSTIAttempt(
            technique="jinja2_math",
            category="detect",
            url="https://example.com?input=%7B%7B7*7%7D%7D",
            payload="{{7*7}}",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=200,
            status_changed=False,
            size_changed=True,
            engine_detected="jinja2",
            vulnerable=True,
            details="Param name: jinja2_math -> ENGINE=jinja2",
            error="",
        )
        assert att.technique == "jinja2_math"
        assert att.vulnerable is True
        assert att.engine_detected == "jinja2"

    def test_frozen(self) -> None:
        att = SSTIAttempt(
            technique="t", category="c", url="u", payload="p",
            status_baseline=200, status_test=200,
            size_baseline=100, size_test=100,
            status_changed=False, size_changed=False,
            engine_detected="", vulnerable=False,
            details="d", error="",
        )
        with pytest.raises(AttributeError):
            att.technique = "new"  # type: ignore[misc]


class TestSSTIResult:
    """Testes para SSTIResult dataclass."""

    def test_creation(self) -> None:
        result = SSTIResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=1000,
            tls=True,
            attempts=[],
            vulnerable_engines=[],
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


class TestTestParamSSTI:
    """Testes para _test_param_ssti."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"result: 49"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_param_ssti(
            client, "https://example.com", (200, 100, b"ok"),
        )
        assert len(attempts) > 0
        assert all(isinstance(a, SSTIAttempt) for a in attempts)

    @pytest.mark.asyncio
    async def test_error_handled(self) -> None:
        import httpx
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_param_ssti(
            client, "https://example.com", (200, 100, b"ok"),
        )
        assert len(attempts) > 0
        assert any(a.error for a in attempts)


class TestTestHeaderSSTI:
    """Testes para _test_header_ssti."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_header_ssti(
            client, "https://example.com", (200, 100, b"ok"),
        )
        assert len(attempts) > 0


class TestTestBodySSTI:
    """Testes para _test_body_ssti."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.post = AsyncMock(return_value=resp)

        attempts = await _test_body_ssti(
            client, "https://example.com", (200, 100, b"ok"),
        )
        assert len(attempts) > 0


class TestTestExploit:
    """Testes para _test_exploit."""

    @pytest.mark.asyncio
    async def test_returns_empty_if_no_engines(self) -> None:
        client = AsyncMock()
        attempts = await _test_exploit(
            client, "https://example.com", (200, 100, b"ok"), [],
        )
        assert len(attempts) == 0

    @pytest.mark.asyncio
    async def test_returns_attempts_for_engine(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"uid=33(www-data)"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_exploit(
            client, "https://example.com", (200, 100, b"ok"), ["jinja2"],
        )
        assert len(attempts) > 0


class TestTestBypass:
    """Testes para _test_bypass."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"49"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_bypass(
            client, "https://example.com", (200, 100, b"ok"),
        )
        assert len(attempts) == 11


class TestBuildParser:
    """Testes para build_parser."""

    def test_has_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "detect"])
        assert args.category == "detect"

    def test_category_choices(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "exploit"])
        assert args.category == "exploit"


class TestPrintResults:
    """Testes para print_results."""

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        import re
        result = SSTIResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=1000,
            tls=True,
            attempts=[],
            vulnerable_engines=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        captured = capsys.readouterr()
        clean = re.sub(r"\033\[[0-9;]*m", "", captured.out)
        assert "SSTI" in clean

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        import re
        result = SSTIResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=1000,
            tls=False,
            attempts=[],
            vulnerable_engines=["jinja2"],
            blocked_techniques=[],
            issues=["VULN: jinja2_math"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        clean = re.sub(r"\033\[[0-9;]*m", "", captured.out)
        assert "JINJA2" in clean


class TestMain:
    """Testes para main."""

    def test_no_url(self) -> None:
        with patch("sys.argv", ["mytools-sstdetect"]), \
             patch("mytools.web.sstidetect.run_main_loop", return_value=1) as mock_loop:
            result = main()
            assert result == 1
            mock_loop.assert_called_once()
