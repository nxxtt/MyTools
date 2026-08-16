#!/usr/bin/env python3
"""Testes unitarios do modulo de SSTI Detection."""

import argparse
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import mytools.web.sstidetect as sstidetect_module
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
    run_once,
    run_scan,
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

    def test_has_handlebars_math(self) -> None:
        assert any("handlebars_math" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_go_math(self) -> None:
        assert any("go_math" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_blade_math(self) -> None:
        assert any("blade_math" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_razor_math(self) -> None:
        assert any("razor_math" in p[0] for p in _DETECT_PAYLOADS)

    def test_count(self) -> None:
        assert len(_DETECT_PAYLOADS) == 23


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

    def test_has_handlebars_rce(self) -> None:
        assert any("handlebars_rce" in p[0] for p in _EXPLOIT_PAYLOADS)

    def test_has_go_env(self) -> None:
        assert any("go_env" in p[0] for p in _EXPLOIT_PAYLOADS)

    def test_has_blade_config(self) -> None:
        assert any("blade_config" in p[0] for p in _EXPLOIT_PAYLOADS)

    def test_has_razor_process(self) -> None:
        assert any("razor_process" in p[0] for p in _EXPLOIT_PAYLOADS)

    def test_count(self) -> None:
        assert len(_EXPLOIT_PAYLOADS) == 10


class TestBypassPayloads:
    """Testes para _BYPASS_PAYLOADS."""

    def test_has_jinja2_space(self) -> None:
        assert any("jinja2_space" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_jinja2_hex(self) -> None:
        assert any("jinja2_hex" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_twig_comment(self) -> None:
        assert any("twig_comment" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_handlebars_space(self) -> None:
        assert any("handlebars_space" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_go_space(self) -> None:
        assert any("go_space" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_blade_space(self) -> None:
        assert any("blade_space" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_razor_space(self) -> None:
        assert any("razor_space" in p[0] for p in _BYPASS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BYPASS_PAYLOADS) == 15


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

    def test_handlebars(self) -> None:
        assert _extract_engine("handlebars_math") == "handlebars"

    def test_go(self) -> None:
        assert _extract_engine("go_math") == "go"

    def test_blade(self) -> None:
        assert _extract_engine("blade_math") == "blade"

    def test_razor(self) -> None:
        assert _extract_engine("razor_math") == "razor"


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

    def test_digit_word_boundary(self) -> None:
        with patch("re.search", return_value=MagicMock()) as mock_search:
            assert _check_response(b"abc", "49") is True
        mock_search.assert_any_call(r"\b49\b", "abc")

    def test_digit_not_expected_value(self) -> None:
        assert _check_response(b"abc", "123") is False

    def test_digit_word_boundary_no_match(self) -> None:
        assert _check_response(b"abc", "49") is False

    def test_digit_value_error(self) -> None:
        assert _check_response(b"abc", "\u00b2") is False

    def test_digit_not_part_of_bigger_number(self) -> None:
        assert _check_response(b"value 149 end", "49") is False

    def test_digit_not_part_of_word(self) -> None:
        assert _check_response(b"pizza2slices", "2") is False

    def test_standalone_digit_still_matches(self) -> None:
        assert _check_response(b"result: 49", "49") is True

    def test_class_not_substring_of_word(self) -> None:
        assert _check_response(b"subclassing a config", "class") is False

    def test_class_standalone_word_matches(self) -> None:
        assert _check_response(b"a class of users", "class") is True

    def test_long_unique_word_uses_substring(self) -> None:
        assert _check_response(b"abc handlebars_xyz", "handlebars") is True

    def test_empty_expected(self) -> None:
        assert _check_response(b"result: 49", "") is False


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
            engine_detected="",
            vulnerable=False,
            details="d",
            error="",
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
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        assert len(attempts) > 0
        assert all(isinstance(a, SSTIAttempt) for a in attempts)

    @pytest.mark.asyncio
    async def test_error_handled(self) -> None:
        import httpx

        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_param_ssti(
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        assert len(attempts) > 0
        assert any(a.error for a in attempts)

    @pytest.mark.asyncio
    async def test_second_order_confirmed(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"result: 49"
        client.get = AsyncMock(return_value=resp)

        with patch(
            "mytools.web.sstidetect.verify_positive",
            new_callable=AsyncMock,
            return_value=(True, "56"),
        ):
            attempts = await _test_param_ssti(
                client,
                "https://example.com",
                (200, 100, b"ok"),
            )
        vuln = [a for a in attempts if a.vulnerable]
        assert len(vuln) > 0
        assert vuln[0].engine_detected == "jinja2"
        assert vuln[0].exploit == "{{7*7}}"

    @pytest.mark.asyncio
    async def test_second_order_no_verify_payload(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"result: 49"
        client.get = AsyncMock(return_value=resp)

        with patch("mytools.web.sstidetect.get_verify_payload", return_value=None):
            attempts = await _test_param_ssti(
                client,
                "https://example.com",
                (200, 100, b"ok"),
            )
        vuln = [a for a in attempts if a.vulnerable]
        assert len(vuln) > 0
        assert all("2nd-order" not in a.details for a in vuln)

    @pytest.mark.asyncio
    async def test_page_with_config_class_text_not_flagged(self) -> None:
        page = b"<html>app configuration class settings</html>"
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = page
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_param_ssti(
            client,
            "https://example.com",
            (200, 100, page),
        )
        assert not any(a.vulnerable for a in attempts)


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
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        assert len(attempts) > 0

    @pytest.mark.asyncio
    async def test_error_handled(self) -> None:
        import httpx

        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_header_ssti(
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        assert len(attempts) > 0
        assert any(a.error for a in attempts)

    @pytest.mark.asyncio
    async def test_page_with_config_class_text_not_flagged(self) -> None:
        page = b"<html>app configuration class settings</html>"
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = page
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_header_ssti(
            client,
            "https://example.com",
            (200, 100, page),
        )
        assert not any(a.vulnerable for a in attempts)

    @pytest.mark.asyncio
    async def test_second_order_confirmed(self) -> None:
        detect_resp = MagicMock()
        detect_resp.status_code = 200
        detect_resp.content = b"result: 49"
        verify_resp = MagicMock()
        verify_resp.status_code = 200
        verify_resp.content = b"verify 56"

        def fake_get(
            url: str,
            headers: dict[str, str] | None = None,
            follow_redirects: bool = False,
        ) -> MagicMock:
            if headers and any("7*8" in str(v) for v in headers.values()):
                return verify_resp
            return detect_resp

        client = AsyncMock()
        client.get = AsyncMock(side_effect=fake_get)

        attempts = await _test_header_ssti(
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        vuln = [a for a in attempts if a.vulnerable]
        assert len(vuln) > 0
        assert all(a.engine_detected for a in vuln)

    @pytest.mark.asyncio
    async def test_second_order_no_verify_payload(self) -> None:
        detect_resp = MagicMock()
        detect_resp.status_code = 200
        detect_resp.content = b"result: 49"
        client = AsyncMock()
        client.get = AsyncMock(return_value=detect_resp)

        with patch("mytools.web.sstidetect.get_verify_payload", return_value=None):
            attempts = await _test_header_ssti(
                client,
                "https://example.com",
                (200, 100, b"ok"),
            )
        vuln = [a for a in attempts if a.vulnerable]
        assert len(vuln) > 0
        assert all("2nd-order" not in a.details for a in vuln)

    @pytest.mark.asyncio
    async def test_second_order_verify_request_error(self) -> None:
        import httpx

        detect_resp = MagicMock()
        detect_resp.status_code = 200
        detect_resp.content = b"result: 49"

        def fake_get(
            url: str,
            headers: dict[str, str] | None = None,
            follow_redirects: bool = False,
        ) -> MagicMock:
            if headers and any("7*8" in str(v) for v in headers.values()):
                raise httpx.RequestError("boom")
            return detect_resp

        client = AsyncMock()
        client.get = AsyncMock(side_effect=fake_get)

        attempts = await _test_header_ssti(
            client,
            "https://example.com",
            (200, 100, b"ok"),
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
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        assert len(attempts) > 0

    @pytest.mark.asyncio
    async def test_error_handled(self) -> None:
        import httpx

        client = AsyncMock()
        client.post = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_body_ssti(
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        assert len(attempts) > 0
        assert all(a.error for a in attempts)

    @pytest.mark.asyncio
    async def test_page_with_config_class_text_not_flagged(self) -> None:
        page = b"<html>app configuration class settings</html>"
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = page
        client.post = AsyncMock(return_value=resp)

        attempts = await _test_body_ssti(
            client,
            "https://example.com",
            (200, 100, page),
        )
        assert not any(a.vulnerable for a in attempts)

    @pytest.mark.asyncio
    async def test_second_order_confirmed(self) -> None:
        detect_resp = MagicMock()
        detect_resp.status_code = 200
        detect_resp.content = b"result: 49"
        verify_resp = MagicMock()
        verify_resp.status_code = 200
        verify_resp.content = b"verify 56"

        def fake_post(
            url: str,
            json: dict[str, str] | None = None,
            data: dict[str, str] | None = None,
            follow_redirects: bool = False,
        ) -> MagicMock:
            body = json or data or {}
            if any("7*8" in str(v) for v in body.values()):
                return verify_resp
            return detect_resp

        client = AsyncMock()
        client.post = AsyncMock(side_effect=fake_post)

        attempts = await _test_body_ssti(
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        vuln = [a for a in attempts if a.vulnerable]
        assert len(vuln) > 0
        assert all(a.engine_detected for a in vuln)

    @pytest.mark.asyncio
    async def test_second_order_no_verify_payload(self) -> None:
        detect_resp = MagicMock()
        detect_resp.status_code = 200
        detect_resp.content = b"result: 49"
        client = AsyncMock()
        client.post = AsyncMock(return_value=detect_resp)

        with patch("mytools.web.sstidetect.get_verify_payload", return_value=None):
            attempts = await _test_body_ssti(
                client,
                "https://example.com",
                (200, 100, b"ok"),
            )
        vuln = [a for a in attempts if a.vulnerable]
        assert len(vuln) > 0
        assert all("2nd-order" not in a.details for a in vuln)

    @pytest.mark.asyncio
    async def test_second_order_verify_request_error(self) -> None:
        import httpx

        detect_resp = MagicMock()
        detect_resp.status_code = 200
        detect_resp.content = b"result: 49"

        def fake_post(
            url: str,
            json: dict[str, str] | None = None,
            data: dict[str, str] | None = None,
            follow_redirects: bool = False,
        ) -> MagicMock:
            body = json or data or {}
            if any("7*8" in str(v) for v in body.values()):
                raise httpx.RequestError("boom")
            return detect_resp

        client = AsyncMock()
        client.post = AsyncMock(side_effect=fake_post)

        attempts = await _test_body_ssti(
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        assert len(attempts) > 0


class TestTestExploit:
    """Testes para _test_exploit."""

    @pytest.mark.asyncio
    async def test_returns_empty_if_no_engines(self) -> None:
        client = AsyncMock()
        attempts = await _test_exploit(
            client,
            "https://example.com",
            (200, 100, b"ok"),
            [],
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
            client,
            "https://example.com",
            (200, 100, b"ok"),
            ["jinja2"],
        )
        assert len(attempts) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx

        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_exploit(
            client,
            "https://example.com",
            (200, 100, b"ok"),
            ["jinja2"],
        )
        assert len(attempts) > 0
        assert all(a.error for a in attempts)


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
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        assert len(attempts) == 15

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx

        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_bypass(
            client,
            "https://example.com",
            (200, 100, b"ok"),
        )
        assert len(attempts) == 15
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

    def test_vulnerable_with_attempt(self, capsys: pytest.CaptureFixture[str]) -> None:
        import re

        attempt = SSTIAttempt(
            technique="jinja2_math",
            category="detect",
            url="https://example.com",
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
            exploit="{{7*7}}",
            tool="Tplmap",
        )
        result = SSTIResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=1000,
            tls=True,
            attempts=[attempt],
            vulnerable_engines=["jinja2"],
            blocked_techniques=[],
            issues=["VULN: jinja2_math"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        clean = re.sub(r"\033\[[0-9;]*m", "", captured.out)
        assert "JINJA2" in clean
        assert "Severidade: ALTA" in clean

    def test_with_errors(self, capsys: pytest.CaptureFixture[str]) -> None:
        import re

        attempt = SSTIAttempt(
            technique="jinja2_math",
            category="detect",
            url="https://example.com",
            payload="{{7*7}}",
            status_baseline=200,
            status_test=0,
            size_baseline=100,
            size_test=0,
            status_changed=False,
            size_changed=False,
            engine_detected="",
            vulnerable=False,
            details="",
            error="Connection refused",
        )
        result = SSTIResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=1000,
            tls=True,
            attempts=[attempt],
            vulnerable_engines=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        captured = capsys.readouterr()
        clean = re.sub(r"\033\[[0-9;]*m", "", captured.out)
        assert "Erros (1)" in clean
        assert "Connection refused" in clean


def _make_scan_client() -> AsyncMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.content = b"ok"
    client = AsyncMock()
    client.get.return_value = resp
    client.post.return_value = resp
    client.aclose = AsyncMock()
    return client


class TestRunScan:
    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        client = _make_scan_client()
        with (
            patch("mytools.web.sstidetect.create_async_client", return_value=client),
            patch(
                "mytools.web.sstidetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(0, 0, b""),
            ),
        ):
            code = await run_scan("https://example.com", [], 10, 5, None, False)
        assert code == 1
        client.aclose.assert_awaited()

    @pytest.mark.asyncio
    async def test_all_categories_secure(self) -> None:
        client = _make_scan_client()
        with (
            patch("mytools.web.sstidetect.create_async_client", return_value=client),
            patch(
                "mytools.web.sstidetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"ok"),
            ),
            patch(
                "mytools.web.sstidetect._test_param_ssti",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.sstidetect._test_header_ssti",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.sstidetect._test_body_ssti",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.sstidetect._test_bypass",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            code = await run_scan("https://example.com", [], 10, 5, None, False)
        assert code == 0
        client.aclose.assert_awaited()

    @pytest.mark.asyncio
    async def test_exploit_only_no_engines(self) -> None:
        client = _make_scan_client()
        with (
            patch("mytools.web.sstidetect.create_async_client", return_value=client),
            patch(
                "mytools.web.sstidetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"ok"),
            ),
        ):
            code = await run_scan(
                "https://example.com", ["exploit"], 10, 5, None, False
            )
        assert code == 0

    @pytest.mark.asyncio
    async def test_task_exception_skipped(self) -> None:
        client = _make_scan_client()
        with (
            patch("mytools.web.sstidetect.create_async_client", return_value=client),
            patch(
                "mytools.web.sstidetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"ok"),
            ),
            patch(
                "mytools.web.sstidetect._test_param_ssti",
                new_callable=AsyncMock,
                side_effect=RuntimeError("boom"),
            ),
            patch(
                "mytools.web.sstidetect._test_header_ssti",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.sstidetect._test_body_ssti",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.sstidetect._test_bypass",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            code = await run_scan("https://example.com", [], 10, 5, None, False)
        assert code == 0

    @pytest.mark.asyncio
    async def test_vulnerable_with_exploit_and_output(self, tmp_path: Path) -> None:
        client = _make_scan_client()
        vuln = SSTIAttempt(
            technique="jinja2_math",
            category="detect",
            url="https://example.com",
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
            exploit="{{7*7}}",
            tool="Tplmap",
        )
        out = str(tmp_path / "out.json")
        with (
            patch("mytools.web.sstidetect.create_async_client", return_value=client),
            patch(
                "mytools.web.sstidetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"ok"),
            ),
            patch(
                "mytools.web.sstidetect._test_param_ssti",
                new_callable=AsyncMock,
                return_value=[vuln],
            ),
            patch(
                "mytools.web.sstidetect._test_exploit",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            code = await run_scan(
                "https://example.com", ["detect", "exploit"], 10, 5, out, False
            )
        assert code == 1
        assert tmp_path.joinpath("out.json").exists()

    @pytest.mark.asyncio
    async def test_json_output(self) -> None:
        client = _make_scan_client()
        with (
            patch("mytools.web.sstidetect.create_async_client", return_value=client),
            patch(
                "mytools.web.sstidetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 100, b"ok"),
            ),
            patch(
                "mytools.web.sstidetect._test_param_ssti",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.sstidetect._test_header_ssti",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.sstidetect._test_body_ssti",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.sstidetect._test_bypass",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch("mytools.web.sstidetect.print_json") as mock_print,
        ):
            code = await run_scan(
                "https://example.com", [], 10, 5, None, False, json_output=True
            )
        assert code == 0
        mock_print.assert_called_once()


def _run_once_args(**overrides: object) -> argparse.Namespace:
    defaults: dict[str, object] = {
        "url": "https://example.com",
        "category": None,
        "timeout": 10,
        "concurrency": 5,
        "output": None,
        "verbose": False,
        "log_file": None,
        "theme": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestRunOnce:
    def test_no_category(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sstidetect_module, "run_scan", AsyncMock(return_value=0))
        assert run_once(_run_once_args()) == 0

    def test_with_category(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sstidetect_module, "run_scan", AsyncMock(return_value=1))
        assert run_once(_run_once_args(category="detect")) == 1


class TestMainGuard:
    def test_main_guard(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import runpy

        def _raise() -> int:
            raise SystemExit(0)

        monkeypatch.setattr(sstidetect_module, "main", _raise)
        with pytest.raises(SystemExit):
            runpy.run_module("mytools.web.sstidetect", run_name="__main__")


class TestMain:
    """Testes para main."""

    def test_no_url(self) -> None:
        with (
            patch("sys.argv", ["mytools-sstdetect"]),
            patch("mytools.web.sstidetect.run_main_loop", return_value=1) as mock_loop,
        ):
            result = main()
            assert result == 1
            mock_loop.assert_called_once()
