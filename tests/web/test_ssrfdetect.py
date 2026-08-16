#!/usr/bin/env python3
"""Testes unitarios do modulo de SSRF Detection."""

import argparse
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mytools.web.ssrfdetect import (
    _BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    _CLOUD_PAYLOADS,
    _DETECT_PAYLOADS,
    _DETECT_PAYLOADS_DEFAULT,
    _HEADER_PAYLOADS,
    _INTERNAL_PAYLOADS,
    _URL_PARAMS,
    SSRFAttempt,
    SSRFResult,
    _check_ssrf_response,
    _load_ssrf_payloads,
    _test_baseline,
    _test_bypass,
    _test_cloud,
    _test_detect,
    _test_header,
    _test_internal,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
    safe_asyncio_run,
)


def _ns(**overrides: object) -> argparse.Namespace:
    ns = argparse.Namespace(
        url="https://example.com",
        category=None,
        timeout=10,
        concurrency=5,
        output=None,
        verbose=False,
        proxy=None,
        log_file=None,
        json_output=False,
    )
    for key, value in overrides.items():
        setattr(ns, key, value)
    return ns


def _attempt(
    *,
    technique: str = "localhost_80_url",
    vulnerable: bool = False,
    error: str = "",
    details: str = "",
    exploit: str = "",
) -> SSRFAttempt:
    return SSRFAttempt(
        technique=technique,
        category="detect",
        url="https://example.com?url=http://127.0.0.1:80",
        payload="http://127.0.0.1:80",
        status_baseline=200,
        status_test=200,
        size_baseline=1000,
        size_test=1000,
        time_baseline=0.5,
        time_test=0.5,
        status_changed=False,
        size_changed=False,
        time_changed=False,
        vulnerable=vulnerable,
        details=details,
        error=error,
        exploit=exploit,
        tool="curl",
    )


class TestURLParams:
    """Testes para _URL_PARAMS."""

    def test_has_url(self) -> None:
        assert "url" in _URL_PARAMS

    def test_has_link(self) -> None:
        assert "link" in _URL_PARAMS

    def test_has_redirect(self) -> None:
        assert "redirect" in _URL_PARAMS

    def test_has_file(self) -> None:
        assert "file" in _URL_PARAMS

    def test_has_proxy(self) -> None:
        assert "proxy" in _URL_PARAMS

    def test_count(self) -> None:
        assert len(_URL_PARAMS) == 25


class TestDetectPayloads:
    """Testes para _DETECT_PAYLOADS."""

    def test_has_localhost(self) -> None:
        assert any("localhost" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_private_ip(self) -> None:
        assert any("private" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_metadata(self) -> None:
        assert any("metadata" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_decimal_ip(self) -> None:
        assert any("decimal" in p[0] for p in _DETECT_PAYLOADS)

    def test_count(self) -> None:
        assert len(_DETECT_PAYLOADS) == 15


class TestInternalPayloads:
    """Testes para _INTERNAL_PAYLOADS."""

    def test_has_mysql(self) -> None:
        assert any("mysql" in p[0] for p in _INTERNAL_PAYLOADS)

    def test_has_redis(self) -> None:
        assert any("redis" in p[0] for p in _INTERNAL_PAYLOADS)

    def test_has_mongodb(self) -> None:
        assert any("mongodb" in p[0] for p in _INTERNAL_PAYLOADS)

    def test_has_docker(self) -> None:
        assert any("docker" in p[0] for p in _INTERNAL_PAYLOADS)

    def test_count(self) -> None:
        assert len(_INTERNAL_PAYLOADS) == 10


class TestBypassPayloads:
    """Testes para _BYPASS_PAYLOADS."""

    def test_has_decimal(self) -> None:
        assert any("decimal" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_octal(self) -> None:
        assert any("octal" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_ipv6(self) -> None:
        assert any("ipv6" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_url_encoded(self) -> None:
        assert any("encoded" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_at_bypass(self) -> None:
        assert any("at_bypass" in p[0] for p in _BYPASS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BYPASS_PAYLOADS) == 15


class TestCloudPayloads:
    """Testes para _CLOUD_PAYLOADS."""

    def test_has_aws(self) -> None:
        assert any("aws" in p[0] for p in _CLOUD_PAYLOADS)

    def test_has_gcp(self) -> None:
        assert any("gcp" in p[0] for p in _CLOUD_PAYLOADS)

    def test_has_azure(self) -> None:
        assert any("azure" in p[0] for p in _CLOUD_PAYLOADS)

    def test_count(self) -> None:
        assert len(_CLOUD_PAYLOADS) == 10


class TestHeaderPayloads:
    """Testes para _HEADER_PAYLOADS."""

    def test_has_xff(self) -> None:
        assert any("xff" in p[0] for p in _HEADER_PAYLOADS)

    def test_has_x_real_ip(self) -> None:
        assert any("x_real_ip" in p[0] for p in _HEADER_PAYLOADS)

    def test_has_forwarded(self) -> None:
        assert any("forwarded" in p[0] for p in _HEADER_PAYLOADS)

    def test_count(self) -> None:
        assert len(_HEADER_PAYLOADS) == 8


class TestLoadSSRFPayloads:
    def test_non_list_returns_default(self) -> None:
        with patch(
            "mytools.data.load_payloads",
            return_value={"detect_payloads": "not-a-list"},
        ):
            result = _load_ssrf_payloads("detect_payloads", _DETECT_PAYLOADS_DEFAULT)
        assert result == _DETECT_PAYLOADS_DEFAULT

    def test_converts_nested_lists_to_tuples(self) -> None:
        with patch(
            "mytools.data.load_payloads",
            return_value={
                "detect_payloads": [["custom", "http://127.0.0.1", "response"]]
            },
        ):
            result = _load_ssrf_payloads("detect_payloads", _DETECT_PAYLOADS_DEFAULT)
        assert result == [("custom", "http://127.0.0.1", "response")]


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_has_detect(self) -> None:
        assert "detect" in _CATEGORY_MAP

    def test_has_internal(self) -> None:
        assert "internal" in _CATEGORY_MAP

    def test_has_bypass(self) -> None:
        assert "bypass" in _CATEGORY_MAP

    def test_has_cloud(self) -> None:
        assert "cloud" in _CATEGORY_MAP

    def test_has_header(self) -> None:
        assert "header" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 5


class TestCheckSSRFResponse:
    """Testes para _check_ssrf_response."""

    def test_found(self) -> None:
        assert _check_ssrf_response(b"ami-id-123", 200, ["ami-id"]) is True

    def test_not_found(self) -> None:
        assert _check_ssrf_response(b"error", 200, ["ami-id"]) is False

    def test_empty_body(self) -> None:
        assert _check_ssrf_response(b"", 200, ["ami-id"]) is False

    def test_status_zero(self) -> None:
        assert _check_ssrf_response(b"ami-id", 0, ["ami-id"]) is False

    def test_case_insensitive(self) -> None:
        assert _check_ssrf_response(b"AMI-ID", 200, ["ami-id"]) is True


class TestSSRFAttempt:
    """Testes para SSRFAttempt dataclass."""

    def test_creation(self) -> None:
        att = SSRFAttempt(
            technique="localhost_80_url",
            category="detect",
            url="https://example.com?url=http://127.0.0.1:80",
            payload="http://127.0.0.1:80",
            status_baseline=200,
            status_test=302,
            size_baseline=1000,
            size_test=0,
            time_baseline=0.5,
            time_test=2.0,
            status_changed=True,
            size_changed=True,
            time_changed=True,
            vulnerable=True,
            details="Param url: localhost_80 -> changed",
            error="",
        )
        assert att.technique == "localhost_80_url"
        assert att.vulnerable is True
        assert att.time_changed is True

    def test_frozen(self) -> None:
        att = SSRFAttempt(
            technique="t",
            category="c",
            url="u",
            payload="p",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=100,
            time_baseline=0.5,
            time_test=0.5,
            status_changed=False,
            size_changed=False,
            time_changed=False,
            vulnerable=False,
            details="d",
            error="",
        )
        with pytest.raises(AttributeError):
            att.technique = "new"  # type: ignore[misc]


class TestSSRFResult:
    """Testes para SSRFResult dataclass."""

    def test_creation(self) -> None:
        result = SSRFResult(
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

        status, size, body, elapsed = await _test_baseline(
            client, "https://example.com"
        )
        assert status == 200
        assert size == 5
        assert body == b"hello"
        assert elapsed >= 0

    @pytest.mark.asyncio
    async def test_error(self) -> None:
        import httpx

        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        status, size, body, _elapsed = await _test_baseline(
            client, "https://example.com"
        )
        assert status == 0
        assert size == 0
        assert body == b""


class TestTestDetect:
    """Testes para _test_detect."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_detect(
            client,
            "https://example.com",
            (200, 100, b"ok", 0.5),
        )
        assert len(attempts) > 0
        assert all(isinstance(a, SSRFAttempt) for a in attempts)

    @pytest.mark.asyncio
    async def test_error_handled(self) -> None:
        import httpx

        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_detect(
            client,
            "https://example.com",
            (200, 100, b"ok", 0.5),
        )
        assert len(attempts) > 0
        assert any(a.error for a in attempts)


class TestTestInternal:
    """Testes para _test_internal."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_internal(
            client,
            "https://example.com",
            (200, 100, b"ok", 0.5),
        )
        assert len(attempts) > 0

    @pytest.mark.asyncio
    async def test_error_handled(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_internal(
            client,
            "https://example.com",
            (200, 100, b"ok", 0.5),
        )
        assert len(attempts) > 0
        assert any(a.error for a in attempts)


class TestTestBypass:
    """Testes para _test_bypass."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_bypass(
            client,
            "https://example.com",
            (200, 100, b"ok", 0.5),
        )
        assert len(attempts) > 0

    @pytest.mark.asyncio
    async def test_error_handled(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_bypass(
            client,
            "https://example.com",
            (200, 100, b"ok", 0.5),
        )
        assert len(attempts) > 0
        assert any(a.error for a in attempts)


class TestTestCloud:
    """Testes para _test_cloud."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_cloud(
            client,
            "https://example.com",
            (200, 100, b"ok", 0.5),
        )
        assert len(attempts) > 0

    @pytest.mark.asyncio
    async def test_error_handled(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_cloud(
            client,
            "https://example.com",
            (200, 100, b"ok", 0.5),
        )
        assert len(attempts) > 0
        assert any(a.error for a in attempts)


class TestSSRFDetectionRegression:
    """Regressao: todas as payloads rodam e deteccao usa indicador/baseline."""

    @staticmethod
    def _client(resp) -> AsyncMock:
        client = AsyncMock()
        client.get = AsyncMock(return_value=resp)
        return client

    @staticmethod
    def _resp(status: int = 200, content: bytes = b"ok") -> MagicMock:
        resp = MagicMock()
        resp.status_code = status
        resp.content = content
        return resp

    @pytest.mark.asyncio
    async def test_detect_covers_all_payloads(self) -> None:
        attempts = await _test_detect(
            self._client(self._resp()),
            "https://example.com",
            (200, 100, b"ok", 0.5),
        )
        assert len(attempts) == len(_URL_PARAMS[:8]) * len(_DETECT_PAYLOADS)
        assert any("metadata_aws" in a.technique for a in attempts)
        assert any("hex_ip" in a.technique for a in attempts)

    @pytest.mark.asyncio
    async def test_internal_covers_all_payloads(self) -> None:
        attempts = await _test_internal(
            self._client(self._resp()),
            "https://example.com",
            (200, 100, b"ok", 0.5),
        )
        assert len(attempts) == len(_URL_PARAMS[:5]) * len(_INTERNAL_PAYLOADS)
        assert any("internal_gitlab" in a.technique for a in attempts)
        assert any("internal_jenkins" in a.technique for a in attempts)

    @pytest.mark.asyncio
    async def test_cloud_covers_all_payloads(self) -> None:
        attempts = await _test_cloud(
            self._client(self._resp()),
            "https://example.com",
            (200, 100, b"ok", 0.5),
        )
        assert len(attempts) == len(_URL_PARAMS[:5]) * len(_CLOUD_PAYLOADS)
        assert any("kubernetes" in a.technique for a in attempts)
        assert any("aws_metadata_iam" in a.technique for a in attempts)

    @pytest.mark.asyncio
    async def test_indicator_in_test_not_baseline_is_vulnerable(self) -> None:
        attempts = await _test_detect(
            self._client(self._resp(content=b"ami-id-12345")),
            "https://example.com",
            (200, 100, b"<html>baseline</html>", 0.5),
        )
        aws = [a for a in attempts if "metadata_aws" in a.technique]
        assert aws
        assert all(a.vulnerable for a in aws)

    @pytest.mark.asyncio
    async def test_indicator_also_in_baseline_not_vulnerable(self) -> None:
        attempts = await _test_detect(
            self._client(self._resp(content=b"<html>ami-id</html>")),
            "https://example.com",
            (200, 100, b"ami-id-baseline", 0.5),
        )
        aws = [a for a in attempts if "metadata_aws" in a.technique]
        assert aws
        assert not any(a.vulnerable for a in aws)

    @pytest.mark.asyncio
    async def test_generic_payload_requires_stable_diff(self) -> None:
        attempts = await _test_detect(
            self._client(self._resp(status=302, content=b"x" * 500)),
            "https://example.com",
            (200, 100, b"ok", 0.5),
        )
        localhost = [a for a in attempts if "localhost_80" in a.technique]
        assert localhost
        assert all(a.vulnerable for a in localhost)

    @pytest.mark.asyncio
    async def test_dynamic_page_not_vulnerable(self) -> None:
        attempts = await _test_detect(
            self._client(self._resp(status=302, content=b"ok")),
            "https://example.com",
            (200, 100, b"ok", 0.5),
        )
        localhost = [a for a in attempts if "localhost_80" in a.technique]
        assert localhost
        assert not any(a.vulnerable for a in localhost)


class TestTestHeader:
    """Testes para _test_header."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        client = AsyncMock()
        resp = MagicMock()
        resp.status_code = 200
        resp.content = b"ok"
        client.get = AsyncMock(return_value=resp)

        attempts = await _test_header(
            client,
            "https://example.com",
            (200, 100, b"ok", 0.5),
        )
        assert len(attempts) == 8

    @pytest.mark.asyncio
    async def test_error_handled(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.RequestError("fail"))

        attempts = await _test_header(
            client,
            "https://example.com",
            (200, 100, b"ok", 0.5),
        )
        assert len(attempts) == 8
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
        args = parser.parse_args(["https://example.com", "-c", "cloud"])
        assert args.category == "cloud"


class TestPrintResults:
    """Testes para print_results."""

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        import re

        result = SSRFResult(
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
        clean = re.sub(r"\033\[[0-9;]*m", "", captured.out)
        assert "SSRF" in clean

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        import re

        result = SSRFResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=1000,
            tls=False,
            attempts=[],
            vulnerable_techniques=["localhost_80_url"],
            blocked_techniques=[],
            issues=["VULN: localhost_80_url"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        clean = re.sub(r"\033\[[0-9;]*m", "", captured.out)
        assert "VULNERAVEIS" in clean

    def test_vulnerable_with_attempt_and_errors(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import re

        att = _attempt(
            vulnerable=True,
            details="Param url: localhost_80_url -> changed",
            exploit="curl http://169.254.169.254/latest/meta-data/",
        )
        err = _attempt(technique="blocked_x", error="connection refused")
        result = SSRFResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=1000,
            tls=False,
            attempts=[att, err],
            vulnerable_techniques=["localhost_80_url"],
            blocked_techniques=["blocked_x"],
            issues=["VULN: localhost_80_url"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        clean = re.sub(r"\033\[[0-9;]*m", "", captured.out)
        assert "Erros" in clean
        assert "curl http://169.254.169.254" in clean


class TestMain:
    """Testes para main."""

    def test_no_url(self) -> None:
        with (
            patch("sys.argv", ["mytools-ssrfdetect"]),
            patch("mytools.web.ssrfdetect.run_main_loop", return_value=1) as mock_loop,
        ):
            result = main()
            assert result == 1
            mock_loop.assert_called_once()


class TestRunScan:
    @pytest.mark.asyncio
    async def test_baseline_failure_returns_1(self) -> None:
        mock_client = AsyncMock()
        with (
            patch(
                "mytools.web.ssrfdetect.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.ssrfdetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(0, 0, b"", 0.0),
            ),
        ):
            result = await run_scan("https://example.com", [], 10, 5, None, False)
        assert result == 1

    @pytest.mark.asyncio
    async def test_secure_all_categories(self) -> None:
        mock_client = AsyncMock()
        baseline = (200, 1000, b"ok", 0.5)
        with (
            patch(
                "mytools.web.ssrfdetect.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.ssrfdetect._test_baseline",
                new_callable=AsyncMock,
                return_value=baseline,
            ),
            patch(
                "mytools.web.ssrfdetect._test_detect",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.ssrfdetect._test_internal",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.ssrfdetect._test_bypass",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.ssrfdetect._test_cloud",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.ssrfdetect._test_header",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = await run_scan("https://example.com", [], 10, 5, None, False)
        assert result == 0

    @pytest.mark.asyncio
    async def test_vulnerable_json_output(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mock_client = AsyncMock()
        vuln = _attempt(vulnerable=True, details="Param url: x")
        with (
            patch(
                "mytools.web.ssrfdetect.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.ssrfdetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 1000, b"ok", 0.5),
            ),
            patch(
                "mytools.web.ssrfdetect._test_detect",
                new_callable=AsyncMock,
                return_value=[vuln],
            ),
        ):
            result = await run_scan(
                "https://example.com", ["detect"], 10, 5, None, False, None, True
            )
        assert result == 1
        out = capsys.readouterr().out
        assert '"overall_status": "vulnerable"' in out

    @pytest.mark.asyncio
    async def test_invalid_category(self) -> None:
        mock_client = AsyncMock()
        with (
            patch(
                "mytools.web.ssrfdetect.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.ssrfdetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 1000, b"ok", 0.5),
            ),
        ):
            result = await run_scan(
                "https://example.com", ["invalid"], 10, 5, None, False
            )
        assert result == 0

    @pytest.mark.asyncio
    async def test_uppercase_https_detected_as_tls(self) -> None:
        mock_client = AsyncMock()
        captured: list[SSRFResult] = []
        with (
            patch(
                "mytools.web.ssrfdetect.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.ssrfdetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 1000, b"ok", 0.5),
            ),
            patch(
                "mytools.web.ssrfdetect._test_detect",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.ssrfdetect._test_internal",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.ssrfdetect._test_bypass",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.ssrfdetect._test_cloud",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.ssrfdetect._test_header",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.ssrfdetect.print_results",
                side_effect=lambda result: captured.append(result),
            ),
        ):
            result = await run_scan("HTTPS://example.com", [], 10, 5, None, False)
        assert result == 0
        assert captured
        assert captured[0].tls is True

    @pytest.mark.asyncio
    async def test_output_file_written(self, tmp_path: Path) -> None:
        mock_client = AsyncMock()
        with (
            patch(
                "mytools.web.ssrfdetect.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.ssrfdetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 1000, b"ok", 0.5),
            ),
            patch(
                "mytools.web.ssrfdetect._test_detect",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            out = str(tmp_path / "out.json")
            result = await run_scan(
                "https://example.com", ["detect"], 10, 5, out, False
            )
        assert result == 0
        assert (tmp_path / "out.json").exists()

    @pytest.mark.asyncio
    async def test_gather_exception_is_skipped(self) -> None:
        mock_client = AsyncMock()
        with (
            patch(
                "mytools.web.ssrfdetect.create_async_client",
                return_value=mock_client,
            ),
            patch(
                "mytools.web.ssrfdetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 1000, b"ok", 0.5),
            ),
            patch(
                "mytools.web.ssrfdetect._test_detect",
                new_callable=AsyncMock,
                side_effect=RuntimeError("boom"),
            ),
        ):
            result = await run_scan(
                "https://example.com", ["detect"], 10, 5, None, False
            )
        assert result == 0


class TestRunOnce:
    def test_no_category_returns_0(self) -> None:
        with patch(
            "mytools.web.ssrfdetect.run_scan",
            new_callable=AsyncMock,
            return_value=0,
        ) as mock_scan:
            assert run_once(_ns()) == 0
        mock_scan.assert_called_once()

    def test_with_category_returns_1(self) -> None:
        with patch(
            "mytools.web.ssrfdetect.run_scan",
            new_callable=AsyncMock,
            return_value=1,
        ) as mock_scan:
            assert run_once(_ns(category="detect")) == 1
        _, kwargs = mock_scan.call_args
        assert kwargs["categories"] == ["detect"]

    def test_forwards_proxy(self) -> None:
        with patch(
            "mytools.web.ssrfdetect.run_scan",
            new_callable=AsyncMock,
            return_value=0,
        ) as mock_scan:
            run_once(_ns(proxy="http://127.0.0.1:8080"))
        _, kwargs = mock_scan.call_args
        assert kwargs["proxy"] == "http://127.0.0.1:8080"

    def test_creates_client_with_proxy(self) -> None:
        with (
            patch(
                "mytools.web.ssrfdetect.create_async_client",
                return_value=AsyncMock(),
            ) as mock_client,
            patch(
                "mytools.web.ssrfdetect._test_baseline",
                new_callable=AsyncMock,
                return_value=(200, 1000, b"ok", 0.5),
            ),
        ):
            safe_asyncio_run(
                run_scan(
                    "https://example.com", ["detect"], 10, 5, None, False, "http://p"
                )
            )
        mock_client.assert_called_once_with(timeout=10, proxy="http://p")


class TestMainGuard:
    def test_guard_runs(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.web.ssrfdetect", run_name="__main__")
