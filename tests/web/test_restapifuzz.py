import argparse
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mytools.web.restapifuzz import (
    RestFuzzAttempt,
    RestFuzzResult,
    _get_endpoints,
    _get_list,
    _get_str_list,
    _get_tuple_list,
    _probe_openapi,
    _test_endpoint_baseline,
    build_parser,
    print_results,
    run_scan,
)

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Payload loading
# ---------------------------------------------------------------------------


class TestGetList:
    def test_returns_default_on_missing(self) -> None:
        result = _get_list("nonexistent_key_xyz", [1, 2, 3])
        assert result == [1, 2, 3]

    def test_returns_empty_for_missing(self) -> None:
        result = _get_list("nonexistent_key_xyz", [])
        assert result == []


class TestGetStrList:
    def test_returns_string_list(self) -> None:
        result = _get_str_list("nonexistent_key_xyz", ["a", "b"])
        assert result == ["a", "b"]


class TestGetTupleList:
    def test_returns_default_on_missing(self) -> None:
        default = [("a", "b")]
        result = _get_tuple_list("nonexistent_key_xyz", default)
        assert result == default


# ---------------------------------------------------------------------------
# _probe_openapi
# ---------------------------------------------------------------------------


class TestProbeOpenAPI:
    @pytest.mark.asyncio
    async def test_returns_none_on_no_spec(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.content = b""

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        result = await _probe_openapi(mock_client, "https://api.example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_invalid_json(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"not json"
        mock_resp.headers = {"content-type": "application/json"}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        result = await _probe_openapi(mock_client, "https://api.example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_none_on_no_paths(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"openapi": "3.0.0"}'
        mock_resp.headers = {"content-type": "application/json"}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        result = await _probe_openapi(mock_client, "https://api.example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_returns_endpoints_from_spec(self) -> None:
        spec = {"openapi": "3.0.0", "paths": {"/users": {}, "/products": {}}}
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = __import__("json").dumps(spec).encode()
        mock_resp.headers = {"content-type": "application/json"}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        result = await _probe_openapi(mock_client, "https://api.example.com")
        assert result == ["/users", "/products"]


# ---------------------------------------------------------------------------
# _test_endpoint_baseline
# ---------------------------------------------------------------------------


class TestTestEndpointBaseline:
    @pytest.mark.asyncio
    async def test_returns_status(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"OK"
        mock_resp.headers = {"content-type": "application/json"}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        status, size, ct = await _test_endpoint_baseline(
            mock_client,
            "https://api.example.com/users",
        )
        assert status == 200
        assert size == 2
        assert ct == "application/json"

    @pytest.mark.asyncio
    async def test_returns_error_on_exception(self) -> None:
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("connection refused")

        status, size, ct = await _test_endpoint_baseline(
            mock_client,
            "https://api.example.com/users",
        )
        assert status == 0
        assert size == 0
        assert ct == ""


# ---------------------------------------------------------------------------
# _get_endpoints
# ---------------------------------------------------------------------------


class TestGetEndpoints:
    def test_returns_user_endpoints_if_provided(self) -> None:
        result = _get_endpoints(None, "https://api.example.com", ["/a", "/b"])
        assert result == ["/a", "/b"]

    def test_returns_fallback_if_no_client(self) -> None:
        result = _get_endpoints(None, "https://api.example.com", None)
        assert isinstance(result, list)
        assert len(result) > 0


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
        args = parser.parse_args(["https://api.example.com"])
        assert args.url == "https://api.example.com"

    def test_default_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://api.example.com"])
        assert args.categories == ["all"]

    def test_single_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://api.example.com", "-c", "auth_bypass"])
        assert args.categories == ["auth_bypass"]

    def test_multiple_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "https://api.example.com",
                "-c",
                "auth_bypass",
                "content_type",
            ]
        )
        assert args.categories == ["auth_bypass", "content_type"]

    def test_all_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "https://api.example.com",
                "-c",
                "auth_bypass",
                "content_type",
                "version_enum",
                "hateoas",
            ]
        )
        assert len(args.categories) == 4

    def test_invalid_category(self) -> None:
        parser = build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["https://api.example.com", "-c", "invalid"])

    def test_custom_endpoints(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "https://api.example.com",
                "--endpoints",
                "/users",
                "/orders",
            ]
        )
        assert args.endpoints == ["/users", "/orders"]

    def test_default_concurrency(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://api.example.com"])
        assert args.concurrency == 5

    def test_custom_concurrency(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://api.example.com", "--concurrency", "10"])
        assert args.concurrency == 10


# ---------------------------------------------------------------------------
# run_scan (async mock)
# ---------------------------------------------------------------------------


class TestRunScan:
    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 0
        mock_resp.content = b""
        mock_resp.headers = {}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("mytools.web.restapifuzz.create_async_client", return_value=mock_client),
            patch("mytools.web.restapifuzz._get_endpoints", return_value=["/users"]),
            patch("mytools.web.restapifuzz._test_endpoint_baseline", return_value=(0, 0, "")),
        ):
            result = await run_scan("https://api.example.com")
            assert isinstance(result, RestFuzzResult)
            assert result.endpoints_tested == 1

    @pytest.mark.asyncio
    async def test_scan_returns_result(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"data": "ok"}'
        mock_resp.headers = {"content-type": "application/json"}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("mytools.web.restapifuzz.create_async_client", return_value=mock_client),
            patch("mytools.web.restapifuzz._get_endpoints", return_value=["/users"]),
            patch("mytools.web.restapifuzz._test_endpoint_baseline", return_value=(200, 15, "application/json")),
        ):
            result = await run_scan(
                "https://api.example.com",
                categories=["hateoas"],
            )
            assert isinstance(result, RestFuzzResult)
            assert result.overall_status in ("secure", "vulnerable")

    @pytest.mark.asyncio
    async def test_auth_bypass_category(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_resp.content = b"unauthorized"
        mock_resp.headers = {"content-type": "application/json"}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with (
            patch("mytools.web.restapifuzz.create_async_client", return_value=mock_client),
            patch("mytools.web.restapifuzz._get_endpoints", return_value=["/admin"]),
            patch("mytools.web.restapifuzz._test_endpoint_baseline", return_value=(401, 12, "application/json")),
        ):
            result = await run_scan(
                "https://api.example.com",
                categories=["auth_bypass"],
            )
            assert isinstance(result, RestFuzzResult)
            assert result.baseline_status == 401


# ---------------------------------------------------------------------------
# print_results
# ---------------------------------------------------------------------------


class TestPrintResults:
    def test_prints_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = RestFuzzResult(
            target="https://api.example.com",
            endpoints_tested=1,
            baseline_status=200,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "SECURE" in captured.out

    def test_prints_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        attempt = RestFuzzAttempt(
            technique="bearer_empty",
            category="auth_bypass",
            endpoint="/admin",
            url="https://api.example.com/admin",
            payload="Authorization: ",
            method="GET",
            status_baseline=401,
            status_test=200,
            size_baseline=12,
            size_test=100,
            content_type_changed=False,
            vulnerable=True,
            details="Auth bypass: 401->200",
            error="",
            exploit="curl -H 'Authorization: ' 'https://api.example.com/admin'",
            tool="curl",
        )
        result = RestFuzzResult(
            target="https://api.example.com",
            endpoints_tested=1,
            baseline_status=401,
            tls=True,
            attempts=[attempt],
            vulnerable_techniques=["bearer_empty"],
            issues=["1 tecnicas vulneraveis encontradas"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "VULNERAVEL" in captured.out
        assert "bearer_empty" in captured.out
