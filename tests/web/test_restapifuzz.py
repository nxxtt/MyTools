import argparse
import asyncio
import runpy
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mytools.web.restapifuzz import (
    _FALLBACK_ENDPOINTS_DEFAULT,
    RestFuzzAttempt,
    RestFuzzResult,
    _get_endpoints,
    _get_list,
    _get_str_list,
    _get_tuple_list,
    _probe_openapi,
    _test_auth_bypass,
    _test_content_type,
    _test_endpoint_baseline,
    _test_hateoas,
    _test_version_enum,
    build_parser,
    main,
    print_results,
    run_once,
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
    async def test_empty_paths_returns_none(self) -> None:
        spec = {"openapi": "3.0.0", "paths": {}}
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = __import__("json").dumps(spec).encode()
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
            patch(
                "mytools.web.restapifuzz.create_async_client", return_value=mock_client
            ),
            patch("mytools.web.restapifuzz._get_endpoints", return_value=["/users"]),
            patch(
                "mytools.web.restapifuzz._test_endpoint_baseline",
                new_callable=AsyncMock,
                return_value=(0, 0, ""),
            ),
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
            patch(
                "mytools.web.restapifuzz.create_async_client", return_value=mock_client
            ),
            patch("mytools.web.restapifuzz._get_endpoints", return_value=["/users"]),
            patch(
                "mytools.web.restapifuzz._test_endpoint_baseline",
                new_callable=AsyncMock,
                return_value=(200, 15, "application/json"),
            ),
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
            patch(
                "mytools.web.restapifuzz.create_async_client", return_value=mock_client
            ),
            patch("mytools.web.restapifuzz._get_endpoints", return_value=["/admin"]),
            patch(
                "mytools.web.restapifuzz._test_endpoint_baseline",
                new_callable=AsyncMock,
                return_value=(401, 12, "application/json"),
            ),
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

    def test_prints_vulnerable_without_matching_attempt(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
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
            exploit="",
            tool="",
        )
        secure_attempt = RestFuzzAttempt(
            technique="type_confusion",
            category="content_type",
            endpoint="/api",
            url="https://api.example.com/api",
            payload="application/xml",
            method="POST",
            status_baseline=200,
            status_test=200,
            size_baseline=10,
            size_test=10,
            content_type_changed=False,
            vulnerable=False,
            details="",
            error="",
            exploit="",
            tool="",
        )
        result = RestFuzzResult(
            target="https://api.example.com",
            endpoints_tested=1,
            baseline_status=401,
            tls=True,
            attempts=[attempt, secure_attempt],
            vulnerable_techniques=["ghost_technique"],
            issues=["1 tecnicas vulneraveis encontradas"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "VULNERAVEL" in captured.out
        assert "ghost_technique" in captured.out


# ---------------------------------------------------------------------------
# _probe_openapi extra branches
# ---------------------------------------------------------------------------


class TestProbeOpenAPIExtra:
    @pytest.mark.asyncio
    async def test_non_json_content_type_skipped(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"<html></html>"
        mock_resp.headers = {"content-type": "text/html"}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        result = await _probe_openapi(mock_client, "https://api.example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_non_dict_spec_skipped(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"[1, 2, 3]"
        mock_resp.headers = {"content-type": "application/json"}

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        result = await _probe_openapi(mock_client, "https://api.example.com")
        assert result is None


# ---------------------------------------------------------------------------
# _get_endpoints with client
# ---------------------------------------------------------------------------


class TestGetEndpointsWithClient:
    def test_detects_endpoints_via_probe(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            mock_client = AsyncMock()
            with patch(
                "mytools.web.restapifuzz._probe_openapi",
                new_callable=AsyncMock,
                return_value=["/users"],
            ):
                result = _get_endpoints(mock_client, "https://api.example.com", None)
        finally:
            loop.close()
            asyncio.set_event_loop(None)
        assert result == ["/users"]

    def test_returns_fallback_when_probe_none(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            mock_client = AsyncMock()
            with patch(
                "mytools.web.restapifuzz._probe_openapi",
                new_callable=AsyncMock,
                return_value=None,
            ):
                result = _get_endpoints(mock_client, "https://api.example.com", None)
        finally:
            loop.close()
            asyncio.set_event_loop(None)
        assert result == list(_FALLBACK_ENDPOINTS_DEFAULT)


# ---------------------------------------------------------------------------
# _test_auth_bypass branches
# ---------------------------------------------------------------------------


class TestAuthBypass:
    @pytest.mark.asyncio
    async def test_not_protected_returns_empty(self) -> None:
        mock_client = AsyncMock()
        mock_client.base_url = "https://api.example.com/"
        result = await _test_auth_bypass(mock_client, "/admin", (200, 10, ""))
        assert result == []

    @pytest.mark.asyncio
    async def test_request_errors_recorded(self) -> None:
        mock_client = AsyncMock()
        mock_client.base_url = "https://api.example.com/"
        mock_client.get.side_effect = httpx.RequestError("boom")
        result = await _test_auth_bypass(mock_client, "/admin", (401, 10, ""))
        assert result
        assert all(a.error for a in result)


# ---------------------------------------------------------------------------
# _test_content_type
# ---------------------------------------------------------------------------


class TestContentType:
    @pytest.mark.asyncio
    async def test_full_scan(self) -> None:
        mock_client = AsyncMock()
        mock_client.base_url = "https://api.example.com/"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {"content-type": "application/json"}
        mock_client.post.return_value = mock_resp
        result = await _test_content_type(
            mock_client, "/users", (400, 5, "application/json")
        )
        assert result
        assert any(a.vulnerable for a in result)

    @pytest.mark.asyncio
    async def test_zero_baseline_returns_empty(self) -> None:
        mock_client = AsyncMock()
        mock_client.base_url = "https://api.example.com/"
        result = await _test_content_type(mock_client, "/users", (0, 0, ""))
        assert result == []

    @pytest.mark.asyncio
    async def test_request_errors_recorded(self) -> None:
        mock_client = AsyncMock()
        mock_client.base_url = "https://api.example.com/"
        mock_client.post.side_effect = httpx.RequestError("boom")
        result = await _test_content_type(mock_client, "/users", (400, 5, ""))
        assert result
        assert all(a.error for a in result)


# ---------------------------------------------------------------------------
# _test_version_enum
# ---------------------------------------------------------------------------


class TestVersionEnum:
    @pytest.mark.asyncio
    async def test_full_scan(self) -> None:
        mock_client = AsyncMock()
        mock_client.base_url = "https://api.example.com/"
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {"content-type": "application/json"}
        mock_client.get.return_value = mock_resp
        result = await _test_version_enum(
            mock_client, "/users", "https://api.example.com", (404, 5, "")
        )
        assert result
        assert any(a.vulnerable for a in result)

    @pytest.mark.asyncio
    async def test_request_errors_recorded(self) -> None:
        mock_client = AsyncMock()
        mock_client.base_url = "https://api.example.com/"
        mock_client.get.side_effect = httpx.RequestError("boom")
        result = await _test_version_enum(
            mock_client, "/users", "https://api.example.com", (404, 5, "")
        )
        assert result
        assert all(a.error for a in result)


# ---------------------------------------------------------------------------
# _test_hateoas branches
# ---------------------------------------------------------------------------


class TestHateoas:
    @pytest.mark.asyncio
    async def test_zero_baseline_returns_empty(self) -> None:
        mock_client = AsyncMock()
        mock_client.base_url = "https://api.example.com/"
        result = await _test_hateoas(mock_client, "/users", (0, 0, ""))
        assert result == []

    @pytest.mark.asyncio
    async def test_request_errors_recorded(self) -> None:
        mock_client = AsyncMock()
        mock_client.base_url = "https://api.example.com/"
        mock_client.request.side_effect = httpx.RequestError("boom")
        mock_client.get.side_effect = httpx.RequestError("boom")
        result = await _test_hateoas(
            mock_client, "/users", (404, 5, "application/json")
        )
        assert result
        assert all(a.error for a in result)


# ---------------------------------------------------------------------------
# run_scan extra branches
# ---------------------------------------------------------------------------


class TestRunScanExtra:
    @staticmethod
    def _mock_client() -> AsyncMock:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b'{"data": "ok"}'
        mock_resp.headers = {"content-type": "application/json"}
        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        return mock_client

    @pytest.mark.asyncio
    async def test_no_scheme_all_categories(self) -> None:
        mock_client = self._mock_client()
        with (
            patch(
                "mytools.web.restapifuzz.create_async_client",
                return_value=mock_client,
            ),
            patch("mytools.web.restapifuzz._get_endpoints", return_value=["/users"]),
            patch(
                "mytools.web.restapifuzz._test_endpoint_baseline",
                new_callable=AsyncMock,
                return_value=(200, 3, "application/json"),
            ),
            patch(
                "mytools.web.restapifuzz._test_auth_bypass",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.restapifuzz._test_content_type",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.restapifuzz._test_version_enum",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.restapifuzz._test_hateoas",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = await run_scan("api.example.com", categories=["all"])
        assert result.target == "http://api.example.com"
        assert result.overall_status == "secure"

    @pytest.mark.asyncio
    async def test_vulnerable_techniques_dedup(self) -> None:
        mock_client = self._mock_client()
        vuln_att = RestFuzzAttempt(
            technique="bearer_empty",
            category="auth_bypass",
            endpoint="/admin",
            url="http://api.example.com/admin",
            payload="Authorization: ",
            method="GET",
            status_baseline=401,
            status_test=200,
            size_baseline=10,
            size_test=100,
            content_type_changed=False,
            vulnerable=True,
            details="Auth bypass",
            error="",
            exploit="",
            tool="",
        )
        with (
            patch(
                "mytools.web.restapifuzz.create_async_client",
                return_value=mock_client,
            ),
            patch("mytools.web.restapifuzz._get_endpoints", return_value=["/admin"]),
            patch(
                "mytools.web.restapifuzz._test_endpoint_baseline",
                new_callable=AsyncMock,
                return_value=(401, 12, "application/json"),
            ),
            patch(
                "mytools.web.restapifuzz._test_auth_bypass",
                new_callable=AsyncMock,
                return_value=[vuln_att, vuln_att],
            ),
            patch(
                "mytools.web.restapifuzz._test_content_type",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.restapifuzz._test_version_enum",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.restapifuzz._test_hateoas",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = await run_scan(
                "https://api.example.com", categories=["auth_bypass"]
            )
        assert result.overall_status == "vulnerable"
        assert result.vulnerable_techniques == ["bearer_empty"]
        assert result.issues == ["1 tecnicas vulneraveis encontradas"]

    @pytest.mark.asyncio
    async def test_tester_exception_ignored(self) -> None:
        mock_client = self._mock_client()
        with (
            patch(
                "mytools.web.restapifuzz.create_async_client",
                return_value=mock_client,
            ),
            patch("mytools.web.restapifuzz._get_endpoints", return_value=["/admin"]),
            patch(
                "mytools.web.restapifuzz._test_endpoint_baseline",
                new_callable=AsyncMock,
                return_value=(401, 12, "application/json"),
            ),
            patch(
                "mytools.web.restapifuzz._test_auth_bypass",
                new_callable=AsyncMock,
                side_effect=RuntimeError("boom"),
            ),
            patch(
                "mytools.web.restapifuzz._test_content_type",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.restapifuzz._test_version_enum",
                new_callable=AsyncMock,
                return_value=[],
            ),
            patch(
                "mytools.web.restapifuzz._test_hateoas",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            result = await run_scan(
                "https://api.example.com", categories=["auth_bypass"]
            )
        assert result.overall_status == "secure"
        assert result.attempts == []


# ---------------------------------------------------------------------------
# run_once / main / guard
# ---------------------------------------------------------------------------


class TestRunOnce:
    def test_secure_returns_0(self) -> None:
        result = RestFuzzResult(
            target="http://api.example.com",
            endpoints_tested=1,
            baseline_status=200,
            tls=False,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        args = build_parser().parse_args(["http://api.example.com"])
        with patch(
            "mytools.web.restapifuzz.run_scan",
            new_callable=AsyncMock,
            return_value=result,
        ):
            assert run_once(args) == 0

    def test_json_output_and_error_status(self, tmp_path) -> None:
        result = RestFuzzResult(
            target="http://api.example.com",
            endpoints_tested=1,
            baseline_status=200,
            tls=False,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="error",
        )
        out = tmp_path / "out.json"
        args = build_parser().parse_args(
            ["--json", "-o", str(out), "http://api.example.com"]
        )
        with patch(
            "mytools.web.restapifuzz.run_scan",
            new_callable=AsyncMock,
            return_value=result,
        ):
            assert run_once(args) == 1
        assert out.exists()

    def test_empty_categories_defaults_to_all(self) -> None:
        result = RestFuzzResult(
            target="http://api.example.com",
            endpoints_tested=1,
            baseline_status=200,
            tls=False,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        args = build_parser().parse_args(
            ["http://api.example.com", "-c", "auth_bypass"]
        )
        args.categories = []
        with patch(
            "mytools.web.restapifuzz.run_scan",
            new_callable=AsyncMock,
            return_value=result,
        ) as mock_scan:
            assert run_once(args) == 0
        assert mock_scan.call_args.kwargs["categories"] == ["all"]


class TestMainEntry:
    def test_main(self) -> None:
        with patch("mytools.web.restapifuzz.run_main_loop", return_value=0):
            assert main() == 0

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.restapifuzz", run_name="__main__")
        assert exc_info.value.code == 0
