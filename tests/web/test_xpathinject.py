#!/usr/bin/env python3
"""Testes unitarios do modulo de XPath Injection."""
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mytools.web.xpathinject import (
    _AUTH_BYPASS_PAYLOADS,
    _BLIND_PAYLOADS,
    _BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    _DETECT_PAYLOADS,
    _EXTRACT_PAYLOADS,
    _XPATH_PARAMS,
    XPathiAttempt,
    XPathiResult,
    _check_xpath_response,
    _test_auth_bypass,
    _test_baseline,
    _test_blind,
    _test_bypass,
    _test_detect,
    _test_extract,
    build_parser,
    main,
    print_results,
)


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_has_detect(self) -> None:
        assert "detect" in _CATEGORY_MAP

    def test_has_auth_bypass(self) -> None:
        assert "auth_bypass" in _CATEGORY_MAP

    def test_has_extract(self) -> None:
        assert "extract" in _CATEGORY_MAP

    def test_has_blind(self) -> None:
        assert "blind" in _CATEGORY_MAP

    def test_has_bypass(self) -> None:
        assert "bypass" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 5


class TestDetectPayloads:
    """Testes para _DETECT_PAYLOADS."""

    def test_has_always_true_string(self) -> None:
        assert any("always_true_string" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_always_true_paren(self) -> None:
        assert any("always_true_paren" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_select_all(self) -> None:
        assert any("select_all" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_string_all(self) -> None:
        assert any("string_all" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_count_elements(self) -> None:
        assert any("count_elements" in p[0] for p in _DETECT_PAYLOADS)

    def test_count(self) -> None:
        assert len(_DETECT_PAYLOADS) == 5


class TestAuthBypassPayloads:
    """Testes para _AUTH_BYPASS_PAYLOADS."""

    def test_has_admin_tautology(self) -> None:
        assert any("admin_tautology" in p[0] for p in _AUTH_BYPASS_PAYLOADS)

    def test_has_admin_wildcard(self) -> None:
        assert any("admin_wildcard" in p[0] for p in _AUTH_BYPASS_PAYLOADS)

    def test_has_admin_or_empty(self) -> None:
        assert any("admin_or_empty" in p[0] for p in _AUTH_BYPASS_PAYLOADS)

    def test_has_admin_xpath_or(self) -> None:
        assert any("admin_xpath_or" in p[0] for p in _AUTH_BYPASS_PAYLOADS)

    def test_has_admin_double_quote(self) -> None:
        assert any("admin_double_quote" in p[0] for p in _AUTH_BYPASS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_AUTH_BYPASS_PAYLOADS) == 5


class TestExtractPayloads:
    """Testes para _EXTRACT_PAYLOADS."""

    def test_has_extract_user(self) -> None:
        assert any("extract_user" in p[0] for p in _EXTRACT_PAYLOADS)

    def test_has_extract_password(self) -> None:
        assert any("extract_password" in p[0] for p in _EXTRACT_PAYLOADS)

    def test_has_extract_concat(self) -> None:
        assert any("extract_concat" in p[0] for p in _EXTRACT_PAYLOADS)

    def test_has_extract_all_nodes(self) -> None:
        assert any("extract_all_nodes" in p[0] for p in _EXTRACT_PAYLOADS)

    def test_has_extract_node_name(self) -> None:
        assert any("extract_node_name" in p[0] for p in _EXTRACT_PAYLOADS)

    def test_count(self) -> None:
        assert len(_EXTRACT_PAYLOADS) == 5


class TestBlindPayloads:
    """Testes para _BLIND_PAYLOADS."""

    def test_has_blind_first_char(self) -> None:
        assert any("blind_first_char" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_length(self) -> None:
        assert any("blind_length" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_substring(self) -> None:
        assert any("blind_substring" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_boolean(self) -> None:
        assert any("blind_boolean" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_name(self) -> None:
        assert any("blind_name" in p[0] for p in _BLIND_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BLIND_PAYLOADS) == 5


class TestBypassPayloads:
    """Testes para _BYPASS_PAYLOADS."""

    def test_has_unicode(self) -> None:
        assert any("unicode" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_comment(self) -> None:
        assert any("comment" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_whitespace(self) -> None:
        assert any("whitespace" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_double_encode(self) -> None:
        assert any("double_encode" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_null_terminator(self) -> None:
        assert any("null_terminator" in p[0] for p in _BYPASS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BYPASS_PAYLOADS) == 5


class TestXPathParams:
    """Testes para _XPATH_PARAMS."""

    def test_has_user(self) -> None:
        assert "user" in _XPATH_PARAMS

    def test_has_username(self) -> None:
        assert "username" in _XPATH_PARAMS

    def test_has_search(self) -> None:
        assert "search" in _XPATH_PARAMS

    def test_has_xpath(self) -> None:
        assert "xpath" in _XPATH_PARAMS

    def test_count(self) -> None:
        assert len(_XPATH_PARAMS) == 12


class TestXPathiAttempt:
    """Testes para dataclass XPathiAttempt."""

    def test_create(self) -> None:
        attempt = XPathiAttempt(
            technique="always_true_string_user",
            category="detect",
            payload="' or '1'='1",
            param="user",
            method="post_form",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=200,
            status_changed=False,
            size_changed=True,
            vulnerable=True,
            details="bypass found",
            error="",
        )
        assert attempt.technique == "always_true_string_user"
        assert attempt.vulnerable is True

    def test_immutable(self) -> None:
        attempt = XPathiAttempt(
            technique="test", category="detect", payload="'",
            param="user", method="post_form", status_baseline=200, status_test=200,
            size_baseline=100, size_test=100, status_changed=False,
            size_changed=False, vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            attempt.technique = "changed"  # type: ignore[misc]


class TestXPathiResult:
    """Testes para dataclass XPathiResult."""

    def test_create(self) -> None:
        result = XPathiResult(
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
        assert result.target == "https://example.com"
        assert result.overall_status == "secure"

    def test_immutable(self) -> None:
        result = XPathiResult(
            target="t", baseline_status=200, baseline_size=100,
            tls=True, attempts=[], vulnerable_techniques=[],
            blocked_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            result.target = "changed"  # type: ignore[misc]


class TestCheckXPathResponse:
    """Testes para _check_xpath_response."""

    def test_welcome_detected(self) -> None:
        assert _check_xpath_response(b"welcome back", 200, ["welcome"])

    def test_not_detected(self) -> None:
        assert not _check_xpath_response(b"error 404", 200, ["welcome"])

    def test_status_zero(self) -> None:
        assert not _check_xpath_response(b"welcome", 0, ["welcome"])

    def test_case_insensitive(self) -> None:
        assert _check_xpath_response(b"WELCOME", 200, ["welcome"])

    def test_multiple_indicators(self) -> None:
        assert _check_xpath_response(b"success: token issued", 200, ["success", "token"])

    def test_empty_body(self) -> None:
        assert not _check_xpath_response(b"", 200, ["welcome"])


class TestTestBaseline:
    """Testes para _test_baseline."""

    @pytest.mark.asyncio
    async def test_success(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client.get.return_value = mock_resp

        status, size, body = await _test_baseline(mock_client, "https://example.com")
        assert status == 200
        assert size == 2
        assert body == b"ok"

    @pytest.mark.asyncio
    async def test_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("fail")

        status, size, body = await _test_baseline(mock_client, "https://example.com")
        assert status == 0
        assert size == 0
        assert body == b""


class TestTestDetect:
    """Testes para _test_detect."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"welcome back success token"
        mock_client.post.return_value = mock_resp
        mock_client.get.return_value = mock_resp

        results = await _test_detect(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_detect(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestAuthBypass:
    """Testes para _test_auth_bypass."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"success token"
        mock_client.post.return_value = mock_resp
        mock_client.get.return_value = mock_resp

        results = await _test_auth_bypass(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_auth_bypass(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestExtract:
    """Testes para _test_extract."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client.post.return_value = mock_resp
        mock_client.get.return_value = mock_resp

        results = await _test_extract(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_extract(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestBlind:
    """Testes para _test_blind."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client.get.return_value = mock_resp

        results = await _test_blind(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_blind(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestBypass:
    """Testes para _test_bypass."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client.post.return_value = mock_resp

        results = await _test_bypass(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_bypass(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestPrintResults:
    """Testes para print_results."""

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = XPathiResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=["always_true_string_user"],
            blocked_techniques=[],
            issues=["VULN: always_true_string_user"],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "VULNERAVEIS" in output

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = XPathiResult(
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
        output = capsys.readouterr().out
        assert "Nenhuma XPath Injection detectada" in output


@pytest.mark.smoke
class TestBuildParser:
    """Testes para build_parser."""

    def test_has_url(self) -> None:
        parser = build_parser()
        assert any(a.dest == "url" for a in parser._actions)

    def test_has_category(self) -> None:
        parser = build_parser()
        assert any(a.dest == "category" for a in parser._actions)

    def test_has_concurrency(self) -> None:
        parser = build_parser()
        assert any(a.dest == "concurrency" for a in parser._actions)

    def test_category_choices(self) -> None:
        parser = build_parser()
        for action in parser._actions:
            if action.dest == "category":
                assert set(action.choices or []) == set(_CATEGORY_MAP.keys())


class TestMain:
    """Testes para main()."""

    def test_main_returns_int(self) -> None:
        with patch("sys.argv", ["mytools-xpathi"]), \
             patch("mytools.web.xpathinject.run_main_loop", return_value=0) as mock_loop:
            result = main()
            assert isinstance(result, int)
            mock_loop.assert_called_once()

    def test_main_passes_args(self) -> None:
        with patch("sys.argv", ["mytools-xpathi", "https://example.com"]), \
             patch("mytools.web.xpathinject.run_main_loop", return_value=0):
            result = main()
            assert result == 0


class TestIntegration:
    """Testes de integracao com mocks."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_run_scan_all_categories(self) -> None:
        from mytools.web.xpathinject import run_scan

        respx.route(method="GET", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="not vulnerable"),
        )
        respx.route(method="POST", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="not vulnerable"),
        )
        result = await run_scan(
            target="https://example.com",
            categories=[],
            timeout=10,
            concurrency=5,
            output_file=None,
            verbose=False,
        )
        assert result == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_run_scan_vulnerable(self) -> None:
        from mytools.web.xpathinject import run_scan

        respx.route(method="GET", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="ok"),
        )
        respx.route(method="POST", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="welcome success token"),
        )
        result = await run_scan(
            target="https://example.com",
            categories=["detect"],
            timeout=10,
            concurrency=5,
            output_file=None,
            verbose=False,
        )
        assert result == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_run_scan_connection_error(self) -> None:
        from mytools.web.xpathinject import run_scan

        respx.route(url__startswith="https://example.com/").mock(
            side_effect=httpx.ConnectError("Connection refused"),
        )
        result = await run_scan(
            target="https://example.com",
            categories=["detect"],
            timeout=10,
            concurrency=5,
            output_file=None,
            verbose=False,
        )
        assert result == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_run_scan_with_output(self, tmp_path: object) -> None:
        from mytools.web.xpathinject import run_scan

        respx.route(method="GET", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="ok"),
        )
        respx.route(method="POST", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="not vulnerable"),
        )
        output_file = str(tmp_path) + "/output.json"  # type: ignore[operator]
        result = await run_scan(
            target="https://example.com",
            categories=["detect"],
            timeout=10,
            concurrency=5,
            output_file=output_file,
            verbose=False,
        )
        assert result == 0

    def test_run_once(self) -> None:
        args = MagicMock()
        args.url = "https://example.com"
        args.category = "detect"
        args.timeout = 10
        args.concurrency = 5
        args.output = None
        args.verbose = False

        with patch("mytools.web.xpathinject.safe_asyncio_run", return_value=0) as mock_run:
            from mytools.web.xpathinject import run_once
            result = run_once(args)
            assert result == 0
            mock_run.assert_called_once()

    def test_run_once_no_category(self) -> None:
        args = MagicMock()
        args.url = "https://example.com"
        args.category = None
        args.timeout = 10
        args.concurrency = 5
        args.output = None
        args.verbose = False

        with patch("mytools.web.xpathinject.safe_asyncio_run", return_value=0):
            from mytools.web.xpathinject import run_once
            result = run_once(args)
            assert result == 0
