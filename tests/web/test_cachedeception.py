#!/usr/bin/env python3
"""Testes unitarios do modulo de Web Cache Deception."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.cachedeception import (
    _BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    _EXTENSION_PAYLOADS,
    _FRAMEWORK_PAYLOADS,
    _PARAMETER_PAYLOADS,
    _PATH_PAYLOADS,
    _SENSITIVE_PATHS,
    DeceptionAttempt,
    DeceptionResult,
    _check_deception_response,
    _test_baseline,
    _test_bypass,
    _test_extension,
    _test_framework,
    _test_parameter,
    _test_path,
    build_parser,
    main,
    print_results,
)


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_has_extension(self) -> None:
        assert "extension" in _CATEGORY_MAP

    def test_has_path(self) -> None:
        assert "path" in _CATEGORY_MAP

    def test_has_parameter(self) -> None:
        assert "parameter" in _CATEGORY_MAP

    def test_has_framework(self) -> None:
        assert "framework" in _CATEGORY_MAP

    def test_has_bypass(self) -> None:
        assert "bypass" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 5


class TestExtensionPayloads:
    """Testes para _EXTENSION_PAYLOADS."""

    def test_has_css_ext(self) -> None:
        assert any("css_ext" in p[0] for p in _EXTENSION_PAYLOADS)

    def test_has_js_ext(self) -> None:
        assert any("js_ext" in p[0] for p in _EXTENSION_PAYLOADS)

    def test_has_png_ext(self) -> None:
        assert any("png_ext" in p[0] for p in _EXTENSION_PAYLOADS)

    def test_has_gif_ext(self) -> None:
        assert any("gif_ext" in p[0] for p in _EXTENSION_PAYLOADS)

    def test_has_ico_ext(self) -> None:
        assert any("ico_ext" in p[0] for p in _EXTENSION_PAYLOADS)

    def test_count(self) -> None:
        assert len(_EXTENSION_PAYLOADS) == 5

    def test_all_have_extension(self) -> None:
        for _, payload, _ in _EXTENSION_PAYLOADS:
            assert payload.endswith((".css", ".js", ".png", ".gif", ".ico"))


class TestPathPayloads:
    """Testes para _PATH_PAYLOADS."""

    def test_has_trailing_slash(self) -> None:
        assert any("trailing_slash" in p[0] for p in _PATH_PAYLOADS)

    def test_has_double_slash(self) -> None:
        assert any("double_slash" in p[0] for p in _PATH_PAYLOADS)

    def test_has_semicolon_path(self) -> None:
        assert any("semicolon_path" in p[0] for p in _PATH_PAYLOADS)

    def test_has_fragment_bypass(self) -> None:
        assert any("fragment_bypass" in p[0] for p in _PATH_PAYLOADS)

    def test_has_case_path(self) -> None:
        assert any("case_path" in p[0] for p in _PATH_PAYLOADS)

    def test_count(self) -> None:
        assert len(_PATH_PAYLOADS) == 5


class TestParameterPayloads:
    """Testes para _PARAMETER_PAYLOADS."""

    def test_has_cache_param(self) -> None:
        assert any("cache_param" in p[0] for p in _PARAMETER_PAYLOADS)

    def test_has_utm_source(self) -> None:
        assert any("utm_source" in p[0] for p in _PARAMETER_PAYLOADS)

    def test_has_cb_param(self) -> None:
        assert any("cb_param" in p[0] for p in _PARAMETER_PAYLOADS)

    def test_has_nocache_bypass(self) -> None:
        assert any("nocache_bypass" in p[0] for p in _PARAMETER_PAYLOADS)

    def test_has_version_param(self) -> None:
        assert any("version_param" in p[0] for p in _PARAMETER_PAYLOADS)

    def test_count(self) -> None:
        assert len(_PARAMETER_PAYLOADS) == 5

    def test_all_have_question_mark(self) -> None:
        for _, payload, _ in _PARAMETER_PAYLOADS:
            assert payload.startswith("?")


class TestFrameworkPayloads:
    """Testes para _FRAMEWORK_PAYLOADS."""

    def test_has_django_static(self) -> None:
        assert any("django_static" in p[0] for p in _FRAMEWORK_PAYLOADS)

    def test_has_flask_static(self) -> None:
        assert any("flask_static" in p[0] for p in _FRAMEWORK_PAYLOADS)

    def test_has_express_static(self) -> None:
        assert any("express_static" in p[0] for p in _FRAMEWORK_PAYLOADS)

    def test_has_rails_asset(self) -> None:
        assert any("rails_asset" in p[0] for p in _FRAMEWORK_PAYLOADS)

    def test_has_spring_static(self) -> None:
        assert any("spring_static" in p[0] for p in _FRAMEWORK_PAYLOADS)

    def test_count(self) -> None:
        assert len(_FRAMEWORK_PAYLOADS) == 5

    def test_all_have_static_path(self) -> None:
        for _, payload, _ in _FRAMEWORK_PAYLOADS:
            assert any(p in payload for p in ["/static/", "/public/", "/assets/", "/resources/"])


class TestBypassPayloads:
    """Testes para _BYPASS_PAYLOADS."""

    def test_has_double_encode(self) -> None:
        assert any("double_encode" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_null_byte(self) -> None:
        assert any("null_byte" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_unicode_path(self) -> None:
        assert any("unicode_path" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_backslash_path(self) -> None:
        assert any("backslash_path" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_case_extension(self) -> None:
        assert any("case_extension" in p[0] for p in _BYPASS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BYPASS_PAYLOADS) == 5


class TestSensitivePaths:
    """Testes para _SENSITIVE_PATHS."""

    def test_has_admin(self) -> None:
        assert "/admin" in _SENSITIVE_PATHS

    def test_has_secret(self) -> None:
        assert "/secret" in _SENSITIVE_PATHS

    def test_has_profile(self) -> None:
        assert "/profile" in _SENSITIVE_PATHS

    def test_has_dashboard(self) -> None:
        assert "/dashboard" in _SENSITIVE_PATHS

    def test_count(self) -> None:
        assert len(_SENSITIVE_PATHS) == 10


class TestDeceptionAttempt:
    """Testes para dataclass DeceptionAttempt."""

    def test_create(self) -> None:
        attempt = DeceptionAttempt(
            technique="css_ext",
            category="extension",
            payload="/admin.css",
            param="/admin",
            method="get_path",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=200,
            status_changed=False,
            size_changed=True,
            vulnerable=True,
            details="admin found",
            error="",
        )
        assert attempt.technique == "css_ext"
        assert attempt.vulnerable is True

    def test_immutable(self) -> None:
        attempt = DeceptionAttempt(
            technique="test", category="extension", payload="p",
            param="/admin", method="get_path", status_baseline=200, status_test=200,
            size_baseline=100, size_test=100, status_changed=False,
            size_changed=False, vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            attempt.technique = "changed"  # type: ignore[misc]


class TestDeceptionResult:
    """Testes para dataclass DeceptionResult."""

    def test_create(self) -> None:
        result = DeceptionResult(
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
        result = DeceptionResult(
            target="t", baseline_status=200, baseline_size=100,
            tls=True, attempts=[], vulnerable_techniques=[],
            blocked_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            result.target = "changed"  # type: ignore[misc]


class TestCheckDeceptionResponse:
    """Testes para _check_deception_response."""

    def test_cache_hit_detected(self) -> None:
        assert _check_deception_response(b"ok", 200, {"x-cache": "HIT"}, ["HIT"])

    def test_not_detected(self) -> None:
        assert not _check_deception_response(b"error 404", 200, {}, ["admin"])

    def test_status_zero(self) -> None:
        assert not _check_deception_response(b"ok", 0, {}, ["HIT"])

    def test_case_insensitive(self) -> None:
        assert _check_deception_response(b"HIT", 200, {"x-cache": "HIT"}, ["hit"])

    def test_header_match(self) -> None:
        assert _check_deception_response(b"", 200, {"x-cache": "HIT"}, ["hit"])

    def test_empty_body(self) -> None:
        assert not _check_deception_response(b"", 200, {}, ["admin"])


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


class TestTestExtension:
    """Testes para _test_extension."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"admin"
        mock_resp.headers = {"x-cache": "HIT"}
        mock_client.get.return_value = mock_resp

        results = await _test_extension(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_extension(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestPath:
    """Testes para _test_path."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"admin"
        mock_resp.headers = {"x-cache": "HIT"}
        mock_client.get.return_value = mock_resp

        results = await _test_path(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_path(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestParameter:
    """Testes para _test_parameter."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_resp.headers = {"cache-control": "public"}
        mock_client.get.return_value = mock_resp

        results = await _test_parameter(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_parameter(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestFramework:
    """Testes para _test_framework."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"static"
        mock_resp.headers = {"x-cache": "HIT"}
        mock_client.get.return_value = mock_resp

        results = await _test_framework(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_framework(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestBypass:
    """Testes para _test_bypass."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"admin"
        mock_resp.headers = {"x-cache": "HIT"}
        mock_client.get.return_value = mock_resp

        results = await _test_bypass(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_bypass(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestPrintResults:
    """Testes para print_results."""

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = DeceptionResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[
                DeceptionAttempt(
                    technique="css_ext", category="extension",
                    payload="/admin.css", param="/admin",
                    method="get_path", status_baseline=200, status_test=200,
                    size_baseline=100, size_test=200, status_changed=False,
                    size_changed=True, vulnerable=True, details="admin found",
                    error="",
                ),
            ],
            vulnerable_techniques=["css_ext"],
            blocked_techniques=[],
            issues=["VULN: css_ext via /admin"],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "VULNERABILIDADES DETECTADAS" in output

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = DeceptionResult(
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
        assert "Nenhuma Web Cache Deception detectada" in output


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
        with patch("sys.argv", ["mytools-cachedec"]), \
             patch("mytools.web.cachedeception.run_main_loop", return_value=0) as mock_loop:
            result = main()
            assert isinstance(result, int)
            mock_loop.assert_called_once()

    def test_main_passes_args(self) -> None:
        with patch("sys.argv", ["mytools-cachedec", "https://example.com"]), \
             patch("mytools.web.cachedeception.run_main_loop", return_value=0):
            result = main()
            assert result == 0


class TestIntegration:
    """Testes de integracao com mocks."""

    @pytest.mark.asyncio
    async def test_run_scan_all_categories(self) -> None:
        from mytools.web.cachedeception import run_scan

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"not vulnerable"
        mock_resp.headers = {}
        mock_client.get.return_value = mock_resp
        mock_client.post.return_value = mock_resp

        with patch("mytools.web.cachedeception.create_async_client", return_value=mock_client):
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
    async def test_run_scan_vulnerable(self) -> None:
        from mytools.web.cachedeception import run_scan

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client

        mock_baseline = MagicMock()
        mock_baseline.status_code = 200
        mock_baseline.content = b"ok"
        mock_baseline.headers = {}

        mock_vuln = MagicMock()
        mock_vuln.status_code = 200
        mock_vuln.content = b"admin"
        mock_vuln.headers = {"x-cache": "HIT"}

        call_count = 0

        async def side_effect_get(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count <= 1:
                return mock_baseline
            return mock_vuln

        mock_client.get = AsyncMock(side_effect=side_effect_get)
        mock_client.post = AsyncMock(return_value=mock_vuln)

        with patch("mytools.web.cachedeception.create_async_client", return_value=mock_client):
            result = await run_scan(
                target="https://example.com",
                categories=["extension"],
                timeout=10,
                concurrency=5,
                output_file=None,
                verbose=False,
            )
            assert result == 1

    @pytest.mark.asyncio
    async def test_run_scan_connection_error(self) -> None:
        from mytools.web.cachedeception import run_scan

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.status_code = 0
        mock_resp.content = b""
        mock_resp.headers = {}
        mock_client.get.return_value = mock_resp

        with patch("mytools.web.cachedeception.create_async_client", return_value=mock_client):
            result = await run_scan(
                target="https://example.com",
                categories=["extension"],
                timeout=10,
                concurrency=5,
                output_file=None,
                verbose=False,
            )
            assert result == 1

    @pytest.mark.asyncio
    async def test_run_scan_with_output(self, tmp_path: object) -> None:
        from mytools.web.cachedeception import run_scan

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_get = MagicMock()
        mock_get.status_code = 200
        mock_get.content = b"ok"
        mock_get.headers = {}
        mock_client.get.return_value = mock_get

        mock_post = MagicMock()
        mock_post.status_code = 200
        mock_post.content = b"not vulnerable"
        mock_post.headers = {}
        mock_client.post.return_value = mock_post

        output_file = str(tmp_path) + "/output.json"  # type: ignore[operator]
        with patch("mytools.web.cachedeception.create_async_client", return_value=mock_client):
            result = await run_scan(
                target="https://example.com",
                categories=["extension"],
                timeout=10,
                concurrency=5,
                output_file=output_file,
                verbose=False,
            )
            assert result == 0

    def test_run_once(self) -> None:
        args = MagicMock()
        args.url = "https://example.com"
        args.category = "extension"
        args.timeout = 10
        args.concurrency = 5
        args.output = None
        args.verbose = False

        with patch("mytools.web.cachedeception.safe_asyncio_run", return_value=0) as mock_run:
            from mytools.web.cachedeception import run_once
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

        with patch("mytools.web.cachedeception.safe_asyncio_run", return_value=0):
            from mytools.web.cachedeception import run_once
            result = run_once(args)
            assert result == 0
