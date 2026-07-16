#!/usr/bin/env python3
"""Testes unitarios do modulo de Deserialization Injection."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.deserialinject import (
    _BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    _DETECT_PAYLOADS,
    _JAVA_PAYLOADS,
    _PHP_PAYLOADS,
    _PYTHON_PAYLOADS,
    _SSI_PARAMS,
    DeserialAttempt,
    DeserialResult,
    _check_deserial_response,
    _test_baseline,
    _test_bypass,
    _test_detect,
    _test_java,
    _test_php,
    _test_python,
    build_parser,
    main,
    print_results,
)


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_has_php(self) -> None:
        assert "php" in _CATEGORY_MAP

    def test_has_java(self) -> None:
        assert "java" in _CATEGORY_MAP

    def test_has_python(self) -> None:
        assert "python" in _CATEGORY_MAP

    def test_has_detect(self) -> None:
        assert "detect" in _CATEGORY_MAP

    def test_has_bypass(self) -> None:
        assert "bypass" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 5


class TestPHPPayloads:
    """Testes para _PHP_PAYLOADS."""

    def test_has_php_basic(self) -> None:
        assert any("php_basic" in p[0] for p in _PHP_PAYLOADS)

    def test_has_php_pop_chain(self) -> None:
        assert any("php_pop_chain" in p[0] for p in _PHP_PAYLOADS)

    def test_has_php_ref_inject(self) -> None:
        assert any("php_ref_inject" in p[0] for p in _PHP_PAYLOADS)

    def test_has_php_array_cast(self) -> None:
        assert any("php_array_cast" in p[0] for p in _PHP_PAYLOADS)

    def test_has_php_object_inject(self) -> None:
        assert any("php_object_inject" in p[0] for p in _PHP_PAYLOADS)

    def test_count(self) -> None:
        assert len(_PHP_PAYLOADS) == 5

    def test_all_have_serialize(self) -> None:
        for _, payload, _ in _PHP_PAYLOADS:
            assert any(k in payload for k in ["O:", "a:", "R:"])


class TestJavaPayloads:
    """Testes para _JAVA_PAYLOADS."""

    def test_has_java_magic_bytes(self) -> None:
        assert any("java_magic_bytes" in p[0] for p in _JAVA_PAYLOADS)

    def test_has_java_obj_stream(self) -> None:
        assert any("java_obj_stream" in p[0] for p in _JAVA_PAYLOADS)

    def test_has_java_gadget_cc(self) -> None:
        assert any("java_gadget_cc" in p[0] for p in _JAVA_PAYLOADS)

    def test_has_java_gadget_spring(self) -> None:
        assert any("java_gadget_spring" in p[0] for p in _JAVA_PAYLOADS)

    def test_has_java_jndi(self) -> None:
        assert any("java_jndi" in p[0] for p in _JAVA_PAYLOADS)

    def test_count(self) -> None:
        assert len(_JAVA_PAYLOADS) == 5


class TestPythonPayloads:
    """Testes para _PYTHON_PAYLOADS."""

    def test_has_python_pickle(self) -> None:
        assert any("python_pickle" in p[0] for p in _PYTHON_PAYLOADS)

    def test_has_python_reduce(self) -> None:
        assert any("python_reduce" in p[0] for p in _PYTHON_PAYLOADS)

    def test_has_python_yaml(self) -> None:
        assert any("python_yaml" in p[0] for p in _PYTHON_PAYLOADS)

    def test_has_python_marshal(self) -> None:
        assert any("python_marshal" in p[0] for p in _PYTHON_PAYLOADS)

    def test_has_python_shelve(self) -> None:
        assert any("python_shelve" in p[0] for p in _PYTHON_PAYLOADS)

    def test_count(self) -> None:
        assert len(_PYTHON_PAYLOADS) == 5


class TestDetectPayloads:
    """Testes para _DETECT_PAYLOADS."""

    def test_has_error_leak(self) -> None:
        assert any("error_leak" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_timing_anomaly(self) -> None:
        assert any("timing_anomaly" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_reflected_data(self) -> None:
        assert any("reflected_data" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_type_confusion(self) -> None:
        assert any("type_confusion" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_cookie_inject(self) -> None:
        assert any("cookie_inject" in p[0] for p in _DETECT_PAYLOADS)

    def test_count(self) -> None:
        assert len(_DETECT_PAYLOADS) == 5


class TestBypassPayloads:
    """Testes para _BYPASS_PAYLOADS."""

    def test_has_url_encode(self) -> None:
        assert any("url_encode" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_base64_wrap(self) -> None:
        assert any("base64_wrap" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_double_encode(self) -> None:
        assert any("double_encode" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_gzip_compress(self) -> None:
        assert any("gzip_compress" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_nested_serial(self) -> None:
        assert any("nested_serial" in p[0] for p in _BYPASS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BYPASS_PAYLOADS) == 5


class TestSSIParams:
    """Testes para _SSI_PARAMS."""

    def test_has_data(self) -> None:
        assert "data" in _SSI_PARAMS

    def test_has_json(self) -> None:
        assert "json" in _SSI_PARAMS

    def test_has_payload(self) -> None:
        assert "payload" in _SSI_PARAMS

    def test_has_input(self) -> None:
        assert "input" in _SSI_PARAMS

    def test_count(self) -> None:
        assert len(_SSI_PARAMS) == 15


class TestDeserialAttempt:
    """Testes para dataclass DeserialAttempt."""

    def test_create(self) -> None:
        attempt = DeserialAttempt(
            technique="php_basic",
            category="php",
            payload='O:4:"User":1:{s:4:"name";s:6:"admin";}',
            param="data",
            method="post_json",
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
        assert attempt.technique == "php_basic"
        assert attempt.vulnerable is True

    def test_immutable(self) -> None:
        attempt = DeserialAttempt(
            technique="test", category="php", payload="p",
            param="data", method="post_json", status_baseline=200, status_test=200,
            size_baseline=100, size_test=100, status_changed=False,
            size_changed=False, vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            attempt.technique = "changed"  # type: ignore[misc]


class TestDeserialResult:
    """Testes para dataclass DeserialResult."""

    def test_create(self) -> None:
        result = DeserialResult(
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
        result = DeserialResult(
            target="t", baseline_status=200, baseline_size=100,
            tls=True, attempts=[], vulnerable_techniques=[],
            blocked_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            result.target = "changed"  # type: ignore[misc]


class TestCheckDeserialResponse:
    """Testes para _check_deserial_response."""

    def test_admin_detected(self) -> None:
        assert _check_deserial_response(b"admin", 200, ["admin"])

    def test_not_detected(self) -> None:
        assert not _check_deserial_response(b"error 404", 200, ["admin"])

    def test_status_zero(self) -> None:
        assert not _check_deserial_response(b"admin", 0, ["admin"])

    def test_case_insensitive(self) -> None:
        assert _check_deserial_response(b"ADMIN", 200, ["admin"])

    def test_multiple_indicators(self) -> None:
        assert _check_deserial_response(b"O:4:User", 200, ["O:4", "User"])

    def test_empty_body(self) -> None:
        assert not _check_deserial_response(b"", 200, ["admin"])


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


class TestTestPHP:
    """Testes para _test_php."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"admin"
        mock_client.post.return_value = mock_resp

        results = await _test_php(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_php(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestJava:
    """Testes para _test_java."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"java"
        mock_client.post.return_value = mock_resp

        results = await _test_java(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_java(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestPython:
    """Testes para _test_python."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"pickle"
        mock_client.post.return_value = mock_resp

        results = await _test_python(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_python(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestDetect:
    """Testes para _test_detect."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"admin"
        mock_client.post.return_value = mock_resp

        results = await _test_detect(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_detect(mock_client, "https://example.com", (200, 100, b""))
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
        result = DeserialResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[
                DeserialAttempt(
                    technique="php_basic", category="php",
                    payload='O:4:"User":1:{s:4:"name";s:6:"admin";}', param="data",
                    method="post_json", status_baseline=200, status_test=200,
                    size_baseline=100, size_test=200, status_changed=False,
                    size_changed=True, vulnerable=True, details="admin found",
                    error="",
                ),
            ],
            vulnerable_techniques=["php_basic"],
            blocked_techniques=[],
            issues=["VULN: php_basic via data"],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "VULNERABILIDADES DETECTADAS" in output

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = DeserialResult(
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
        assert "Nenhuma Deserialization Injection detectada" in output


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
        with patch("sys.argv", ["mytools-deserial"]), \
             patch("mytools.web.deserialinject.run_main_loop", return_value=0) as mock_loop:
            result = main()
            assert isinstance(result, int)
            mock_loop.assert_called_once()

    def test_main_passes_args(self) -> None:
        with patch("sys.argv", ["mytools-deserial", "https://example.com"]), \
             patch("mytools.web.deserialinject.run_main_loop", return_value=0):
            result = main()
            assert result == 0


class TestIntegration:
    """Testes de integracao com mocks."""

    @pytest.mark.asyncio
    async def test_run_scan_all_categories(self) -> None:
        from mytools.web.deserialinject import run_scan

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"not vulnerable"
        mock_client.get.return_value = mock_resp
        mock_client.post.return_value = mock_resp

        with patch("mytools.web.deserialinject.create_async_client", return_value=mock_client):
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
        from mytools.web.deserialinject import run_scan

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_get = MagicMock()
        mock_get.status_code = 200
        mock_get.content = b"ok"
        mock_client.get.return_value = mock_get

        mock_post = MagicMock()
        mock_post.status_code = 200
        mock_post.content = b"admin"
        mock_client.post.return_value = mock_post

        with patch("mytools.web.deserialinject.create_async_client", return_value=mock_client):
            result = await run_scan(
                target="https://example.com",
                categories=["php"],
                timeout=10,
                concurrency=5,
                output_file=None,
                verbose=False,
            )
            assert result == 1

    @pytest.mark.asyncio
    async def test_run_scan_connection_error(self) -> None:
        from mytools.web.deserialinject import run_scan

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.status_code = 0
        mock_resp.content = b""
        mock_client.get.return_value = mock_resp

        with patch("mytools.web.deserialinject.create_async_client", return_value=mock_client):
            result = await run_scan(
                target="https://example.com",
                categories=["php"],
                timeout=10,
                concurrency=5,
                output_file=None,
                verbose=False,
            )
            assert result == 1

    @pytest.mark.asyncio
    async def test_run_scan_with_output(self, tmp_path: object) -> None:
        from mytools.web.deserialinject import run_scan

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_get = MagicMock()
        mock_get.status_code = 200
        mock_get.content = b"ok"
        mock_client.get.return_value = mock_get

        mock_post = MagicMock()
        mock_post.status_code = 200
        mock_post.content = b"not vulnerable"
        mock_client.post.return_value = mock_post

        output_file = str(tmp_path) + "/output.json"  # type: ignore[operator]
        with patch("mytools.web.deserialinject.create_async_client", return_value=mock_client):
            result = await run_scan(
                target="https://example.com",
                categories=["php"],
                timeout=10,
                concurrency=5,
                output_file=output_file,
                verbose=False,
            )
            assert result == 0

    def test_run_once(self) -> None:
        args = MagicMock()
        args.url = "https://example.com"
        args.category = "php"
        args.timeout = 10
        args.concurrency = 5
        args.output = None
        args.verbose = False

        with patch("mytools.web.deserialinject.safe_asyncio_run", return_value=0) as mock_run:
            from mytools.web.deserialinject import run_once
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

        with patch("mytools.web.deserialinject.safe_asyncio_run", return_value=0):
            from mytools.web.deserialinject import run_once
            result = run_once(args)
            assert result == 0
