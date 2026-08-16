#!/usr/bin/env python3
"""Testes unitarios do modulo de Deserialization Injection."""

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mytools.web.deserialinject import (
    _BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    _DETECT_PAYLOADS,
    _DOTNET_PAYLOADS,
    _JAVA_PAYLOADS,
    _NODEJS_PAYLOADS,
    _PHP_PAYLOADS,
    _PYTHON_PAYLOADS,
    _RUBY_PAYLOADS,
    _SSI_PARAMS,
    DeserialAttempt,
    DeserialResult,
    _check_deserial_response,
    _test_baseline,
    _test_bypass,
    _test_detect,
    _test_dotnet,
    _test_java,
    _test_nodejs,
    _test_php,
    _test_python,
    _test_ruby,
    banner_art,
    build_parser,
    main,
    print_results,
)


def _read_json_output(path: str) -> dict:
    """Le um arquivo JSON de saida (helper sincrono p/ testes async)."""

    return json.loads(Path(path).read_text(encoding="utf-8"))


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

    def test_has_ruby(self) -> None:
        assert "ruby" in _CATEGORY_MAP

    def test_has_dotnet(self) -> None:
        assert "dotnet" in _CATEGORY_MAP

    def test_has_nodejs(self) -> None:
        assert "nodejs" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 8


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
            technique="test",
            category="php",
            payload="p",
            param="data",
            method="post_json",
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
            target="t",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
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

        results = await _test_python(
            mock_client, "https://example.com", (200, 100, b"")
        )
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_python(
            mock_client, "https://example.com", (200, 100, b"")
        )
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

        results = await _test_detect(
            mock_client, "https://example.com", (200, 100, b"")
        )
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_detect(
            mock_client, "https://example.com", (200, 100, b"")
        )
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

        results = await _test_bypass(
            mock_client, "https://example.com", (200, 100, b"")
        )
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_bypass(
            mock_client, "https://example.com", (200, 100, b"")
        )
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

    def test_vulnerable_without_details(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = DeserialResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[
                DeserialAttempt(
                    technique="php_basic",
                    category="php",
                    payload="payload",
                    param="data",
                    method="post_json",
                    status_baseline=200,
                    status_test=200,
                    size_baseline=100,
                    size_test=200,
                    status_changed=False,
                    size_changed=True,
                    vulnerable=True,
                    details="",
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
        assert "php_basic" in output

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

    def test_with_blocked_and_errors(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = DeserialResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[
                DeserialAttempt(
                    technique="php_basic",
                    category="php",
                    payload="payload",
                    param="data",
                    method="post_json",
                    status_baseline=200,
                    status_test=0,
                    size_baseline=100,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error="403 Forbidden",
                ),
                DeserialAttempt(
                    technique="java_ysoserial",
                    category="java",
                    payload="payload",
                    param="data",
                    method="post_json",
                    status_baseline=200,
                    status_test=0,
                    size_baseline=100,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error="Connection refused",
                ),
            ],
            vulnerable_techniques=[],
            blocked_techniques=["php_basic"],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "payloads bloqueados (403/429)" in output
        assert "1 erros de conexao" in output


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
        with (
            patch("sys.argv", ["mytools-deserial"]),
            patch(
                "mytools.web.deserialinject.run_main_loop", return_value=0
            ) as mock_loop,
        ):
            result = main()
            assert isinstance(result, int)
            mock_loop.assert_called_once()

    def test_main_passes_args(self) -> None:
        with (
            patch("sys.argv", ["mytools-deserial", "https://example.com"]),
            patch("mytools.web.deserialinject.run_main_loop", return_value=0),
        ):
            result = main()
            assert result == 0


class TestMainGuard:
    """Testes para o guard if __name__ == '__main__'."""

    def test_guard_runs(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit),
        ):
            import runpy

            runpy.run_module("mytools.web.deserialinject", run_name="__main__")


class TestBannerArt:
    """Testes para banner_art."""

    def test_runs(self) -> None:
        banner_art()


class TestRubyPayloads:
    """Testes para _RUBY_PAYLOADS."""

    def test_not_empty(self) -> None:
        assert len(_RUBY_PAYLOADS) > 0

    def test_count(self) -> None:
        assert len(_RUBY_PAYLOADS) == 5

    def test_has_marshal(self) -> None:
        names = [t[0] for t in _RUBY_PAYLOADS]
        assert "ruby_marshal" in names

    def test_has_yaml(self) -> None:
        names = [t[0] for t in _RUBY_PAYLOADS]
        assert "ruby_yaml" in names

    def test_has_erb(self) -> None:
        names = [t[0] for t in _RUBY_PAYLOADS]
        assert "ruby_erb" in names

    def test_tuple_format(self) -> None:
        for item in _RUBY_PAYLOADS:
            assert isinstance(item, tuple)
            assert len(item) == 3


class TestDotnetPayloads:
    """Testes para _DOTNET_PAYLOADS."""

    def test_not_empty(self) -> None:
        assert len(_DOTNET_PAYLOADS) > 0

    def test_count(self) -> None:
        assert len(_DOTNET_PAYLOADS) == 5

    def test_has_binary(self) -> None:
        names = [t[0] for t in _DOTNET_PAYLOADS]
        assert "dotnet_binary" in names

    def test_has_viewstate(self) -> None:
        names = [t[0] for t in _DOTNET_PAYLOADS]
        assert "dotnet_viewstate" in names

    def test_has_jsonnet(self) -> None:
        names = [t[0] for t in _DOTNET_PAYLOADS]
        assert "dotnet_jsonnet" in names

    def test_tuple_format(self) -> None:
        for item in _DOTNET_PAYLOADS:
            assert isinstance(item, tuple)
            assert len(item) == 3


class TestNodejsPayloads:
    """Testes para _NODEJS_PAYLOADS."""

    def test_not_empty(self) -> None:
        assert len(_NODEJS_PAYLOADS) > 0

    def test_count(self) -> None:
        assert len(_NODEJS_PAYLOADS) == 5

    def test_has_serialize(self) -> None:
        names = [t[0] for t in _NODEJS_PAYLOADS]
        assert "node_serialize" in names

    def test_has_child(self) -> None:
        names = [t[0] for t in _NODEJS_PAYLOADS]
        assert "node_child" in names

    def test_has_fs(self) -> None:
        names = [t[0] for t in _NODEJS_PAYLOADS]
        assert "node_fs" in names

    def test_tuple_format(self) -> None:
        for item in _NODEJS_PAYLOADS:
            assert isinstance(item, tuple)
            assert len(item) == 3


class TestTestRuby:
    """Testes para _test_ruby."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"admin"
        mock_client.post.return_value = mock_resp
        results = await _test_ruby(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.ConnectError("fail")
        results = await _test_ruby(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestDotnet:
    """Testes para _test_dotnet."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"admin"
        mock_client.post.return_value = mock_resp
        results = await _test_dotnet(
            mock_client, "https://example.com", (200, 100, b"")
        )
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.ConnectError("fail")
        results = await _test_dotnet(
            mock_client, "https://example.com", (200, 100, b"")
        )
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestNodejs:
    """Testes para _test_nodejs."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"admin"
        mock_client.post.return_value = mock_resp
        results = await _test_nodejs(
            mock_client, "https://example.com", (200, 100, b"")
        )
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.ConnectError("fail")
        results = await _test_nodejs(
            mock_client, "https://example.com", (200, 100, b"")
        )
        assert len(results) > 0
        assert all(r.error for r in results)


class TestBinaryPayloads:
    """Os payloads binarios devem ser bytes reais, nao escape-text."""

    def test_java_magic_bytes_are_bytes(self) -> None:
        java = {t: (p, i) for t, p, i in _JAVA_PAYLOADS}
        for t in (
            "java_magic_bytes",
            "java_obj_stream",
            "java_gadget_cc",
            "java_gadget_spring",
        ):
            payload, indicators = java[t]
            assert isinstance(payload, bytes)
            assert payload[:2] == b"\xac\xed"
            assert b"\xac\xed" in indicators

    def test_java_jndi_stays_str(self) -> None:
        java = {t: (p, i) for t, p, i in _JAVA_PAYLOADS}
        assert isinstance(java["java_jndi"][0], str)

    def test_python_binary_payloads_are_bytes(self) -> None:
        py = {t: (p, i) for t, p, i in _PYTHON_PAYLOADS}
        for t in ("python_pickle", "python_marshal", "python_shelve"):
            assert isinstance(py[t][0], bytes)

    def test_python_text_payloads_stay_str(self) -> None:
        py = {t: (p, i) for t, p, i in _PYTHON_PAYLOADS}
        for t in ("python_reduce", "python_yaml"):
            assert isinstance(py[t][0], str)

    def test_ruby_marshal_is_bytes(self) -> None:
        ruby = {t: (p, i) for t, p, i in _RUBY_PAYLOADS}
        assert isinstance(ruby["ruby_marshal"][0], bytes)
        assert b"\x04\x08" in ruby["ruby_marshal"][1]


class TestCheckDeserialResponseBytes:
    """Indicadores de bytes devem ser casados contra o corpo cru."""

    def test_bytes_indicator_in_raw_body(self) -> None:
        assert _check_deserial_response(b"\xac\xed\x00\x05", 200, [b"\xac\xed", "java"])

    def test_bytes_indicator_not_present(self) -> None:
        assert not _check_deserial_response(b"java html page", 200, [b"\xac\xed"])

    def test_mixed_str_and_bytes_indicators(self) -> None:
        assert _check_deserial_response(
            b"java serialization", 200, [b"\xac\xed", "serialization"]
        )

    def test_escape_text_does_not_match_bytes_indicator(self) -> None:
        assert not _check_deserial_response(b"\\xac\\xed", 200, [b"\xac\xed"])


class TestSendSites:
    """Send sites enviam content bytes e fazem um request por payload."""

    @pytest.mark.asyncio
    async def test_java_sends_bytes_once_per_payload(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"java"
        mock_client.post.return_value = mock_resp

        results = await _test_java(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == len(_JAVA_PAYLOADS)
        assert mock_client.post.call_count == len(_JAVA_PAYLOADS)
        for call in mock_client.post.call_args_list:
            assert isinstance(call.kwargs.get("content"), bytes)

    @pytest.mark.asyncio
    async def test_python_sends_bytes_once_per_payload(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"python"
        mock_client.post.return_value = mock_resp

        results = await _test_python(
            mock_client, "https://example.com", (200, 100, b"")
        )
        assert len(results) == len(_PYTHON_PAYLOADS)
        assert mock_client.post.call_count == len(_PYTHON_PAYLOADS)
        for call in mock_client.post.call_args_list:
            assert isinstance(call.kwargs.get("content"), bytes)

    @pytest.mark.asyncio
    async def test_ruby_sends_bytes_content_without_crash(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ruby"
        mock_client.post.return_value = mock_resp

        results = await _test_ruby(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) == len(_RUBY_PAYLOADS)
        assert mock_client.post.call_count == len(_RUBY_PAYLOADS)
        for call in mock_client.post.call_args_list:
            assert isinstance(call.kwargs.get("content"), bytes)

    @pytest.mark.asyncio
    async def test_dotnet_sends_once_per_payload(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"dotnet"
        mock_client.post.return_value = mock_resp

        results = await _test_dotnet(
            mock_client, "https://example.com", (200, 100, b"")
        )
        assert len(results) == len(_DOTNET_PAYLOADS)
        assert mock_client.post.call_count == len(_DOTNET_PAYLOADS)


class TestTimingAnomalyBaseline:
    """timing_anomaly deve comparar com um baseline benigno."""

    @pytest.mark.asyncio
    async def test_vulnerable_when_slow_and_faster_than_baseline(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client.post.return_value = mock_resp

        values = iter([0.0, 0.1, 0.2, 3.5] * 3)
        with patch("mytools.web.deserialinject.time.monotonic", side_effect=values):
            results = await _test_detect(
                mock_client, "https://example.com", (200, 100, b"")
            )
        timing = [r for r in results if r.technique == "timing_anomaly"]
        assert timing
        assert all(r.vulnerable for r in timing)

    @pytest.mark.asyncio
    async def test_not_vulnerable_when_baseline_equally_slow(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client.post.return_value = mock_resp

        values = iter([0.0, 3.0, 3.1, 5.5] * 3)
        with patch("mytools.web.deserialinject.time.monotonic", side_effect=values):
            results = await _test_detect(
                mock_client, "https://example.com", (200, 100, b"")
            )
        timing = [r for r in results if r.technique == "timing_anomaly"]
        assert timing
        assert all(not r.vulnerable for r in timing)

    @pytest.mark.asyncio
    async def test_not_vulnerable_when_fast(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client.post.return_value = mock_resp

        values = iter([0.0, 0.1, 0.2, 0.5] * 3)
        with patch("mytools.web.deserialinject.time.monotonic", side_effect=values):
            results = await _test_detect(
                mock_client, "https://example.com", (200, 100, b"")
            )
        timing = [r for r in results if r.technique == "timing_anomaly"]
        assert timing
        assert all(not r.vulnerable for r in timing)


class TestIntegration:
    """Testes de integracao com mocks."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_run_scan_all_categories(self) -> None:
        from mytools.web.deserialinject import run_scan

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
    async def test_run_scan_json_output(self) -> None:
        from mytools.web.deserialinject import run_scan

        respx.route(method="GET", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="not vulnerable"),
        )
        respx.route(method="POST", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="not vulnerable"),
        )
        with patch("mytools.web.deserialinject.print_json") as mock_print:
            result = await run_scan(
                target="https://example.com",
                categories=["php"],
                timeout=10,
                concurrency=5,
                output_file=None,
                verbose=False,
                json_output=True,
            )
        assert result == 0
        mock_print.assert_called_once()

    @pytest.mark.asyncio
    @respx.mock
    async def test_run_scan_vulnerable(self) -> None:
        from mytools.web.deserialinject import run_scan

        respx.route(method="GET", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="ok"),
        )
        respx.route(method="POST", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="admin"),
        )
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
    @respx.mock
    async def test_run_scan_connection_error(self) -> None:
        from mytools.web.deserialinject import run_scan

        respx.route(url__startswith="https://example.com/").mock(
            side_effect=httpx.ConnectError("Connection refused"),
        )
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
    @respx.mock
    async def test_run_scan_invalid_category(self) -> None:
        from mytools.web.deserialinject import run_scan

        respx.route(method="GET", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="ok"),
        )
        respx.route(method="POST", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="not vulnerable"),
        )
        result = await run_scan(
            target="https://example.com",
            categories=["invalid"],
            timeout=10,
            concurrency=5,
            output_file=None,
            verbose=False,
        )
        assert result == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_run_scan_with_output(self, tmp_path: object) -> None:
        from mytools.web.deserialinject import run_scan

        respx.route(method="GET", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="ok"),
        )
        respx.route(method="POST", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="not vulnerable"),
        )
        output_file = str(tmp_path) + "/output.json"  # type: ignore[operator]
        result = await run_scan(
            target="https://example.com",
            categories=["php"],
            timeout=10,
            concurrency=5,
            output_file=output_file,
            verbose=False,
        )
        assert result == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_run_scan_with_output_binary_payload(self, tmp_path: object) -> None:
        from mytools.web.deserialinject import run_scan

        respx.route(method="GET", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="ok"),
        )
        respx.route(method="POST", url__startswith="https://example.com/").mock(
            return_value=httpx.Response(200, text="not vulnerable"),
        )
        output_file = str(tmp_path) + "/output_bin.json"  # type: ignore[operator]
        result = await run_scan(
            target="https://example.com",
            categories=["java"],
            timeout=10,
            concurrency=5,
            output_file=output_file,
            verbose=False,
        )
        assert result == 0

        data = _read_json_output(output_file)
        assert len(data["attempts"]) == len(_JAVA_PAYLOADS)
        assert all(isinstance(a["payload"], str) for a in data["attempts"])
        assert any(a["payload"].startswith("aced") for a in data["attempts"])

    def test_run_once(self) -> None:
        args = MagicMock()
        args.url = "https://example.com"
        args.category = "php"
        args.timeout = 10
        args.concurrency = 5
        args.output = None
        args.verbose = False
        args.log_file = None
        args.theme = None

        with patch(
            "mytools.web.deserialinject.run_scan",
            new_callable=AsyncMock,
            return_value=0,
        ) as mock_scan:
            from mytools.web.deserialinject import run_once

            result = run_once(args)
            assert result == 0
            mock_scan.assert_called_once()

    def test_run_once_no_category(self) -> None:
        args = MagicMock()
        args.url = "https://example.com"
        args.category = None
        args.timeout = 10
        args.concurrency = 5
        args.output = None
        args.verbose = False
        args.log_file = None
        args.theme = None

        with patch(
            "mytools.web.deserialinject.run_scan",
            new_callable=AsyncMock,
            return_value=0,
        ):
            from mytools.web.deserialinject import run_once

            result = run_once(args)
            assert result == 0
