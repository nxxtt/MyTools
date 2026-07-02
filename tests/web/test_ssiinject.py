#!/usr/bin/env python3
"""Testes unitarios do modulo de SSI Injection."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.ssiinject import (
    _BLIND_PAYLOADS,
    _BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    _DETECT_PAYLOADS,
    _FILE_READ_PAYLOADS,
    _RCE_PAYLOADS,
    _SSI_PARAMS,
    SSIiAttempt,
    SSIiResult,
    _check_ssi_response,
    _test_baseline,
    _test_blind,
    _test_bypass,
    _test_detect,
    _test_file_read,
    _test_rce,
    build_parser,
    main,
    print_results,
)


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_has_detect(self) -> None:
        assert "detect" in _CATEGORY_MAP

    def test_has_rce(self) -> None:
        assert "rce" in _CATEGORY_MAP

    def test_has_file_read(self) -> None:
        assert "file_read" in _CATEGORY_MAP

    def test_has_blind(self) -> None:
        assert "blind" in _CATEGORY_MAP

    def test_has_bypass(self) -> None:
        assert "bypass" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 5


class TestDetectPayloads:
    """Testes para _DETECT_PAYLOADS."""

    def test_has_basic_echo(self) -> None:
        assert any("basic_echo" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_basic_exec(self) -> None:
        assert any("basic_exec" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_basic_include(self) -> None:
        assert any("basic_include" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_basic_config(self) -> None:
        assert any("basic_config" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_basic_printenv(self) -> None:
        assert any("basic_printenv" in p[0] for p in _DETECT_PAYLOADS)

    def test_count(self) -> None:
        assert len(_DETECT_PAYLOADS) == 5

    def test_all_have_ssi_comment(self) -> None:
        for _, payload, _ in _DETECT_PAYLOADS:
            assert "<!--#" in payload


class TestRCEPayloads:
    """Testes para _RCE_PAYLOADS."""

    def test_has_exec_whoami(self) -> None:
        assert any("exec_whoami" in p[0] for p in _RCE_PAYLOADS)

    def test_has_exec_id(self) -> None:
        assert any("exec_id" in p[0] for p in _RCE_PAYLOADS)

    def test_has_exec_ls(self) -> None:
        assert any("exec_ls" in p[0] for p in _RCE_PAYLOADS)

    def test_has_exec_cat(self) -> None:
        assert any("exec_cat" in p[0] for p in _RCE_PAYLOADS)

    def test_has_exec_uname(self) -> None:
        assert any("exec_uname" in p[0] for p in _RCE_PAYLOADS)

    def test_count(self) -> None:
        assert len(_RCE_PAYLOADS) == 5


class TestFileReadPayloads:
    """Testes para _FILE_READ_PAYLOADS."""

    def test_has_include_passwd(self) -> None:
        assert any("include_passwd" in p[0] for p in _FILE_READ_PAYLOADS)

    def test_has_include_hosts(self) -> None:
        assert any("include_hosts" in p[0] for p in _FILE_READ_PAYLOADS)

    def test_has_include_etc(self) -> None:
        assert any("include_etc" in p[0] for p in _FILE_READ_PAYLOADS)

    def test_has_include_proc(self) -> None:
        assert any("include_proc" in p[0] for p in _FILE_READ_PAYLOADS)

    def test_has_include_iis(self) -> None:
        assert any("include_iis" in p[0] for p in _FILE_READ_PAYLOADS)

    def test_count(self) -> None:
        assert len(_FILE_READ_PAYLOADS) == 5


class TestBlindPayloads:
    """Testes para _BLIND_PAYLOADS."""

    def test_has_blind_sleep(self) -> None:
        assert any("blind_sleep" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_expr(self) -> None:
        assert any("blind_expr" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_len(self) -> None:
        assert any("blind_len" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_md5(self) -> None:
        assert any("blind_md5" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_hash(self) -> None:
        assert any("blind_hash" in p[0] for p in _BLIND_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BLIND_PAYLOADS) == 5


class TestBypassPayloads:
    """Testes para _BYPASS_PAYLOADS."""

    def test_has_url_encode(self) -> None:
        assert any("url_encode" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_double_encode(self) -> None:
        assert any("double_encode" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_null_byte(self) -> None:
        assert any("null_byte" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_case_variation(self) -> None:
        assert any("case_variation" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_nesting(self) -> None:
        assert any("nesting" in p[0] for p in _BYPASS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BYPASS_PAYLOADS) == 5


class TestSSIParams:
    """Testes para _SSI_PARAMS."""

    def test_has_user(self) -> None:
        assert "user" in _SSI_PARAMS

    def test_has_search(self) -> None:
        assert "search" in _SSI_PARAMS

    def test_has_comment(self) -> None:
        assert "comment" in _SSI_PARAMS

    def test_has_name(self) -> None:
        assert "name" in _SSI_PARAMS

    def test_has_file(self) -> None:
        assert "file" in _SSI_PARAMS

    def test_count(self) -> None:
        assert len(_SSI_PARAMS) == 15


class TestSSIiAttempt:
    """Testes para dataclass SSIiAttempt."""

    def test_create(self) -> None:
        attempt = SSIiAttempt(
            technique="basic_exec_user",
            category="detect",
            payload="<!--#exec cmd=\"id\"-->",
            param="user",
            method="post_form",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=200,
            status_changed=False,
            size_changed=True,
            vulnerable=True,
            details="uid found",
            error="",
        )
        assert attempt.technique == "basic_exec_user"
        assert attempt.vulnerable is True

    def test_immutable(self) -> None:
        attempt = SSIiAttempt(
            technique="test", category="detect", payload="p",
            param="user", method="post_form", status_baseline=200, status_test=200,
            size_baseline=100, size_test=100, status_changed=False,
            size_changed=False, vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            attempt.technique = "changed"  # type: ignore[misc]


class TestSSIiResult:
    """Testes para dataclass SSIiResult."""

    def test_create(self) -> None:
        result = SSIiResult(
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
        result = SSIiResult(
            target="t", baseline_status=200, baseline_size=100,
            tls=True, attempts=[], vulnerable_techniques=[],
            blocked_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            result.target = "changed"  # type: ignore[misc]


class TestCheckSSIResponse:
    """Testes para _check_ssi_response."""

    def test_uid_detected(self) -> None:
        assert _check_ssi_response(b"uid=33(www-data)", 200, ["uid="])

    def test_not_detected(self) -> None:
        assert not _check_ssi_response(b"error 404", 200, ["uid="])

    def test_status_zero(self) -> None:
        assert not _check_ssi_response(b"uid=", 0, ["uid="])

    def test_case_insensitive(self) -> None:
        assert _check_ssi_response(b"WWW-DATA", 200, ["www-data"])

    def test_multiple_indicators(self) -> None:
        assert _check_ssi_response(b"uid=33 gid=33", 200, ["uid=", "gid="])

    def test_empty_body(self) -> None:
        assert not _check_ssi_response(b"", 200, ["uid="])


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
        mock_resp.content = b"uid=33(www-data)"
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


class TestTestRCE:
    """Testes para _test_rce."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"uid=33(www-data) gid=33(www-data)"
        mock_client.post.return_value = mock_resp
        mock_client.get.return_value = mock_resp

        results = await _test_rce(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_rce(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestFileRead:
    """Testes para _test_file_read."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"root:x:0:0:root:/root:/bin/bash"
        mock_client.post.return_value = mock_resp
        mock_client.get.return_value = mock_resp

        results = await _test_file_read(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_file_read(mock_client, "https://example.com", (200, 100, b""))
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
        mock_resp.content = b"uid=33"
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
        result = SSIiResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=["exec_whoami_user"],
            blocked_techniques=[],
            issues=["VULN: exec_whoami_user"],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "VULNERAVEIS" in output

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = SSIiResult(
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
        assert "Nenhuma SSI Injection detectada" in output


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
                assert set(action.choices) == set(_CATEGORY_MAP.keys())


class TestMain:
    """Testes para main()."""

    def test_main_returns_int(self) -> None:
        with patch("sys.argv", ["mytools-ssiinject"]), \
             patch("mytools.web.ssiinject.run_main_loop", return_value=0) as mock_loop:
            result = main()
            assert isinstance(result, int)
            mock_loop.assert_called_once()

    def test_main_passes_args(self) -> None:
        with patch("sys.argv", ["mytools-ssiinject", "https://example.com"]), \
             patch("mytools.web.ssiinject.run_main_loop", return_value=0):
            result = main()
            assert result == 0


class TestIntegration:
    """Testes de integracao com mocks."""

    @pytest.mark.asyncio
    async def test_run_scan_all_categories(self) -> None:
        from mytools.web.ssiinject import run_scan

        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"not vulnerable"
        mock_client.get.return_value = mock_resp
        mock_client.post.return_value = mock_resp

        with patch("mytools.web.ssiinject.create_async_client", return_value=mock_client):
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
        from mytools.web.ssiinject import run_scan

        mock_client = AsyncMock()
        mock_get = MagicMock()
        mock_get.status_code = 200
        mock_get.content = b"ok"
        mock_client.get.return_value = mock_get

        mock_post = MagicMock()
        mock_post.status_code = 200
        mock_post.content = b"uid=33(www-data) gid=33(www-data)"
        mock_client.post.return_value = mock_post

        with patch("mytools.web.ssiinject.create_async_client", return_value=mock_client):
            result = await run_scan(
                target="https://example.com",
                categories=["rce"],
                timeout=10,
                concurrency=5,
                output_file=None,
                verbose=False,
            )
            assert result == 1

    @pytest.mark.asyncio
    async def test_run_scan_connection_error(self) -> None:
        from mytools.web.ssiinject import run_scan

        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 0
        mock_resp.content = b""
        mock_client.get.return_value = mock_resp

        with patch("mytools.web.ssiinject.create_async_client", return_value=mock_client):
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
    async def test_run_scan_with_output(self, tmp_path: object) -> None:
        from mytools.web.ssiinject import run_scan

        mock_client = AsyncMock()
        mock_get = MagicMock()
        mock_get.status_code = 200
        mock_get.content = b"ok"
        mock_client.get.return_value = mock_get

        mock_post = MagicMock()
        mock_post.status_code = 200
        mock_post.content = b"not vulnerable"
        mock_client.post.return_value = mock_post

        output_file = str(tmp_path) + "/output.json"  # type: ignore[operator]
        with patch("mytools.web.ssiinject.create_async_client", return_value=mock_client):
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

        with patch("mytools.web.ssiinject.safe_asyncio_run", return_value=0) as mock_run:
            from mytools.web.ssiinject import run_once
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

        with patch("mytools.web.ssiinject.safe_asyncio_run", return_value=0):
            from mytools.web.ssiinject import run_once
            result = run_once(args)
            assert result == 0
