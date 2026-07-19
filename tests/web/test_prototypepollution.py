#!/usr/bin/env python3
"""Testes unitarios do modulo de Prototype Pollution."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.prototypepollution import (
    _BLIND_PAYLOADS,
    _BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    _CONSTRUCTOR_PAYLOADS,
    _DETECT_PAYLOADS,
    _IMPACT_PAYLOADS,
    _SSI_PARAMS,
    PollAttempt,
    PollResult,
    _check_poll_response,
    _test_baseline,
    _test_blind,
    _test_bypass,
    _test_constructor,
    _test_detect,
    _test_impact,
    build_parser,
    main,
    print_results,
)


class TestCategoryMap:
    """Testes para _CATEGORY_MAP."""

    def test_has_detect(self) -> None:
        assert "detect" in _CATEGORY_MAP

    def test_has_constructor(self) -> None:
        assert "constructor" in _CATEGORY_MAP

    def test_has_bypass(self) -> None:
        assert "bypass" in _CATEGORY_MAP

    def test_has_blind(self) -> None:
        assert "blind" in _CATEGORY_MAP

    def test_has_impact(self) -> None:
        assert "impact" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 5


class TestDetectPayloads:
    """Testes para _DETECT_PAYLOADS."""

    def test_has_proto_basic(self) -> None:
        assert any("proto_basic" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_proto_admin(self) -> None:
        assert any("proto_admin" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_proto_role(self) -> None:
        assert any("proto_role" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_proto_settings(self) -> None:
        assert any("proto_settings" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_proto_version(self) -> None:
        assert any("proto_version" in p[0] for p in _DETECT_PAYLOADS)

    def test_count(self) -> None:
        assert len(_DETECT_PAYLOADS) == 5

    def test_all_have_proto(self) -> None:
        for _, payload, _ in _DETECT_PAYLOADS:
            assert "__proto__" in payload or "polluted" in payload.lower()


class TestConstructorPayloads:
    """Testes para _CONSTRUCTOR_PAYLOADS."""

    def test_has_ctor_basic(self) -> None:
        assert any("ctor_basic" in p[0] for p in _CONSTRUCTOR_PAYLOADS)

    def test_has_ctor_admin(self) -> None:
        assert any("ctor_admin" in p[0] for p in _CONSTRUCTOR_PAYLOADS)

    def test_has_ctor_role(self) -> None:
        assert any("ctor_role" in p[0] for p in _CONSTRUCTOR_PAYLOADS)

    def test_has_ctor_proto(self) -> None:
        assert any("ctor_proto" in p[0] for p in _CONSTRUCTOR_PAYLOADS)

    def test_has_ctor_inject(self) -> None:
        assert any("ctor_inject" in p[0] for p in _CONSTRUCTOR_PAYLOADS)

    def test_count(self) -> None:
        assert len(_CONSTRUCTOR_PAYLOADS) == 5


class TestBypassPayloads:
    """Testes para _BYPASS_PAYLOADS."""

    def test_has_url_encode(self) -> None:
        assert any("url_encode" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_double_encode(self) -> None:
        assert any("double_encode" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_nested(self) -> None:
        assert any("nested" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_array_bracket(self) -> None:
        assert any("array_bracket" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_dot_notation(self) -> None:
        assert any("dot_notation" in p[0] for p in _BYPASS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BYPASS_PAYLOADS) == 5


class TestBlindPayloads:
    """Testes para _BLIND_PAYLOADS."""

    def test_has_blind_timing(self) -> None:
        assert any("blind_timing" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_reflection(self) -> None:
        assert any("blind_reflection" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_stored(self) -> None:
        assert any("blind_stored" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_header(self) -> None:
        assert any("blind_header" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_cookie(self) -> None:
        assert any("blind_cookie" in p[0] for p in _BLIND_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BLIND_PAYLOADS) == 5


class TestImpactPayloads:
    """Testes para _IMPACT_PAYLOADS."""

    def test_has_impact_isadmin(self) -> None:
        assert any("impact_isadmin" in p[0] for p in _IMPACT_PAYLOADS)

    def test_has_impact_role(self) -> None:
        assert any("impact_role" in p[0] for p in _IMPACT_PAYLOADS)

    def test_has_impact_settings(self) -> None:
        assert any("impact_settings" in p[0] for p in _IMPACT_PAYLOADS)

    def test_has_impact_rce(self) -> None:
        assert any("impact_rce" in p[0] for p in _IMPACT_PAYLOADS)

    def test_has_impact_xss(self) -> None:
        assert any("impact_xss" in p[0] for p in _IMPACT_PAYLOADS)

    def test_count(self) -> None:
        assert len(_IMPACT_PAYLOADS) == 5


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


class TestPollAttempt:
    """Testes para dataclass PollAttempt."""

    def test_create(self) -> None:
        attempt = PollAttempt(
            technique="proto_basic",
            category="detect",
            payload='{"__proto__":{"polluted":true}}',
            param="data",
            method="post_json",
            status_baseline=200,
            status_test=200,
            size_baseline=100,
            size_test=200,
            status_changed=False,
            size_changed=True,
            vulnerable=True,
            details="polluted found",
            error="",
        )
        assert attempt.technique == "proto_basic"
        assert attempt.vulnerable is True

    def test_immutable(self) -> None:
        attempt = PollAttempt(
            technique="test", category="detect", payload="p",
            param="data", method="post_json", status_baseline=200, status_test=200,
            size_baseline=100, size_test=100, status_changed=False,
            size_changed=False, vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            attempt.technique = "changed"  # type: ignore[misc]


class TestPollResult:
    """Testes para dataclass PollResult."""

    def test_create(self) -> None:
        result = PollResult(
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
        result = PollResult(
            target="t", baseline_status=200, baseline_size=100,
            tls=True, attempts=[], vulnerable_techniques=[],
            blocked_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            result.target = "changed"  # type: ignore[misc]


class TestCheckPollResponse:
    """Testes para _check_poll_response."""

    def test_polluted_detected(self) -> None:
        assert _check_poll_response(b"polluted", 200, ["polluted"])

    def test_not_detected(self) -> None:
        assert not _check_poll_response(b"error 404", 200, ["polluted"])

    def test_status_zero(self) -> None:
        assert not _check_poll_response(b"polluted", 0, ["polluted"])

    def test_case_insensitive(self) -> None:
        assert _check_poll_response(b"POLLUTED", 200, ["polluted"])

    def test_multiple_indicators(self) -> None:
        assert _check_poll_response(b"isAdmin=true", 200, ["isAdmin", "true"])

    def test_empty_body(self) -> None:
        assert not _check_poll_response(b"", 200, ["polluted"])


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
        mock_resp.content = b"polluted"
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


class TestTestConstructor:
    """Testes para _test_constructor."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"polluted"
        mock_client.post.return_value = mock_resp

        results = await _test_constructor(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_constructor(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestBypass:
    """Testes para _test_bypass."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"polluted"
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


class TestTestBlind:
    """Testes para _test_blind."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client.post.return_value = mock_resp

        results = await _test_blind(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_blind(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestTestImpact:
    """Testes para _test_impact."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"isAdmin=true"
        mock_client.post.return_value = mock_resp

        results = await _test_impact(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")

        results = await _test_impact(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0
        assert all(r.error for r in results)


class TestPrintResults:
    """Testes para print_results."""

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = PollResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[
                PollAttempt(
                    technique="proto_basic", category="detect",
                    payload='{"__proto__":{"polluted":true}}', param="data",
                    method="post_json", status_baseline=200, status_test=200,
                    size_baseline=100, size_test=200, status_changed=False,
                    size_changed=True, vulnerable=True, details="polluted found",
                    error="",
                ),
            ],
            vulnerable_techniques=["proto_basic"],
            blocked_techniques=[],
            issues=["VULN: proto_basic via data"],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "VULNERABILIDADES DETECTADAS" in output

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = PollResult(
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
        assert "Nenhuma Prototype Pollution detectada" in output


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
        with patch("sys.argv", ["mytools-protopoll"]), \
             patch("mytools.web.prototypepollution.run_main_loop", return_value=0) as mock_loop:
            result = main()
            assert isinstance(result, int)
            mock_loop.assert_called_once()

    def test_main_passes_args(self) -> None:
        with patch("sys.argv", ["mytools-protopoll", "https://example.com"]), \
             patch("mytools.web.prototypepollution.run_main_loop", return_value=0):
            result = main()
            assert result == 0


class TestIntegration:
    """Testes de integracao com mocks."""

    @pytest.mark.asyncio
    async def test_run_scan_all_categories(self) -> None:
        from mytools.web.prototypepollution import run_scan

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"not vulnerable"
        mock_client.get.return_value = mock_resp
        mock_client.post.return_value = mock_resp

        with patch("mytools.web.prototypepollution.create_async_client", return_value=mock_client):
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
        from mytools.web.prototypepollution import run_scan

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_get = MagicMock()
        mock_get.status_code = 200
        mock_get.content = b"ok"
        mock_client.get.return_value = mock_get

        mock_post = MagicMock()
        mock_post.status_code = 200
        mock_post.content = b"polluted"
        mock_client.post.return_value = mock_post

        with patch("mytools.web.prototypepollution.create_async_client", return_value=mock_client):
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
    async def test_run_scan_connection_error(self) -> None:
        from mytools.web.prototypepollution import run_scan

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_resp = MagicMock()
        mock_resp.status_code = 0
        mock_resp.content = b""
        mock_client.get.return_value = mock_resp

        with patch("mytools.web.prototypepollution.create_async_client", return_value=mock_client):
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
        from mytools.web.prototypepollution import run_scan

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
        with patch("mytools.web.prototypepollution.create_async_client", return_value=mock_client):
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

        with patch("mytools.web.prototypepollution.safe_asyncio_run", return_value=0) as mock_run:
            from mytools.web.prototypepollution import run_once
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

        with patch("mytools.web.prototypepollution.safe_asyncio_run", return_value=0):
            from mytools.web.prototypepollution import run_once
            result = run_once(args)
            assert result == 0
