#!/usr/bin/env python3
"""Testes unitarios do modulo de LDAP Injection."""
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.ldapiinject import (
    _AUTH_BYPASS_PAYLOADS,
    _BLIND_PAYLOADS,
    _BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    _DETECT_PAYLOADS,
    _LDAP_PARAMS,
    _SEARCH_PAYLOADS,
    LDAPiAttempt,
    LDAPiResult,
    _check_ldap_response,
    _test_auth_bypass,
    _test_baseline,
    _test_blind,
    _test_bypass,
    _test_detect,
    _test_search,
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

    def test_has_search(self) -> None:
        assert "search" in _CATEGORY_MAP

    def test_has_blind(self) -> None:
        assert "blind" in _CATEGORY_MAP

    def test_has_bypass(self) -> None:
        assert "bypass" in _CATEGORY_MAP

    def test_count(self) -> None:
        assert len(_CATEGORY_MAP) == 5


class TestDetectPayloads:
    """Testes para _DETECT_PAYLOADS."""

    def test_has_wildcard(self) -> None:
        assert any("wildcard" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_close_filter(self) -> None:
        assert any("close_filter" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_always_true(self) -> None:
        assert any("always_true" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_objectclass(self) -> None:
        assert any("objectclass" in p[0] for p in _DETECT_PAYLOADS)

    def test_has_presence(self) -> None:
        assert any("presence" in p[0] for p in _DETECT_PAYLOADS)

    def test_count(self) -> None:
        assert len(_DETECT_PAYLOADS) == 5


class TestAuthBypassPayloads:
    """Testes para _AUTH_BYPASS_PAYLOADS."""

    def test_has_admin_or(self) -> None:
        assert any("admin_or" in p[0] for p in _AUTH_BYPASS_PAYLOADS)

    def test_has_close_paren(self) -> None:
        assert any("close_paren" in p[0] for p in _AUTH_BYPASS_PAYLOADS)

    def test_has_star_close(self) -> None:
        assert any("star_close" in p[0] for p in _AUTH_BYPASS_PAYLOADS)

    def test_has_admin_true(self) -> None:
        assert any("admin_true" in p[0] for p in _AUTH_BYPASS_PAYLOADS)

    def test_has_null_bypass(self) -> None:
        assert any("null_bypass" in p[0] for p in _AUTH_BYPASS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_AUTH_BYPASS_PAYLOADS) == 5


class TestSearchPayloads:
    """Testes para _SEARCH_PAYLOADS."""

    def test_has_enum_users(self) -> None:
        assert any("enum_users" in p[0] for p in _SEARCH_PAYLOADS)

    def test_has_enum_groups(self) -> None:
        assert any("enum_groups" in p[0] for p in _SEARCH_PAYLOADS)

    def test_has_enum_attrs(self) -> None:
        assert any("enum_attrs" in p[0] for p in _SEARCH_PAYLOADS)

    def test_has_enum_dn(self) -> None:
        assert any("enum_dn" in p[0] for p in _SEARCH_PAYLOADS)

    def test_has_wildcard_all(self) -> None:
        assert any("wildcard_all" in p[0] for p in _SEARCH_PAYLOADS)

    def test_count(self) -> None:
        assert len(_SEARCH_PAYLOADS) == 5


class TestBlindPayloads:
    """Testes para _BLIND_PAYLOADS."""

    def test_has_blind_user(self) -> None:
        assert any("blind_user" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_pass(self) -> None:
        assert any("blind_pass" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_dn(self) -> None:
        assert any("blind_dn" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_email(self) -> None:
        assert any("blind_email" in p[0] for p in _BLIND_PAYLOADS)

    def test_has_blind_member(self) -> None:
        assert any("blind_member" in p[0] for p in _BLIND_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BLIND_PAYLOADS) == 5


class TestBypassPayloads:
    """Testes para _BYPASS_PAYLOADS."""

    def test_has_unicode(self) -> None:
        assert any("unicode" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_null_terminator(self) -> None:
        assert any("null_terminator" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_double_encode(self) -> None:
        assert any("double_encode" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_space_bypass(self) -> None:
        assert any("space_bypass" in p[0] for p in _BYPASS_PAYLOADS)

    def test_has_special_chars(self) -> None:
        assert any("special_chars" in p[0] for p in _BYPASS_PAYLOADS)

    def test_count(self) -> None:
        assert len(_BYPASS_PAYLOADS) == 5


class TestLDAPParams:
    """Testes para _LDAP_PARAMS."""

    def test_has_user(self) -> None:
        assert "user" in _LDAP_PARAMS

    def test_has_username(self) -> None:
        assert "username" in _LDAP_PARAMS

    def test_has_search(self) -> None:
        assert "search" in _LDAP_PARAMS

    def test_has_filter(self) -> None:
        assert "filter" in _LDAP_PARAMS

    def test_has_uid(self) -> None:
        assert "uid" in _LDAP_PARAMS

    def test_has_dn(self) -> None:
        assert "dn" in _LDAP_PARAMS

    def test_count(self) -> None:
        assert len(_LDAP_PARAMS) == 12


class TestLDAPiAttempt:
    """Testes para dataclass LDAPiAttempt."""

    def test_create(self) -> None:
        attempt = LDAPiAttempt(
            technique="wildcard_user",
            category="detect",
            payload="*",
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
        assert attempt.technique == "wildcard_user"
        assert attempt.vulnerable is True

    def test_immutable(self) -> None:
        attempt = LDAPiAttempt(
            technique="test", category="detect", payload="*",
            param="user", method="post_form", status_baseline=200, status_test=200,
            size_baseline=100, size_test=100, status_changed=False,
            size_changed=False, vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            attempt.technique = "changed"  # type: ignore[misc]


class TestLDAPiResult:
    """Testes para dataclass LDAPiResult."""

    def test_create(self) -> None:
        result = LDAPiResult(
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
        result = LDAPiResult(
            target="t", baseline_status=200, baseline_size=100,
            tls=True, attempts=[], vulnerable_techniques=[],
            blocked_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            result.target = "changed"  # type: ignore[misc]


class TestCheckLDAPResponse:
    """Testes para _check_ldap_response."""

    def test_welcome_detected(self) -> None:
        assert _check_ldap_response(b"welcome back", 200, ["welcome"])

    def test_not_detected(self) -> None:
        assert not _check_ldap_response(b"error 404", 200, ["welcome"])

    def test_status_zero(self) -> None:
        assert not _check_ldap_response(b"welcome", 0, ["welcome"])

    def test_case_insensitive(self) -> None:
        assert _check_ldap_response(b"WELCOME", 200, ["welcome"])

    def test_multiple_indicators(self) -> None:
        assert _check_ldap_response(b"success: token issued", 200, ["success", "token"])

    def test_empty_body(self) -> None:
        assert not _check_ldap_response(b"", 200, ["welcome"])


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


class TestTestSearch:
    """Testes para _test_search."""

    @pytest.mark.asyncio
    async def test_returns_attempts(self) -> None:
        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client.post.return_value = mock_resp
        mock_client.get.return_value = mock_resp

        results = await _test_search(mock_client, "https://example.com", (200, 100, b""))
        assert len(results) > 0

    @pytest.mark.asyncio
    async def test_request_error(self) -> None:
        import httpx
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")
        mock_client.get.side_effect = httpx.RequestError("fail")

        results = await _test_search(mock_client, "https://example.com", (200, 100, b""))
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
        result = LDAPiResult(
            target="https://example.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=["wildcard_user"],
            blocked_techniques=[],
            issues=["VULN: wildcard_user"],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "VULNERAVEIS" in output

    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = LDAPiResult(
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
        assert "Nenhuma LDAP Injection detectada" in output


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
        with patch("sys.argv", ["mytools-ldapi"]), \
             patch("mytools.web.ldapiinject.run_main_loop", return_value=0) as mock_loop:
            result = main()
            assert isinstance(result, int)
            mock_loop.assert_called_once()

    def test_main_passes_args(self) -> None:
        with patch("sys.argv", ["mytools-ldapi", "https://example.com"]), \
             patch("mytools.web.ldapiinject.run_main_loop", return_value=0):
            result = main()
            assert result == 0


class TestIntegration:
    """Testes de integracao com mocks."""

    @pytest.mark.asyncio
    async def test_run_scan_all_categories(self) -> None:
        from mytools.web.ldapiinject import run_scan

        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"not vulnerable"
        mock_client.get.return_value = mock_resp
        mock_client.post.return_value = mock_resp

        with patch("mytools.web.ldapiinject.create_async_client", return_value=mock_client):
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
        from mytools.web.ldapiinject import run_scan

        mock_client = AsyncMock()
        mock_get = MagicMock()
        mock_get.status_code = 200
        mock_get.content = b"ok"
        mock_client.get.return_value = mock_get

        mock_post = MagicMock()
        mock_post.status_code = 200
        mock_post.content = b"welcome success token"
        mock_client.post.return_value = mock_post

        with patch("mytools.web.ldapiinject.create_async_client", return_value=mock_client):
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
        from mytools.web.ldapiinject import run_scan

        mock_client = AsyncMock()
        mock_resp = MagicMock()
        mock_resp.status_code = 0
        mock_resp.content = b""
        mock_client.get.return_value = mock_resp

        with patch("mytools.web.ldapiinject.create_async_client", return_value=mock_client):
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
        from mytools.web.ldapiinject import run_scan

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
        with patch("mytools.web.ldapiinject.create_async_client", return_value=mock_client):
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

        with patch("mytools.web.ldapiinject.safe_asyncio_run", return_value=0) as mock_run:
            from mytools.web.ldapiinject import run_once
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

        with patch("mytools.web.ldapiinject.safe_asyncio_run", return_value=0):
            from mytools.web.ldapiinject import run_once
            result = run_once(args)
            assert result == 0
