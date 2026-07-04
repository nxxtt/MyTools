#!/usr/bin/env python3
"""Testes unitarios do modulo de Cookie Domain Boundary."""
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mytools.web.cookieboundary import (
    _CATEGORY_MAP,
    _COOKIE_PATH_TRAVERSAL_PAYLOADS,
    _CSRF_COOKIE_NAMES,
    _CSRF_FIELD_NAMES,
    CookieBoundaryAttempt,
    CookieBoundaryResult,
    CookieInfo,
    _extract_target_domain,
    _is_csrf_cookie,
    _is_public_suffix,
    _parse_cookie,
    _test_cookie_quoting,
    _test_csrf_subdomain,
    _test_domain_attributes,
    _test_double_submit,
    _test_flag_attributes,
    _test_path_attributes,
    _test_path_traversal_active,
    _test_samesite_dns_bypass,
    build_parser,
    print_results,
)


# ─── Category Map ────────────────────────────────────────────────────────────
class TestCategoryMap:
    def test_has_eight_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 8

    def test_categories_are_correct(self) -> None:
        expected = {"domain", "flags", "path", "path_traversal", "double_submit", "samesite_dns", "csrf_subdomain", "cookie_quoting"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_domain_has_five_techniques(self) -> None:
        assert len(_CATEGORY_MAP["domain"]) == 5

    def test_flags_has_four_techniques(self) -> None:
        assert len(_CATEGORY_MAP["flags"]) == 4

    def test_path_has_two_techniques(self) -> None:
        assert len(_CATEGORY_MAP["path"]) == 2

    def test_path_traversal_has_nine_techniques(self) -> None:
        assert len(_CATEGORY_MAP["path_traversal"]) == 9

    def test_double_submit_has_five_techniques(self) -> None:
        assert len(_CATEGORY_MAP["double_submit"]) == 5

    def test_samesite_dns_has_six_techniques(self) -> None:
        assert len(_CATEGORY_MAP["samesite_dns"]) == 6

    def test_csrf_subdomain_has_six_techniques(self) -> None:
        assert len(_CATEGORY_MAP["csrf_subdomain"]) == 6

    def test_cookie_quoting_has_six_techniques(self) -> None:
        assert len(_CATEGORY_MAP["cookie_quoting"]) == 6


# ─── Parse Cookie ────────────────────────────────────────────────────────────
class TestParseCookie:
    def test_simple_cookie(self) -> None:
        c = _parse_cookie("session=abc123")
        assert c.name == "session"
        assert c.value == "abc123"
        assert c.domain == ""
        assert c.path == ""
        assert c.secure is False
        assert c.httponly is False
        assert c.samesite == ""

    def test_cookie_with_flags(self) -> None:
        c = _parse_cookie("token=xyz; Path=/; Secure; HttpOnly; SameSite=Strict")
        assert c.name == "token"
        assert c.value == "xyz"
        assert c.path == "/"
        assert c.secure is True
        assert c.httponly is True
        assert c.samesite == "strict"

    def test_cookie_with_domain(self) -> None:
        c = _parse_cookie("id=1; Domain=.example.com; Path=/api")
        assert c.name == "id"
        assert c.domain == ".example.com"
        assert c.path == "/api"

    def test_cookie_no_equals(self) -> None:
        c = _parse_cookie("invalidcookie")
        assert c.name == "invalidcookie"
        assert c.value == ""

    def test_cookie_domain_quoted(self) -> None:
        c = _parse_cookie('id=1; Domain=".example.com"')
        assert c.domain == ".example.com"

    def test_quoted_value_with_semicolons(self) -> None:
        c = _parse_cookie('name="val;ue"; Path=/')
        assert c.name == "name"
        assert c.value == "val;ue"
        assert c.path == "/"

    def test_quoted_value_backslash_escape(self) -> None:
        c = _parse_cookie(r'name="val\"ue"')
        assert c.name == "name"
        assert c.value == 'val"ue'

    def test_quoted_value_double_backslash(self) -> None:
        c = _parse_cookie(r'name="val\\""')
        assert c.name == "name"
        assert c.value == "val\\"

    def test_quoted_value_with_flags(self) -> None:
        c = _parse_cookie('name="val;ue"; Secure; HttpOnly')
        assert c.value == "val;ue"
        assert c.secure is True
        assert c.httponly is True

    def test_unbalanced_quotes(self) -> None:
        c = _parse_cookie('name="value; Path=/')
        assert c.name == "name"

    def test_empty_quoted_value(self) -> None:
        c = _parse_cookie('name=""; Path=/')
        assert c.value == ""
        assert c.path == "/"

    def test_whitespace_in_value(self) -> None:
        c = _parse_cookie("name=  abc  ; Path=/")
        assert c.value == "  abc  "

    def test_null_byte_in_value(self) -> None:
        c = _parse_cookie("name=abc\x00def; Path=/")
        assert c.value == "abc\x00def"

    def test_domain_backslash_escape(self) -> None:
        c = _parse_cookie(r'name=val; Domain="exam\.ple.com"')
        assert c.domain == "exam.ple.com"


# ─── Extract Target Domain ───────────────────────────────────────────────────
class TestExtractTargetDomain:
    def test_simple_domain(self) -> None:
        assert _extract_target_domain("https://example.com") == "example.com"

    def test_subdomain(self) -> None:
        assert _extract_target_domain("https://api.example.com") == "example.com"

    def test_deep_subdomain(self) -> None:
        assert _extract_target_domain("https://a.b.c.example.com") == "example.com"

    def test_ip_address(self) -> None:
        assert _extract_target_domain("http://192.168.1.1") == "1.1"

    def test_single_label(self) -> None:
        assert _extract_target_domain("http://localhost") == "localhost"

    def test_co_uk(self) -> None:
        assert _extract_target_domain("https://example.co.uk") == "co.uk"


# ─── Is Public Suffix ────────────────────────────────────────────────────────
class TestIsPublicSuffix:
    def test_com(self) -> None:
        assert _is_public_suffix("com") is True

    def test_org(self) -> None:
        assert _is_public_suffix("org") is True

    def test_co_uk(self) -> None:
        assert _is_public_suffix("co.uk") is True

    def test_not_public(self) -> None:
        assert _is_public_suffix("example.com") is False

    def test_not_public_subdomain(self) -> None:
        assert _is_public_suffix("api.example.com") is False


# ─── Test Domain Attributes ──────────────────────────────────────────────────
class TestDomainAttributes:
    def test_domain_absent(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        results = _test_domain_attributes(cookies, "example.com")
        assert len(results) == 1
        assert results[0].technique == "domain_absent"
        assert results[0].vulnerable is True

    def test_domain_wildcard(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain=".", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        results = _test_domain_attributes(cookies, "example.com")
        assert len(results) == 1
        assert results[0].technique == "domain_wildcard"
        assert results[0].vulnerable is True

    def test_domain_public_suffix(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain=".com", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        results = _test_domain_attributes(cookies, "example.com")
        assert len(results) == 1
        assert results[0].technique == "domain_public_suffix"
        assert results[0].vulnerable is True

    def test_domain_mismatch(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain=".evil.com", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        results = _test_domain_attributes(cookies, "example.com")
        assert len(results) == 1
        assert results[0].technique == "domain_mismatch"
        assert results[0].vulnerable is True

    def test_domain_overly_broad(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain=".example.com", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        results = _test_domain_attributes(cookies, "api.example.com")
        assert len(results) == 1
        assert results[0].technique == "domain_overly_broad"
        assert results[0].vulnerable is True

    def test_domain_correct(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="example.com", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        results = _test_domain_attributes(cookies, "example.com")
        assert len(results) == 1
        assert results[0].vulnerable is False


# ─── Test Flag Attributes ────────────────────────────────────────────────────
class TestFlagAttributes:
    def test_all_flags_present(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        results = _test_flag_attributes(cookies)
        assert len(results) == 4
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) == 0

    def test_no_httponly(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/",
            secure=True, httponly=False, samesite="Strict", raw="",
        )]
        results = _test_flag_attributes(cookies)
        no_http = [r for r in results if r.technique == "flag_no_httponly"]
        assert len(no_http) == 1
        assert no_http[0].vulnerable is True

    def test_no_secure(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/",
            secure=False, httponly=True, samesite="Strict", raw="",
        )]
        results = _test_flag_attributes(cookies)
        no_sec = [r for r in results if r.technique == "flag_no_secure"]
        assert len(no_sec) == 1
        assert no_sec[0].vulnerable is True

    def test_no_samesite(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/",
            secure=True, httponly=True, samesite="", raw="",
        )]
        results = _test_flag_attributes(cookies)
        no_ss = [r for r in results if r.technique == "flag_no_samesite"]
        assert len(no_ss) == 1
        assert no_ss[0].vulnerable is True

    def test_samesite_none(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/",
            secure=True, httponly=True, samesite="None", raw="",
        )]
        results = _test_flag_attributes(cookies)
        ss_none = [r for r in results if r.technique == "flag_samesite_none"]
        assert len(ss_none) == 1
        assert ss_none[0].vulnerable is True

    def test_multiple_cookies(self) -> None:
        cookies = [
            CookieInfo(name="a", value="1", domain="", path="/",
                       secure=True, httponly=True, samesite="Lax", raw=""),
            CookieInfo(name="b", value="2", domain="", path="/",
                       secure=False, httponly=False, samesite="", raw=""),
        ]
        results = _test_flag_attributes(cookies)
        assert len(results) == 7


# ─── Test Path Attributes ────────────────────────────────────────────────────
class TestPathAttributes:
    def test_path_absent(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        results = _test_path_attributes(cookies)
        assert len(results) == 1
        assert results[0].technique == "path_absent"
        assert results[0].vulnerable is True

    def test_path_root(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        results = _test_path_attributes(cookies)
        assert len(results) == 1
        assert results[0].technique == "path_overly_broad"
        assert results[0].vulnerable is True

    def test_path_restricted(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/api",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        results = _test_path_attributes(cookies)
        assert len(results) == 1
        assert results[0].technique == "path_overly_broad"
        assert results[0].vulnerable is False


# ─── Dataclasses ─────────────────────────────────────────────────────────────
class TestCookieInfo:
    def test_frozen(self) -> None:
        c = CookieInfo(
            name="test", value="abc", domain="", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )
        with pytest.raises(AttributeError):
            c.name = "other"  # type: ignore[misc]

    def test_slots(self) -> None:
        c = CookieInfo(
            name="test", value="abc", domain="", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )
        assert not hasattr(c, "__dict__")


class TestCookieBoundaryAttempt:
    def test_frozen(self) -> None:
        a = CookieBoundaryAttempt(
            technique="test", category="domain", cookie_name="session",
            attribute_tested="Domain", attribute_value=".example.com",
            vulnerable=True, details="test", error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "other"  # type: ignore[misc]


class TestCookieBoundaryResult:
    def test_frozen(self) -> None:
        r = CookieBoundaryResult(
            target="https://test.com", target_domain="test.com", tls=True,
            cookies_found=[], attempts=[],
            vulnerable_techniques=[], protected_techniques=[],
            issues=[], overall_status="safe",
        )
        with pytest.raises(AttributeError):
            r.target = "other"  # type: ignore[misc]


# ─── Print Results ───────────────────────────────────────────────────────────
class TestPrintResults:
    def test_vulnerable_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CookieBoundaryResult(
            target="https://test.com", target_domain="test.com", tls=True,
            cookies_found=[CookieInfo(
                name="session", value="abc", domain="", path="/",
                secure=False, httponly=False, samesite="", raw="",
            )],
            attempts=[CookieBoundaryAttempt(
                technique="flag_no_httponly", category="flags",
                cookie_name="session", attribute_tested="HttpOnly",
                attribute_value="False", vulnerable=True,
                details="Cookie 'session' sem HttpOnly", error="",
            )],
            vulnerable_techniques=["flag_no_httponly"],
            protected_techniques=[], issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Vulnerabilidades detectadas" in output
        assert "flag_no_httponly" in output

    def test_safe_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CookieBoundaryResult(
            target="https://test.com", target_domain="test.com", tls=True,
            cookies_found=[], attempts=[],
            vulnerable_techniques=[], protected_techniques=[],
            issues=[], overall_status="safe",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Nenhuma vulnerabilidade" in output

    def test_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CookieBoundaryResult(
            target="https://test.com", target_domain="test.com", tls=True,
            cookies_found=[], attempts=[],
            vulnerable_techniques=[], protected_techniques=[],
            issues=["Nenhum Set-Cookie detectado"],
            overall_status="unknown",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Observacoes" in output

    def test_cookies_listed(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = CookieBoundaryResult(
            target="https://test.com", target_domain="test.com", tls=True,
            cookies_found=[CookieInfo(
                name="session", value="abc123", domain=".test.com", path="/",
                secure=True, httponly=True, samesite="Lax", raw="",
            )],
            attempts=[], vulnerable_techniques=[], protected_techniques=[],
            issues=[], overall_status="safe",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Cookies detectados" in output
        assert "session" in output


# ─── Cookie Path Traversal Payloads ──────────────────────────────────────────
class TestCookiePathTraversalPayloads:
    def test_has_six_payloads(self) -> None:
        assert len(_COOKIE_PATH_TRAVERSAL_PAYLOADS) == 6

    def test_all_have_technique(self) -> None:
        for tech, _suffix, _desc in _COOKIE_PATH_TRAVERSAL_PAYLOADS:
            assert tech.startswith("traversal_")

    def test_all_suffixes_start_with_slash(self) -> None:
        for _tech, suffix, _desc in _COOKIE_PATH_TRAVERSAL_PAYLOADS:
            assert suffix.startswith("/")


# ─── Test Path Traversal Active ──────────────────────────────────────────────
class TestPathTraversalActive:
    @pytest.mark.asyncio
    async def test_no_scoped_cookies(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        mock_client = AsyncMock()
        results = await _test_path_traversal_active(mock_client, "https://test.com", cookies)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_scoped_cookie_no_leak(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/api",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        mock_resp = MagicMock()
        mock_resp.headers = MagicMock()
        mock_resp.headers.get_list = MagicMock(return_value=[])
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        results = await _test_path_traversal_active(mock_client, "https://test.com", cookies)
        assert len(results) > 0
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) == 0

    @pytest.mark.asyncio
    async def test_scoped_cookie_leak(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/api",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        mock_resp = MagicMock()
        mock_resp.headers = MagicMock()
        mock_resp.headers.get_list = MagicMock(return_value=["session=stolen; Path=/api"])
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        results = await _test_path_traversal_active(mock_client, "https://test.com", cookies)
        assert len(results) > 0
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) > 0

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/api",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))

        results = await _test_path_traversal_active(mock_client, "https://test.com", cookies)
        assert len(results) > 0
        errors = [r for r in results if r.error]
        assert len(errors) > 0

    @pytest.mark.asyncio
    async def test_case_variation(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/Api",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        mock_resp = MagicMock()
        mock_resp.headers = MagicMock()
        mock_resp.headers.get_list = MagicMock(return_value=["session=stolen"])
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        results = await _test_path_traversal_active(mock_client, "https://test.com", cookies)
        case_techs = [r for r in results if r.technique == "traversal_case_variation"]
        assert len(case_techs) == 1

    @pytest.mark.asyncio
    async def test_trailing_slash(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/api",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        mock_resp = MagicMock()
        mock_resp.headers = MagicMock()
        mock_resp.headers.get_list = MagicMock(return_value=["session=stolen"])
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        results = await _test_path_traversal_active(mock_client, "https://test.com", cookies)
        trail_techs = [r for r in results if r.technique == "traversal_trailing_slash"]
        assert len(trail_techs) == 1

    @pytest.mark.asyncio
    async def test_prefix_match(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/api",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        mock_resp = MagicMock()
        mock_resp.headers = MagicMock()
        mock_resp.headers.get_list = MagicMock(return_value=["session=stolen"])
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)

        results = await _test_path_traversal_active(mock_client, "https://test.com", cookies)
        prefix_techs = [r for r in results if r.technique == "traversal_prefix_match"]
        assert len(prefix_techs) == 1


# ─── CSRF Cookie Names ───────────────────────────────────────────────────────
class TestCSRFCookieNames:
    def test_has_expected_names(self) -> None:
        assert "csrf_token" in _CSRF_COOKIE_NAMES
        assert "xsrf-token" in _CSRF_COOKIE_NAMES
        assert "csrftoken" in _CSRF_COOKIE_NAMES

    def test_is_frozen(self) -> None:
        assert isinstance(_CSRF_COOKIE_NAMES, frozenset)


class TestCSRFCFieldNames:
    def test_has_expected_names(self) -> None:
        assert "csrf_token" in _CSRF_FIELD_NAMES
        assert "authenticity_token" in _CSRF_FIELD_NAMES

    def test_is_frozen(self) -> None:
        assert isinstance(_CSRF_FIELD_NAMES, frozenset)


# ─── Is CSRF Cookie ──────────────────────────────────────────────────────────
class TestIsCsrfCookie:
    def test_csrf_token(self) -> None:
        assert _is_csrf_cookie("csrf_token") is True

    def test_xsrf_token(self) -> None:
        assert _is_csrf_cookie("XSRF-TOKEN") is True

    def test_csrftoken(self) -> None:
        assert _is_csrf_cookie("csrftoken") is True

    def test_session_cookie(self) -> None:
        assert _is_csrf_cookie("session_id") is False

    def test_empty(self) -> None:
        assert _is_csrf_cookie("") is False

    def test_partial_match(self) -> None:
        assert _is_csrf_cookie("my_csrf_token") is True


# ─── Test Double Submit ──────────────────────────────────────────────────────
class TestDoubleSubmit:
    @pytest.mark.asyncio
    async def test_no_csrf_cookies(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        mock_client = AsyncMock()
        results = await _test_double_submit(mock_client, "https://test.com", cookies)
        assert len(results) == 0

    @pytest.mark.asyncio
    async def test_csrf_cookie_no_httponly(self) -> None:
        cookies = [CookieInfo(
            name="csrf_token", value="abc123", domain="", path="/",
            secure=True, httponly=False, samesite="Strict", raw="",
        )]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.content = b"<html></html>"
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)

        results = await _test_double_submit(mock_client, "https://test.com", cookies)
        no_http = [r for r in results if r.technique == "ds_cookie_no_httponly"]
        assert len(no_http) == 1
        assert no_http[0].vulnerable is True

    @pytest.mark.asyncio
    async def test_csrf_cookie_no_samesite(self) -> None:
        cookies = [CookieInfo(
            name="XSRF-TOKEN", value="xyz", domain="", path="/",
            secure=True, httponly=True, samesite="", raw="",
        )]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.content = b"<html></html>"
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)

        results = await _test_double_submit(mock_client, "https://test.com", cookies)
        no_ss = [r for r in results if r.technique == "ds_cookie_no_samesite"]
        assert len(no_ss) == 1
        assert no_ss[0].vulnerable is True

    @pytest.mark.asyncio
    async def test_csrf_cookie_samesite_none(self) -> None:
        cookies = [CookieInfo(
            name="csrf", value="val", domain="", path="/",
            secure=True, httponly=True, samesite="None", raw="",
        )]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.content = b"<html></html>"
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)

        results = await _test_double_submit(mock_client, "https://test.com", cookies)
        ss_none = [r for r in results if r.technique == "ds_cookie_no_samesite"]
        assert len(ss_none) == 1
        assert ss_none[0].vulnerable is True

    @pytest.mark.asyncio
    async def test_csrf_cookie_no_secure(self) -> None:
        cookies = [CookieInfo(
            name="csrftoken", value="tok", domain="", path="/",
            secure=False, httponly=True, samesite="Strict", raw="",
        )]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.content = b"<html></html>"
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)

        results = await _test_double_submit(mock_client, "https://test.com", cookies)
        no_sec = [r for r in results if r.technique == "ds_cookie_no_secure"]
        assert len(no_sec) == 1
        assert no_sec[0].vulnerable is True

    @pytest.mark.asyncio
    async def test_csrf_cookie_overly_broad_domain(self) -> None:
        cookies = [CookieInfo(
            name="csrf_token", value="v", domain=".com", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.content = b"<html></html>"
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)

        results = await _test_double_submit(mock_client, "https://test.com", cookies)
        broad = [r for r in results if r.technique == "ds_cookie_overly_broad_domain"]
        assert len(broad) == 1
        assert broad[0].vulnerable is True

    @pytest.mark.asyncio
    async def test_csrf_pattern_confirmed(self) -> None:
        cookies = [CookieInfo(
            name="csrf_token", value="abc", domain="", path="/",
            secure=True, httponly=False, samesite="Strict", raw="",
        )]
        form_html = b'<html><form><input type="hidden" name="csrf_token" value="abc"></form></html>'
        mock_headers = MagicMock()
        mock_headers.multi_items.return_value = []
        mock_headers.get_list.return_value = []
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = mock_headers
        mock_resp.content = form_html
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)

        results = await _test_double_submit(mock_client, "https://test.com", cookies)
        pattern = [r for r in results if r.technique == "ds_token_in_cookie_vs_field"]
        assert len(pattern) == 1
        assert pattern[0].vulnerable is True

    @pytest.mark.asyncio
    async def test_csrf_pattern_not_detected(self) -> None:
        cookies = [CookieInfo(
            name="csrf_token", value="abc", domain="", path="/",
            secure=True, httponly=False, samesite="Strict", raw="",
        )]
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.headers = {}
        mock_resp.content = b"<html><body>No forms here</body></html>"
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(return_value=mock_resp)

        results = await _test_double_submit(mock_client, "https://test.com", cookies)
        pattern = [r for r in results if r.technique == "ds_token_in_cookie_vs_field"]
        assert len(pattern) == 1
        assert pattern[0].vulnerable is False

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        cookies = [CookieInfo(
            name="csrf", value="v", domain="", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        mock_client = AsyncMock()
        mock_client.request = AsyncMock(side_effect=httpx.RequestError("timeout"))

        results = await _test_double_submit(mock_client, "https://test.com", cookies)
        assert len(results) > 0
        errors = [r for r in results if r.error]
        assert len(errors) > 0


# ─── SameSite DNS Bypass ──────────────────────────────────────────────────────
class TestSameSiteDnsBypass:
    @pytest.mark.asyncio
    async def test_no_lax_cookies_returns_empty(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="test.com", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        client = AsyncMock()
        result = await _test_samesite_dns_bypass(client, "https://target.com", cookies)
        assert result == []

    @pytest.mark.asyncio
    async def test_lax_cookie_detected(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="test.com", path="/",
            secure=True, httponly=True, samesite="Lax", raw="",
        )]
        client = AsyncMock()
        result = await _test_samesite_dns_bypass(client, "https://target.com", cookies)
        techniques = [a.technique for a in result]
        assert "samesite_lax_detected" in techniques

    @pytest.mark.asyncio
    async def test_missing_samesite_detected(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="test.com", path="/",
            secure=True, httponly=True, samesite="", raw="",
        )]
        client = AsyncMock()
        result = await _test_samesite_dns_bypass(client, "https://target.com", cookies)
        techniques = [a.technique for a in result]
        assert "samesite_missing_detected" in techniques

    @pytest.mark.asyncio
    @patch("mytools.dns.dnsrebinding.scan_rebinding")
    async def test_dns_rebindable_ttl(self, mock_scan: MagicMock) -> None:
        from mytools.dns.dnsrebinding import RebindingResult
        mock_scan.return_value = [RebindingResult(
            domain="target.com", check="ttl", severity="high",
            detail="TTL baixo",
        )]
        cookies = [CookieInfo(
            name="session", value="abc", domain="test.com", path="/",
            secure=True, httponly=True, samesite="Lax", raw="",
        )]
        client = AsyncMock()
        result = await _test_samesite_dns_bypass(client, "https://target.com", cookies)
        techniques = [a.technique for a in result]
        assert "dns_rebindable_ttl" in techniques

    @pytest.mark.asyncio
    @patch("mytools.dns.dnsrebinding.scan_rebinding")
    async def test_dns_rebindable_wildcard(self, mock_scan: MagicMock) -> None:
        from mytools.dns.dnsrebinding import RebindingResult
        mock_scan.return_value = [RebindingResult(
            domain="target.com", check="wildcard", severity="medium",
            detail="Wildcard detectado",
        )]
        cookies = [CookieInfo(
            name="session", value="abc", domain="test.com", path="/",
            secure=True, httponly=True, samesite="Lax", raw="",
        )]
        client = AsyncMock()
        result = await _test_samesite_dns_bypass(client, "https://target.com", cookies)
        techniques = [a.technique for a in result]
        assert "dns_rebindable_wildcard" in techniques

    @pytest.mark.asyncio
    @patch("mytools.dns.dnsrebinding.scan_rebinding")
    async def test_dns_rebindable_ip_flip(self, mock_scan: MagicMock) -> None:
        from mytools.dns.dnsrebinding import RebindingResult
        mock_scan.return_value = [RebindingResult(
            domain="target.com", check="ip_flip", severity="critical",
            detail="IP flip detectado",
        )]
        cookies = [CookieInfo(
            name="session", value="abc", domain="test.com", path="/",
            secure=True, httponly=True, samesite="Lax", raw="",
        )]
        client = AsyncMock()
        result = await _test_samesite_dns_bypass(client, "https://target.com", cookies)
        techniques = [a.technique for a in result]
        assert "dns_rebindable_ip_flip" in techniques
        assert "samesite_dns_bypass_risk" in techniques

    @pytest.mark.asyncio
    @patch("mytools.dns.dnsrebinding.scan_rebinding")
    async def test_no_rebinding_returns_no_risk(self, mock_scan: MagicMock) -> None:
        from mytools.dns.dnsrebinding import RebindingResult
        mock_scan.return_value = [RebindingResult(
            domain="target.com", check="ttl", severity="info",
            detail="TTL normal",
        )]
        cookies = [CookieInfo(
            name="session", value="abc", domain="test.com", path="/",
            secure=True, httponly=True, samesite="Lax", raw="",
        )]
        client = AsyncMock()
        result = await _test_samesite_dns_bypass(client, "https://target.com", cookies)
        techniques = [a.technique for a in result]
        assert "samesite_lax_detected" in techniques
        assert "samesite_dns_bypass_risk" not in techniques

    @pytest.mark.asyncio
    async def test_no_domain_returns_only_lax_checks(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="test.com", path="/",
            secure=True, httponly=True, samesite="Lax", raw="",
        )]
        client = AsyncMock()
        result = await _test_samesite_dns_bypass(client, "https://", cookies)
        techniques = [a.technique for a in result]
        assert "samesite_lax_detected" in techniques
        assert not any(t.startswith("dns_") for t in techniques)

    @pytest.mark.asyncio
    @patch("mytools.dns.dnsrebinding.scan_rebinding")
    async def test_scan_rebinding_error(self, mock_scan: MagicMock) -> None:
        mock_scan.side_effect = Exception("DNS timeout")
        cookies = [CookieInfo(
            name="session", value="abc", domain="test.com", path="/",
            secure=True, httponly=True, samesite="Lax", raw="",
        )]
        client = AsyncMock()
        result = await _test_samesite_dns_bypass(client, "https://target.com", cookies)
        techniques = [a.technique for a in result]
        assert "samesite_lax_detected" in techniques
        error_attempts = [a for a in result if a.error]
        assert len(error_attempts) == 1
        assert "DNS timeout" in error_attempts[0].error


# ─── CSRF Subdomain Bypass ────────────────────────────────────────────────────
class TestCsrfSubdomain:
    @pytest.mark.asyncio
    async def test_no_csrf_cookies_returns_empty(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc", domain="test.com", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        client = AsyncMock()
        result = await _test_csrf_subdomain(client, "https://target.com", cookies)
        assert result == []

    @pytest.mark.asyncio
    @patch("mytools.dns.subdomainenum.passive_enumeration")
    async def test_csrf_cookie_wildcard_domain(self, mock_enum: MagicMock) -> None:
        mock_enum.return_value = []
        cookies = [CookieInfo(
            name="csrf_token", value="abc123", domain=".target.com", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        client = AsyncMock()
        result = await _test_csrf_subdomain(client, "https://target.com", cookies)
        techniques = [a.technique for a in result]
        assert "csrf_subdomain_wildcard_domain" in techniques

    @pytest.mark.asyncio
    @patch("mytools.dns.subdomainenum.passive_enumeration")
    async def test_csrf_cookie_broad_domain(self, mock_enum: MagicMock) -> None:
        mock_enum.return_value = []
        cookies = [CookieInfo(
            name="csrf_token", value="abc123", domain="other.target.com", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        client = AsyncMock()
        result = await _test_csrf_subdomain(client, "https://target.com", cookies)
        techniques = [a.technique for a in result]
        assert "csrf_subdomain_cookie_scope" in techniques

    @pytest.mark.asyncio
    @patch("mytools.dns.subdomainenum.passive_enumeration")
    async def test_csrf_cookie_no_httponly(self, mock_enum: MagicMock) -> None:
        mock_enum.return_value = []
        cookies = [CookieInfo(
            name="XSRF-TOKEN", value="xyz", domain="", path="/",
            secure=True, httponly=False, samesite="Strict", raw="",
        )]
        client = AsyncMock()
        result = await _test_csrf_subdomain(client, "https://target.com", cookies)
        techniques = [a.technique for a in result]
        assert "csrf_subdomain_no_httponly" in techniques

    @pytest.mark.asyncio
    @patch("mytools.dns.subdomainenum.passive_enumeration")
    async def test_csrf_cookie_samesite_none(self, mock_enum: MagicMock) -> None:
        mock_enum.return_value = []
        cookies = [CookieInfo(
            name="csrf_token", value="abc", domain="", path="/",
            secure=True, httponly=True, samesite="None", raw="",
        )]
        client = AsyncMock()
        result = await _test_csrf_subdomain(client, "https://target.com", cookies)
        techniques = [a.technique for a in result]
        assert "csrf_subdomain_samesite_none" in techniques

    @pytest.mark.asyncio
    @patch("mytools.dns.subdomainenum.passive_enumeration")
    async def test_subdomains_discovered(self, mock_enum: MagicMock) -> None:
        from mytools.dns.subdomainenum import SubdomainResult
        mock_enum.return_value = [
            SubdomainResult(subdomain="api.target.com", status="passive"),
            SubdomainResult(subdomain="dev.target.com", status="passive"),
        ]
        cookies = [CookieInfo(
            name="csrf_token", value="abc", domain="", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        client = AsyncMock()
        result = await _test_csrf_subdomain(client, "https://target.com", cookies)
        techniques = [a.technique for a in result]
        assert "csrf_subdomain_takeover_risk" in techniques

    @pytest.mark.asyncio
    @patch("mytools.dns.subdomainenum.passive_enumeration")
    async def test_combined_risk(self, mock_enum: MagicMock) -> None:
        from mytools.dns.subdomainenum import SubdomainResult
        mock_enum.return_value = [
            SubdomainResult(subdomain="api.target.com", status="passive"),
        ]
        cookies = [CookieInfo(
            name="csrf_token", value="abc", domain=".target.com", path="/",
            secure=True, httponly=False, samesite="None", raw="",
        )]
        client = AsyncMock()
        result = await _test_csrf_subdomain(client, "https://target.com", cookies)
        techniques = [a.technique for a in result]
        assert "csrf_subdomain_combined_risk" in techniques

    @pytest.mark.asyncio
    async def test_no_domain_returns_early(self) -> None:
        cookies = [CookieInfo(
            name="csrf_token", value="abc", domain="", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        client = AsyncMock()
        result = await _test_csrf_subdomain(client, "https://", cookies)
        techniques = [a.technique for a in result]
        assert not any(t.startswith("csrf_subdomain_") for t in techniques)

    @pytest.mark.asyncio
    @patch("mytools.dns.subdomainenum.passive_enumeration")
    async def test_passive_enum_error(self, mock_enum: MagicMock) -> None:
        mock_enum.side_effect = Exception("DNS timeout")
        cookies = [CookieInfo(
            name="csrf_token", value="abc", domain="", path="/",
            secure=True, httponly=True, samesite="Strict", raw="",
        )]
        client = AsyncMock()
        result = await _test_csrf_subdomain(client, "https://target.com", cookies)
        error_attempts = [a for a in result if a.error]
        assert len(error_attempts) == 1
        assert "DNS timeout" in error_attempts[0].error

    @pytest.mark.asyncio
    @patch("mytools.dns.subdomainenum.passive_enumeration")
    async def test_single_risk_no_combined(self, mock_enum: MagicMock) -> None:
        mock_enum.return_value = []
        cookies = [CookieInfo(
            name="csrf_token", value="abc", domain="", path="/",
            secure=True, httponly=False, samesite="Strict", raw="",
        )]
        client = AsyncMock()
        result = await _test_csrf_subdomain(client, "https://target.com", cookies)
        techniques = [a.technique for a in result]
        assert "csrf_subdomain_no_httponly" in techniques
        assert "csrf_subdomain_combined_risk" not in techniques


# ─── Cookie Quoting ──────────────────────────────────────────────────────────
class TestCookieQuoting:
    def test_no_issues_returns_empty(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc123", domain="", path="/",
            secure=True, httponly=True, samesite="strict", raw="session=abc123; Path=/; Secure; HttpOnly",
        )]
        result = _test_cookie_quoting(cookies)
        assert result == []

    def test_semicolon_in_value(self) -> None:
        cookies = [CookieInfo(
            name="session", value="val;ue", domain="", path="/",
            secure=False, httponly=False, samesite="", raw='session="val;ue"',
        )]
        result = _test_cookie_quoting(cookies)
        techniques = [a.technique for a in result]
        assert "quoting_semicolon_in_value" in techniques

    def test_backslash_in_value(self) -> None:
        cookies = [CookieInfo(
            name="session", value=r'val"ue', domain="", path="/",
            secure=False, httponly=False, samesite="",
            raw=r'session="val\"ue"',
        )]
        result = _test_cookie_quoting(cookies)
        techniques = [a.technique for a in result]
        assert "quoting_backslash_escape" in techniques

    def test_null_byte_in_value(self) -> None:
        cookies = [CookieInfo(
            name="session", value="abc\x00def", domain="", path="/",
            secure=False, httponly=False, samesite="",
            raw="session=abc\x00def",
        )]
        result = _test_cookie_quoting(cookies)
        techniques = [a.technique for a in result]
        assert "quoting_null_byte" in techniques

    def test_comma_separator(self) -> None:
        cookies = [CookieInfo(
            name="session", value="v", domain="", path="",
            secure=False, httponly=False, samesite="",
            raw="session=v, Path=/, Secure",
        )]
        result = _test_cookie_quoting(cookies)
        techniques = [a.technique for a in result]
        assert "quoting_comma_separator" in techniques

    def test_unbalanced_quotes(self) -> None:
        cookies = [CookieInfo(
            name="session", value="value", domain="", path="",
            secure=False, httponly=False, samesite="",
            raw='session="value; Path=/',
        )]
        result = _test_cookie_quoting(cookies)
        techniques = [a.technique for a in result]
        assert "quoting_unbalanced_quotes" in techniques

    def test_whitespace_in_value(self) -> None:
        cookies = [CookieInfo(
            name="session", value="  abc  ", domain="", path="/",
            secure=False, httponly=False, samesite="",
            raw="session=  abc  ; Path=/",
        )]
        result = _test_cookie_quoting(cookies)
        techniques = [a.technique for a in result]
        assert "quoting_whitespace_in_value" in techniques

    def test_multiple_cookies_mixed_issues(self) -> None:
        cookies = [
            CookieInfo(
                name="a", value="v;1", domain="", path="",
                secure=False, httponly=False, samesite="", raw='a="v;1"',
            ),
            CookieInfo(
                name="b", value="x\x00y", domain="", path="",
                secure=False, httponly=False, samesite="", raw="b=x\x00y",
            ),
        ]
        result = _test_cookie_quoting(cookies)
        techniques = [a.technique for a in result]
        assert "quoting_semicolon_in_value" in techniques
        assert "quoting_null_byte" in techniques


# ─── Build Parser ────────────────────────────────────────────────────────────
class TestBuildParser:
    def test_has_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.url == "https://test.com"

    def test_has_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "-c", "domain"])
        assert args.category == "domain"

    def test_default_category_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.category == "all"

    def test_all_categories(self) -> None:
        parser = build_parser()
        for cat in ["all", "domain", "flags", "path", "path_traversal", "double_submit", "samesite_dns", "csrf_subdomain", "cookie_quoting"]:
            args = parser.parse_args(["https://test.com", "-c", cat])
            assert args.category == cat


# ─── Run Once ────────────────────────────────────────────────────────────────
class TestRunOnce:
    @patch("mytools.web.cookieboundary.run_scan")
    def test_run_once(self, mock_run: MagicMock) -> None:
        mock_run.return_value = 0
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        from mytools.web.cookieboundary import run_once
        result = run_once(args)
        assert result == 0
        mock_run.assert_called_once()
