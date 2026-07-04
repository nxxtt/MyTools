#!/usr/bin/env python3
"""Testes unitarios do modulo de Cookie Domain Boundary."""
from unittest.mock import MagicMock, patch

import pytest

from mytools.web.cookieboundary import (
    _CATEGORY_MAP,
    CookieBoundaryAttempt,
    CookieBoundaryResult,
    CookieInfo,
    _extract_target_domain,
    _is_public_suffix,
    _parse_cookie,
    _test_domain_attributes,
    _test_flag_attributes,
    _test_path_attributes,
    build_parser,
    print_results,
)


# ─── Category Map ────────────────────────────────────────────────────────────
class TestCategoryMap:
    def test_has_three_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 3

    def test_categories_are_correct(self) -> None:
        expected = {"domain", "flags", "path"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_domain_has_five_techniques(self) -> None:
        assert len(_CATEGORY_MAP["domain"]) == 5

    def test_flags_has_four_techniques(self) -> None:
        assert len(_CATEGORY_MAP["flags"]) == 4

    def test_path_has_two_techniques(self) -> None:
        assert len(_CATEGORY_MAP["path"]) == 2


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
        for cat in ["all", "domain", "flags", "path"]:
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
