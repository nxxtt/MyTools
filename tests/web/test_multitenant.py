"""Testes do módulo multitenant.py — Multi-Tenant Security Testing."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from mytools.web.multitenant import (
    _CATEGORY_MAP,
    _CATEGORY_TESTERS,
    TenantAttempt,
    TenantResult,
    _check_vulnerable,
    _detect_current_tenant,
    _encode_jwt_payload,
    _extract_cookie_domain,
    _extract_cookie_samesite,
    _make_attempt,
    _parse_jwt_payload,
    build_parser,
    print_results,
    run_scan,
)

# ─── Helpers ─────────────────────────────────────────────────────────────────


def _mock_response(
    status: int = 200,
    body: bytes = b"",
    headers: dict[str, str] | None = None,
) -> tuple[int, httpx.Headers, bytes, dict[str, list[str]]]:
    """Cria tuple simulando retorno de fetch()."""
    h = httpx.Headers(headers or {})
    return (status, h, body, {})


def _make_baseline(target: str = "https://example.com") -> tuple[int, int]:
    """Retorna baseline fake."""
    return 200, 1000


# ─── Dataclass Tests ─────────────────────────────────────────────────────────


class TestTenantAttempt:
    def test_creation(self) -> None:
        a = TenantAttempt(
            technique="header_x_tenant_id",
            category="tenant_id",
            tenant_id="TENANT_A",
            endpoint="https://example.com/api",
            payload="X-Tenant-ID: TENANT_B",
            status_baseline=200,
            status_test=200,
            size_baseline=1000,
            size_test=1000,
            status_changed=False,
            size_changed=False,
            vulnerable=False,
            details="",
            error="",
        )
        assert a.technique == "header_x_tenant_id"
        assert a.category == "tenant_id"
        assert a.vulnerable is False

    def test_frozen(self) -> None:
        a = TenantAttempt(
            technique="test", category="test", tenant_id="t",
            endpoint="http://x", payload="", status_baseline=200,
            status_test=200, size_baseline=0, size_test=0,
            status_changed=False, size_changed=False, vulnerable=False,
            details="", error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]

    def test_is_frozen_and_slotted(self) -> None:
        a = TenantAttempt(
            technique="t", category="c", tenant_id="tid",
            endpoint="ep", payload="p", status_baseline=200,
            status_test=200, size_baseline=10, size_test=10,
            status_changed=False, size_changed=False, vulnerable=False,
            details="", error="",
        )
        assert hasattr(a, "__slots__")


class TestTenantResult:
    def test_creation(self) -> None:
        r = TenantResult(
            target="https://example.com",
            tls=True,
            baseline_status=200,
            baseline_size=1000,
            current_tenant="TENANT_A",
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.current_tenant == "TENANT_A"
        assert r.tls is True

    def test_frozen(self) -> None:
        r = TenantResult(
            target="https://x", tls=True, baseline_status=200,
            baseline_size=0, current_tenant="t", attempts=[],
            vulnerable_techniques=[], blocked_techniques=[],
            issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]


# ─── Category Map Tests ─────────────────────────────────────────────────────


class TestCategoryMap:
    def test_has_four_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 4

    def test_categories_match_testers(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_TESTERS, f"No tester for {cat}"

    def test_tenant_id_techniques(self) -> None:
        assert "header_x_tenant_id" in _CATEGORY_MAP["tenant_id"]
        assert "cookie_tenant_id" in _CATEGORY_MAP["tenant_id"]
        assert "jwt_tenant_claim" in _CATEGORY_MAP["tenant_id"]

    def test_subdomain_isolation_techniques(self) -> None:
        assert "cookie_domain_wildcard" in _CATEGORY_MAP["subdomain_isolation"]
        assert "samesite_none_bypass" in _CATEGORY_MAP["subdomain_isolation"]

    def test_shared_resource_techniques(self) -> None:
        assert "uuid_enumeration" in _CATEGORY_MAP["shared_resource"]
        assert "path_traversal_tenant" in _CATEGORY_MAP["shared_resource"]

    def test_cross_tenant_ssrf_techniques(self) -> None:
        assert "metadata_service" in _CATEGORY_MAP["cross_tenant_ssrf"]
        assert "internal_ip_range" in _CATEGORY_MAP["cross_tenant_ssrf"]


# ─── Helper Function Tests ──────────────────────────────────────────────────


class TestCheckVulnerable:
    def test_found_indicator(self) -> None:
        vuln, details = _check_vulnerable(b'user_id: 12345', ["user_id"])
        assert vuln is True
        assert "user_id" in details

    def test_not_found(self) -> None:
        vuln, _ = _check_vulnerable(b"hello world", ["user_id"])
        assert vuln is False

    def test_case_insensitive(self) -> None:
        vuln, _ = _check_vulnerable(b"USER_ID: abc", ["user_id"])
        assert vuln is True

    def test_multiple_indicators(self) -> None:
        vuln, _details = _check_vulnerable(
            b"balance: 100, email: test@test.com",
            ["balance", "email"],
        )
        assert vuln is True

    def test_empty_body(self) -> None:
        vuln, _ = _check_vulnerable(b"", ["user_id"])
        assert vuln is False

    def test_error_indicators(self) -> None:
        vuln, _ = _check_vulnerable(b"forbidden access", ["forbidden"])
        assert vuln is True


class TestDetectCurrentTenant:
    def test_tenant_id_in_json(self) -> None:
        body = json.dumps({"tenant_id": "ACME_CORP"}).encode()
        assert _detect_current_tenant(body) == "ACME_CORP"

    def test_tenant_in_json(self) -> None:
        body = json.dumps({"tenant": "ORG_123"}).encode()
        assert _detect_current_tenant(body) == "ORG_123"

    def test_org_id_in_json(self) -> None:
        body = json.dumps({"org_id": "ORG_456"}).encode()
        assert _detect_current_tenant(body) == "ORG_456"

    def test_account_id_in_json(self) -> None:
        body = json.dumps({"account_id": "ACC_789"}).encode()
        assert _detect_current_tenant(body) == "ACC_789"

    def test_no_tenant(self) -> None:
        body = b"hello world"
        assert _detect_current_tenant(body) == "unknown"

    def test_nested_json(self) -> None:
        body = json.dumps({"user": {"tenant_id": "NESTED_1"}}).encode()
        assert _detect_current_tenant(body) == "NESTED_1"


class TestExtractCookieDomain:
    def test_with_domain(self) -> None:
        headers = {"Set-Cookie": "session=abc; Domain=.example.com"}
        assert _extract_cookie_domain(headers) == ".example.com"

    def test_without_domain(self) -> None:
        headers = {"Set-Cookie": "session=abc"}
        assert _extract_cookie_domain(headers) is None

    def test_multiple_cookies(self) -> None:
        headers = {"Set-Cookie": "a=1; Domain=.a.com"}
        result = _extract_cookie_domain(headers)
        assert result == ".a.com"


class TestExtractCookieSameSite:
    def test_strict(self) -> None:
        headers = {"Set-Cookie": "s=1; SameSite=Strict"}
        assert _extract_cookie_samesite(headers) == "Strict"

    def test_none(self) -> None:
        headers = {"Set-Cookie": "s=1; SameSite=None; Secure"}
        assert _extract_cookie_samesite(headers) == "None"

    def test_not_set(self) -> None:
        headers = {"Set-Cookie": "s=1"}
        assert _extract_cookie_samesite(headers) is None


class TestJWTPayload:
    def test_parse_valid(self) -> None:
        import base64

        payload = {"sub": "123", "tenant": "ACME"}
        payload_json = json.dumps(payload, separators=(",", ":"))
        payload_b64 = base64.urlsafe_b64encode(payload_json.encode()).rstrip(b"=").decode()
        token = f"header.{payload_b64}.sig"
        result = _parse_jwt_payload(token)
        assert result is not None
        assert result["tenant"] == "ACME"

    def test_parse_invalid(self) -> None:
        assert _parse_jwt_payload("not.a.jwt") is None

    def test_parse_too_short(self) -> None:
        assert _parse_jwt_payload("abc") is None

    def test_encode(self) -> None:
        token = _encode_jwt_payload({"tenant": "OTHER"})
        assert token.startswith("eyJ")
        parts = token.split(".")
        assert len(parts) == 3


class TestMakeAttempt:
    def test_fields(self) -> None:
        a = _make_attempt(
            technique="test_tech",
            category="test_cat",
            tenant_id="T1",
            endpoint="http://x",
            payload="p",
            b_status=200,
            b_size=100,
            t_status=403,
            t_size=160,
            vulnerable=True,
            details="found something",
        )
        assert a.technique == "test_tech"
        assert a.status_changed is True
        assert a.size_changed is True
        assert a.vulnerable is True

    def test_no_change(self) -> None:
        a = _make_attempt(
            technique="t", category="c", tenant_id="tid",
            endpoint="ep", payload="", b_status=200, b_size=100,
            t_status=200, t_size=100, vulnerable=False,
        )
        assert a.status_changed is False
        assert a.size_changed is False


# ─── Parser Tests ────────────────────────────────────────────────────────────


class TestBuildParser:
    def test_has_url_arg(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "tenant_id", "shared_resource"])
        assert args.categories == ["tenant_id", "shared_resource"]


# ─── Run Scan Tests ──────────────────────────────────────────────────────────


class TestRunScan:
    @pytest.mark.asyncio
    async def test_secure_baseline(self) -> None:
        baseline = _mock_response(200, b'{"tenant_id": "TENANT_A"}')

        with patch("mytools.web.multitenant.fetch", new_callable=AsyncMock) as mock_fetch:
            mock_fetch.return_value = baseline

            result = await run_scan(
                target="https://example.com",
                categories=["tenant_id"],
                timeout=5.0,
                output_file=None,
            )
            assert isinstance(result, TenantResult)
            assert result.overall_status in ("secure", "vulnerable")
            assert result.current_tenant == "TENANT_A"

    @pytest.mark.asyncio
    async def test_empty_categories(self) -> None:
        async def _mock_fetch(*_args: object, **_kwargs: object) -> tuple[int, httpx.Headers, bytes, dict[str, list[str]]]:
            return _mock_response(404, b"not found")

        with patch("mytools.web.multitenant.fetch", side_effect=_mock_fetch):
            result = await run_scan(
                target="https://example.com",
                categories=[],
                timeout=5.0,
                output_file=None,
            )
            assert result.overall_status == "secure"
            assert len(result.attempts) == 0


# ─── Print Results Tests ─────────────────────────────────────────────────────


class TestPrintResults:
    def test_print_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = TenantResult(
            target="https://example.com",
            tls=True,
            baseline_status=200,
            baseline_size=1000,
            current_tenant="TENANT_A",
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "SECURE" in captured.out

    def test_print_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        attempt = TenantAttempt(
            technique="header_x_tenant_id",
            category="tenant_id",
            tenant_id="OTHER",
            endpoint="https://example.com",
            payload="X-Tenant-ID: OTHER",
            status_baseline=200,
            status_test=200,
            size_baseline=1000,
            size_test=1000,
            status_changed=False,
            size_changed=False,
            vulnerable=True,
            details="indicator found",
            error="",
        )
        result = TenantResult(
            target="https://example.com",
            tls=True,
            baseline_status=200,
            baseline_size=1000,
            current_tenant="TENANT_A",
            attempts=[attempt],
            vulnerable_techniques=["header_x_tenant_id"],
            blocked_techniques=[],
            issues=["1 techniques vulnerable"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "VULNERABLE" in captured.out
