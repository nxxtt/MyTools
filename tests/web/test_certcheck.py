"""Testes do modulo certcheck.py — Certificate Checks."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.certcheck import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    _CT_REGIONAL_CAS,
    _CT_SPLIT_WORLD_CAS,
    _HSTS_PRELOAD_DOMAINS,
    CertCheckAttempt,
    CertCheckResult,
    _build_ocsp_request,
    _check_hsts_header,
    _detect_mixed_content,
    _extract_dn,
    _extract_scts_from_tls,
    _extract_scts_from_x509,
    _parse_ocsp_response,
    _parse_url,
    build_parser,
    print_results,
)

# ─── Dataclass Tests ─────────────────────────────────────────────────────────


class TestCertCheckAttempt:
    def test_creation(self) -> None:
        a = CertCheckAttempt(
            technique="ocsp_stapling_check", category="ocsp_stapling",
            description="desc", vulnerable=False, details="test", error="",
            cert_issuer="CN=CA", cert_subject="CN=target", cert_expiry="2025",
            ocsp_status="good", sct_count=3, hsts_preload=True,
        )
        assert a.technique == "ocsp_stapling_check"
        assert a.category == "ocsp_stapling"
        assert a.vulnerable is False

    def test_frozen(self) -> None:
        a = CertCheckAttempt(
            technique="t", category="c", description="d",
            vulnerable=False, details="", error="",
            cert_issuer="", cert_subject="", cert_expiry="",
            ocsp_status="", sct_count=0, hsts_preload=False,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestCertCheckResult:
    def test_creation(self) -> None:
        r = CertCheckResult(
            target="https://example.com", host="example.com", port=443, tls=True,
            cert_issuer="CN=CA", cert_subject="CN=target", cert_expiry="2025",
            chain_valid=True, attempts=[], vulnerable_techniques=[],
            issues=[], overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.chain_valid is True

    def test_frozen(self) -> None:
        r = CertCheckResult(
            target="t", host="h", port=443, tls=True,
            cert_issuer="", cert_subject="", cert_expiry="",
            chain_valid=False, attempts=[], vulnerable_techniques=[],
            issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]


# ─── Category Map Tests ─────────────────────────────────────────────────────


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        expected = {"ocsp_stapling", "cert_chain", "ct_sct", "ct_split_world", "hsts_preload", "mixed_content"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_category_counts(self) -> None:
        assert len(_CATEGORY_MAP["ocsp_stapling"]) == 5
        assert len(_CATEGORY_MAP["cert_chain"]) == 8
        assert len(_CATEGORY_MAP["ct_sct"]) == 4
        assert len(_CATEGORY_MAP["ct_split_world"]) == 3
        assert len(_CATEGORY_MAP["hsts_preload"]) == 5
        assert len(_CATEGORY_MAP["mixed_content"]) == 4

    def test_total_techniques(self) -> None:
        total = sum(len(v) for v in _CATEGORY_MAP.values())
        assert total == 29

    def test_dispatch_matches_map(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_DISPATCH

    def test_all_dispatches_are_coroutines(self) -> None:
        import inspect
        for cat, fn in _CATEGORY_DISPATCH.items():
            assert inspect.iscoroutinefunction(fn), f"{cat} is not a coroutine"


# ─── Helper Tests ────────────────────────────────────────────────────────────


class TestParseUrl:
    def test_https(self) -> None:
        host, path, port, tls = _parse_url("https://example.com/test")
        assert host == "example.com"
        assert path == "/test"
        assert port == 443
        assert tls is True

    def test_http(self) -> None:
        host, path, port, tls = _parse_url("http://example.com:8080/api")
        assert host == "example.com"
        assert path == "/api"
        assert port == 8080
        assert tls is False

    def test_no_scheme(self) -> None:
        host, _path, _port, tls = _parse_url("example.com")
        assert host == "example.com"
        assert tls is True


class TestExtractDn:
    def test_normal(self) -> None:
        dn = ((("CN", "example.com"),), (("O", "Let's Encrypt"),))
        result = _extract_dn(dn)
        assert "CN=example.com" in result
        assert "O=Let's Encrypt" in result

    def test_empty(self) -> None:
        assert _extract_dn(()) == ""

    def test_invalid(self) -> None:
        assert _extract_dn("invalid") == ""


class TestDetectMixedContent:
    def test_active_mixed(self) -> None:
        html = '<script src="http://evil.com/x.js"></script>'
        result = _detect_mixed_content(html, "https://example.com")
        assert len(result["active_mixed"]) == 1

    def test_passive_mixed(self) -> None:
        html = '<img src="http://example.com/img.png">'
        result = _detect_mixed_content(html, "https://example.com")
        assert len(result["passive_mixed"]) == 1

    def test_no_mixed(self) -> None:
        html = '<script src="https://cdn.com/x.js"></script>'
        result = _detect_mixed_content(html, "https://example.com")
        assert len(result["active_mixed"]) == 0
        assert len(result["passive_mixed"]) == 0

    def test_multiple_active(self) -> None:
        html = '''
        <script src="http://a.com/x.js"></script>
        <iframe src="http://b.com/frame.html"></iframe>
        '''
        result = _detect_mixed_content(html, "https://example.com")
        assert len(result["active_mixed"]) == 2

    def test_upgrade_insecure(self) -> None:
        assert _detect_mixed_content("", "https://example.com")["has_upgrade_insecure"] is False

    def test_csp_upgrade(self) -> None:
        assert _detect_mixed_content("", "https://example.com")["has_csp_upgrade"] is False


class TestExtractScts:
    def test_extract_tls_no_cert(self) -> None:
        assert _extract_scts_from_tls(b"") == 0

    def test_extract_x509_no_cert(self) -> None:
        assert _extract_scts_from_x509(b"") == 0


class TestBuildOcspRequest:
    def test_invalid_der(self) -> None:
        assert _build_ocsp_request(b"", b"") == b""


class TestParseOcspResponse:
    def test_invalid_der(self) -> None:
        result = _parse_ocsp_response(b"")
        assert result["response_status"] == "parse_error"


class TestCheckHstsHeader:
    @pytest.mark.asyncio
    async def test_no_response(self) -> None:
        with patch("httpx.AsyncClient", side_effect=Exception("no connection")):
            result = await _check_hsts_header("https://example.com", 5.0)
            assert result["hsts_present"] is False

    @pytest.mark.asyncio
    async def test_with_hsts(self) -> None:
        mock_resp = MagicMock()
        mock_resp.headers = {"strict-transport-security": "max-age=31536000; includeSubDomains; preload"}
        mock_client = AsyncMock()
        mock_client.head = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await _check_hsts_header("https://example.com", 5.0)
            assert result["hsts_present"] is True
            assert result["max_age"] == 31536000
            assert result["include_subdomains"] is True
            assert result["preload"] is True


# ─── Constants Tests ─────────────────────────────────────────────────────────


class TestConstants:
    def test_hsts_preload_domains(self) -> None:
        assert "google.com" in _HSTS_PRELOAD_DOMAINS
        assert "github.com" in _HSTS_PRELOAD_DOMAINS

    def test_ct_split_world_cas(self) -> None:
        assert "Let's Encrypt" in _CT_SPLIT_WORLD_CAS
        assert "DigiCert" in _CT_SPLIT_WORLD_CAS

    def test_ct_regional_cas(self) -> None:
        assert "CNNIC" in _CT_REGIONAL_CAS
        assert "CFCA" in _CT_REGIONAL_CAS


# ─── Print Results Tests ─────────────────────────────────────────────────────


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = CertCheckResult(
            target="https://example.com", host="example.com", port=443, tls=True,
            cert_issuer="CN=CA", cert_subject="CN=target", cert_expiry="2025",
            chain_valid=True, attempts=[], vulnerable_techniques=[],
            issues=[], overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Certificate Checks" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = CertCheckResult(
            target="https://example.com", host="example.com", port=443, tls=True,
            cert_issuer="CN=CA", cert_subject="CN=target", cert_expiry="2025",
            chain_valid=False, attempts=[], vulnerable_techniques=["expired"],
            issues=["Errors: test_error"], overall_status="vulnerable",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output
        assert "Errors:" in output


# ─── CLI Tests ───────────────────────────────────────────────────────────────


class TestCLI:
    def test_build_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_build_parser_with_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "ocsp_stapling", "cert_chain"])
        assert args.categories == ["ocsp_stapling", "cert_chain"]

    def test_build_parser_all_choices(self) -> None:
        parser = build_parser()
        for cat in _CATEGORY_MAP:
            args = parser.parse_args(["https://example.com", "-c", cat])
            assert args.categories == [cat]


# ─── Async Category Tests (Mocked) ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_category_dispatch_all_return_lists() -> None:
    """All category dispatchers should return a list."""
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn("example.com", 443, "/", 5.0, True, 0, 0)
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, CertCheckAttempt)
            assert attempt.category == cat
