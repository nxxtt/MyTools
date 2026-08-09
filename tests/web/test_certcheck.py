"""Testes do modulo certcheck.py — Certificate Checks."""

from __future__ import annotations

import argparse
import datetime
import runpy
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx
from cryptography import x509 as crypto_x509
from cryptography.hazmat.primitives import hashes as crypto_hashes
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa as crypto_rsa
from cryptography.x509 import ocsp as crypto_ocsp
from cryptography.x509.oid import NameOID, ObjectIdentifier

from mytools.web.certcheck import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    _CT_REGIONAL_CAS,
    _CT_SPLIT_WORLD_CAS,
    _HSTS_PRELOAD_DOMAINS,
    CertCheckAttempt,
    CertCheckResult,
    _build_ocsp_request,
    _check_chrome_preload,
    _check_hsts_header,
    _check_ocsp_stapling_raw,
    _detect_mixed_content,
    _extract_dn,
    _extract_scts_from_tls,
    _extract_scts_from_x509,
    _fetch_crt_sh,
    _fetch_page_content,
    _get_cert_info,
    _parse_ocsp_response,
    _parse_url,
    _test_cert_chain,
    _test_ct_sct,
    _test_ct_split_world,
    _test_hsts_preload,
    _test_mixed_content,
    _test_ocsp_stapling,
    build_parser,
    print_results,
    run_once,
    run_scan,
)

# ─── Dataclass Tests ─────────────────────────────────────────────────────────


class TestCertCheckAttempt:
    def test_creation(self) -> None:
        a = CertCheckAttempt(
            technique="ocsp_stapling_check",
            category="ocsp_stapling",
            description="desc",
            vulnerable=False,
            details="test",
            error="",
            cert_issuer="CN=CA",
            cert_subject="CN=target",
            cert_expiry="2025",
            ocsp_status="good",
            sct_count=3,
            hsts_preload=True,
        )
        assert a.technique == "ocsp_stapling_check"
        assert a.category == "ocsp_stapling"
        assert a.vulnerable is False

    def test_frozen(self) -> None:
        a = CertCheckAttempt(
            technique="t",
            category="c",
            description="d",
            vulnerable=False,
            details="",
            error="",
            cert_issuer="",
            cert_subject="",
            cert_expiry="",
            ocsp_status="",
            sct_count=0,
            hsts_preload=False,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestCertCheckResult:
    def test_creation(self) -> None:
        r = CertCheckResult(
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            cert_issuer="CN=CA",
            cert_subject="CN=target",
            cert_expiry="2025",
            chain_valid=True,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.chain_valid is True

    def test_frozen(self) -> None:
        r = CertCheckResult(
            target="t",
            host="h",
            port=443,
            tls=True,
            cert_issuer="",
            cert_subject="",
            cert_expiry="",
            chain_valid=False,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]


# ─── Category Map Tests ─────────────────────────────────────────────────────


class TestCategoryMap:
    def test_all_categories_present(self) -> None:
        expected = {
            "ocsp_stapling",
            "cert_chain",
            "ct_sct",
            "ct_split_world",
            "hsts_preload",
            "mixed_content",
        }
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
        html = """
        <script src="http://a.com/x.js"></script>
        <iframe src="http://b.com/frame.html"></iframe>
        """
        result = _detect_mixed_content(html, "https://example.com")
        assert len(result["active_mixed"]) == 2

    def test_upgrade_insecure(self) -> None:
        assert (
            _detect_mixed_content("", "https://example.com")["has_upgrade_insecure"]
            is False
        )

    def test_csp_upgrade(self) -> None:
        assert (
            _detect_mixed_content("", "https://example.com")["has_csp_upgrade"] is False
        )


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
        mock_resp.headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains; preload"
        }
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
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            cert_issuer="CN=CA",
            cert_subject="CN=target",
            cert_expiry="2025",
            chain_valid=True,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(r)
        output = capsys.readouterr().out
        assert "Certificate Checks" in output
        assert "SECURE" in output

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = CertCheckResult(
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            cert_issuer="CN=CA",
            cert_subject="CN=target",
            cert_expiry="2025",
            chain_valid=False,
            attempts=[],
            vulnerable_techniques=["expired"],
            issues=["Errors: test_error"],
            overall_status="vulnerable",
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
        args = parser.parse_args(
            ["https://example.com", "-c", "ocsp_stapling", "cert_chain"]
        )
        assert args.categories == ["ocsp_stapling", "cert_chain"]

    def test_build_parser_all_choices(self) -> None:
        parser = build_parser()
        for cat in _CATEGORY_MAP:
            args = parser.parse_args(["https://example.com", "-c", cat])
            assert args.categories == [cat]


# ─── Async Category Tests (Mocked) ──────────────────────────────────────────


@pytest.mark.asyncio
@pytest.mark.network
@respx.mock
@patch(
    "mytools.web.certcheck._get_cert_info",
    return_value={
        "cert": {},
        "cert_der": b"",
        "issuer": "CN=Mock CA",
        "subject": "CN=example.com",
        "not_after": "Jan 1 00:00:00 2030 GMT",
        "chain_length": 2,
        "san": (("DNS", "example.com"),),
        "cipher_bits": 256,
    },
)
async def test_category_dispatch_all_return_lists(_mock_cert: MagicMock) -> None:
    """All category dispatchers should return a list."""
    respx.route().mock(return_value=httpx.Response(403))
    for cat, fn in _CATEGORY_DISPATCH.items():
        result = await fn("example.com", 443, "/", 5.0, True, 0, 0)
        assert isinstance(result, list), f"{cat} did not return a list"
        assert len(result) > 0, f"{cat} returned empty list"
        for attempt in result:
            assert isinstance(attempt, CertCheckAttempt)
            assert attempt.category == cat


# ─── Print Results Branch Tests ──────────────────────────────────────────────


class TestPrintResultsBranches:
    def test_attempts_grouped_by_category(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        vuln = CertCheckAttempt(
            technique="expired",
            category="cert_chain",
            description="d",
            vulnerable=True,
            details="Expired",
            error="",
            cert_issuer="CA",
            cert_subject="t",
            cert_expiry="2020",
            ocsp_status="",
            sct_count=0,
            hsts_preload=False,
            exploit="expired_cert",
            tool="certcheck",
        )
        ok = CertCheckAttempt(
            technique="hsts_header",
            category="hsts_preload",
            description="d",
            vulnerable=False,
            details="ok",
            error="",
            cert_issuer="CA",
            cert_subject="t",
            cert_expiry="2030",
            ocsp_status="",
            sct_count=0,
            hsts_preload=True,
        )
        result = CertCheckResult(
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            cert_issuer="CA",
            cert_subject="t",
            cert_expiry="2030",
            chain_valid=True,
            attempts=[vuln, ok],
            vulnerable_techniques=["expired"],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "cert_chain: 1 vulnerable(s)" in output
        assert "hsts_preload: secure" in output
        assert "expired: Expired" in output
        assert "Exploit: expired_cert" in output


# ─── Cert Generation Helpers ─────────────────────────────────────────────────


def _make_cert(
    extensions: list[tuple[crypto_x509.ExtensionType, bool]] | None = None,
    cn: str = "example.com",
) -> tuple[crypto_x509.Certificate, crypto_rsa.RSAPrivateKey]:
    key = crypto_rsa.generate_private_key(public_exponent=65537, key_size=1024)
    now = datetime.datetime.now(datetime.UTC)
    name = crypto_x509.Name([crypto_x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    builder = (
        crypto_x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
    )
    for ext, critical in extensions or []:
        builder = builder.add_extension(ext, critical)
    return builder.sign(key, crypto_hashes.SHA256()), key


def _ocsp_url_cert_der() -> bytes:
    aia = crypto_x509.AuthorityInformationAccess(
        [
            crypto_x509.AccessDescription(
                ObjectIdentifier("1.3.6.1.5.5.7.48.1"),
                crypto_x509.UniformResourceIdentifier("http://ocsp.example.com"),
            )
        ]
    )
    cert, _key = _make_cert([(aia, False)])
    return cert.public_bytes(crypto_serialization.Encoding.DER)


def _unrecognized_ext_cert_der() -> bytes:
    uni = crypto_x509.UnrecognizedExtension(
        ObjectIdentifier("1.3.6.1.4.1.11129.2.4.5"), b"\x00\x04\x00\x00"
    )
    cert, _key = _make_cert([(uni, False)])
    return cert.public_bytes(crypto_serialization.Encoding.DER)


def _self_signed_cert_pair() -> tuple[bytes, bytes]:
    cert, _key = _make_cert()
    der = cert.public_bytes(crypto_serialization.Encoding.DER)
    return der, der


def _ocsp_response_der(status: str = "good") -> bytes:
    cert, key = _make_cert()
    now = datetime.datetime.now(datetime.UTC)
    builder = crypto_ocsp.OCSPResponseBuilder()
    if status == "good":
        builder = builder.add_response(
            cert=cert,
            issuer=cert,
            algorithm=crypto_hashes.SHA256(),
            cert_status=crypto_ocsp.OCSPCertStatus.GOOD,
            this_update=now,
            next_update=now + datetime.timedelta(days=1),
            revocation_time=None,
            revocation_reason=None,
        )
    else:
        builder = builder.add_response(
            cert=cert,
            issuer=cert,
            algorithm=crypto_hashes.SHA256(),
            cert_status=crypto_ocsp.OCSPCertStatus.REVOKED,
            this_update=now,
            next_update=None,
            revocation_time=now,
            revocation_reason=crypto_x509.ReasonFlags.key_compromise,
        )
    builder = builder.responder_id(crypto_ocsp.OCSPResponderEncoding.HASH, cert)
    resp = builder.sign(key, crypto_hashes.SHA256())
    return resp.public_bytes(crypto_serialization.Encoding.DER)


# ─── Socket Fakes ────────────────────────────────────────────────────────────


class _FakeSock:
    def __init__(self, exc: Exception | None = None) -> None:
        self.exc = exc

    def __enter__(self) -> _FakeSock:
        return self

    def __exit__(self, *args: object) -> bool:
        return False


class _FakeSSock:
    def __init__(
        self,
        cert: dict | None = None,
        cert_der: bytes | None = b"",
        cipher: tuple | None = ("AES", "TLSv1.3", 256),
        version: str | None = "TLSv1.3",
        chain: list | None = None,
    ) -> None:
        self._cert = cert
        self._cert_der = cert_der
        self._cipher = cipher
        self._version = version
        self._chain = chain

    def getpeercert(self, binary_form: bool = False) -> dict | bytes | None:
        return self._cert_der if binary_form else self._cert

    def cipher(self) -> tuple | None:
        return self._cipher

    def version(self) -> str | None:
        return self._version

    def get_unverified_chain(self) -> list:
        if self._chain is None:
            raise RuntimeError("no chain available")
        return self._chain

    def __enter__(self) -> _FakeSSock:
        return self

    def __exit__(self, *args: object) -> bool:
        return False


class _FakeCtx:
    def __init__(self, ssock: _FakeSSock | None = None, *args: object) -> None:
        self._ssock = ssock or _FakeSSock()
        self.check_hostname = True
        self.verify_mode: object = None
        self.options = 0
        self.ciphers: str | None = None
        self.alpn: list[str] | None = None

    def set_ciphers(self, ciphers: str) -> None:
        self.ciphers = ciphers

    def set_alpn_protocols(self, protocols: list[str]) -> None:
        self.alpn = protocols

    def wrap_socket(
        self, sock: object, server_hostname: str | None = None
    ) -> _FakeSSock:
        self.wrapped_hostname = server_hostname
        return self._ssock


# ─── _get_cert_info Tests ────────────────────────────────────────────────────


class TestGetCertInfo:
    def _patch(self, monkeypatch: pytest.MonkeyPatch, ctx: _FakeCtx) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck.socket.create_connection",
            lambda *a, **k: _FakeSock(),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck.ssl.create_default_context",
            lambda *a, **k: ctx,
        )

    def test_full(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cert = {
            "subject": ((("CN", "example.com"),),),
            "issuer": ((("CN", "Root CA"),),),
            "serialNumber": "1234",
            "notBefore": "Aug 1 00:00:00 2026 GMT",
            "notAfter": "Aug 1 12:00:00 2030 GMT",
            "subjectAltName": (("DNS", "example.com"),),
            "OCSP": ("http://ocsp.example.com",),
            "caIssuers": ("http://ca.example.com",),
            "crlDistributionPoints": ("http://crl.example.com",),
        }
        ssock = _FakeSSock(
            cert=cert,
            cert_der=b"\x30\x00",
            cipher=("AES", "TLSv1.3", 256),
            version="TLSv1.3",
            chain=[b"c1", b"c2"],
        )
        self._patch(monkeypatch, _FakeCtx(ssock=ssock))
        info = _get_cert_info("example.com", 443, 5.0)
        assert info["chain_length"] == 2
        assert info["cipher"] == "AES"
        assert info["cipher_bits"] == 256
        assert info["version"] == "TLSv1.3"
        assert info["subject"] == "CN=example.com"
        assert info["issuer"] == "CN=Root CA"

    def test_chain_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(monkeypatch, _FakeCtx(ssock=_FakeSSock(cert={}, chain=None)))
        info = _get_cert_info("example.com", 443, 5.0)
        assert info["chain_length"] == 1
        assert info["chain_certs"] == []

    def test_no_cipher_or_version(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch(
            monkeypatch, _FakeCtx(ssock=_FakeSSock(cert={}, cipher=None, version=None))
        )
        info = _get_cert_info("example.com", 443, 5.0)
        assert info["cipher"] == "unknown"
        assert info["cipher_bits"] == 0
        assert info["version"] == "unknown"

    def test_connection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(*args: object, **kwargs: object) -> _FakeSock:
            raise OSError("conn refused")

        monkeypatch.setattr("mytools.web.certcheck.socket.create_connection", _raise)
        info = _get_cert_info("example.com", 443, 5.0)
        assert "error" in info


# ─── _build_ocsp_request Tests ───────────────────────────────────────────────


class TestBuildOcspRequestValid:
    def test_valid_cert_pair(self) -> None:
        cert_der, issuer_der = _self_signed_cert_pair()
        req = _build_ocsp_request(cert_der, issuer_der)
        assert len(req) > 0


# ─── _check_ocsp_stapling_raw Tests ──────────────────────────────────────────


class _FakeAccessMethod:
    def __str__(self) -> str:
        return "1.3.6.1.5.5.7.48.1"


class _FakeAccessDesc:
    access_method = _FakeAccessMethod()
    access_location = SimpleNamespace(value="http://ocsp.example.com")


class _FakeAIAValue:
    def __iter__(self) -> object:
        return iter([_FakeAccessDesc()])


class TestCheckOcspStaplingRaw:
    def _patch(self, monkeypatch: pytest.MonkeyPatch, ctx: _FakeCtx) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck.socket.create_connection",
            lambda *a, **k: _FakeSock(),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck.ssl.SSLContext",
            lambda *a, **k: ctx,
        )

    def test_ocsp_url_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ssock = _FakeSSock(cert_der=b"\x30\x00")
        self._patch(monkeypatch, _FakeCtx(ssock=ssock))
        monkeypatch.setattr(
            "cryptography.x509.load_der_x509_certificate",
            lambda *a, **k: _FakeCert([_FakeExt(_FakeAIAValue())]),
        )
        result = _check_ocsp_stapling_raw("example.com", 443, 5.0)
        assert result["stapling"] is True
        assert result["response_status"] == "stapled"
        assert result["responder_url"] == "http://ocsp.example.com"

    def test_real_aia_no_match(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ssock = _FakeSSock(cert_der=_ocsp_url_cert_der())
        self._patch(monkeypatch, _FakeCtx(ssock=ssock))
        result = _check_ocsp_stapling_raw("example.com", 443, 5.0)
        assert result["stapling"] is False
        assert result["responder_url"] == ""

    def test_cert_der_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ssock = _FakeSSock(cert_der=None)
        self._patch(monkeypatch, _FakeCtx(ssock=ssock))
        result = _check_ocsp_stapling_raw("example.com", 443, 5.0)
        assert result["stapling"] is False
        assert result["response_status"] == "unknown"

    def test_crypto_parse_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ssock = _FakeSSock(cert_der=b"\x30\x00")
        self._patch(monkeypatch, _FakeCtx(ssock=ssock))

        def _raise(*args: object, **kwargs: object) -> None:
            raise ValueError("bad der")

        monkeypatch.setattr("cryptography.x509.load_der_x509_certificate", _raise)
        result = _check_ocsp_stapling_raw("example.com", 443, 5.0)
        assert result["stapling"] is False
        assert result["response_status"] == "unknown"

    def test_unrecognized_extension(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ssock = _FakeSSock(cert_der=_unrecognized_ext_cert_der())
        self._patch(monkeypatch, _FakeCtx(ssock=ssock))
        result = _check_ocsp_stapling_raw("example.com", 443, 5.0)
        assert result["stapling"] is False

    def test_connection_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(*args: object, **kwargs: object) -> _FakeSock:
            raise OSError("conn refused")

        monkeypatch.setattr("mytools.web.certcheck.socket.create_connection", _raise)
        result = _check_ocsp_stapling_raw("example.com", 443, 5.0)
        assert result["stapling"] is False


# ─── _parse_ocsp_response Tests ──────────────────────────────────────────────


class TestParseOcspResponseValid:
    def test_good(self) -> None:
        result = _parse_ocsp_response(_ocsp_response_der("good"))
        assert result["response_status"] == "good"
        assert result["this_update"] != ""
        assert result["next_update"] != ""

    def test_revoked(self) -> None:
        result = _parse_ocsp_response(_ocsp_response_der("revoked"))
        assert result["response_status"] == "revoked"
        assert result["revocation_status"] == "revoked"
        assert result["next_update"] == ""

    def test_fake_no_timestamps(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = SimpleNamespace(
            certificate_status=crypto_ocsp.OCSPCertStatus.GOOD,
            this_update_utc=None,
            next_update_utc=None,
        )
        monkeypatch.setattr(
            "cryptography.x509.ocsp.load_der_ocsp_response",
            lambda *a, **k: fake,
        )
        result = _parse_ocsp_response(b"\x00")
        assert result["response_status"] == "good"
        assert result["this_update"] == ""
        assert result["next_update"] == ""


# ─── SCT Extraction Tests ────────────────────────────────────────────────────


class _FakeExt:
    def __init__(self, value: object, oid: str = "1.2.3.4") -> None:
        self.value = value
        self.oid = SimpleNamespace(dotted_string=oid)


class _FakeCert:
    def __init__(self, extensions: list[_FakeExt]) -> None:
        self.extensions = extensions


class _RaisesOnIter:
    def __iter__(self) -> object:
        raise ValueError("boom")


class TestExtractSctsTls:
    def _patch_cert(self, monkeypatch: pytest.MonkeyPatch, cert: _FakeCert) -> None:
        monkeypatch.setattr(
            "cryptography.x509.load_der_x509_certificate",
            lambda *a, **k: cert,
        )

    def test_iterable_extension_counts(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cert = _FakeCert([_FakeExt([1, 2, 3])])
        self._patch_cert(monkeypatch, cert)
        assert _extract_scts_from_tls(b"\x00") == 3

    def test_non_iterable_extension_skipped(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cert = _FakeCert([_FakeExt(42), _FakeExt([9])])
        self._patch_cert(monkeypatch, cert)
        assert _extract_scts_from_tls(b"\x00") == 1

    def test_iteration_error_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cert = _FakeCert([_FakeExt(_RaisesOnIter())])
        self._patch_cert(monkeypatch, cert)
        assert _extract_scts_from_tls(b"\x00") == 0


class TestExtractSctsX509:
    def _patch_cert(self, monkeypatch: pytest.MonkeyPatch, cert: _FakeCert) -> None:
        monkeypatch.setattr(
            "cryptography.x509.load_der_x509_certificate",
            lambda *a, **k: cert,
        )

    def test_sct_extension_counted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cert = _FakeCert([_FakeExt([1, 2, 3], oid="1.3.6.1.4.1.11129.2.4.5")])
        self._patch_cert(monkeypatch, cert)
        assert _extract_scts_from_x509(b"\x00") == 3

    def test_sct_extension_parse_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cert = _FakeCert([_FakeExt(_RaisesOnIter(), oid="1.3.6.1.4.1.11129.2.4.5")])
        self._patch_cert(monkeypatch, cert)
        assert _extract_scts_from_x509(b"\x00") == 1

    def test_non_sct_oid_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cert = _FakeCert([_FakeExt([1, 2, 3], oid="1.2.3.4")])
        self._patch_cert(monkeypatch, cert)
        assert _extract_scts_from_x509(b"\x00") == 0


# ─── crt.sh / Preload / Page Fetch Tests ─────────────────────────────────────


class TestFetchCrtSh:
    @pytest.mark.asyncio
    @respx.mock
    async def test_ok(self) -> None:
        respx.route().mock(
            return_value=httpx.Response(200, json=[{"issuer_name": "Let's Encrypt"}])
        )
        data = await _fetch_crt_sh("example.com", 5.0)
        assert len(data) == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_non_200(self) -> None:
        respx.route().mock(return_value=httpx.Response(403))
        data = await _fetch_crt_sh("example.com", 5.0)
        assert data == []

    @pytest.mark.asyncio
    async def test_exception(self) -> None:
        with patch("httpx.AsyncClient", side_effect=Exception("no")):
            data = await _fetch_crt_sh("example.com", 5.0)
            assert data == []


class TestCheckChromePreload:
    @pytest.mark.asyncio
    @respx.mock
    async def test_present(self) -> None:
        respx.route().mock(return_value=httpx.Response(200, json={"status": "present"}))
        assert await _check_chrome_preload("example.com", 5.0) is True

    @pytest.mark.asyncio
    @respx.mock
    async def test_not_present(self) -> None:
        respx.route().mock(return_value=httpx.Response(200, json={"status": "unknown"}))
        assert await _check_chrome_preload("example.com", 5.0) is False

    @pytest.mark.asyncio
    async def test_fallback_known_domain(self) -> None:
        with patch("httpx.AsyncClient", side_effect=Exception("no")):
            assert await _check_chrome_preload("google.com", 5.0) is True

    @pytest.mark.asyncio
    async def test_fallback_unknown_domain(self) -> None:
        with patch("httpx.AsyncClient", side_effect=Exception("no")):
            assert await _check_chrome_preload("unknown.com", 5.0) is False


class TestFetchPageContent:
    @pytest.mark.asyncio
    @respx.mock
    async def test_ok(self) -> None:
        respx.route().mock(return_value=httpx.Response(200, text="<html></html>"))
        html = await _fetch_page_content("https://example.com", 5.0)
        assert "<html>" in html

    @pytest.mark.asyncio
    async def test_exception(self) -> None:
        with patch("httpx.AsyncClient", side_effect=Exception("no")):
            assert await _fetch_page_content("https://example.com", 5.0) == ""


class TestCheckHstsHeaderBranches:
    @pytest.mark.asyncio
    async def test_no_max_age(self) -> None:
        mock_resp = MagicMock()
        mock_resp.headers = {"strict-transport-security": "includeSubDomains"}
        mock_client = AsyncMock()
        mock_client.head = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("httpx.AsyncClient", return_value=mock_client):
            result = await _check_hsts_header("https://example.com", 5.0)
            assert result["hsts_present"] is True
            assert result["max_age"] == 0
            assert result["include_subdomains"] is True


# ─── Category Test Functions ─────────────────────────────────────────────────


def _cert_info(
    not_after: object = "Aug 1 12:00:00 2030 GMT",
    not_before: object = "Aug 1 00:00:00 2026 GMT",
    chain_length: object = 2,
    san: object = (("DNS", "example.com"),),
    cipher_bits: object = 256,
    **extra: object,
) -> dict:
    info: dict = {
        "cert": {"notBefore": not_before},
        "cert_der": b"",
        "issuer": "CN=Mock CA",
        "subject": "CN=example.com",
        "not_after": not_after,
        "not_before": not_before,
        "chain_length": chain_length,
        "san": san,
        "cipher_bits": cipher_bits,
        "ca_issuers": (),
        "crl_distribution": (),
    }
    info.update(extra)
    return info


def _ocsp_info(**extra: object) -> dict:
    info: dict = {
        "stapling": True,
        "response_status": "good",
        "revocation_status": "good",
        "responder_url": "http://ocsp.example.com",
    }
    info.update(extra)
    return info


class TestTestOcspStapling:
    @pytest.mark.asyncio
    async def test_happy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._check_ocsp_stapling_raw",
            lambda *a, **k: _ocsp_info(),
        )
        attempts = await _test_ocsp_stapling("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 5
        assert not any(a.error for a in attempts)
        assert attempts[0].technique == "ocsp_stapling_check"
        assert attempts[0].vulnerable is False

    @pytest.mark.asyncio
    async def test_no_stapling(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._check_ocsp_stapling_raw",
            lambda *a, **k: _ocsp_info(
                stapling=False,
                response_status="revoked",
                revocation_status="revoked",
                responder_url="",
            ),
        )
        attempts = await _test_ocsp_stapling("example.com", 443, "/", 5.0, True, 0, 0)
        assert attempts[0].vulnerable is True
        assert attempts[3].vulnerable is True
        assert attempts[4].vulnerable is True

    @pytest.mark.asyncio
    async def test_cert_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: {"error": "boom"},
        )
        attempts = await _test_ocsp_stapling("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 1
        assert attempts[0].ocsp_status == "error"

    @pytest.mark.asyncio
    async def test_tech_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        mock_info = MagicMock()
        mock_info.get.side_effect = RuntimeError("boom")
        monkeypatch.setattr(
            "mytools.web.certcheck._check_ocsp_stapling_raw",
            lambda *a, **k: mock_info,
        )
        attempts = await _test_ocsp_stapling("example.com", 443, "/", 5.0, True, 0, 0)
        assert all(a.error != "" for a in attempts)


class _BadStr:
    def __str__(self) -> str:
        raise ValueError("bad str")


class _BadCompare:
    def __gt__(self, other: object) -> bool:
        return True

    def __lt__(self, other: object) -> object:
        raise ValueError("bad compare")


class TestTestCertChain:
    @pytest.mark.asyncio
    async def test_normal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(chain_length=3, cipher_bits=4096),
        )
        attempts = await _test_cert_chain("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 8
        assert not any(a.vulnerable for a in attempts)

    @pytest.mark.asyncio
    async def test_no_expiry_no_san(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(not_after="", san=()),
        )
        attempts = await _test_cert_chain("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 8
        assert attempts[3].vulnerable is False
        assert attempts[5].vulnerable is True

    @pytest.mark.asyncio
    async def test_bad_string_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(not_after=_BadStr()),
        )
        attempts = await _test_cert_chain("example.com", 443, "/", 5.0, True, 0, 0)
        assert sum(1 for a in attempts if a.error) == 1
        assert attempts[3].error != ""

    @pytest.mark.asyncio
    async def test_expired_and_weak(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(
                not_after="Jan 1 00:00:00 2020 GMT",
                chain_length=1,
                issuer="",
                subject="",
                san=(("DNS", "other.com"),),
                cipher_bits=1024,
                ca_issuers=("http://ca.example.com",),
                crl_distribution=("http://crl.example.com",),
            ),
        )
        attempts = await _test_cert_chain("www.example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 8
        assert attempts[0].vulnerable is True
        assert attempts[2].vulnerable is True
        assert attempts[3].vulnerable is True
        assert attempts[5].vulnerable is True
        assert attempts[6].vulnerable is True
        assert attempts[7].details == "HPKP: present"

    @pytest.mark.asyncio
    async def test_not_yet_valid(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(not_before="Jan 1 00:00:00 2035 GMT"),
        )
        attempts = await _test_cert_chain("example.com", 443, "/", 5.0, True, 0, 0)
        assert attempts[4].vulnerable is True

    @pytest.mark.asyncio
    async def test_invalid_dates(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(not_after="garbage", not_before="garbage"),
        )
        attempts = await _test_cert_chain("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 8

    @pytest.mark.asyncio
    async def test_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: {"error": "boom"},
        )
        attempts = await _test_cert_chain("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 1
        assert attempts[0].technique == "full_chain"


class TestTestCtSct:
    @pytest.mark.asyncio
    async def test_happy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        attempts = await _test_ct_sct("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 4
        assert attempts[0].vulnerable is True

    @pytest.mark.asyncio
    async def test_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: {"error": "boom"},
        )
        attempts = await _test_ct_sct("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 1
        assert attempts[0].technique == "sct_tls_extension"

    @pytest.mark.asyncio
    async def test_compare_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        bad = _BadCompare()
        monkeypatch.setattr(
            "mytools.web.certcheck._extract_scts_from_tls",
            lambda *a, **k: bad,
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._extract_scts_from_x509",
            lambda *a, **k: bad,
        )
        attempts = await _test_ct_sct("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 4
        assert attempts[2].error != ""
        assert attempts[0].vulnerable is False


class _NoLen:
    def __iter__(self) -> object:
        return iter([{"issuer_name": "Let's Encrypt"}])


class TestTestCtSplitWorld:
    @pytest.mark.asyncio
    async def test_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._fetch_crt_sh",
            AsyncMock(return_value=[]),
        )
        attempts = await _test_ct_split_world("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 3
        assert attempts[0].vulnerable is True

    @pytest.mark.asyncio
    async def test_with_regional(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._fetch_crt_sh",
            AsyncMock(
                return_value=[
                    {"issuer_name": "CNNIC"},
                    {"issuer_name": "Let's Encrypt"},
                    {"issuer_name": "Unknown CA"},
                    {},
                ]
            ),
        )
        attempts = await _test_ct_split_world("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 3
        assert attempts[1].vulnerable is True
        assert attempts[2].vulnerable is True

    @pytest.mark.asyncio
    async def test_len_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._fetch_crt_sh",
            AsyncMock(return_value=_NoLen()),
        )
        attempts = await _test_ct_split_world("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 3
        assert attempts[0].error != ""


class TestTestHstsPreload:
    @pytest.mark.asyncio
    async def test_happy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._check_hsts_header",
            AsyncMock(
                return_value={
                    "hsts_present": True,
                    "max_age": 31536000,
                    "include_subdomains": True,
                    "preload": True,
                    "raw_header": "max-age=31536000",
                }
            ),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._check_chrome_preload",
            AsyncMock(return_value=True),
        )
        attempts = await _test_hsts_preload("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 5
        assert not any(a.vulnerable for a in attempts)
        assert attempts[4].hsts_preload is True

    @pytest.mark.asyncio
    async def test_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._check_hsts_header",
            AsyncMock(
                return_value={
                    "hsts_present": False,
                    "max_age": 0,
                    "include_subdomains": False,
                    "preload": False,
                    "raw_header": "",
                }
            ),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._check_chrome_preload",
            AsyncMock(return_value=False),
        )
        attempts = await _test_hsts_preload("example.com", 443, "/", 5.0, False, 0, 0)
        assert all(a.vulnerable for a in attempts)

    @pytest.mark.asyncio
    async def test_tech_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        mock_info = MagicMock()
        mock_info.get.side_effect = RuntimeError("boom")
        monkeypatch.setattr(
            "mytools.web.certcheck._check_hsts_header",
            AsyncMock(return_value=mock_info),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._check_chrome_preload",
            AsyncMock(return_value=False),
        )
        attempts = await _test_hsts_preload("example.com", 443, "/", 5.0, True, 0, 0)
        assert sum(1 for a in attempts if a.error) == 4
        assert attempts[4].vulnerable is True


class _BadLen:
    def __len__(self) -> int:
        raise ValueError("bad len")

    def __iter__(self) -> object:
        return iter([])


class TestTestMixedContent:
    @pytest.mark.asyncio
    async def test_not_tls(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        attempts = await _test_mixed_content("example.com", 80, "/", 5.0, False, 0, 0)
        assert len(attempts) == 4
        assert all("not HTTPS" in a.details for a in attempts)

    @pytest.mark.asyncio
    async def test_https_with_mixed(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._fetch_page_content",
            AsyncMock(
                return_value=(
                    '<script src="http://evil.com/x.js"></script>'
                    '<img src="http://evil.com/i.png">'
                )
            ),
        )
        mock_resp = MagicMock()
        mock_resp.headers = {
            "upgrade-insecure-requests": "1",
            "content-security-policy": "upgrade-insecure-requests",
        }
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("httpx.AsyncClient", return_value=mock_client):
            attempts = await _test_mixed_content(
                "example.com", 443, "/", 5.0, True, 0, 0
            )
        assert len(attempts) == 4
        assert attempts[0].vulnerable is True
        assert attempts[1].vulnerable is True
        assert attempts[2].vulnerable is False
        assert attempts[3].vulnerable is False

    @pytest.mark.asyncio
    async def test_https_without_headers(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._fetch_page_content",
            AsyncMock(return_value="<html></html>"),
        )
        mock_resp = MagicMock()
        mock_resp.headers = {}
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        with patch("httpx.AsyncClient", return_value=mock_client):
            attempts = await _test_mixed_content(
                "example.com", 443, "/", 5.0, True, 0, 0
            )
        assert attempts[2].vulnerable is True
        assert attempts[3].vulnerable is True

    @pytest.mark.asyncio
    async def test_http_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._fetch_page_content",
            AsyncMock(return_value=""),
        )
        with patch("httpx.AsyncClient", side_effect=Exception("no")):
            attempts = await _test_mixed_content(
                "example.com", 443, "/", 5.0, True, 0, 0
            )
        assert len(attempts) == 4
        assert attempts[2].vulnerable is True

    @pytest.mark.asyncio
    async def test_detect_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.certcheck._get_cert_info",
            lambda *a, **k: _cert_info(),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._fetch_page_content",
            AsyncMock(return_value="<html></html>"),
        )
        monkeypatch.setattr(
            "mytools.web.certcheck._detect_mixed_content",
            lambda *a, **k: {
                "active_mixed": _BadLen(),
                "passive_mixed": _BadLen(),
                "has_upgrade_insecure": False,
                "has_csp_upgrade": False,
            },
        )
        attempts = await _test_mixed_content("example.com", 443, "/", 5.0, True, 0, 0)
        assert attempts[0].error != ""
        assert attempts[1].error != ""


# ─── run_scan / run_once Tests ───────────────────────────────────────────────


def _scan_mocks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mytools.web.certcheck._get_cert_info",
        lambda *a, **k: _cert_info(),
    )
    monkeypatch.setattr(
        "mytools.web.certcheck._check_ocsp_stapling_raw",
        lambda *a, **k: _ocsp_info(),
    )
    monkeypatch.setattr(
        "mytools.web.certcheck._fetch_crt_sh",
        AsyncMock(return_value=[]),
    )
    monkeypatch.setattr(
        "mytools.web.certcheck._check_hsts_header",
        AsyncMock(
            return_value={
                "hsts_present": True,
                "max_age": 31536000,
                "include_subdomains": True,
                "preload": True,
                "raw_header": "max-age=31536000",
            }
        ),
    )
    monkeypatch.setattr(
        "mytools.web.certcheck._check_chrome_preload",
        AsyncMock(return_value=True),
    )
    monkeypatch.setattr(
        "mytools.web.certcheck._fetch_page_content",
        AsyncMock(return_value="<html></html>"),
    )


class TestRunScan:
    @pytest.mark.asyncio
    async def test_all_categories(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _scan_mocks(monkeypatch)
        result = await run_scan("https://example.com", None, 5.0, None)
        assert len(result.attempts) > 0
        assert result.chain_valid is True
        assert result.overall_status == "vulnerable"

    @pytest.mark.asyncio
    async def test_bogus_category(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _scan_mocks(monkeypatch)
        result = await run_scan("https://example.com", ["bogus"], 5.0, None)
        assert result.attempts == []

    @pytest.mark.asyncio
    async def test_tester_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _scan_mocks(monkeypatch)

        async def boom(*args: object, **kwargs: object) -> list:
            raise RuntimeError("boom")

        monkeypatch.setattr(
            "mytools.web.certcheck._CATEGORY_DISPATCH",
            {"bad": boom},
        )
        result = await run_scan("https://example.com", ["bad"], 5.0, None)
        assert len(result.attempts) == 1
        assert result.attempts[0].technique == "bad_error"

    @pytest.mark.asyncio
    async def test_json_output(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _scan_mocks(monkeypatch)
        result = await run_scan(
            "https://example.com", ["cert_chain"], 5.0, None, json_output=True
        )
        output = capsys.readouterr().out
        assert '"overall_status"' in output
        assert result.overall_status == "vulnerable"

    @pytest.mark.asyncio
    async def test_output_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _scan_mocks(monkeypatch)
        written: list[object] = []
        monkeypatch.setattr(
            "mytools.web.certcheck.write_output",
            lambda *a, **k: written.append(a),
        )
        await run_scan("https://example.com", ["cert_chain"], 5.0, "out.json")
        assert len(written) == 1


class TestRunOnce:
    def test_vulnerable_returns_one(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _scan_mocks(monkeypatch)
        args = argparse.Namespace(
            url="https://example.com",
            categories=None,
            timeout=5.0,
            output=None,
            json_output=False,
        )
        rc = run_once(args)
        capsys.readouterr()
        assert rc == 1

    def test_secure_returns_zero(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _scan_mocks(monkeypatch)
        args = argparse.Namespace(
            url="https://example.com",
            categories=["ocsp_stapling"],
            timeout=5.0,
            output=None,
            json_output=False,
        )
        rc = run_once(args)
        capsys.readouterr()
        assert rc == 0


# ─── __main__ Guard ──────────────────────────────────────────────────────────


class TestMainGuard:
    def test_run_as_main(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_loop = MagicMock(return_value=0)
        monkeypatch.setattr("mytools.core.utils.run_main_loop", mock_loop)
        with (
            pytest.raises(SystemExit),
            patch("sys.argv", ["mytools-certcheck", "https://example.com"]),
        ):
            runpy.run_module("mytools.web.certcheck", run_name="__main__")
        mock_loop.assert_called()
