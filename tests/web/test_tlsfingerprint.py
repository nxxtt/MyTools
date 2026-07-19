"""Testes do modulo tlsfingerprint.py — TLS Fingerprinting."""

from __future__ import annotations

import pytest

from mytools.web.tlsfingerprint import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    CHROME_PROFILE,
    FIREFOX_PROFILE,
    TLSFingerprintAttempt,
    TLSFingerprintResult,
    _alpn_extension,
    _build_client_hello,
    _build_client_hello_from_profile,
    _compute_ja3,
    _compute_ja4,
    _ec_point_formats_extension,
    _key_share_extension,
    _parse_server_hello,
    _parse_url,
    _signature_algorithms_extension,
    _sni_extension,
    _supported_groups_extension,
    _supported_versions_extension,
    build_parser,
    print_results,
)

# ─── Dataclass Tests ─────────────────────────────────────────────────────────


class TestTLSFingerprintAttempt:
    def test_creation(self) -> None:
        a = TLSFingerprintAttempt(
            technique="ja3_hash", category="tls_fingerprint", description="desc",
            ja3="abc123", ja4="t13d0516h2_abc123_def456",
            cipher_suite="TLS_AES_128_GCM_SHA256", tls_version="0x0304",
            alpn="h2", vulnerable=False, details="test", error="",
        )
        assert a.technique == "ja3_hash"
        assert a.ja3 == "abc123"
        assert a.vulnerable is False

    def test_frozen(self) -> None:
        a = TLSFingerprintAttempt(
            technique="t", category="c", description="d",
            ja3="", ja4="", cipher_suite="", tls_version="",
            alpn="", vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestTLSFingerprintResult:
    def test_creation(self) -> None:
        r = TLSFingerprintResult(
            target="https://example.com", host="example.com", port=443, tls=True,
            server_cipher="TLS_AES_128_GCM_SHA256", server_version="TLSv1.3",
            ja3_hash="abc", ja4_hash="def",
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.ja3_hash == "abc"

    def test_frozen(self) -> None:
        r = TLSFingerprintResult(
            target="t", host="h", port=443, tls=True,
            server_cipher="", server_version="",
            ja3_hash="", ja4_hash="",
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]


# ─── Category Map Tests ─────────────────────────────────────────────────────


class TestCategoryMap:
    def test_has_four_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 4

    def test_categories_match_dispatch(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_DISPATCH, f"No dispatch for {cat}"

    def test_tls_fingerprint_techniques(self) -> None:
        assert len(_CATEGORY_MAP["tls_fingerprint"]) == 5

    def test_tls_replay_techniques(self) -> None:
        assert len(_CATEGORY_MAP["tls_replay"]) == 5

    def test_key_exchange_techniques(self) -> None:
        assert len(_CATEGORY_MAP["key_exchange"]) == 5

    def test_cipher_audit_techniques(self) -> None:
        assert len(_CATEGORY_MAP["cipher_audit"]) == 5

    def test_all_categories_have_unique_techniques(self) -> None:
        all_techs: list[str] = []
        for techs in _CATEGORY_MAP.values():
            all_techs.extend(techs)
        assert len(all_techs) == len(set(all_techs))


# ─── Browser Profile Tests ──────────────────────────────────────────────────


class TestBrowserProfiles:
    def test_chrome_has_ciphers(self) -> None:
        assert len(CHROME_PROFILE.ciphers) > 0

    def test_firefox_has_ciphers(self) -> None:
        assert len(FIREFOX_PROFILE.ciphers) > 0

    def test_chrome_has_alpn(self) -> None:
        assert "h2" in CHROME_PROFILE.alpn

    def test_firefox_has_groups(self) -> None:
        assert len(FIREFOX_PROFILE.groups) > 0


# ─── Extension Builder Tests ────────────────────────────────────────────────


class TestExtensionBuilders:
    def test_sni_extension(self) -> None:
        ext = _sni_extension("example.com")
        assert ext[:2] == b"\x00\x00"
        assert b"example.com" in ext

    def test_supported_groups(self) -> None:
        ext = _supported_groups_extension([0x001D, 0x0017])
        assert ext[:2] == b"\x00\x0a"

    def test_ec_point_formats(self) -> None:
        ext = _ec_point_formats_extension()
        assert ext[:2] == b"\x00\x0b"

    def test_signature_algorithms(self) -> None:
        ext = _signature_algorithms_extension([0x0403, 0x0804])
        assert ext[:2] == b"\x00\x0d"

    def test_supported_versions(self) -> None:
        ext = _supported_versions_extension()
        assert ext[:2] == b"\x00\x2b"

    def test_key_share(self) -> None:
        ext = _key_share_extension([(0x001D, b"\x00" * 32)])
        assert ext[:2] == b"\x00\x33"

    def test_alpn_extension(self) -> None:
        ext = _alpn_extension(["h2", "http/1.1"])
        assert ext[:2] == b"\x00\x10"
        assert b"h2" in ext


# ─── ClientHello Builder Tests ──────────────────────────────────────────────


class TestBuildClientHello:
    def test_returns_bytes_and_metadata(self) -> None:
        data, meta = _build_client_hello("example.com")
        assert isinstance(data, bytes)
        assert isinstance(meta, dict)

    def test_starts_with_record_header(self) -> None:
        data, _ = _build_client_hello("example.com")
        assert data[0] == 0x16

    def test_has_sni(self) -> None:
        _, meta = _build_client_hello("example.com")
        assert meta["sni"] == "example.com"

    def test_custom_ciphers(self) -> None:
        _data, meta = _build_client_hello("example.com", ciphers=[0x1301, 0x1302])
        assert 0x1301 in meta["ciphers"]
        assert 0x1302 in meta["ciphers"]

    def test_from_profile(self) -> None:
        data, meta = _build_client_hello_from_profile("example.com", CHROME_PROFILE)
        assert isinstance(data, bytes)
        assert len(meta["ciphers"]) > 0


# ─── JA3/JA4 Computation Tests ──────────────────────────────────────────────


class TestJA3JA4:
    def test_ja3_returns_hex(self) -> None:
        _, meta = _build_client_hello("example.com")
        ja3 = _compute_ja3(meta)
        assert len(ja3) == 32
        assert all(c in "0123456789abcdef" for c in ja3)

    def test_ja4_returns_format(self) -> None:
        _, meta = _build_client_hello("example.com")
        ja4 = _compute_ja4(meta)
        parts = ja4.split("_")
        assert len(parts) == 3
        assert parts[0].startswith("t13")

    def test_ja3_excludes_grease(self) -> None:
        meta = {
            "legacy_version": 771,
            "ciphers": [0x0A0A, 0x1301, 0x1A1A, 0x1302],
            "extensions": [0, 23],
            "groups": [0x001D],
            "point_formats": [0],
        }
        ja3 = _compute_ja3(meta)
        assert len(ja3) == 32

    def test_ja4_deterministic(self) -> None:
        _, meta = _build_client_hello("example.com")
        ja4_a = _compute_ja4(meta)
        ja4_b = _compute_ja4(meta)
        assert ja4_a == ja4_b


# ─── ServerHello Parser Tests ───────────────────────────────────────────────


class TestParseServerHello:
    def test_handles_too_short(self) -> None:
        result = _parse_server_hello(b"\x00\x01")
        assert result["error"] is not None

    def test_handles_not_server_hello(self) -> None:
        data = b"\x16\x03\x03\x00\x05\x01\x00\x00\x01\x00"
        result = _parse_server_hello(data)
        assert result["error"] is not None

    def test_parses_valid_header(self) -> None:
        data = b"\x16\x03\x03\x00\x35\x02\x00\x00\x31\x03\x03" + b"\x00" * 32
        data += b"\x20" + b"\x00" * 32
        data += b"\x13\x01"
        data += b"\x00"
        result = _parse_server_hello(data)
        assert result["version"] == 0x0303
        assert result["cipher_suite"] == 0x1301


# ─── URL Parser Tests ────────────────────────────────────────────────────────


class TestParseUrl:
    def test_https(self) -> None:
        host, path, port, tls = _parse_url("https://example.com/test")
        assert host == "example.com"
        assert path == "/test"
        assert port == 443
        assert tls is True

    def test_http(self) -> None:
        _host, _path, port, tls = _parse_url("http://example.com/test")
        assert port == 80
        assert tls is False

    def test_custom_port(self) -> None:
        _host, _path, port, _tls = _parse_url("https://example.com:8443/test")
        assert port == 8443

    def test_default_path(self) -> None:
        _host, path, _port, _tls = _parse_url("https://example.com")
        assert path == "/"


# ─── Parser Tests ────────────────────────────────────────────────────────────


@pytest.mark.smoke
class TestBuildParser:
    def test_has_url_arg(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "https://example.com",
            "-c", "tls_fingerprint", "cipher_audit",
        ])
        assert args.categories == ["tls_fingerprint", "cipher_audit"]

    def test_no_categories_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.categories is None

    def test_has_output_in_parser(self) -> None:
        parser = build_parser()
        assert any(a.dest == "output" for a in parser._actions)

    def test_has_timeout_in_parser(self) -> None:
        parser = build_parser()
        assert any(a.dest == "timeout" for a in parser._actions)


# ─── Print Results Tests ─────────────────────────────────────────────────────


class TestPrintResults:
    def test_print_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = TLSFingerprintResult(
            target="https://example.com", host="example.com", port=443, tls=True,
            server_cipher="TLS_AES_128_GCM_SHA256", server_version="TLSv1.3",
            ja3_hash="abc123", ja4_hash="t13d0516h2_abc123_def456",
            attempts=[], vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "SECURE" in output

    def test_print_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        attempt = TLSFingerprintAttempt(
            technique="deprecated_ciphers", category="cipher_audit", description="desc",
            ja3="", ja4="", cipher_suite="RC4", tls_version="TLSv1.2",
            alpn="h2", vulnerable=True, details="Found RC4", error="",
        )
        result = TLSFingerprintResult(
            target="https://example.com", host="example.com", port=443, tls=True,
            server_cipher="RC4_128_SHA", server_version="TLSv1.2",
            ja3_hash="abc", ja4_hash="def",
            attempts=[attempt], vulnerable_techniques=["deprecated_ciphers"],
            issues=[], overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output

    def test_print_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = TLSFingerprintResult(
            target="https://example.com", host="example.com", port=443, tls=True,
            server_cipher="AES", server_version="TLSv1.3",
            ja3_hash="abc", ja4_hash="def",
            attempts=[], vulnerable_techniques=[],
            issues=["Errors: technique1"], overall_status="secure",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Issues:" in output
