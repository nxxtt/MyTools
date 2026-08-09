"""Testes do modulo tlsfingerprint.py — TLS Fingerprinting."""

from __future__ import annotations

import argparse
import runpy
import ssl
import struct
from unittest.mock import MagicMock, patch

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
    _create_tls_socket,
    _ec_point_formats_extension,
    _get_cert_info,
    _key_share_extension,
    _padding_extension,
    _parse_server_hello,
    _parse_url,
    _probe_cipher,
    _send_raw_tls,
    _signature_algorithms_extension,
    _sni_extension,
    _supported_groups_extension,
    _supported_versions_extension,
    _test_cipher_audit,
    _test_key_exchange,
    _test_tls_fingerprint,
    _test_tls_replay,
    build_parser,
    print_results,
    run_once,
    run_scan,
)

# ─── Dataclass Tests ─────────────────────────────────────────────────────────


class TestTLSFingerprintAttempt:
    def test_creation(self) -> None:
        a = TLSFingerprintAttempt(
            technique="ja3_hash",
            category="tls_fingerprint",
            description="desc",
            ja3="abc123",
            ja4="t13d0516h2_abc123_def456",
            cipher_suite="TLS_AES_128_GCM_SHA256",
            tls_version="0x0304",
            alpn="h2",
            vulnerable=False,
            details="test",
            error="",
        )
        assert a.technique == "ja3_hash"
        assert a.ja3 == "abc123"
        assert a.vulnerable is False

    def test_frozen(self) -> None:
        a = TLSFingerprintAttempt(
            technique="t",
            category="c",
            description="d",
            ja3="",
            ja4="",
            cipher_suite="",
            tls_version="",
            alpn="",
            vulnerable=False,
            details="",
            error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestTLSFingerprintResult:
    def test_creation(self) -> None:
        r = TLSFingerprintResult(
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            server_cipher="TLS_AES_128_GCM_SHA256",
            server_version="TLSv1.3",
            ja3_hash="abc",
            ja4_hash="def",
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.ja3_hash == "abc"

    def test_frozen(self) -> None:
        r = TLSFingerprintResult(
            target="t",
            host="h",
            port=443,
            tls=True,
            server_cipher="",
            server_version="",
            ja3_hash="",
            ja4_hash="",
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
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
        args = parser.parse_args(
            [
                "https://example.com",
                "-c",
                "tls_fingerprint",
                "cipher_audit",
            ]
        )
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
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            server_cipher="TLS_AES_128_GCM_SHA256",
            server_version="TLSv1.3",
            ja3_hash="abc123",
            ja4_hash="t13d0516h2_abc123_def456",
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "SECURE" in output

    def test_print_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        attempt = TLSFingerprintAttempt(
            technique="deprecated_ciphers",
            category="cipher_audit",
            description="desc",
            ja3="",
            ja4="",
            cipher_suite="RC4",
            tls_version="TLSv1.2",
            alpn="h2",
            vulnerable=True,
            details="Found RC4",
            error="",
        )
        result = TLSFingerprintResult(
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            server_cipher="RC4_128_SHA",
            server_version="TLSv1.2",
            ja3_hash="abc",
            ja4_hash="def",
            attempts=[attempt],
            vulnerable_techniques=["deprecated_ciphers"],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output

    def test_print_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = TLSFingerprintResult(
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            server_cipher="AES",
            server_version="TLSv1.3",
            ja3_hash="abc",
            ja4_hash="def",
            attempts=[],
            vulnerable_techniques=[],
            issues=["Errors: technique1"],
            overall_status="secure",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Issues:" in output

    def test_print_secure_category(self, capsys: pytest.CaptureFixture[str]) -> None:
        attempt = TLSFingerprintAttempt(
            technique="ja3_hash",
            category="tls_fingerprint",
            description="desc",
            ja3="abc",
            ja4="def",
            cipher_suite="TLS_AES_128_GCM_SHA256",
            tls_version="TLSv1.3",
            alpn="h2",
            vulnerable=False,
            details="ok",
            error="",
        )
        result = TLSFingerprintResult(
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            server_cipher="AES",
            server_version="TLSv1.3",
            ja3_hash="abc",
            ja4_hash="def",
            attempts=[attempt],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "tls_fingerprint: secure" in output


# ─── Padding Extension Tests ─────────────────────────────────────────────────


class TestPaddingExtension:
    def test_no_padding_when_already_long_enough(self) -> None:
        assert _padding_extension(10, 20) == b""

    def test_no_padding_when_equal(self) -> None:
        assert _padding_extension(10, 10) == b""

    def test_no_padding_when_pad_negative(self) -> None:
        assert _padding_extension(10, 9) == b""

    def test_padding_built(self) -> None:
        ext = _padding_extension(100, 10)
        assert ext[:2] == b"\x00\x15"
        assert len(ext) == 86 + 4


# ─── ServerHello Extension Parsing ───────────────────────────────────────────


def _server_hello(alpn_proto: bytes = b"h2") -> bytes:
    body = b"\x03\x04" + b"\x00" * 32 + b"\x00" + b"\x13\x01" + b"\x00"
    alpn_data = (
        struct.pack(">H", len(alpn_proto) + 1) + bytes([len(alpn_proto)]) + alpn_proto
    )
    ext_data = struct.pack(">HH", 0x0010, len(alpn_data)) + alpn_data
    body += struct.pack(">H", len(ext_data)) + ext_data
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake


class TestParseServerHelloExtensions:
    def test_parses_extensions_and_alpn(self) -> None:
        result = _parse_server_hello(_server_hello())
        assert result["version"] == 0x0304
        assert result["cipher_suite"] == 0x1301
        assert 0x0010 in result["extensions"]
        assert result["alpn"] == "h2"

    def test_alpn_ignored_when_short_data(self) -> None:
        body = b"\x03\x04" + b"\x00" * 32 + b"\x00" + b"\x13\x01" + b"\x00"
        alpn_data = b"\x00\x09\x00"
        ext_data = struct.pack(">HH", 0x0010, len(alpn_data)) + alpn_data
        body += struct.pack(">H", len(ext_data)) + ext_data
        handshake = b"\x02" + len(body).to_bytes(3, "big") + body
        result = _parse_server_hello(
            b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake
        )
        assert result["alpn"] is None

    def test_struct_error_is_caught(self) -> None:
        data = b"\x16\x03\x03\x00\x05\x02\x00\x00\x01\x00"
        result = _parse_server_hello(data)
        assert result["error"] is not None

    def test_no_alpn_extension(self) -> None:
        body = b"\x03\x04" + b"\x00" * 32 + b"\x00" + b"\x13\x01" + b"\x00"
        body += struct.pack(">H", 0)
        handshake = b"\x02" + len(body).to_bytes(3, "big") + body
        result = _parse_server_hello(
            b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake
        )
        assert result["version"] == 0x0304
        assert result["alpn"] is None

    def test_alpn_too_short(self) -> None:
        body = b"\x03\x04" + b"\x00" * 32 + b"\x00" + b"\x13\x01" + b"\x00"
        alpn_data = b"\x00"
        ext_data = struct.pack(">HH", 0x0010, len(alpn_data)) + alpn_data
        body += struct.pack(">H", len(ext_data)) + ext_data
        handshake = b"\x02" + len(body).to_bytes(3, "big") + body
        result = _parse_server_hello(
            b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake
        )
        assert result["alpn"] is None

    def test_alpn_proto_truncated(self) -> None:
        body = b"\x03\x04" + b"\x00" * 32 + b"\x00" + b"\x13\x01" + b"\x00"
        alpn_data = b"\x00\x01\x03\x00"
        ext_data = struct.pack(">HH", 0x0010, len(alpn_data)) + alpn_data
        body += struct.pack(">H", len(ext_data)) + ext_data
        handshake = b"\x02" + len(body).to_bytes(3, "big") + body
        result = _parse_server_hello(
            b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake
        )
        assert result["alpn"] is None


# ─── JA3/JA4 Branch Tests ────────────────────────────────────────────────────


class TestJA3JA4Branches:
    def test_ja4_without_sig_algorithms(self) -> None:
        meta = {
            "tls_version": 0x0303,
            "sni": None,
            "ciphers": [0x1301],
            "extensions": [0],
            "alpn": [],
            "sig_algorithms": [],
        }
        ja4 = _compute_ja4(meta)
        assert ja4.startswith("t12i")


# ─── URL Parser Branch Tests ─────────────────────────────────────────────────


class TestParseUrlBranches:
    def test_https_with_query(self) -> None:
        _host, path, _port, _tls = _parse_url("https://example.com/x?a=1&b=2")
        assert path == "/x?a=1&b=2"


# ─── Socket Fakes ────────────────────────────────────────────────────────────


class _FakeSock:
    def __init__(
        self,
        chunks: list[bytes] | None = None,
        exc: Exception | None = None,
    ) -> None:
        self.chunks = list(chunks or [])
        self.exc = exc
        self.closed = False
        self.sent = b""

    def sendall(self, data: bytes) -> None:
        self.sent += data

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout

    def recv(self, size: int) -> bytes:
        if self.exc is not None:
            raise self.exc
        if not self.chunks:
            return b""
        return self.chunks.pop(0)

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> _FakeSock:
        return self

    def __exit__(self, *args: object) -> bool:
        self.close()
        return False


class _FakeSSock:
    def __init__(
        self,
        cipher: tuple | None = ("AES", "TLSv1.3", 128),
        version: str | None = "TLSv1.3",
        alpn: str | None = "h2",
        shared: list | None = None,
        cert: dict | None = None,
    ) -> None:
        self._cipher = cipher
        self._version = version
        self._alpn = alpn
        self._shared = shared
        self._cert = cert
        self.closed = False

    def cipher(self) -> tuple | None:
        return self._cipher

    def version(self) -> str | None:
        return self._version

    def selected_alpn_protocol(self) -> str | None:
        return self._alpn

    def shared_ciphers(self) -> list | None:
        return self._shared

    def getpeercert(self, binary_form: bool = False) -> dict | None:
        if binary_form:
            return getattr(self, "_cert_der", None)
        return self._cert

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> _FakeSSock:
        return self

    def __exit__(self, *args: object) -> bool:
        self.close()
        return False


class _FakeCtx:
    def __init__(self, ssock: _FakeSSock | None = None, *args: object) -> None:
        self._ssock = ssock or _FakeSSock()
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


# ─── Raw TLS Send Tests ──────────────────────────────────────────────────────


class TestSendRawTls:
    def _patch_sock(self, monkeypatch: pytest.MonkeyPatch, sock: _FakeSock) -> None:
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint.socket.create_connection",
            lambda *a, **k: sock,
        )

    def test_full_record(self, monkeypatch: pytest.MonkeyPatch) -> None:
        payload = b"\x01\x02\x03\x04"
        rec = b"\x16\x03\x03" + struct.pack(">H", len(payload)) + payload
        self._patch_sock(monkeypatch, _FakeSock(chunks=[rec]))
        data, rtt = _send_raw_tls("example.com", 443, 5.0, b"hello")
        assert data == rec
        assert rtt >= 0

    def test_partial_then_complete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        payload = b"\x01\x02\x03\x04"
        rec = b"\x16\x03\x03" + struct.pack(">H", len(payload)) + payload
        self._patch_sock(monkeypatch, _FakeSock(chunks=[rec[:5], rec[5:]]))
        data, _rtt = _send_raw_tls("example.com", 443, 5.0, b"hello")
        assert data == rec

    def test_sub_5_bytes_then_complete(self, monkeypatch: pytest.MonkeyPatch) -> None:
        payload = b"\x01\x02\x03\x04"
        rec = b"\x16\x03\x03" + struct.pack(">H", len(payload)) + payload
        self._patch_sock(monkeypatch, _FakeSock(chunks=[rec[:3], rec[3:]]))
        data, _rtt = _send_raw_tls("example.com", 443, 5.0, b"hello")
        assert data == rec

    def test_empty_recv_breaks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_sock(monkeypatch, _FakeSock(chunks=[]))
        data, _rtt = _send_raw_tls("example.com", 443, 5.0, b"hello")
        assert data == b""

    def test_timeout_error_breaks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_sock(monkeypatch, _FakeSock(chunks=[], exc=TimeoutError("timeout")))
        data, _rtt = _send_raw_tls("example.com", 443, 5.0, b"hello")
        assert data == b""

    def test_os_error_breaks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._patch_sock(monkeypatch, _FakeSock(chunks=[], exc=OSError("reset")))
        data, _rtt = _send_raw_tls("example.com", 443, 5.0, b"hello")
        assert data == b""


# ─── TLS Socket Creation Tests ───────────────────────────────────────────────


class TestCreateTlsSocket:
    def test_with_ciphers_and_alpn(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _FakeCtx()
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint.socket.create_connection",
            lambda *a, **k: _FakeSock(),
        )
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint.ssl.SSLContext",
            lambda *a, **k: ctx,
        )
        ssock = _create_tls_socket("example.com", 443, 5.0, ciphers="HIGH", alpn=["h2"])
        assert ctx.ciphers == "HIGH"
        assert ctx.alpn == ["h2"]
        assert ssock is not None

    def test_without_optional_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ctx = _FakeCtx()
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint.socket.create_connection",
            lambda *a, **k: _FakeSock(),
        )
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint.ssl.SSLContext",
            lambda *a, **k: ctx,
        )
        _create_tls_socket("example.com", 443, 5.0)
        assert ctx.ciphers is None
        assert ctx.alpn is None


# ─── Cipher Probe Tests ──────────────────────────────────────────────────────


class TestProbeCipher:
    def test_accepted(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._create_tls_socket",
            lambda *a, **k: _FakeSSock(),
        )
        ok, info = _probe_cipher("example.com", 443, 5.0, "RSA")
        assert ok is True
        assert "TLSv1.3" in info

    def test_no_negotiated_cipher(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._create_tls_socket",
            lambda *a, **k: _FakeSSock(cipher=None),
        )
        ok, info = _probe_cipher("example.com", 443, 5.0, "RSA")
        assert ok is True
        assert info.endswith("/?")

    def test_ssl_error_from_cipher(self, monkeypatch: pytest.MonkeyPatch) -> None:
        class _ErrSock:
            def __init__(self) -> None:
                self.closed = False

            def cipher(self) -> tuple:
                raise ssl.SSLError("boom")

            def close(self) -> None:
                self.closed = True

        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._create_tls_socket",
            lambda *a, **k: _ErrSock(),
        )
        ok, info = _probe_cipher("example.com", 443, 5.0, "RSA")
        assert ok is False
        assert "boom" in info

    def test_ssl_error_from_connect(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(*args: object, **kwargs: object) -> _FakeSSock:
            raise ssl.SSLError("handshake failed")

        monkeypatch.setattr("mytools.web.tlsfingerprint._create_tls_socket", _raise)
        ok, _info = _probe_cipher("example.com", 443, 5.0, "RSA")
        assert ok is False

    def test_generic_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(*args: object, **kwargs: object) -> _FakeSSock:
            raise RuntimeError("boom")

        monkeypatch.setattr("mytools.web.tlsfingerprint._create_tls_socket", _raise)
        ok, info = _probe_cipher("example.com", 443, 5.0, "RSA")
        assert ok is False
        assert "boom" in info


# ─── Cert Info Tests ─────────────────────────────────────────────────────────


class TestGetCertInfo:
    def test_full(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cert = {
            "subject": ((("CN", "example.com"), ("O", "ACME")),),
            "issuer": ((("CN", "Root CA"),),),
            "notAfter": "Aug 1 12:00:00 2030 GMT",
        }
        ssock = _FakeSSock(
            cipher=("TLS_AES_128_GCM_SHA256", "TLSv1.3", 128),
            version="TLSv1.3",
            alpn="h2",
            shared=[("c", "TLSv1.3", 128)],
            cert=cert,
        )
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._create_tls_socket",
            lambda *a, **k: ssock,
        )
        info = _get_cert_info("example.com", 443, 5.0)
        assert info["subject"] == {"CN": "example.com"}
        assert info["issuer"] == {"CN": "Root CA"}
        assert info["not_after"] == "Aug 1 12:00:00 2030 GMT"
        assert info["cipher"] == "TLS_AES_128_GCM_SHA256"
        assert info["cipher_bits"] == 128
        assert info["version"] == "TLSv1.3"
        assert info["alpn"] == "h2"
        assert info["shared_ciphers_count"] == 1

    def test_no_cert(self, monkeypatch: pytest.MonkeyPatch) -> None:
        ssock = _FakeSSock(cipher=None, version=None, alpn=None, shared=None, cert=None)
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._create_tls_socket",
            lambda *a, **k: ssock,
        )
        info = _get_cert_info("example.com", 443, 5.0)
        assert info["cipher"] == "unknown"
        assert info["cipher_bits"] == 0
        assert info["version"] == "unknown"
        assert info["shared_ciphers_count"] == 0

    def test_empty_subject_issuer_entries(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        cert = {
            "subject": ((("CN", "example.com"),), ()),
            "issuer": ((), (("CN", "Root CA"),)),
            "notAfter": "Aug 1 12:00:00 2030 GMT",
        }
        ssock = _FakeSSock(cert=cert)
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._create_tls_socket",
            lambda *a, **k: ssock,
        )
        info = _get_cert_info("example.com", 443, 5.0)
        assert info["subject"] == {"CN": "example.com"}
        assert info["issuer"] == {"CN": "Root CA"}
        assert info["not_after"] == "Aug 1 12:00:00 2030 GMT"

    def test_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(*args: object, **kwargs: object) -> _FakeSSock:
            raise OSError("conn refused")

        monkeypatch.setattr("mytools.web.tlsfingerprint._create_tls_socket", _raise)
        info = _get_cert_info("example.com", 443, 5.0)
        assert "error" in info


# ─── Async Category Tests ────────────────────────────────────────────────────


class TestTestTlsFingerprint:
    @pytest.mark.asyncio
    async def test_happy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sh = _server_hello()
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._send_raw_tls",
            lambda *a, **k: (sh, 12.5),
        )
        attempts = await _test_tls_fingerprint("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 5
        assert all(a.error == "" for a in attempts)
        assert attempts[0].technique == "ja3_hash"
        assert attempts[0].ja3 != ""
        assert attempts[0].cipher_suite == "TLS_AES_128_GCM_SHA256"
        assert attempts[0].alpn == "h2"

    @pytest.mark.asyncio
    async def test_send_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(*args: object, **kwargs: object) -> tuple[bytes, float]:
            raise ConnectionResetError("reset")

        monkeypatch.setattr("mytools.web.tlsfingerprint._send_raw_tls", _raise)
        attempts = await _test_tls_fingerprint("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 5
        assert all(a.error != "" for a in attempts)


class TestTestTlsReplay:
    @pytest.mark.asyncio
    async def test_happy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        sh = _server_hello()
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._send_raw_tls",
            lambda *a, **k: (sh, 10.0),
        )
        attempts = await _test_tls_replay("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 5
        assert attempts[0].technique == "chrome_profile"
        assert all(a.error == "" for a in attempts)

    @pytest.mark.asyncio
    async def test_send_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(*args: object, **kwargs: object) -> tuple[bytes, float]:
            raise ConnectionResetError("reset")

        monkeypatch.setattr("mytools.web.tlsfingerprint._send_raw_tls", _raise)
        attempts = await _test_tls_replay("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 5
        assert all(a.error != "" for a in attempts)


class TestTestKeyExchange:
    @pytest.mark.asyncio
    async def test_happy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cert_info = {
            "cipher": "ECDHE_RSA_AES_128_GCM_SHA256",
            "version": "TLSv1.3",
            "alpn": "h2",
        }
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._get_cert_info",
            lambda *a, **k: cert_info,
        )
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._probe_cipher",
            lambda *a, **k: (True, "TLSv1.3/TLS_AES_128_GCM_SHA256"),
        )
        attempts = await _test_key_exchange("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 5
        assert any(a.exploit for a in attempts)
        assert attempts[0].technique == "rsa_keyexchange"

    @pytest.mark.asyncio
    async def test_probe_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cert_info = {
            "cipher": "ECDHE_RSA_AES_128_GCM_SHA256",
            "version": "TLSv1.3",
            "alpn": "h2",
        }
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._get_cert_info",
            lambda *a, **k: cert_info,
        )

        def probe(
            _host: str, _port: int, _timeout: float, cipher_name: str
        ) -> tuple[bool, str]:
            if cipher_name == "RSA_AES_128_GCM_SHA256":
                raise RuntimeError("boom")
            return False, "TLSv1.3/x"

        monkeypatch.setattr("mytools.web.tlsfingerprint._probe_cipher", probe)
        attempts = await _test_key_exchange("example.com", 443, "/", 5.0, True, 0, 0)
        assert attempts[0].error != ""


class TestTestCipherAudit:
    @pytest.mark.asyncio
    async def test_happy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cert_info = {
            "cipher": "TLS_AES_128_GCM_SHA256",
            "cipher_bits": 128,
            "version": "TLSv1.3",
            "alpn": "h2",
        }
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._get_cert_info",
            lambda *a, **k: cert_info,
        )
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._probe_cipher",
            lambda *a, **k: (False, "rejected"),
        )
        attempts = await _test_cipher_audit("example.com", 443, "/", 5.0, True, 0, 0)
        assert len(attempts) == 5
        assert attempts[0].technique == "deprecated_ciphers"
        assert all(a.error == "" for a in attempts)

    @pytest.mark.asyncio
    async def test_weak_ciphers_found(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cert_info = {
            "cipher": "RSA_RC4_128_SHA",
            "cipher_bits": 128,
            "version": "TLSv1.2",
            "alpn": "none",
        }
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._get_cert_info",
            lambda *a, **k: cert_info,
        )
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._probe_cipher",
            lambda *a, **k: (True, "accepted"),
        )
        attempts = await _test_cipher_audit("example.com", 443, "/", 5.0, True, 0, 0)
        assert attempts[0].vulnerable is True
        assert attempts[1].vulnerable is True
        assert attempts[2].vulnerable is True
        assert attempts[3].vulnerable is True
        assert any(a.exploit for a in attempts)

    @pytest.mark.asyncio
    async def test_small_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        cert_info = {
            "cipher": "UNKNOWN_0x9999",
            "cipher_bits": 40,
            "version": "TLSv1.2",
            "alpn": "none",
        }
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._get_cert_info",
            lambda *a, **k: cert_info,
        )
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._probe_cipher",
            lambda *a, **k: (False, "rejected"),
        )
        attempts = await _test_cipher_audit("example.com", 443, "/", 5.0, True, 0, 0)
        assert attempts[4].vulnerable is True


# ─── run_scan / run_once Tests ───────────────────────────────────────────────


def _scan_mocks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        "mytools.web.tlsfingerprint._get_cert_info",
        lambda *a, **k: {
            "cipher": "TLS_AES_128_GCM_SHA256",
            "version": "TLSv1.3",
            "alpn": "h2",
            "cipher_bits": 128,
        },
    )
    sh = _server_hello()
    monkeypatch.setattr(
        "mytools.web.tlsfingerprint._send_raw_tls",
        lambda *a, **k: (sh, 10.0),
    )
    monkeypatch.setattr(
        "mytools.web.tlsfingerprint._probe_cipher",
        lambda *a, **k: (False, "rejected"),
    )


class TestRunScan:
    @pytest.mark.asyncio
    async def test_bogus_category(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _scan_mocks(monkeypatch)
        result = await run_scan("https://example.com", ["bogus"], 5.0, None)
        assert result.attempts == []
        assert result.overall_status == "secure"

    @pytest.mark.asyncio
    async def test_tester_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _scan_mocks(monkeypatch)

        async def boom(*args: object, **kwargs: object) -> list:
            raise RuntimeError("boom")

        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._CATEGORY_DISPATCH",
            {"bad": boom},
        )
        result = await run_scan("https://example.com", ["bad"], 5.0, None)
        assert len(result.attempts) == 1
        assert result.attempts[0].technique == "bad_error"

    @pytest.mark.asyncio
    async def test_output_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _scan_mocks(monkeypatch)
        written: list[object] = []
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint.write_output",
            lambda *a, **k: written.append(a),
        )
        result = await run_scan(
            "https://example.com", ["cipher_audit"], 5.0, "out.json"
        )
        assert len(written) == 1
        assert result.overall_status == "secure"


class TestRunOnce:
    def test_secure_returns_zero(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _scan_mocks(monkeypatch)
        args = argparse.Namespace(
            url="https://example.com", categories=None, timeout=5.0, output=None
        )
        rc = run_once(args)
        capsys.readouterr()
        assert rc == 0

    def test_vulnerable_returns_one(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        _scan_mocks(monkeypatch)
        monkeypatch.setattr(
            "mytools.web.tlsfingerprint._probe_cipher",
            lambda *a, **k: (True, "accepted"),
        )
        args = argparse.Namespace(
            url="https://example.com", categories=None, timeout=5.0, output=None
        )
        rc = run_once(args)
        capsys.readouterr()
        assert rc == 1


# ─── __main__ Guard ──────────────────────────────────────────────────────────


class TestMainGuard:
    def test_run_as_main(self, monkeypatch: pytest.MonkeyPatch) -> None:
        mock_loop = MagicMock(return_value=0)
        monkeypatch.setattr("mytools.core.utils.run_main_loop", mock_loop)
        with (
            pytest.raises(SystemExit),
            patch("sys.argv", ["mytools-tlsfp", "https://example.com"]),
        ):
            runpy.run_module("mytools.web.tlsfingerprint", run_name="__main__")
        mock_loop.assert_called()
