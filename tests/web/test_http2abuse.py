"""Testes do modulo http2abuse.py — HTTP/2 Abuse."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mytools.web.http2abuse import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    HTTP2Attempt,
    HTTP2Result,
    _create_h2_connection,
    _fingerprint_server,
    _parse_url,
    build_parser,
    print_results,
)

# ─── HTTP2Attempt Tests ──────────────────────────────────────────────────────


class TestHTTP2Attempt:
    def test_creation(self) -> None:
        a = HTTP2Attempt(
            technique="test",
            category="cat",
            description="desc",
            h2_supported=True,
            settings_observed={},
            vulnerable=False,
            details="",
            error="",
        )
        assert a.technique == "test"
        assert a.vulnerable is False

    def test_frozen(self) -> None:
        a = HTTP2Attempt(
            technique="t", category="c", description="d",
            h2_supported=True, settings_observed={},
            vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "x"  # type: ignore[misc]


# ─── HTTP2Result Tests ──────────────────────────────────────────────────────


class TestHTTP2Result:
    def test_creation(self) -> None:
        r = HTTP2Result(
            target="https://example.com",
            host="example.com",
            port=443,
            h2_supported=True,
            server_settings={"MAX_FRAME_SIZE": 16384},
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.target == "https://example.com"
        assert r.overall_status == "secure"

    def test_frozen(self) -> None:
        r = HTTP2Result(
            target="t", host="h", port=443, h2_supported=True,
            server_settings={}, attempts=[], vulnerable_techniques=[],
            issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "x"  # type: ignore[misc]


# ─── Category Map Tests ──────────────────────────────────────────────────────


class TestCategoryMap:
    def test_has_seven_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 7

    def test_categories_match_dispatch(self) -> None:
        assert set(_CATEGORY_MAP.keys()) == set(_CATEGORY_DISPATCH.keys())

    def test_h2_downgrade_techniques(self) -> None:
        assert len(_CATEGORY_MAP["h2_downgrade"]) == 4

    def test_h2_fingerprint_techniques(self) -> None:
        assert len(_CATEGORY_MAP["h2_fingerprint"]) == 4

    def test_h2_stream_abuse_techniques(self) -> None:
        assert len(_CATEGORY_MAP["h2_stream_abuse"]) == 4

    def test_h2_reset_attack_techniques(self) -> None:
        assert len(_CATEGORY_MAP["h2_reset_attack"]) == 4

    def test_h2_settings_abuse_techniques(self) -> None:
        assert len(_CATEGORY_MAP["h2_settings_abuse"]) == 4

    def test_h2_priority_attack_techniques(self) -> None:
        assert len(_CATEGORY_MAP["h2_priority_attack"]) == 4

    def test_h2_push_abuse_techniques(self) -> None:
        assert len(_CATEGORY_MAP["h2_push_abuse"]) == 4


# ─── Parse URL Tests ────────────────────────────────────────────────────────


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

    def test_query_string(self) -> None:
        _host, path, _port, _tls = _parse_url("https://example.com/path?key=val")
        assert path == "/path?key=val"

    def test_default_path(self) -> None:
        _host, path, _port, _tls = _parse_url("https://example.com")
        assert path == "/"


# ─── Fingerprint Tests ──────────────────────────────────────────────────────


class TestFingerprint:
    def test_nginx(self) -> None:
        settings = {"MAX_FRAME_SIZE": 16384, "HEADER_TABLE_SIZE": 4096}
        assert _fingerprint_server(settings) == "nginx"

    def test_cloudflare(self) -> None:
        settings = {"MAX_FRAME_SIZE": 16384, "HEADER_TABLE_SIZE": 1000}
        assert _fingerprint_server(settings) == "cloudflare"

    def test_unknown(self) -> None:
        settings = {"MAX_FRAME_SIZE": 99999}
        assert _fingerprint_server(settings) == "unknown"

    def test_empty(self) -> None:
        assert _fingerprint_server({}) == "unknown"


# ─── Connection Tests ────────────────────────────────────────────────────────


class TestCreateH2Connection:
    def test_creates_tls_socket(self) -> None:
        with patch("mytools.web.http2abuse._create_tls_socket") as mock_tls:
            mock_sock = MagicMock()
            mock_tls.return_value = mock_sock
            mock_sock.selected_alpn_protocol.return_value = "h2"

            with patch("h2.connection.H2Connection") as MockH2:
                mock_conn = MagicMock()
                MockH2.return_value = mock_conn
                mock_conn.data_to_send.return_value = b"preface"

                _sock, _conn = _create_h2_connection("example.com", 443, 5.0)
                mock_tls.assert_called_once_with("example.com", 443, 5.0)
                mock_sock.sendall.assert_called_once_with(b"preface")


# ─── Build Parser Tests ──────────────────────────────────────────────────────


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
            "-c", "h2_downgrade", "h2_fingerprint",
        ])
        assert args.categories == ["h2_downgrade", "h2_fingerprint"]

    def test_no_categories_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.categories is None


# ─── Print Results Tests ─────────────────────────────────────────────────────


class TestPrintResults:
    def test_print_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = HTTP2Result(
            target="https://example.com",
            host="example.com",
            port=443,
            h2_supported=True,
            server_settings={"MAX_FRAME_SIZE": 16384},
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "SECURE" in output

    def test_print_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        attempt = HTTP2Attempt(
            technique="test",
            category="h2_downgrade",
            description="desc",
            h2_supported=True,
            settings_observed={},
            vulnerable=True,
            details="found",
            error="",
        )
        result = HTTP2Result(
            target="https://example.com",
            host="example.com",
            port=443,
            h2_supported=True,
            server_settings={},
            attempts=[attempt],
            vulnerable_techniques=["test"],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output


# ─── Dry Run / Main Tests ───────────────────────────────────────────────────


class TestDryRun:
    def test_has_url_in_parser(self) -> None:
        parser = build_parser()
        assert any(a.dest == "url" for a in parser._actions)

    def test_has_output_in_parser(self) -> None:
        parser = build_parser()
        assert any(a.dest == "output" for a in parser._actions)

    def test_has_timeout_in_parser(self) -> None:
        parser = build_parser()
        assert any(a.dest == "timeout" for a in parser._actions)
