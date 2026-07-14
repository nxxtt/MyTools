"""Testes do módulo httsmuggle.py — HTTP Request Smuggling."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mytools.web.httsmuggle import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    SmuggleAttempt,
    SmuggleResult,
    _build_chunked_cl_payload,
    _build_clte_payload,
    _build_pipeline_payload,
    _build_tecl_payload,
    _build_tete_duplicate,
    _build_tete_obfuscation,
    _build_tete_whitespace,
    _check_response_differs,
    _check_smuggled_response,
    _create_connection,
    _parse_url,
    _send_raw,
    build_parser,
    print_results,
)

# ─── Dataclass Tests ─────────────────────────────────────────────────────────


class TestSmuggleAttempt:
    def test_creation(self) -> None:
        a = SmuggleAttempt(
            technique="clte_basic",
            category="cl_te",
            method="POST",
            path="/",
            te_header="chunked",
            cl_header="3",
            smuggled_request="POST /admin HTTP/1.1",
            status_baseline=200,
            status_test=200,
            size_baseline=1000,
            size_test=1000,
            response_differs=False,
            smuggled_executed=False,
            vulnerable=False,
            details="",
            error="",
        )
        assert a.technique == "clte_basic"
        assert a.category == "cl_te"
        assert a.vulnerable is False

    def test_frozen(self) -> None:
        a = SmuggleAttempt(
            technique="t", category="c", method="M", path="/",
            te_header="", cl_header="", smuggled_request="",
            status_baseline=200, status_test=200, size_baseline=0,
            size_test=0, response_differs=False, smuggled_executed=False,
            vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestSmuggleResult:
    def test_creation(self) -> None:
        r = SmuggleResult(
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            baseline_status=200,
            baseline_size=1000,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.host == "example.com"
        assert r.tls is True

    def test_frozen(self) -> None:
        r = SmuggleResult(
            target="https://x", host="x", port=443, tls=True,
            baseline_status=200, baseline_size=0, attempts=[],
            vulnerable_techniques=[], blocked_techniques=[],
            issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]


# ─── Category Map Tests ─────────────────────────────────────────────────────


class TestCategoryMap:
    def test_has_five_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 5

    def test_categories_match_dispatch(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_DISPATCH, f"No dispatch for {cat}"

    def test_cl_te_techniques(self) -> None:
        assert "clte_basic" in _CATEGORY_MAP["cl_te"]

    def test_te_cl_techniques(self) -> None:
        assert "tecl_basic" in _CATEGORY_MAP["te_cl"]

    def test_te_te_techniques(self) -> None:
        assert "tete_duplicate" in _CATEGORY_MAP["te_te"]

    def test_pipeline_techniques(self) -> None:
        assert "pipeline_basic" in _CATEGORY_MAP["pipeline"]


# ─── URL Parser Tests ────────────────────────────────────────────────────────


class TestParseUrl:
    def test_http(self) -> None:
        host, path, port, tls = _parse_url("http://example.com/api")
        assert host == "example.com"
        assert path == "/api"
        assert port == 80
        assert tls is False

    def test_https(self) -> None:
        host, path, port, tls = _parse_url("https://example.com:8443/test")
        assert host == "example.com"
        assert path == "/test"
        assert port == 8443
        assert tls is True

    def test_query_string(self) -> None:
        _host, path, _port, _tls = _parse_url("http://example.com/path?key=val")
        assert path == "/path?key=val"

    def test_default_path(self) -> None:
        _host, path, _port, _tls = _parse_url("http://example.com")
        assert path == "/"


# ─── Payload Builder Tests ──────────────────────────────────────────────────


class TestPayloadBuilders:
    def test_clte_contains_both_headers(self) -> None:
        payload = _build_clte_payload("POST", "/", "example.com")
        assert b"Content-Length: 3" in payload
        assert b"Transfer-Encoding: chunked" in payload
        assert b"0\r\n\r\n" in payload
        assert b"X-Smuggled: CLTE" in payload

    def test_tecl_contains_both_headers(self) -> None:
        payload = _build_tecl_payload("POST", "/", "example.com")
        assert b"Transfer-Encoding: chunked" in payload
        assert b"Content-Length: 3" in payload
        assert b"X-Smuggled: TECL" in payload

    def test_tete_duplicate(self) -> None:
        payload = _build_tete_duplicate("POST", "/", "example.com")
        assert b"Transfer-Encoding: chunked" in payload
        assert b"Transfer-Encoding: identity" in payload
        assert b"X-Smuggled: TETE_DUP" in payload

    def test_tete_obfuscation(self) -> None:
        payload = _build_tete_obfuscation("POST", "/", "example.com")
        assert b"Transfer-Encoding: x, chunked" in payload
        assert b"X-Smuggled: TETE_OBF" in payload

    def test_tete_whitespace(self) -> None:
        payload = _build_tete_whitespace("POST", "/", "example.com")
        assert b"Transfer-Encoding : chunked" in payload
        assert b"X-Smuggled: TETE_WS" in payload

    def test_chunked_cl(self) -> None:
        payload = _build_chunked_cl_payload("POST", "/", "example.com")
        assert b"Transfer-Encoding: chunked" in payload
        assert b"Content-Length: 6" in payload
        assert b"X-Smuggled: CHUNKED_CL" in payload

    def test_pipeline(self) -> None:
        payload = _build_pipeline_payload("example.com", "/")
        assert b"GET / HTTP/1.1" in payload
        assert b"GET /admin HTTP/1.1" in payload
        assert b"X-Smuggled: PIPELINE" in payload


# ─── Response Analysis Tests ─────────────────────────────────────────────────


class TestCheckSmuggledResponse:
    def test_found_marker(self) -> None:
        response = b"HTTP/1.1 200 OK\r\n\r\nX-Smuggled: CLTE"
        vuln, details = _check_smuggled_response(response, "X-Smuggled: CLTE")
        assert vuln is True
        assert "CLTE" in details

    def test_not_found(self) -> None:
        response = b"HTTP/1.1 404 Not Found\r\n\r\nNot found"
        vuln, _ = _check_smuggled_response(response, "X-Smuggled: CLTE")
        assert vuln is False

    def test_case_insensitive(self) -> None:
        response = b"HTTP/1.1 200 OK\r\n\r\nx-smuggled: clte"
        vuln, _ = _check_smuggled_response(response, "X-Smuggled: CLTE")
        assert vuln is True

    def test_empty_response(self) -> None:
        vuln, _ = _check_smuggled_response(b"", "X-Smuggled: CLTE")
        assert vuln is False


class TestCheckResponseDiffers:
    def test_identical(self) -> None:
        assert _check_response_differs(b"same", b"same") is False

    def test_different(self) -> None:
        assert _check_response_differs(b"HTTP/1.1 200", b"HTTP/1.1 404") is True

    def test_empty_vs_content(self) -> None:
        assert _check_response_differs(b"", b"data") is True

    def test_content_vs_empty(self) -> None:
        assert _check_response_differs(b"data", b"") is True

    def test_both_empty(self) -> None:
        assert _check_response_differs(b"", b"") is False


# ─── Connection Tests ────────────────────────────────────────────────────────


class TestCreateConnection:
    def test_creates_tcp_socket(self) -> None:
        with patch("socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            result = _create_connection("example.com", 80, 5.0, tls=False)
            assert result == mock_sock
            mock_conn.assert_called_once_with(("example.com", 80), timeout=5.0)

    def test_creates_tls_socket(self) -> None:
        with patch("socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            mock_ctx = MagicMock()
            with patch("ssl.create_default_context", return_value=mock_ctx):
                mock_ctx.wrap_socket.return_value = MagicMock()
                _create_connection("example.com", 443, 5.0, tls=True)
                mock_ctx.wrap_socket.assert_called_once()


# ─── Send Raw Tests ──────────────────────────────────────────────────────────


class TestSendRaw:
    def test_sends_and_receives(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
            b"",
        ]
        status, response = _send_raw(mock_sock, b"GET / HTTP/1.1\r\n\r\n", 5.0)
        assert status == 200
        assert b"hello" in response

    def test_handles_empty_response(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        status, response = _send_raw(mock_sock, b"GET / HTTP/1.1\r\n\r\n", 5.0)
        assert status == 0
        assert response == b""

    def test_handles_timeout(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError("timed out")
        status, _response = _send_raw(mock_sock, b"GET / HTTP/1.1\r\n\r\n", 5.0)
        assert status == 0


# ─── Parser Tests ────────────────────────────────────────────────────────────


class TestBuildParser:
    def test_has_url_arg(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "cl_te", "te_cl"])
        assert args.categories == ["cl_te", "te_cl"]


# ─── Print Results Tests ─────────────────────────────────────────────────────


class TestPrintResults:
    def test_print_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = SmuggleResult(
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            baseline_status=200,
            baseline_size=1000,
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
        attempt = SmuggleAttempt(
            technique="clte_basic",
            category="cl_te",
            method="POST",
            path="/",
            te_header="chunked",
            cl_header="3",
            smuggled_request="POST /admin HTTP/1.1",
            status_baseline=200,
            status_test=200,
            size_baseline=1000,
            size_test=1000,
            response_differs=True,
            smuggled_executed=True,
            vulnerable=True,
            details="Smuggled request executed",
            error="",
        )
        result = SmuggleResult(
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            baseline_status=200,
            baseline_size=1000,
            attempts=[attempt],
            vulnerable_techniques=["clte_basic"],
            blocked_techniques=[],
            issues=["1 techniques vulnerable"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "VULNERABLE" in captured.out
