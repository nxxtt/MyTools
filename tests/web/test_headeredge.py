"""Testes do modulo headeredge.py — Header & Parsing Edge Cases."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mytools.web.headeredge import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    HeaderEdgeAttempt,
    HeaderEdgeResult,
    _build_request,
    _create_connection,
    _get_baseline,
    _parse_url,
    _send_raw,
    _test_absolute_uri,
    _test_duplicate_headers,
    _test_header_case,
    _test_header_whitespace,
    _test_http09_request,
    _test_malformed_version,
    _test_null_request_byte,
    build_parser,
    print_results,
)

# ─── Dataclass Tests ─────────────────────────────────────────────────────────


class TestHeaderEdgeAttempt:
    def test_creation(self) -> None:
        a = HeaderEdgeAttempt(
            technique="dup_host",
            category="duplicate_headers",
            raw_request="GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com",
            status_baseline=200,
            status_test=400,
            size_baseline=1000,
            size_test=200,
            vulnerable=True,
            details="Status: 400 (baseline: 200)",
            error="",
        )
        assert a.technique == "dup_host"
        assert a.category == "duplicate_headers"
        assert a.vulnerable is True

    def test_frozen(self) -> None:
        a = HeaderEdgeAttempt(
            technique="t", category="c", raw_request="r",
            status_baseline=200, status_test=200, size_baseline=0,
            size_test=0, vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestHeaderEdgeResult:
    def test_creation(self) -> None:
        r = HeaderEdgeResult(
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            baseline_status=200,
            baseline_size=1000,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        assert r.overall_status == "secure"
        assert r.host == "example.com"
        assert r.tls is True

    def test_frozen(self) -> None:
        r = HeaderEdgeResult(
            target="t", host="h", port=443, tls=True,
            baseline_status=200, baseline_size=0, attempts=[],
            vulnerable_techniques=[], issues=[], overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]


# ─── Category Map Tests ─────────────────────────────────────────────────────


class TestCategoryMap:
    def test_has_seven_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 7

    def test_categories_match_dispatch(self) -> None:
        for cat in _CATEGORY_MAP:
            assert cat in _CATEGORY_DISPATCH, f"No dispatch for {cat}"

    def test_duplicate_headers_techniques(self) -> None:
        assert len(_CATEGORY_MAP["duplicate_headers"]) == 5

    def test_malformed_version_techniques(self) -> None:
        assert len(_CATEGORY_MAP["malformed_version"]) == 5

    def test_null_request_byte_techniques(self) -> None:
        assert len(_CATEGORY_MAP["null_request_byte"]) == 5

    def test_header_whitespace_techniques(self) -> None:
        assert len(_CATEGORY_MAP["header_whitespace"]) == 5

    def test_header_case_techniques(self) -> None:
        assert len(_CATEGORY_MAP["header_case"]) == 5

    def test_absolute_uri_techniques(self) -> None:
        assert len(_CATEGORY_MAP["absolute_uri"]) == 5

    def test_http09_request_techniques(self) -> None:
        assert len(_CATEGORY_MAP["http09_request"]) == 5

    def test_all_categories_have_unique_techniques(self) -> None:
        all_techs: list[str] = []
        for techs in _CATEGORY_MAP.values():
            all_techs.extend(techs)
        assert len(all_techs) == len(set(all_techs))


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

    def test_query_string(self) -> None:
        _host, path, _port, _tls = _parse_url("https://example.com/path?key=val")
        assert path == "/path?key=val"

    def test_default_path(self) -> None:
        _host, path, _port, _tls = _parse_url("https://example.com")
        assert path == "/"


# ─── Build Request Tests ─────────────────────────────────────────────────────


class TestBuildRequest:
    def test_basic_get(self) -> None:
        req = _build_request("GET", "/", "example.com")
        assert b"GET / HTTP/1.1" in req
        assert b"Host: example.com" in req
        assert req.endswith(b"\r\n\r\n")

    def test_with_extra_headers(self) -> None:
        req = _build_request("GET", "/", "example.com", extra_headers=[("X-Test", "val")])
        assert b"X-Test: val" in req

    def test_with_body(self) -> None:
        req = _build_request("POST", "/", "example.com", body=b"hello")
        assert b"Content-Length: 5" in req
        assert req.endswith(b"hello")

    def test_custom_version(self) -> None:
        req = _build_request("GET", "/", "example.com", version="HTTP/1.0")
        assert b"GET / HTTP/1.0" in req


# ─── Connection Tests ────────────────────────────────────────────────────────


class TestCreateConnection:
    def test_creates_tcp_socket(self) -> None:
        with patch("mytools.web.headeredge.socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            result = _create_connection("example.com", 80, 5.0, tls=False)
            assert result == mock_sock
            mock_conn.assert_called_once_with(("example.com", 80), timeout=5.0)

    def test_creates_tls_socket(self) -> None:
        with patch("mytools.web.headeredge.socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            mock_ctx = MagicMock()
            with patch("mytools.web.headeredge.ssl.create_default_context", return_value=mock_ctx):
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

    def test_handles_oserror(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = OSError("connection reset")
        status, _response = _send_raw(mock_sock, b"GET / HTTP/1.1\r\n\r\n", 5.0)
        assert status == 0


# ─── Baseline Tests ──────────────────────────────────────────────────────────


class TestGetBaseline:
    def test_returns_status_and_size(self) -> None:
        with patch("mytools.web.headeredge._create_connection") as mock_conn, patch("mytools.web.headeredge._send_raw") as mock_send:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            mock_send.return_value = (200, b"HTTP/1.1 200 OK\r\n\r\nbody")
            status, size = _get_baseline("example.com", 80, "/", 5.0, False)
            assert status == 200
            assert size == 23

    def test_handles_connection_error(self) -> None:
        with patch("mytools.web.headeredge._create_connection", side_effect=OSError("fail")):
            status, size = _get_baseline("example.com", 80, "/", 5.0, False)
            assert status == 0
            assert size == 0


# ─── Category Tests: duplicate_headers ───────────────────────────────────────


class TestDuplicateHeaders:
    @pytest.mark.asyncio
    async def test_runs_all_techniques(self) -> None:
        with patch("mytools.web.headeredge._create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
            results = await _test_duplicate_headers(
                "example.com", 80, "/", 5.0, False, 200, 100,
            )
            assert len(results) == 5
            assert all(r.category == "duplicate_headers" for r in results)

    @pytest.mark.asyncio
    async def test_handles_exception(self) -> None:
        with patch("mytools.web.headeredge._create_connection", side_effect=OSError("fail")):
            results = await _test_duplicate_headers(
                "example.com", 80, "/", 5.0, False, 200, 100,
            )
            assert len(results) == 5
            assert all(r.error != "" for r in results)


# ─── Category Tests: malformed_version ───────────────────────────────────────


class TestMalformedVersion:
    @pytest.mark.asyncio
    async def test_runs_all_techniques(self) -> None:
        with patch("mytools.web.headeredge._create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
            results = await _test_malformed_version(
                "example.com", 80, "/", 5.0, False, 200, 100,
            )
            assert len(results) == 5
            assert all(r.category == "malformed_version" for r in results)


# ─── Category Tests: null_request_byte ───────────────────────────────────────


class TestNullRequestByte:
    @pytest.mark.asyncio
    async def test_runs_all_techniques(self) -> None:
        with patch("mytools.web.headeredge._create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
            results = await _test_null_request_byte(
                "example.com", 80, "/", 5.0, False, 200, 100,
            )
            assert len(results) == 5
            assert all(r.category == "null_request_byte" for r in results)


# ─── Category Tests: header_whitespace ───────────────────────────────────────


class TestHeaderWhitespace:
    @pytest.mark.asyncio
    async def test_runs_all_techniques(self) -> None:
        with patch("mytools.web.headeredge._create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
            results = await _test_header_whitespace(
                "example.com", 80, "/", 5.0, False, 200, 100,
            )
            assert len(results) == 5
            assert all(r.category == "header_whitespace" for r in results)


# ─── Category Tests: header_case ─────────────────────────────────────────────


class TestHeaderCase:
    @pytest.mark.asyncio
    async def test_runs_all_techniques(self) -> None:
        with patch("mytools.web.headeredge._create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
            results = await _test_header_case(
                "example.com", 80, "/", 5.0, False, 200, 100,
            )
            assert len(results) == 5
            assert all(r.category == "header_case" for r in results)


# ─── Category Tests: absolute_uri ────────────────────────────────────────────


class TestAbsoluteUri:
    @pytest.mark.asyncio
    async def test_runs_all_techniques(self) -> None:
        with patch("mytools.web.headeredge._create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
            results = await _test_absolute_uri(
                "example.com", 80, "/", 5.0, False, 200, 100,
            )
            assert len(results) == 5
            assert all(r.category == "absolute_uri" for r in results)


# ─── Category Tests: http09_request ──────────────────────────────────────────


class TestHttp09Request:
    @pytest.mark.asyncio
    async def test_runs_all_techniques(self) -> None:
        with patch("mytools.web.headeredge._create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            mock_sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
            results = await _test_http09_request(
                "example.com", 80, "/", 5.0, False, 200, 100,
            )
            assert len(results) == 5
            assert all(r.category == "http09_request" for r in results)


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
            "-c", "duplicate_headers", "null_request_byte",
        ])
        assert args.categories == ["duplicate_headers", "null_request_byte"]

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
        result = HeaderEdgeResult(
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            baseline_status=200,
            baseline_size=1000,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "SECURE" in output

    def test_print_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        attempt = HeaderEdgeAttempt(
            technique="dup_host",
            category="duplicate_headers",
            raw_request="GET / HTTP/1.1\r\nHost: a.com\r\nHost: b.com",
            status_baseline=200,
            status_test=400,
            size_baseline=1000,
            size_test=200,
            vulnerable=True,
            details="Status: 400 (baseline: 200)",
            error="",
        )
        result = HeaderEdgeResult(
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            baseline_status=200,
            baseline_size=1000,
            attempts=[attempt],
            vulnerable_techniques=["dup_host"],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output

    def test_print_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = HeaderEdgeResult(
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            baseline_status=200,
            baseline_size=1000,
            attempts=[],
            vulnerable_techniques=[],
            issues=["Errors: technique1"],
            overall_status="secure",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Issues:" in output
