"""Testes do módulo httsmuggle.py — HTTP Request Smuggling."""

from __future__ import annotations

import argparse
import runpy
from unittest.mock import AsyncMock, MagicMock, patch

import h2.connection
import h2.events
import pytest

from mytools.web.httsmuggle import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    SmuggleAttempt,
    SmuggleResult,
    _build_chunked_cl_payload,
    _build_cl0_payload,
    _build_clte_payload,
    _build_h2c_payload,
    _build_pipeline_payload,
    _build_tecl_payload,
    _build_tete_duplicate,
    _build_tete_obfuscation,
    _build_tete_whitespace,
    _check_response_differs,
    _check_smuggled_response,
    _create_connection,
    _create_h2_smuggle_connection,
    _drain_h2_settings,
    _parse_url,
    _recv_h2_events,
    _send_raw,
    _test_chunked_cl,
    _test_cl0,
    _test_cl_te,
    _test_h2c,
    _test_pipeline,
    _test_te_cl,
    _test_te_te,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
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
            technique="t",
            category="c",
            method="M",
            path="/",
            te_header="",
            cl_header="",
            smuggled_request="",
            status_baseline=200,
            status_test=200,
            size_baseline=0,
            size_test=0,
            response_differs=False,
            smuggled_executed=False,
            vulnerable=False,
            details="",
            error="",
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
            target="https://x",
            host="x",
            port=443,
            tls=True,
            baseline_status=200,
            baseline_size=0,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
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

    def test_cl_te_techniques(self) -> None:
        assert "clte_basic" in _CATEGORY_MAP["cl_te"]

    def test_te_cl_techniques(self) -> None:
        assert "tecl_basic" in _CATEGORY_MAP["te_cl"]

    def test_te_te_techniques(self) -> None:
        assert "tete_duplicate" in _CATEGORY_MAP["te_te"]

    def test_pipeline_techniques(self) -> None:
        assert "pipeline_basic" in _CATEGORY_MAP["pipeline"]

    def test_cl0_techniques(self) -> None:
        assert "cl0_basic" in _CATEGORY_MAP["cl0"]
        assert "cl0_chunked" in _CATEGORY_MAP["cl0"]
        assert "cl0_overlap" in _CATEGORY_MAP["cl0"]

    def test_h2c_techniques(self) -> None:
        assert "h2c_upgrade" in _CATEGORY_MAP["h2c"]
        assert "h2c_direct" in _CATEGORY_MAP["h2c"]
        assert "h2c_downgrade" in _CATEGORY_MAP["h2c"]


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

    def test_cl0(self) -> None:
        payload = _build_cl0_payload("POST", "/", "example.com")
        assert b"Content-Length: 0" in payload
        assert b"0\r\n\r\n" in payload
        assert b"X-Smuggled: CL0" in payload

    def test_cl0_custom_path(self) -> None:
        payload = _build_cl0_payload(
            "GET", "/test", "example.com", smuggled_path="/secret"
        )
        assert b"GET /test HTTP/1.1" in payload
        assert b"GET /secret HTTP/1.1" in payload

    def test_h2c(self) -> None:
        payload = _build_h2c_payload("POST", "/", "example.com")
        assert b"Upgrade: h2c" in payload
        assert b"Connection: Upgrade" in payload
        assert b"X-Smuggled: H2C" in payload

    def test_h2c_custom_path(self) -> None:
        payload = _build_h2c_payload(
            "GET", "/test", "example.com", smuggled_path="/secret"
        )
        assert b"GET /test HTTP/1.1" in payload
        assert b"GET /secret HTTP/1.1" in payload


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

    def test_headers_split_across_chunks(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [
            b"HTTP/1.1 200 OK\r\nContent-Len",
            b"gth: 5\r\n\r\nhello",
            b"",
        ]
        status, response = _send_raw(mock_sock, b"GET / HTTP/1.1\r\n\r\n", 5.0)
        assert status == 200
        assert b"hello" in response

    def test_partial_body_then_complete(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n12345",
            b"67890",
            b"",
        ]
        status, response = _send_raw(mock_sock, b"GET / HTTP/1.1\r\n\r\n", 5.0)
        assert status == 200
        assert response == b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n1234567890"

    def test_no_status_line(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [b"GARBAGE\r\n\r\nbody", b""]
        status, response = _send_raw(mock_sock, b"GET / HTTP/1.1\r\n\r\n", 5.0)
        assert status == 0
        assert response == b"GARBAGE\r\n\r\nbody"


# ─── Parser Tests ────────────────────────────────────────────────────────────


@pytest.mark.smoke
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


# ─── Coverage Extension ──────────────────────────────────────────────────────


class _FakeTime:
    """Stub do modulo time com monotonic controlavel (ramo slow > 2s)."""

    def __init__(self, jump: float) -> None:
        self._t = 0.0
        self._jump = jump

    def monotonic(self) -> float:
        self._t += self._jump
        return self._t


def _attempt(
    technique: str,
    category: str,
    *,
    vulnerable: bool = False,
    error: str = "",
    details: str = "",
) -> SmuggleAttempt:
    return SmuggleAttempt(
        technique=technique,
        category=category,
        method="POST",
        path="/",
        te_header="chunked",
        cl_header="3",
        smuggled_request="",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=100,
        response_differs=False,
        smuggled_executed=vulnerable,
        vulnerable=vulnerable,
        details=details,
        error=error,
    )


class TestSendRawBranchless:
    def test_chunked_without_cl(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nwiki\r\n0\r\n\r\n",
            b"",
        ]
        status, response = _send_raw(mock_sock, b"GET / HTTP/1.1\r\n\r\n", 5.0)
        assert status == 200
        assert b"0\r\n\r\n" in response

    def test_no_content_length_no_te(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = (
            b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody"
        )
        status, response = _send_raw(mock_sock, b"GET / HTTP/1.1\r\n\r\n", 5.0)
        assert status == 200
        assert b"body" in response


class TestCheckSmuggledResponse200:
    def test_200_with_smuggled_marker_text(self) -> None:
        response = b"HTTP/1.1 200 OK\r\n\r\nx-smuggled: none"
        vuln, details = _check_smuggled_response(response, "X-Smuggled: CLTE")
        assert vuln is True
        assert "200" in details


_SIMPLE_TESTERS: list[tuple[object, str, int]] = [
    (_test_cl_te, "X-Smuggled: CLTE", 3),
    (_test_te_cl, "X-Smuggled: TECL", 3),
    (_test_chunked_cl, "X-Smuggled: CHUNKED_CL", 2),
    (_test_cl0, "X-Smuggled: CL0", 3),
]


@pytest.mark.asyncio
@pytest.mark.parametrize("tester,marker,count", _SIMPLE_TESTERS)
async def test_tester_marker_found(tester: object, marker: str, count: int) -> None:
    resp = b"HTTP/1.1 200 OK\r\n\r\n" + marker.encode() + b"\r\n"
    with (
        patch("mytools.web.httsmuggle._create_connection", return_value=MagicMock()),
        patch("mytools.web.httsmuggle._send_raw", return_value=(200, resp)),
    ):
        results = await tester("example.com", 80, "/", 5.0, False, 200, 100)  # type: ignore[operator]
    assert len(results) == count
    assert all(r.vulnerable for r in results)
    assert all(r.error == "" for r in results)


@pytest.mark.asyncio
@pytest.mark.parametrize("tester,marker,count", _SIMPLE_TESTERS)
async def test_tester_slow_response(tester: object, marker: str, count: int) -> None:
    with (
        patch("mytools.web.httsmuggle._create_connection", return_value=MagicMock()),
        patch(
            "mytools.web.httsmuggle._send_raw",
            return_value=(200, b"HTTP/1.1 200 OK\r\n\r\nplain"),
        ),
        patch("mytools.web.httsmuggle.time", _FakeTime(3.0)),
    ):
        results = await tester("example.com", 80, "/", 5.0, False, 200, 100)  # type: ignore[operator]
    assert len(results) == count
    assert all(r.vulnerable for r in results)
    assert all("Slow response" in r.details for r in results)


@pytest.mark.asyncio
@pytest.mark.parametrize("tester,marker,count", _SIMPLE_TESTERS)
async def test_tester_no_false_flag_on_consistent_slow(
    tester: object, marker: str, count: int
) -> None:
    with (
        patch("mytools.web.httsmuggle._create_connection", return_value=MagicMock()),
        patch(
            "mytools.web.httsmuggle._send_raw",
            return_value=(200, b"HTTP/1.1 200 OK\r\n\r\nplain"),
        ),
        patch("mytools.web.httsmuggle.time", _FakeTime(2.5)),
    ):
        results = await tester(  # type: ignore[operator]
            "example.com", 80, "/", 5.0, False, 200, 100, 2.4
        )
    assert len(results) == count
    assert all(not r.vulnerable for r in results)


@pytest.mark.asyncio
@pytest.mark.parametrize("tester,marker,count", _SIMPLE_TESTERS)
async def test_tester_connection_error(tester: object, marker: str, count: int) -> None:
    with patch(
        "mytools.web.httsmuggle._create_connection",
        side_effect=ConnectionResetError("reset"),
    ):
        results = await tester("example.com", 80, "/", 5.0, False, 200, 100)  # type: ignore[operator]
    assert len(results) == count
    assert all(not r.vulnerable for r in results)
    assert all(r.error for r in results)


@pytest.mark.asyncio
async def test_tete_marker_found() -> None:
    resp = (
        b"HTTP/1.1 200 OK\r\n\r\nX-Smuggled: TETE_DUPLICATE "
        b"X-Smuggled: TETE_OBFUSCATION X-Smuggled: TETE_WHITESPACE\r\n"
    )
    with (
        patch("mytools.web.httsmuggle._create_connection", return_value=MagicMock()),
        patch("mytools.web.httsmuggle._send_raw", return_value=(200, resp)),
    ):
        results = await _test_te_te("example.com", 80, "/", 5.0, False, 200, 100)
    assert len(results) == 3
    assert all(r.vulnerable for r in results)


@pytest.mark.asyncio
async def test_tete_slow_response() -> None:
    with (
        patch("mytools.web.httsmuggle._create_connection", return_value=MagicMock()),
        patch(
            "mytools.web.httsmuggle._send_raw",
            return_value=(200, b"HTTP/1.1 200 OK\r\n\r\nplain"),
        ),
        patch("mytools.web.httsmuggle.time", _FakeTime(3.0)),
    ):
        results = await _test_te_te("example.com", 80, "/", 5.0, False, 200, 100)
    assert len(results) == 3
    assert all(r.vulnerable for r in results)
    assert all("Slow response" in r.details for r in results)


@pytest.mark.asyncio
async def test_tete_connection_error() -> None:
    with patch(
        "mytools.web.httsmuggle._create_connection",
        side_effect=ConnectionResetError("reset"),
    ):
        results = await _test_te_te("example.com", 80, "/", 5.0, False, 200, 100)
    assert len(results) == 3
    assert all(r.error for r in results)
    assert all(not r.vulnerable for r in results)


@pytest.mark.asyncio
async def test_te_te_baseline_diff_uses_real_body() -> None:
    plain = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nplain"
    changed = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nothew"
    with (
        patch("mytools.web.httsmuggle._create_connection", return_value=MagicMock()),
        patch(
            "mytools.web.httsmuggle._send_raw",
            side_effect=[(200, plain), (200, plain), (200, changed)],
        ),
    ):
        results = await _test_te_te("example.com", 80, "/", 5.0, False, 200, 100)
    assert len(results) == 3
    assert results[0].response_differs is False
    assert results[1].response_differs is False
    assert results[2].response_differs is True


@pytest.mark.asyncio
async def test_pipeline_desync() -> None:
    resp = (
        b"HTTP/1.1 200 OK\r\n\r\nHTTP/1.1 404 Not Found\r\n\r\nX-Smuggled: PIPELINE\r\n"
    )
    with (
        patch("mytools.web.httsmuggle._create_connection", return_value=MagicMock()),
        patch("mytools.web.httsmuggle._send_raw", return_value=(200, resp)),
    ):
        results = await _test_pipeline("example.com", 80, "/", 5.0, False, 200, 100)
    assert len(results) == 2
    assert all(r.vulnerable for r in results)


@pytest.mark.asyncio
async def test_pipeline_slow() -> None:
    with (
        patch("mytools.web.httsmuggle._create_connection", return_value=MagicMock()),
        patch(
            "mytools.web.httsmuggle._send_raw",
            return_value=(200, b"HTTP/1.1 200 OK\r\n\r\nplain"),
        ),
        patch("mytools.web.httsmuggle.time", _FakeTime(3.0)),
    ):
        results = await _test_pipeline("example.com", 80, "/", 5.0, False, 200, 100)
    assert len(results) == 2
    assert all("Slow response" in r.details for r in results)


@pytest.mark.asyncio
async def test_pipeline_connection_error() -> None:
    with patch(
        "mytools.web.httsmuggle._create_connection",
        side_effect=OSError("boom"),
    ):
        results = await _test_pipeline("example.com", 80, "/", 5.0, False, 200, 100)
    assert len(results) == 2
    assert all(r.error for r in results)


# ─── H2 helpers ──────────────────────────────────────────────────────────────


def test_create_h2_smuggle_connection() -> None:
    fake_sock = MagicMock()
    with patch("mytools.web.httsmuggle._create_connection", return_value=fake_sock):
        sock, conn = _create_h2_smuggle_connection("example.com", 443, 5.0)
    assert sock == fake_sock
    assert isinstance(conn, h2.connection.H2Connection)
    fake_sock.sendall.assert_called_once()


def test_create_h2_smuggle_connection_passes_tls() -> None:
    fake_sock = MagicMock()
    with patch(
        "mytools.web.httsmuggle._create_connection", return_value=fake_sock
    ) as mc:
        _create_h2_smuggle_connection("example.com", 443, 5.0, tls=True)
    mc.assert_called_once_with("example.com", 443, 5.0, True)
    fake_sock.sendall.assert_called_once()


def test_recv_h2_events_normal() -> None:
    fake_sock = MagicMock()
    fake_sock.recv.return_value = b"\x00\x04\x00\x00\x00\x00"
    fake_conn = MagicMock()
    fake_conn.receive_data.return_value = ["ev"]
    events = _recv_h2_events(fake_sock, fake_conn, 5.0)
    assert events == ["ev"]
    fake_conn.receive_data.assert_called_once_with(b"\x00\x04\x00\x00\x00\x00")


def test_recv_h2_events_timeout() -> None:
    fake_sock = MagicMock()
    fake_sock.recv.side_effect = TimeoutError("t")
    assert _recv_h2_events(fake_sock, MagicMock(), 5.0) == []


def test_recv_h2_events_empty() -> None:
    fake_sock = MagicMock()
    fake_sock.recv.return_value = b""
    assert _recv_h2_events(fake_sock, MagicMock(), 5.0) == []


def test_drain_h2_settings_settings_then_break() -> None:
    from h2.settings import ChangedSetting, SettingCodes

    ev = h2.events.RemoteSettingsChanged()
    ev.changed_settings = {
        SettingCodes.MAX_CONCURRENT_STREAMS: ChangedSetting(
            SettingCodes.MAX_CONCURRENT_STREAMS, None, 100
        )
    }
    with patch("mytools.web.httsmuggle._recv_h2_events", side_effect=[[ev], []]):
        result = _drain_h2_settings(MagicMock(), MagicMock(), 5.0)
    assert result["MAX_CONCURRENT_STREAMS"] == 100


def test_drain_h2_settings_terminated() -> None:
    ev = h2.events.ConnectionTerminated()
    with patch("mytools.web.httsmuggle._recv_h2_events", return_value=[ev]):
        result = _drain_h2_settings(MagicMock(), MagicMock(), 5.0)
    assert result == {}


def test_drain_h2_settings_timeout_exit() -> None:
    with patch("mytools.web.httsmuggle._recv_h2_events") as mock_recv:
        result = _drain_h2_settings(MagicMock(), MagicMock(), 0.0)
    assert result == {}
    mock_recv.assert_not_called()


# ─── h2c tester ──────────────────────────────────────────────────────────────


def _h2c_mocks(events: list[object]) -> tuple[MagicMock, MagicMock]:
    fake_sock = MagicMock()
    fake_conn = MagicMock()
    fake_conn.get_next_available_stream_id.return_value = 1
    return fake_sock, fake_conn


@pytest.mark.asyncio
async def test_h2c_full_success() -> None:
    fake_sock = MagicMock()
    fake_conn = MagicMock()
    fake_conn.get_next_available_stream_id.return_value = 1
    events = [
        h2.events.ResponseReceived(
            headers=[(b":status", b"200"), (b"x-smuggled", b"X-Smuggled: H2C_DIRECT")],
            stream_id=1,
        ),
        h2.events.DataReceived(data=b"body", flow_controlled_length=4, stream_id=1),
        h2.events.ConnectionTerminated(),
    ]
    with (
        patch("mytools.web.httsmuggle._create_connection", return_value=MagicMock()),
        patch(
            "mytools.web.httsmuggle._send_raw",
            return_value=(200, b"HTTP/1.1 200 OK\r\n\r\nX-Smuggled: H2C"),
        ),
        patch(
            "mytools.web.httsmuggle._create_h2_smuggle_connection",
            return_value=(fake_sock, fake_conn),
        ),
        patch("mytools.web.httsmuggle._drain_h2_settings", return_value={}),
        patch("mytools.web.httsmuggle._recv_h2_events", return_value=events),
    ):
        results = await _test_h2c("example.com", 443, "/", 5.0, True, 200, 100)
    assert len(results) == 3
    by_tech = {r.technique: r for r in results}
    assert by_tech["h2c_upgrade"].vulnerable
    assert by_tech["h2c_direct"].vulnerable
    assert by_tech["h2c_downgrade"].vulnerable
    fake_conn.acknowledge_received_data.assert_called()


@pytest.mark.asyncio
async def test_h2c_slow_paths() -> None:
    fake_sock = MagicMock()
    fake_conn = MagicMock()
    fake_conn.get_next_available_stream_id.return_value = 1
    events = [h2.events.ResponseReceived(headers=[(b":status", b"404")], stream_id=1)]
    with (
        patch("mytools.web.httsmuggle._create_connection", return_value=MagicMock()),
        patch(
            "mytools.web.httsmuggle._send_raw",
            return_value=(200, b"HTTP/1.1 200 OK\r\n\r\nplain"),
        ),
        patch(
            "mytools.web.httsmuggle._create_h2_smuggle_connection",
            return_value=(fake_sock, fake_conn),
        ),
        patch("mytools.web.httsmuggle._drain_h2_settings", return_value={}),
        patch("mytools.web.httsmuggle._recv_h2_events", return_value=events),
        patch("mytools.web.httsmuggle.time", _FakeTime(3.0)),
    ):
        results = await _test_h2c("example.com", 443, "/", 5.0, True, 200, 100)
    assert len(results) == 3
    by_tech = {r.technique: r for r in results}
    assert by_tech["h2c_upgrade"].vulnerable
    assert by_tech["h2c_direct"].vulnerable
    assert "Slow" in by_tech["h2c_downgrade"].details


@pytest.mark.asyncio
async def test_h2c_all_errors() -> None:
    with patch(
        "mytools.web.httsmuggle._create_connection", side_effect=OSError("boom")
    ):
        results = await _test_h2c("example.com", 443, "/", 5.0, True, 200, 100)
    assert len(results) == 3
    assert all(r.error for r in results)
    assert all(not r.vulnerable for r in results)


# ─── print_results extra branch ──────────────────────────────────────────────


class TestPrintResultsSecureCategory:
    def test_category_without_vulns(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = SmuggleResult(
            target="https://example.com",
            host="example.com",
            port=443,
            tls=True,
            baseline_status=200,
            baseline_size=100,
            attempts=[_attempt("clte_basic", "cl_te")],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "cl_te: secure" in out
        assert "SECURE" in out


# ─── run_scan ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_scan_vulnerable_with_output() -> None:
    attempts = [
        _attempt("clte_basic", "cl_te", vulnerable=True),
        _attempt("tecl_basic", "te_cl", error="connection reset"),
        _attempt("cl0_basic", "cl0"),
    ]
    mock_tester = AsyncMock(return_value=attempts)
    with (
        patch("mytools.web.httsmuggle._CATEGORY_DISPATCH", {"cl_te": mock_tester}),
        patch("mytools.web.httsmuggle._create_connection", return_value=MagicMock()),
        patch("mytools.web.httsmuggle._send_raw", return_value=(200, b"hello")),
        patch("mytools.web.httsmuggle.write_output") as mock_wo,
    ):
        result = await run_scan(
            "https://example.com", ["cl_te", "bogus"], 5.0, "out.json"
        )
    assert result.overall_status == "vulnerable"
    assert result.baseline_status == 200
    assert result.vulnerable_techniques == ["clte_basic"]
    assert result.blocked_techniques == ["tecl_basic"]
    assert "1 techniques vulnerable" in result.issues
    assert "connection issues" in result.issues[-1]
    mock_wo.assert_called_once()


@pytest.mark.asyncio
async def test_run_scan_secure_no_issues() -> None:
    attempts = [_attempt("pipeline_basic", "pipeline")]
    mock_tester = AsyncMock(return_value=attempts)
    with (
        patch("mytools.web.httsmuggle._CATEGORY_DISPATCH", {"pipeline": mock_tester}),
        patch("mytools.web.httsmuggle._create_connection", return_value=MagicMock()),
        patch("mytools.web.httsmuggle._send_raw", return_value=(200, b"hello")),
    ):
        result = await run_scan("https://example.com", ["pipeline"], 5.0, None)
    assert result.overall_status == "secure"
    assert result.issues == []
    assert result.attempts == attempts


@pytest.mark.asyncio
async def test_run_scan_baseline_error_and_unknown_cats() -> None:
    with (
        patch("mytools.web.httsmuggle._CATEGORY_DISPATCH", {}),
        patch(
            "mytools.web.httsmuggle._create_connection", side_effect=OSError("net down")
        ),
    ):
        result = await run_scan("https://example.com", None, 5.0, None)
    assert result.baseline_status == 0
    assert result.baseline_size == 0
    assert result.overall_status == "secure"


# ─── CLI ─────────────────────────────────────────────────────────────────────


class TestRunOnce:
    def test_vulnerable_returns_1(self) -> None:
        mock_result = MagicMock()
        mock_result.overall_status = "vulnerable"
        args = argparse.Namespace(
            url="https://example.com", categories=None, timeout=5.0, output=None
        )
        with (
            patch("mytools.web.httsmuggle.safe_asyncio_run", return_value=mock_result),
            patch("mytools.web.httsmuggle.run_scan", new_callable=MagicMock),
        ):
            assert run_once(args) == 1

    def test_secure_returns_0(self) -> None:
        mock_result = MagicMock()
        mock_result.overall_status = "secure"
        args = argparse.Namespace(
            url="https://example.com", categories=None, timeout=5.0, output=None
        )
        with (
            patch("mytools.web.httsmuggle.safe_asyncio_run", return_value=mock_result),
            patch("mytools.web.httsmuggle.run_scan", new_callable=MagicMock),
        ):
            assert run_once(args) == 0


class TestMain:
    def test_main_calls_loop(self) -> None:
        with patch("mytools.web.httsmuggle.run_main_loop", return_value=0) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.httsmuggle", run_name="__main__")
        assert exc_info.value.code == 0
