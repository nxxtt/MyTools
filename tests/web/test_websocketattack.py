"""Testes do modulo websocketattack.py — WebSocket Security."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mytools.web.websocketattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    WSAttackAttempt,
    WSAttackResult,
    _build_ws_frame,
    _create_connection,
    _generate_ws_key,
    _parse_url,
    _recv_ws_frame,
    _send_ws_frame,
    build_parser,
    print_results,
)

# ─── Dataclass Tests ─────────────────────────────────────────────────────────


class TestWSAttackAttempt:
    def test_creation(self) -> None:
        a = WSAttackAttempt(
            technique="cswh_hijack",
            category="ws_scanner",
            description="desc",
            status_baseline=200,
            status_test=101,
            size_baseline=1000,
            size_test=0,
            vulnerable=True,
            details="handshake aceito",
            error="",
        )
        assert a.technique == "cswh_hijack"
        assert a.category == "ws_scanner"
        assert a.vulnerable is True

    def test_frozen(self) -> None:
        a = WSAttackAttempt(
            technique="t", category="c", description="d",
            status_baseline=200, status_test=200, size_baseline=0,
            size_test=0, vulnerable=False, details="", error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]


class TestWSAttackResult:
    def test_creation(self) -> None:
        r = WSAttackResult(
            target="wss://example.com/ws",
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
        r = WSAttackResult(
            target="t", host="h", port=443, tls=True,
            baseline_status=200, baseline_size=0, attempts=[],
            vulnerable_techniques=[], issues=[], overall_status="secure",
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

    def test_ws_scanner_techniques(self) -> None:
        assert len(_CATEGORY_MAP["ws_scanner"]) == 5

    def test_ws_upgrade_abuse_techniques(self) -> None:
        assert len(_CATEGORY_MAP["ws_upgrade_abuse"]) == 5

    def test_ws_message_inject_techniques(self) -> None:
        assert len(_CATEGORY_MAP["ws_message_inject"]) == 5

    def test_ws_dos_techniques(self) -> None:
        assert len(_CATEGORY_MAP["ws_dos"]) == 5

    def test_ws_compression_bomb_techniques(self) -> None:
        assert len(_CATEGORY_MAP["ws_compression_bomb"]) == 5

    def test_all_categories_have_unique_techniques(self) -> None:
        all_techs: list[str] = []
        for techs in _CATEGORY_MAP.values():
            all_techs.extend(techs)
        assert len(all_techs) == len(set(all_techs))


# ─── URL Parser Tests ────────────────────────────────────────────────────────


class TestParseUrl:
    def test_wss(self) -> None:
        host, path, port, tls = _parse_url("wss://example.com/ws")
        assert host == "example.com"
        assert path == "/ws"
        assert port == 443
        assert tls is True

    def test_ws(self) -> None:
        _host, _path, port, tls = _parse_url("ws://example.com/ws")
        assert port == 80
        assert tls is False

    def test_custom_port(self) -> None:
        _host, _path, port, _tls = _parse_url("wss://example.com:8443/ws")
        assert port == 8443

    def test_query_string(self) -> None:
        _host, path, _port, _tls = _parse_url("wss://example.com/ws?token=abc")
        assert path == "/ws?token=abc"

    def test_default_path(self) -> None:
        _host, path, _port, _tls = _parse_url("wss://example.com")
        assert path == "/"


# ─── WebSocket Frame Tests ───────────────────────────────────────────────────


class TestBuildWsFrame:
    def test_text_frame_masked(self) -> None:
        frame = _build_ws_frame(0x1, b"hello", mask=True)
        assert frame[0] == 0x81
        assert frame[1] & 0x80 == 0x80
        assert frame[1] & 0x7F == 5

    def test_text_frame_unmasked(self) -> None:
        frame = _build_ws_frame(0x1, b"hello", mask=False)
        assert frame[0] == 0x81
        assert frame[1] & 0x80 == 0x00
        assert frame[1] & 0x7F == 5

    def test_ping_frame(self) -> None:
        frame = _build_ws_frame(0x9, b"ping", mask=True)
        assert frame[0] == 0x89

    def test_close_frame(self) -> None:
        frame = _build_ws_frame(0x8, b"", mask=True)
        assert frame[0] == 0x88

    def test_large_payload(self) -> None:
        payload = b"X" * 200
        frame = _build_ws_frame(0x1, payload, mask=False)
        assert frame[1] & 0x7F == 126
        assert len(frame) == 4 + 200

    def test_very_large_payload(self) -> None:
        payload = b"X" * 70000
        frame = _build_ws_frame(0x1, payload, mask=False)
        assert frame[1] & 0x7F == 127


class TestSendWsFrame:
    def test_sends_frame(self) -> None:
        mock_sock = MagicMock()
        result = _send_ws_frame(mock_sock, 0x1, b"hello", mask=False)
        assert result is True
        mock_sock.sendall.assert_called_once()

    def test_handles_error(self) -> None:
        mock_sock = MagicMock()
        mock_sock.sendall.side_effect = OSError("fail")
        result = _send_ws_frame(mock_sock, 0x1, b"hello")
        assert result is False


class TestRecvWsFrame:
    def test_receives_text_frame(self) -> None:
        mock_sock = MagicMock()
        frame = _build_ws_frame(0x1, b"hello", mask=False)
        header = frame[:2]
        payload_part = frame[2:]
        mock_sock.recv.side_effect = [header, payload_part]
        result = _recv_ws_frame(mock_sock, 5.0)
        assert result is not None
        opcode, payload = result
        assert opcode == 0x1
        assert payload == b"hello"

    def test_handles_empty(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        result = _recv_ws_frame(mock_sock, 5.0)
        assert result is None

    def test_handles_timeout(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError("timeout")
        result = _recv_ws_frame(mock_sock, 5.0)
        assert result is None


# ─── Generate Key Tests ──────────────────────────────────────────────────────


class TestGenerateWsKey:
    def test_returns_string(self) -> None:
        key = _generate_ws_key()
        assert isinstance(key, str)

    def test_unique(self) -> None:
        keys = {_generate_ws_key() for _ in range(10)}
        assert len(keys) == 10


# ─── Connection Tests ────────────────────────────────────────────────────────


class TestCreateConnection:
    def test_creates_tcp_socket(self) -> None:
        with patch("mytools.web.websocketattack.socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            result = _create_connection("example.com", 80, 5.0, tls=False)
            assert result == mock_sock

    def test_creates_tls_socket(self) -> None:
        with patch("mytools.web.websocketattack.socket.create_connection") as mock_conn:
            mock_sock = MagicMock()
            mock_conn.return_value = mock_sock
            mock_ctx = MagicMock()
            with patch("mytools.web.websocketattack.ssl.create_default_context", return_value=mock_ctx):
                mock_ctx.wrap_socket.return_value = MagicMock()
                _create_connection("example.com", 443, 5.0, tls=True)
                mock_ctx.wrap_socket.assert_called_once()


# ─── Parser Tests ────────────────────────────────────────────────────────────


class TestBuildParser:
    def test_has_url_arg(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["wss://example.com/ws"])
        assert args.url == "wss://example.com/ws"

    def test_has_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args([
            "wss://example.com/ws",
            "-c", "ws_scanner", "ws_dos",
        ])
        assert args.categories == ["ws_scanner", "ws_dos"]

    def test_no_categories_default(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["wss://example.com/ws"])
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
        result = WSAttackResult(
            target="wss://example.com/ws",
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
        attempt = WSAttackAttempt(
            technique="cswh_hijack",
            category="ws_scanner",
            description="desc",
            status_baseline=200,
            status_test=101,
            size_baseline=1000,
            size_test=0,
            vulnerable=True,
            details="handshake aceito",
            error="",
        )
        result = WSAttackResult(
            target="wss://example.com/ws",
            host="example.com",
            port=443,
            tls=True,
            baseline_status=200,
            baseline_size=1000,
            attempts=[attempt],
            vulnerable_techniques=["cswh_hijack"],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "VULNERABLE" in output

    def test_print_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = WSAttackResult(
            target="wss://example.com/ws",
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
