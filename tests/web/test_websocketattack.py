"""Testes do modulo websocketattack.py — WebSocket Security."""

from __future__ import annotations

import argparse
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.websocketattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    _PAYLOADS_WS_FUZZ,
    WS_OPCODE_CLOSE,
    WS_OPCODE_TEXT,
    WSAttackAttempt,
    WSAttackResult,
    _build_ws_frame,
    _create_connection,
    _generate_ws_key,
    _get_baseline,
    _parse_url,
    _recv_ws_frame,
    _send_http_request,
    _send_ws_frame,
    _test_ws_compression_bomb,
    _test_ws_dos,
    _test_ws_message_inject,
    _test_ws_payload_fuzz,
    _test_ws_scanner,
    _test_ws_upgrade_abuse,
    _ws_handshake,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
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
            technique="t",
            category="c",
            description="d",
            status_baseline=200,
            status_test=200,
            size_baseline=0,
            size_test=0,
            vulnerable=False,
            details="",
            error="",
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
            target="t",
            host="h",
            port=443,
            tls=True,
            baseline_status=200,
            baseline_size=0,
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]


# ─── Category Map Tests ─────────────────────────────────────────────────────


class TestCategoryMap:
    def test_has_six_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 6

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

    def test_ws_payload_fuzz_techniques(self) -> None:
        assert len(_CATEGORY_MAP["ws_payload_fuzz"]) == 7

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
            with patch(
                "mytools.web.websocketattack.ssl.create_default_context",
                return_value=mock_ctx,
            ):
                mock_ctx.wrap_socket.return_value = MagicMock()
                _create_connection("example.com", 443, 5.0, tls=True)
                mock_ctx.wrap_socket.assert_called_once()


# ─── Parser Tests ────────────────────────────────────────────────────────────


@pytest.mark.smoke
class TestBuildParser:
    def test_has_url_arg(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["wss://example.com/ws"])
        assert args.url == "wss://example.com/ws"

    def test_has_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "wss://example.com/ws",
                "-c",
                "ws_scanner",
                "ws_dos",
            ]
        )
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


# ─── Payload Fuzz Tests ──────────────────────────────────────────────────────


class TestPayloadFuzzData:
    def test_payloads_has_seven_techniques(self) -> None:
        assert len(_PAYLOADS_WS_FUZZ) == 7

    def test_each_technique_has_six_fields(self) -> None:
        for entry in _PAYLOADS_WS_FUZZ:
            assert len(entry) == 6

    def test_technique_names(self) -> None:
        names = [e[0] for e in _PAYLOADS_WS_FUZZ]
        assert "xss_reflected" in names
        assert "sqli_error" in names
        assert "cmdi_os" in names
        assert "path_traversal" in names
        assert "nosql_injection" in names
        assert "template_injection" in names
        assert "log_injection" in names

    def test_xss_has_reflection_payloads(self) -> None:
        entry = next(e for e in _PAYLOADS_WS_FUZZ if e[0] == "xss_reflected")
        assert len(entry[2]) >= 3

    def test_sqli_has_timing_payloads(self) -> None:
        entry = next(e for e in _PAYLOADS_WS_FUZZ if e[0] == "sqli_error")
        assert len(entry[4]) >= 1

    def test_cmdi_has_timing_payloads(self) -> None:
        entry = next(e for e in _PAYLOADS_WS_FUZZ if e[0] == "cmdi_os")
        assert len(entry[4]) >= 1

    def test_nosql_has_timing_payloads(self) -> None:
        entry = next(e for e in _PAYLOADS_WS_FUZZ if e[0] == "nosql_injection")
        assert len(entry[4]) >= 1

    def test_ssti_has_timing_payloads(self) -> None:
        entry = next(e for e in _PAYLOADS_WS_FUZZ if e[0] == "template_injection")
        assert len(entry[4]) >= 1

    def test_log_injection_no_timing(self) -> None:
        entry = next(e for e in _PAYLOADS_WS_FUZZ if e[0] == "log_injection")
        assert len(entry[4]) == 0

    def test_timing_thresholds(self) -> None:
        for entry in _PAYLOADS_WS_FUZZ:
            threshold = entry[5]
            if entry[4]:
                assert threshold >= 5.0, f"{entry[0]} threshold too low"

    def test_nosql_thresholdHigher(self) -> None:
        entry = next(e for e in _PAYLOADS_WS_FUZZ if e[0] == "nosql_injection")
        assert entry[5] >= 8.0


class TestPayloadFuzzDetection:
    @pytest.mark.asyncio
    async def test_reflection_detected(self) -> None:
        mock_sock = MagicMock()
        ws_key = "dGVzdA=="
        reflected = b"<script>alert(1)</script>"

        with (
            patch(
                "mytools.web.websocketattack._ws_handshake",
                return_value=(mock_sock, ws_key),
            ),
            patch("mytools.web.websocketattack._send_ws_frame", return_value=True),
            patch(
                "mytools.web.websocketattack._recv_ws_frame",
                return_value=(0x1, reflected),
            ),
        ):
            results = await _test_ws_payload_fuzz(
                "example.com", 80, "/ws", 5.0, False, 200, 1000
            )
            vuln = [
                r for r in results if r.vulnerable and r.technique == "xss_reflected"
            ]
            assert len(vuln) >= 1

    @pytest.mark.asyncio
    async def test_no_reflection_not_vulnerable(self) -> None:
        with (
            patch(
                "mytools.web.websocketattack._ws_handshake",
                return_value=(MagicMock(), "key"),
            ),
            patch("mytools.web.websocketattack._send_ws_frame", return_value=True),
            patch(
                "mytools.web.websocketattack._recv_ws_frame",
                return_value=(0x1, b"different response"),
            ),
        ):
            results = await _test_ws_payload_fuzz(
                "example.com", 80, "/ws", 5.0, False, 200, 1000
            )
            xss_vuln = [
                r for r in results if r.vulnerable and r.technique == "xss_reflected"
            ]
            assert len(xss_vuln) == 0

    @pytest.mark.asyncio
    async def test_log_injection_close_frame(self) -> None:
        with (
            patch(
                "mytools.web.websocketattack._ws_handshake",
                return_value=(MagicMock(), "key"),
            ),
            patch("mytools.web.websocketattack._send_ws_frame", return_value=True),
            patch(
                "mytools.web.websocketattack._recv_ws_frame", return_value=(0x8, b"")
            ),
        ):
            results = await _test_ws_payload_fuzz(
                "example.com", 80, "/ws", 5.0, False, 200, 1000
            )
            log_vuln = [
                r for r in results if r.vulnerable and r.technique == "log_injection"
            ]
            assert len(log_vuln) >= 1

    @pytest.mark.asyncio
    async def test_log_injection_none_response(self) -> None:
        with (
            patch(
                "mytools.web.websocketattack._ws_handshake",
                return_value=(MagicMock(), "key"),
            ),
            patch("mytools.web.websocketattack._send_ws_frame", return_value=True),
            patch("mytools.web.websocketattack._recv_ws_frame", return_value=None),
        ):
            results = await _test_ws_payload_fuzz(
                "example.com", 80, "/ws", 5.0, False, 200, 1000
            )
            log_vuln = [
                r for r in results if r.vulnerable and r.technique == "log_injection"
            ]
            assert len(log_vuln) >= 1

    @pytest.mark.asyncio
    async def test_handshake_failure_skips(self) -> None:
        with (
            patch("mytools.web.websocketattack._ws_handshake", return_value=None),
            patch("mytools.web.websocketattack._send_ws_frame") as mock_send,
        ):
            results = await _test_ws_payload_fuzz(
                "example.com", 80, "/ws", 5.0, False, 200, 1000
            )
            assert results == []
            mock_send.assert_not_called()

    @pytest.mark.asyncio
    async def test_timing_detected(self) -> None:
        import time as _time

        call_count = 0

        def slow_recv(_sock: MagicMock, _timeout: float) -> tuple[int, bytes] | None:
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                _time.sleep(0.05)
                return (0x1, b"ok")
            _time.sleep(0.1)
            return (0x1, b"ok")

        with (
            patch(
                "mytools.web.websocketattack._ws_handshake",
                return_value=(MagicMock(), "key"),
            ),
            patch("mytools.web.websocketattack._send_ws_frame", return_value=True),
            patch("mytools.web.websocketattack._recv_ws_frame", side_effect=slow_recv),
        ):
            results = await _test_ws_payload_fuzz(
                "example.com", 80, "/ws", 5.0, False, 200, 1000
            )
            timing_vuln = [
                r for r in results if r.vulnerable and "_timing" in r.technique
            ]
            assert len(timing_vuln) == 0

    @pytest.mark.asyncio
    async def test_all_results_are_ws_attack_attempt(self) -> None:
        with (
            patch("mytools.web.websocketattack._ws_handshake", return_value=None),
        ):
            results = await _test_ws_payload_fuzz(
                "example.com", 80, "/ws", 5.0, False, 200, 1000
            )
            for r in results:
                assert isinstance(r, WSAttackAttempt)


class TestPayloadFuzzParser:
    def test_parser_accepts_payload_fuzz(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["wss://example.com/ws", "-c", "ws_payload_fuzz"])
        assert args.categories == ["ws_payload_fuzz"]

    def test_parser_accepts_mixed_categories(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "wss://example.com/ws",
                "-c",
                "ws_scanner",
                "ws_payload_fuzz",
            ]
        )
        assert "ws_payload_fuzz" in args.categories


# ─── Handshake Tests ────────────────────────────────────────────────────────


class TestWsHandshake:
    def test_success(self) -> None:
        sock = MagicMock()
        sock.recv.return_value = (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        )
        with (
            patch("mytools.web.websocketattack._create_connection", return_value=sock),
            patch(
                "mytools.web.websocketattack._generate_ws_key", return_value="dGVzdA=="
            ),
        ):
            result = _ws_handshake("example.com", 80, "/ws", 5.0, False)
        assert result is not None
        returned_sock, key = result
        assert key == "dGVzdA=="
        assert returned_sock is sock
        sent = sock.sendall.call_args[0][0]
        assert b"GET /ws HTTP/1.1" in sent
        assert b"Host: example.com" in sent
        assert b"Sec-WebSocket-Version: 13" in sent

    def test_success_with_origin_headers_and_port(self) -> None:
        sock = MagicMock()
        sock.recv.return_value = (
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        )
        with (
            patch("mytools.web.websocketattack._create_connection", return_value=sock),
            patch(
                "mytools.web.websocketattack._generate_ws_key", return_value="dGVzdA=="
            ),
        ):
            result = _ws_handshake(
                "example.com",
                8443,
                "/ws",
                5.0,
                True,
                origin="http://evil.com",
                extra_headers=[("Cookie", "a=b")],
            )
        assert result is not None
        sent = sock.sendall.call_args[0][0]
        assert b"Host: example.com:8443" in sent
        assert b"Origin: http://evil.com" in sent
        assert b"Cookie: a=b" in sent
        sock.close.assert_not_called()

    def test_non_101_response(self) -> None:
        sock = MagicMock()
        sock.recv.return_value = b"HTTP/1.1 404 Not Found\r\n\r\n"
        with (
            patch("mytools.web.websocketattack._create_connection", return_value=sock),
            patch("mytools.web.websocketattack._generate_ws_key", return_value="key"),
        ):
            result = _ws_handshake("example.com", 80, "/ws", 5.0, False)
        assert result is None
        sock.close.assert_called_once()

    def test_empty_chunk(self) -> None:
        sock = MagicMock()
        sock.recv.return_value = b""
        with (
            patch("mytools.web.websocketattack._create_connection", return_value=sock),
            patch("mytools.web.websocketattack._generate_ws_key", return_value="key"),
        ):
            result = _ws_handshake("example.com", 80, "/ws", 5.0, False)
        assert result is None
        sock.close.assert_called_once()

    def test_timeout_during_recv(self) -> None:
        sock = MagicMock()
        sock.recv.side_effect = TimeoutError("t")
        with (
            patch("mytools.web.websocketattack._create_connection", return_value=sock),
            patch("mytools.web.websocketattack._generate_ws_key", return_value="key"),
        ):
            result = _ws_handshake("example.com", 80, "/ws", 5.0, False)
        assert result is None
        sock.close.assert_called_once()

    def test_oserror_during_recv(self) -> None:
        sock = MagicMock()
        sock.recv.side_effect = OSError("e")
        with (
            patch("mytools.web.websocketattack._create_connection", return_value=sock),
            patch("mytools.web.websocketattack._generate_ws_key", return_value="key"),
        ):
            result = _ws_handshake("example.com", 80, "/ws", 5.0, False)
        assert result is None

    def test_create_connection_exception(self) -> None:
        with (
            patch(
                "mytools.web.websocketattack._create_connection",
                side_effect=Exception("boom"),
            ),
            patch("mytools.web.websocketattack._generate_ws_key", return_value="key"),
        ):
            result = _ws_handshake("example.com", 80, "/ws", 5.0, False)
        assert result is None


# ─── Recv Frame Extended Tests ──────────────────────────────────────────────


class TestRecvWsFrameExtended:
    def test_length_126(self) -> None:
        sock = MagicMock()
        frame = _build_ws_frame(0x1, b"X" * 200, mask=False)
        sock.recv.side_effect = [frame[:2], frame[2:4], frame[4:]]
        result = _recv_ws_frame(sock, 5.0)
        assert result is not None
        opcode, payload = result
        assert opcode == 0x1
        assert payload == b"X" * 200

    def test_length_127(self) -> None:
        sock = MagicMock()
        frame = _build_ws_frame(0x1, b"X" * 70000, mask=False)
        sock.recv.side_effect = [frame[:2], frame[2:10], frame[10:]]
        result = _recv_ws_frame(sock, 5.0)
        assert result is not None
        opcode, payload = result
        assert opcode == 0x1
        assert payload == b"X" * 70000

    def test_masked_frame(self) -> None:
        sock = MagicMock()
        frame = _build_ws_frame(0x1, b"hello", mask=True)
        sock.recv.side_effect = [frame[:2], frame[2:6], frame[6:]]
        result = _recv_ws_frame(sock, 5.0)
        assert result == (0x1, b"hello")

    def test_masked_short_key(self) -> None:
        sock = MagicMock()
        sock.recv.side_effect = [b"\x81\x85", b"\x01"]
        assert _recv_ws_frame(sock, 5.0) is None

    def test_short_ext_126(self) -> None:
        sock = MagicMock()
        sock.recv.side_effect = [b"\x81\x7e", b"\x01"]
        assert _recv_ws_frame(sock, 5.0) is None

    def test_short_ext_127(self) -> None:
        sock = MagicMock()
        sock.recv.side_effect = [b"\x81\x7f", b"\x01\x02"]
        assert _recv_ws_frame(sock, 5.0) is None

    def test_empty_chunk_in_payload(self) -> None:
        sock = MagicMock()
        sock.recv.side_effect = [b"\x81\x05", b""]
        result = _recv_ws_frame(sock, 5.0)
        assert result == (0x1, b"")


# ─── Send HTTP Request Tests ────────────────────────────────────────────────


class TestSendHttpRequest:
    def test_with_headers_and_body(self) -> None:
        sock = MagicMock()
        sock.recv.side_effect = [b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello"]
        status, response = _send_http_request(
            sock,
            "POST",
            "/submit",
            "example.com",
            headers=[("X-A", "1")],
            body=b"abcde",
        )
        assert status == 200
        assert response.endswith(b"hello")
        request_bytes = sock.sendall.call_args_list[0][0][0]
        assert request_bytes.startswith(b"POST /submit HTTP/1.1")
        assert b"X-A: 1" in request_bytes
        assert b"Content-Length: 5" in request_bytes
        assert sock.sendall.call_args_list[1][0][0] == b"abcde"

    def test_no_content_length(self) -> None:
        sock = MagicMock()
        sock.recv.side_effect = [b"HTTP/1.1 301 Moved\r\nLocation: /new\r\n\r\n"]
        status, _response = _send_http_request(sock, "GET", "/x", "example.com")
        assert status == 301

    def test_chunked_body_until_complete(self) -> None:
        sock = MagicMock()
        sock.recv.side_effect = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n",
            b"12345",
            b"12345",
        ]
        status, response = _send_http_request(sock, "GET", "/x", "example.com")
        assert status == 200
        assert response.endswith(b"1234512345")

    def test_header_terminator_split_across_chunks(self) -> None:
        sock = MagicMock()
        sock.recv.side_effect = [
            b"HTTP/1.1 200 OK\r\nContent-Len",
            b"gth: 5\r\n\r\nhello",
        ]
        status, response = _send_http_request(sock, "GET", "/x", "example.com")
        assert status == 200
        assert response.endswith(b"hello")

    def test_timeout_breaks_loop(self) -> None:
        sock = MagicMock()
        sock.recv.side_effect = TimeoutError("t")
        status, response = _send_http_request(sock, "GET", "/x", "example.com")
        assert status == 0
        assert response == b""

    def test_oserror_breaks_loop(self) -> None:
        sock = MagicMock()
        sock.recv.side_effect = OSError("e")
        status, _response = _send_http_request(sock, "GET", "/x", "example.com")
        assert status == 0

    def test_empty_recv_breaks(self) -> None:
        sock = MagicMock()
        sock.recv.side_effect = [b""]
        status, _response = _send_http_request(sock, "GET", "/x", "example.com")
        assert status == 0

    def test_invalid_status_parsing(self) -> None:
        sock = MagicMock()
        sock.recv.side_effect = [b"HTTP/1.1 XYZ\r\n\r\n"]
        status, _response = _send_http_request(sock, "GET", "/x", "example.com")
        assert status == 0

    def test_short_first_line(self) -> None:
        sock = MagicMock()
        sock.recv.side_effect = [b"HTTP/1.1\r\n\r\n"]
        status, _response = _send_http_request(sock, "GET", "/x", "example.com")
        assert status == 0


# ─── Baseline Tests ─────────────────────────────────────────────────────────


class TestGetBaseline:
    def test_success(self) -> None:
        sock = MagicMock()
        with (
            patch("mytools.web.websocketattack._create_connection", return_value=sock),
            patch(
                "mytools.web.websocketattack._send_http_request",
                return_value=(200, b"hello"),
            ),
        ):
            status, size = _get_baseline("example.com", 80, "/", 5.0, False)
        assert (status, size) == (200, 5)
        sock.close.assert_called_once()

    def test_exception(self) -> None:
        with patch(
            "mytools.web.websocketattack._create_connection",
            side_effect=OSError("down"),
        ):
            status, size = _get_baseline("example.com", 80, "/", 5.0, False)
        assert (status, size) == (0, 0)


# ─── ws_scanner ─────────────────────────────────────────────────────────────


class TestWsScanner:
    @pytest.mark.asyncio
    async def test_handshakes_ok_insecure(self) -> None:
        mock_sock = MagicMock()
        with patch(
            "mytools.web.websocketattack._ws_handshake",
            return_value=(mock_sock, "key"),
        ):
            results = await _test_ws_scanner(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert len(results) == 5
        insecure = next(r for r in results if r.technique == "insecure_scheme")
        assert insecure.vulnerable is True
        cswh = next(r for r in results if r.technique == "cswh_hijack")
        assert cswh.vulnerable is False
        rate_limit = next(r for r in results if r.technique == "no_rate_limit")
        assert rate_limit.details == "5 conexoes rapidas completadas"

    @pytest.mark.asyncio
    async def test_insecure_scheme_secure_when_tls(self) -> None:
        with patch(
            "mytools.web.websocketattack._ws_handshake",
            return_value=(MagicMock(), "key"),
        ):
            results = await _test_ws_scanner(
                "example.com", 443, "/ws", 5.0, True, 200, 100
            )
        insecure = next(r for r in results if r.technique == "insecure_scheme")
        assert insecure.vulnerable is False
        assert insecure.status_test == 200

    @pytest.mark.asyncio
    async def test_handshake_refused(self) -> None:
        with patch("mytools.web.websocketattack._ws_handshake", return_value=None):
            results = await _test_ws_scanner(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        refused = next(r for r in results if r.technique == "cswh_hijack")
        assert refused.vulnerable is False
        assert "Handshake recusado" in refused.details

    @pytest.mark.asyncio
    async def test_exception(self) -> None:
        with patch(
            "mytools.web.websocketattack._ws_handshake",
            side_effect=Exception("boom"),
        ):
            results = await _test_ws_scanner(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert len(results) == 5
        errored = [r for r in results if r.error]
        assert len(errored) == 4
        assert all(r.technique != "insecure_scheme" for r in errored)


# ─── ws_upgrade_abuse ───────────────────────────────────────────────────────


class TestWsUpgradeAbuse:
    @pytest.mark.asyncio
    async def test_all_rejected(self) -> None:
        sock = MagicMock()
        with (
            patch("mytools.web.websocketattack._create_connection", return_value=sock),
            patch(
                "mytools.web.websocketattack._send_http_request",
                return_value=(404, b"Not Found"),
            ) as mock_send,
        ):
            results = await _test_ws_upgrade_abuse(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert len(results) == 5
        assert all(not r.vulnerable for r in results)
        assert all(r.status_test == 404 for r in results)
        versions = [mock_send.call_args_list[i].kwargs["version"] for i in range(5)]
        assert versions.count("HTTP/1.0") == 1

    @pytest.mark.asyncio
    async def test_all_upgraded(self) -> None:
        sock = MagicMock()
        with (
            patch("mytools.web.websocketattack._create_connection", return_value=sock),
            patch(
                "mytools.web.websocketattack._send_http_request",
                return_value=(101, b"Switching Protocols"),
            ),
        ):
            results = await _test_ws_upgrade_abuse(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert all(r.vulnerable for r in results)
        assert all(r.status_test == 101 for r in results)

    @pytest.mark.asyncio
    async def test_exception(self) -> None:
        with patch(
            "mytools.web.websocketattack._create_connection",
            side_effect=Exception("boom"),
        ):
            results = await _test_ws_upgrade_abuse(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert len(results) == 5
        assert all(r.error for r in results)


# ─── ws_message_inject ──────────────────────────────────────────────────────


class TestWsMessageInject:
    @pytest.mark.asyncio
    async def test_all_responses(self) -> None:
        sent: list[bytes] = []

        def fake_send(
            sock: Any, opcode: int, payload: bytes = b"", mask: bool = True
        ) -> bool:
            sent.append(payload)
            return True

        def fake_recv(sock: Any, timeout: float) -> tuple[int, bytes] | None:
            if not sent:
                return (WS_OPCODE_TEXT, b"echo")
            return (WS_OPCODE_TEXT, sent[-1])

        with (
            patch(
                "mytools.web.websocketattack._ws_handshake",
                return_value=(MagicMock(), "key"),
            ),
            patch("mytools.web.websocketattack._send_ws_frame", side_effect=fake_send),
            patch("mytools.web.websocketattack._recv_ws_frame", side_effect=fake_recv),
        ):
            results = await _test_ws_message_inject(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert len(results) == 5
        assert all(r.vulnerable for r in results)
        assert all(r.status_test == 101 for r in results)

    @pytest.mark.asyncio
    async def test_echo_not_matching_payload_not_vulnerable(self) -> None:
        with (
            patch(
                "mytools.web.websocketattack._ws_handshake",
                return_value=(MagicMock(), "key"),
            ),
            patch("mytools.web.websocketattack._send_ws_frame", return_value=True),
            patch(
                "mytools.web.websocketattack._recv_ws_frame",
                return_value=(WS_OPCODE_TEXT, b"unrelated text"),
            ),
        ):
            results = await _test_ws_message_inject(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert all(not r.vulnerable for r in results)
        assert all(r.status_test == 101 for r in results)

    @pytest.mark.asyncio
    async def test_no_response(self) -> None:
        with (
            patch(
                "mytools.web.websocketattack._ws_handshake",
                return_value=(MagicMock(), "key"),
            ),
            patch("mytools.web.websocketattack._send_ws_frame", return_value=True),
            patch("mytools.web.websocketattack._recv_ws_frame", return_value=None),
        ):
            results = await _test_ws_message_inject(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert all(not r.vulnerable for r in results)
        assert all("Sem resposta" in r.details for r in results)

    @pytest.mark.asyncio
    async def test_handshake_failed(self) -> None:
        with patch("mytools.web.websocketattack._ws_handshake", return_value=None):
            results = await _test_ws_message_inject(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert len(results) == 5
        assert all("Handshake falhou" in r.details for r in results)

    @pytest.mark.asyncio
    async def test_exception(self) -> None:
        with patch(
            "mytools.web.websocketattack._ws_handshake",
            side_effect=Exception("boom"),
        ):
            results = await _test_ws_message_inject(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert all(r.error for r in results)


# ─── ws_dos ─────────────────────────────────────────────────────────────────


class TestWsDos:
    @pytest.mark.asyncio
    async def test_all_close_response(self) -> None:
        mock_sock = MagicMock()
        with (
            patch(
                "mytools.web.websocketattack._ws_handshake",
                return_value=(mock_sock, "key"),
            ),
            patch("mytools.web.websocketattack._send_ws_frame", return_value=True),
            patch(
                "mytools.web.websocketattack._recv_ws_frame",
                return_value=(WS_OPCODE_CLOSE, b""),
            ),
        ):
            results = await _test_ws_dos("example.com", 80, "/ws", 5.0, False, 200, 100)
        assert len(results) == 5
        assert all(not r.vulnerable for r in results)
        assert all("Opcode resposta" in r.details for r in results)
        assert mock_sock.sendall.call_count == 1

    @pytest.mark.asyncio
    async def test_no_response(self) -> None:
        with (
            patch(
                "mytools.web.websocketattack._ws_handshake",
                return_value=(MagicMock(), "key"),
            ),
            patch("mytools.web.websocketattack._send_ws_frame", return_value=True),
            patch("mytools.web.websocketattack._recv_ws_frame", return_value=None),
        ):
            results = await _test_ws_dos("example.com", 80, "/ws", 5.0, False, 200, 100)
        assert all(not r.vulnerable for r in results)
        assert all("Sem resposta" in r.details for r in results)

    @pytest.mark.asyncio
    async def test_handshake_failed(self) -> None:
        with patch("mytools.web.websocketattack._ws_handshake", return_value=None):
            results = await _test_ws_dos("example.com", 80, "/ws", 5.0, False, 200, 100)
        assert len(results) == 5
        assert all("Handshake falhou" in r.details for r in results)

    @pytest.mark.asyncio
    async def test_exception(self) -> None:
        with patch(
            "mytools.web.websocketattack._ws_handshake",
            side_effect=Exception("boom"),
        ):
            results = await _test_ws_dos("example.com", 80, "/ws", 5.0, False, 200, 100)
        assert all(r.error for r in results)


# ─── ws_compression_bomb ────────────────────────────────────────────────────


class TestWsCompressionBomb:
    @pytest.mark.asyncio
    async def test_upgraded_with_deflate_bomb_no_response(self) -> None:
        sock = MagicMock()
        response = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
        )
        with (
            patch("mytools.web.websocketattack._create_connection", return_value=sock),
            patch(
                "mytools.web.websocketattack._send_http_request",
                return_value=(101, response),
            ),
            patch("mytools.web.websocketattack._send_ws_frame", return_value=True),
            patch("mytools.web.websocketattack._recv_ws_frame", return_value=None),
        ):
            results = await _test_ws_compression_bomb(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert len(results) == 5
        assert all(r.vulnerable for r in results)
        assert all(r.status_test == 101 for r in results)
        assert all("bomb" in r.details for r in results)

    @pytest.mark.asyncio
    async def test_upgraded_with_deflate_server_survives(self) -> None:
        sock = MagicMock()
        response = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
        )
        with (
            patch("mytools.web.websocketattack._create_connection", return_value=sock),
            patch(
                "mytools.web.websocketattack._send_http_request",
                return_value=(101, response),
            ),
            patch("mytools.web.websocketattack._send_ws_frame", return_value=True),
            patch(
                "mytools.web.websocketattack._recv_ws_frame",
                return_value=(0x1, b"ok"),
            ),
        ):
            results = await _test_ws_compression_bomb(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert len(results) == 5
        assert all(not r.vulnerable for r in results)
        assert all(r.status_test == 101 for r in results)

    @pytest.mark.asyncio
    async def test_not_upgraded(self) -> None:
        sock = MagicMock()
        with (
            patch("mytools.web.websocketattack._create_connection", return_value=sock),
            patch(
                "mytools.web.websocketattack._send_http_request",
                return_value=(404, b"Not Found"),
            ),
        ):
            results = await _test_ws_compression_bomb(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert all(not r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_exception(self) -> None:
        with patch(
            "mytools.web.websocketattack._create_connection",
            side_effect=Exception("boom"),
        ):
            results = await _test_ws_compression_bomb(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert all(r.error for r in results)

    @pytest.mark.asyncio
    async def test_upgraded_send_frame_fails(self) -> None:
        sock = MagicMock()
        response = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
        )
        with (
            patch("mytools.web.websocketattack._create_connection", return_value=sock),
            patch(
                "mytools.web.websocketattack._send_http_request",
                return_value=(101, response),
            ),
            patch("mytools.web.websocketattack._send_ws_frame", return_value=False),
        ):
            results = await _test_ws_compression_bomb(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert len(results) == 5
        assert all(r.vulnerable for r in results)
        assert all("encerrada apos bomb" in r.details for r in results)

    @pytest.mark.asyncio
    async def test_upgraded_oserror(self) -> None:
        sock = MagicMock()
        response = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Sec-WebSocket-Extensions: permessage-deflate\r\n\r\n"
        )
        with (
            patch("mytools.web.websocketattack._create_connection", return_value=sock),
            patch(
                "mytools.web.websocketattack._send_http_request",
                return_value=(101, response),
            ),
            patch(
                "mytools.web.websocketattack._send_ws_frame",
                side_effect=OSError("reset"),
            ),
        ):
            results = await _test_ws_compression_bomb(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        assert len(results) == 5
        assert all(r.vulnerable for r in results)
        assert all("encerrada apos bomb" in r.details for r in results)


# ─── Payload Fuzz Timing Branch ─────────────────────────────────────────────


class TestPayloadFuzzTiming:
    @pytest.mark.asyncio
    async def test_timing_threshold_reached(self) -> None:
        mock_sock = MagicMock()
        values: list[float] = [0.0, 0.5]
        for _ in range(8):
            values.extend([0.0, 100.0])
        with (
            patch(
                "mytools.web.websocketattack._ws_handshake",
                return_value=(mock_sock, "key"),
            ),
            patch("mytools.web.websocketattack._send_ws_frame", return_value=True),
            patch(
                "mytools.web.websocketattack._recv_ws_frame", return_value=(0x1, b"ok")
            ),
            patch("mytools.web.websocketattack.time.monotonic", side_effect=values),
        ):
            results = await _test_ws_payload_fuzz(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        timing_vuln = [
            r for r in results if r.vulnerable and r.technique.endswith("_timing")
        ]
        assert len(timing_vuln) == 8
        assert all("threshold" in r.details for r in timing_vuln)

    @pytest.mark.asyncio
    async def test_timing_gated_by_baseline_latency(self) -> None:
        mock_sock = MagicMock()
        values: list[float] = [0.0, 100.0]
        for _ in range(8):
            values.extend([0.0, 100.0])
        with (
            patch(
                "mytools.web.websocketattack._ws_handshake",
                return_value=(mock_sock, "key"),
            ),
            patch("mytools.web.websocketattack._send_ws_frame", return_value=True),
            patch(
                "mytools.web.websocketattack._recv_ws_frame", return_value=(0x1, b"ok")
            ),
            patch("mytools.web.websocketattack.time.monotonic", side_effect=values),
        ):
            results = await _test_ws_payload_fuzz(
                "example.com", 80, "/ws", 5.0, False, 200, 100
            )
        timing_vuln = [
            r for r in results if r.vulnerable and r.technique.endswith("_timing")
        ]
        assert len(timing_vuln) == 0


# ─── Print Results Secure Category ──────────────────────────────────────────


class TestPrintResultsSecureCategory:
    def test_print_secure_category(self, capsys: pytest.CaptureFixture[str]) -> None:
        attempt = WSAttackAttempt(
            technique="cswh_hijack",
            category="ws_scanner",
            description="desc",
            status_baseline=200,
            status_test=0,
            size_baseline=1000,
            size_test=0,
            vulnerable=False,
            details="Handshake recusado",
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
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "ws_scanner: secure" in output
        assert "SECURE" in output


# ─── run_scan ───────────────────────────────────────────────────────────────


class TestRunScan:
    @pytest.mark.asyncio
    async def test_full_scan_vulnerable(self) -> None:
        vuln = WSAttackAttempt(
            technique="cswh_hijack",
            category="ws_scanner",
            description="d",
            status_baseline=200,
            status_test=101,
            size_baseline=100,
            size_test=0,
            vulnerable=True,
            details="handshake aceito",
            error="",
        )
        fake_tester = AsyncMock(return_value=[vuln])
        with (
            patch(
                "mytools.web.websocketattack._parse_url",
                return_value=("example.com", "/ws", 80, False),
            ),
            patch(
                "mytools.web.websocketattack._get_baseline",
                return_value=(200, 100),
            ),
            patch(
                "mytools.web.websocketattack._CATEGORY_DISPATCH",
                {"ws_scanner": fake_tester},
            ),
            patch("mytools.web.websocketattack.print_results"),
            patch("mytools.web.websocketattack.write_output") as mock_write,
        ):
            result = await run_scan(
                "ws://example.com/ws", ["ws_scanner"], 5.0, "out.json"
            )
        assert result.overall_status == "vulnerable"
        assert result.baseline_status == 200
        assert result.baseline_size == 100
        assert result.host == "example.com"
        mock_write.assert_called_once()

    @pytest.mark.asyncio
    async def test_unknown_category_skipped(self) -> None:
        with (
            patch(
                "mytools.web.websocketattack._parse_url",
                return_value=("example.com", "/ws", 80, False),
            ),
            patch(
                "mytools.web.websocketattack._get_baseline",
                return_value=(200, 100),
            ),
            patch("mytools.web.websocketattack._CATEGORY_DISPATCH", {}),
            patch("mytools.web.websocketattack.print_results"),
        ):
            result = await run_scan("ws://example.com/ws", ["bogus"], 5.0, None)
        assert result.overall_status == "secure"
        assert result.attempts == []

    @pytest.mark.asyncio
    async def test_default_categories_and_tester_error(self) -> None:
        def bad_tester(*_args: object, **_kwargs: object) -> object:
            raise RuntimeError("boom")

        with (
            patch(
                "mytools.web.websocketattack._parse_url",
                return_value=("example.com", "/ws", 80, False),
            ),
            patch(
                "mytools.web.websocketattack._get_baseline",
                return_value=(200, 100),
            ),
            patch(
                "mytools.web.websocketattack._CATEGORY_DISPATCH",
                {"ws_scanner": bad_tester},
            ),
            patch("mytools.web.websocketattack.print_results"),
        ):
            result = await run_scan("ws://example.com/ws", None, 5.0, None)
        assert any(a.technique == "ws_scanner_error" for a in result.attempts)
        assert result.issues


# ─── Run Once ───────────────────────────────────────────────────────────────


class TestRunOnce:
    def test_vulnerable_returns_1(self) -> None:
        mock_result = MagicMock()
        mock_result.overall_status = "vulnerable"
        args = argparse.Namespace(
            url="ws://example.com/ws", categories=None, timeout=5.0, output=None
        )
        with (
            patch(
                "mytools.web.websocketattack.run_scan",
                MagicMock(return_value=mock_result),
            ),
            patch(
                "mytools.web.websocketattack.safe_asyncio_run",
                side_effect=lambda coro: coro,
            ),
        ):
            assert run_once(args) == 1

    def test_secure_returns_0(self) -> None:
        mock_result = MagicMock()
        mock_result.overall_status = "secure"
        args = argparse.Namespace(
            url="ws://example.com/ws", categories=None, timeout=5.0, output=None
        )
        with (
            patch(
                "mytools.web.websocketattack.run_scan",
                MagicMock(return_value=mock_result),
            ),
            patch(
                "mytools.web.websocketattack.safe_asyncio_run",
                side_effect=lambda coro: coro,
            ),
        ):
            assert run_once(args) == 0


# ─── Main ───────────────────────────────────────────────────────────────────


class TestMain:
    def test_main(self) -> None:
        with patch(
            "mytools.web.websocketattack.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()


class TestMainGuard:
    def test_guard(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-wsattack", "ws://example.com/ws"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.websocketattack", run_name="__main__")
        assert exc_info.value.code == 0
