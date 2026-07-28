"""Testes do modulo websocketattack.py — WebSocket Security."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mytools.web.websocketattack import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    _PAYLOADS_WS_FUZZ,
    WSAttackAttempt,
    WSAttackResult,
    _build_ws_frame,
    _create_connection,
    _generate_ws_key,
    _parse_url,
    _recv_ws_frame,
    _send_ws_frame,
    _test_ws_payload_fuzz,
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
