"""Testes do modulo http2abuse.py — HTTP/2 Abuse."""

from __future__ import annotations

import argparse
from unittest.mock import AsyncMock, MagicMock, patch

import h2.events
import h2.settings
import httpx
import pytest

from mytools.web.http2abuse import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    HTTP2Attempt,
    HTTP2Result,
    _collect_server_settings,
    _create_h2_connection,
    _create_tls_socket,
    _drain_settings,
    _fingerprint_server,
    _parse_url,
    _recv_events,
    _test_h2_downgrade,
    _test_h2_fingerprint,
    _test_h2_push_abuse,
    _test_h2_stream_abuse,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)


def _ns(**overrides: object) -> argparse.Namespace:
    defaults = {
        "url": "https://example.com",
        "categories": None,
        "timeout": 5.0,
        "output": None,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def _result(status: str) -> HTTP2Result:
    return HTTP2Result(
        target="https://example.com",
        host="example.com",
        port=443,
        h2_supported=True,
        server_settings={},
        attempts=[],
        vulnerable_techniques=[],
        issues=[],
        overall_status=status,
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
            technique="t",
            category="c",
            description="d",
            h2_supported=True,
            settings_observed={},
            vulnerable=False,
            details="",
            error="",
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
            target="t",
            host="h",
            port=443,
            h2_supported=True,
            server_settings={},
            attempts=[],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
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

    def test_ipv6(self) -> None:
        host, _path, port, tls = _parse_url("https://[::1]:8443/test")
        assert host == "::1"
        assert port == 8443
        assert tls is True

    def test_fragment(self) -> None:
        _host, path, _port, _tls = _parse_url("https://example.com/path#section")
        assert path == "/path"

    def test_no_scheme(self) -> None:
        host, _path, _port, tls = _parse_url("example.com/test")
        assert host == ""
        assert tls is False


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

    def test_partial_match(self) -> None:
        settings = {"MAX_FRAME_SIZE": 16384}
        assert _fingerprint_server(settings) in ("nginx", "apache", "golang", "node")


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


# ─── _recv_events Tests ─────────────────────────────────────────────────────


class TestRecvEvents:
    def test_normal_data(self) -> None:
        mock_sock = MagicMock()
        mock_conn = MagicMock()
        mock_sock.recv.return_value = b"\x00\x00\x00\x00"
        mock_conn.receive_data.return_value = [h2.events.SettingsAcknowledged()]
        events = _recv_events(mock_sock, mock_conn, 5.0)
        assert len(events) == 1
        mock_sock.settimeout.assert_called_once_with(5.0)

    def test_timeout(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError("timed out")
        events = _recv_events(mock_sock, MagicMock(), 5.0)
        assert events == []

    def test_os_error(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = OSError("Connection reset")
        events = _recv_events(mock_sock, MagicMock(), 5.0)
        assert events == []

    def test_empty_data(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        events = _recv_events(mock_sock, MagicMock(), 5.0)
        assert events == []


# ─── _drain_settings Tests ──────────────────────────────────────────────────


class TestDrainSettings:
    def test_collects_settings(self) -> None:
        mock_sock = MagicMock()
        mock_conn = MagicMock()
        ev = h2.events.RemoteSettingsChanged()
        ev.changed_settings = {
            h2.settings.SettingCodes.MAX_FRAME_SIZE: MagicMock(new_value=16384)
        }
        mock_conn.receive_data.return_value = [ev]

        with patch("mytools.web.http2abuse._recv_events", return_value=[ev]):
            settings = _drain_settings(mock_sock, mock_conn, 5.0)
            assert "MAX_FRAME_SIZE" in settings
            assert settings["MAX_FRAME_SIZE"] == 16384

    def test_connection_terminated(self) -> None:
        ev = h2.events.ConnectionTerminated()
        ev.last_stream_id = 0
        ev.error_code = 0
        ev.additional_data = b""

        with patch("mytools.web.http2abuse._recv_events", return_value=[ev]):
            settings = _drain_settings(MagicMock(), MagicMock(), 5.0)
            assert settings == {}

    def test_empty_events(self) -> None:
        with patch("mytools.web.http2abuse._recv_events", return_value=[]):
            settings = _drain_settings(MagicMock(), MagicMock(), 5.0)
            assert settings == {}


# ─── _collect_server_settings Tests ─────────────────────────────────────────


class TestCollectServerSettings:
    def test_collects_settings(self) -> None:
        mock_sock = MagicMock()
        mock_conn = MagicMock()
        ev = h2.events.RemoteSettingsChanged()
        ev.changed_settings = {
            h2.settings.SettingCodes.HEADER_TABLE_SIZE: MagicMock(new_value=4096)
        }
        mock_conn.receive_data.return_value = [ev]
        result = _collect_server_settings(mock_sock, mock_conn, 5.0)
        assert "HEADER_TABLE_SIZE" in result

    def test_timeout_returns_empty(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.side_effect = TimeoutError("timed out")
        result = _collect_server_settings(mock_sock, MagicMock(), 5.0)
        assert result == {}

    def test_empty_data_returns_empty(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b""
        result = _collect_server_settings(mock_sock, MagicMock(), 5.0)
        assert result == {}


# ─── Build Parser Tests ──────────────────────────────────────────────────────


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
                "h2_downgrade",
                "h2_fingerprint",
            ]
        )
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

    def test_print_with_settings(self, capsys: pytest.CaptureFixture[str]) -> None:
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
        assert "Server Settings" in output

    def test_print_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = HTTP2Result(
            target="https://example.com",
            host="example.com",
            port=443,
            h2_supported=True,
            server_settings={},
            attempts=[],
            vulnerable_techniques=[],
            issues=["Connection failed"],
            overall_status="secure",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Issues" in output
        assert "Connection failed" in output


# ─── Dispatcher Tests (parametrized) ─────────────────────────────────────────


DISPATCHER_PARAMS = list(_CATEGORY_DISPATCH.items())


@pytest.mark.parametrize("cat_name,dispatcher", DISPATCHER_PARAMS)
class TestDispatchers:
    @pytest.mark.asyncio
    async def test_returns_list(self, cat_name: str, dispatcher: object) -> None:
        with (
            patch("mytools.web.http2abuse._create_tls_socket") as mock_tls,
            patch("mytools.web.http2abuse._create_h2_connection") as mock_h2,
            patch("mytools.web.http2abuse._recv_events", return_value=[]),
            patch("mytools.web.http2abuse._drain_settings", return_value={}),
        ):
            mock_sock = MagicMock()
            mock_tls.return_value = mock_sock
            mock_sock.selected_alpn_protocol.return_value = "h2"
            mock_conn = MagicMock()
            mock_h2.return_value = (MagicMock(), mock_conn)
            fn = dispatcher  # type: ignore[misc]
            results = await fn("example.com", 443, "/", 5.0, True, {})  # type: ignore[misc]
            assert isinstance(results, list)
            assert len(results) > 0
            assert all(isinstance(r, HTTP2Attempt) for r in results)

    @pytest.mark.asyncio
    async def test_exception_returns_error(
        self, cat_name: str, dispatcher: object
    ) -> None:
        with (
            patch(
                "mytools.web.http2abuse._create_tls_socket", side_effect=OSError("fail")
            ),
            patch(
                "mytools.web.http2abuse._create_h2_connection",
                side_effect=OSError("fail"),
            ),
        ):
            fn = dispatcher  # type: ignore[misc]
            results = await fn("example.com", 443, "/", 5.0, True, {})  # type: ignore[misc]
            assert isinstance(results, list)
            assert len(results) > 0


# ─── run_scan Tests ──────────────────────────────────────────────────────────


class TestRunScan:
    @pytest.mark.asyncio
    async def test_returns_http2result(self) -> None:
        with (
            patch("mytools.web.http2abuse._create_tls_socket") as mock_tls,
            patch("mytools.web.http2abuse._create_h2_connection") as mock_h2,
            patch("mytools.web.http2abuse._collect_server_settings", return_value={}),
            patch("mytools.web.http2abuse._CATEGORY_DISPATCH") as mock_dispatch,
        ):
            mock_sock = MagicMock()
            mock_tls.return_value = mock_sock
            mock_sock.selected_alpn_protocol.return_value = "h2"
            mock_h2.return_value = (MagicMock(), MagicMock())
            mock_dispatch.get.return_value = AsyncMock(return_value=[])
            result = await run_scan("https://example.com", [], 5.0, None)
            assert isinstance(result, HTTP2Result)
            assert result.host == "example.com"

    @pytest.mark.asyncio
    async def test_h2_not_supported(self) -> None:
        with (
            patch("mytools.web.http2abuse._create_tls_socket") as mock_tls,
            patch("mytools.web.http2abuse._CATEGORY_DISPATCH") as mock_dispatch,
        ):
            mock_sock = MagicMock()
            mock_tls.return_value = mock_sock
            mock_sock.selected_alpn_protocol.return_value = "http/1.1"
            mock_dispatch.get.return_value = AsyncMock(return_value=[])
            result = await run_scan("https://example.com", [], 5.0, None)
            assert result.h2_supported is False

    @pytest.mark.asyncio
    async def test_tls_connect_error(self) -> None:
        with (
            patch(
                "mytools.web.http2abuse._create_tls_socket",
                side_effect=OSError("conn refused"),
            ),
            patch("mytools.web.http2abuse._CATEGORY_DISPATCH") as mock_dispatch,
        ):
            mock_dispatch.get.return_value = AsyncMock(return_value=[])
            result = await run_scan("https://example.com", [], 5.0, None)
            assert result.h2_supported is False

    @pytest.mark.asyncio
    async def test_categories_defaults_to_all(self) -> None:
        with (
            patch(
                "mytools.web.http2abuse._create_tls_socket", side_effect=OSError("fail")
            ),
            patch("mytools.web.http2abuse._CATEGORY_DISPATCH") as mock_dispatch,
        ):
            mock_dispatch.get.return_value = AsyncMock(return_value=[])
            await run_scan("https://example.com", None, 5.0, None)
            assert mock_dispatch.get.call_count == 7

    @pytest.mark.asyncio
    async def test_output_file(self) -> None:
        with (
            patch(
                "mytools.web.http2abuse._create_tls_socket", side_effect=OSError("fail")
            ),
            patch("mytools.web.http2abuse._CATEGORY_DISPATCH") as mock_dispatch,
            patch("mytools.web.http2abuse.write_output") as mock_write,
        ):
            mock_dispatch.get.return_value = AsyncMock(return_value=[])
            await run_scan("https://example.com", [], 5.0, "output.json")
            mock_write.assert_called_once()

    @pytest.mark.asyncio
    async def test_tls_ok_but_h2_connection_fails(self) -> None:
        with (
            patch("mytools.web.http2abuse._create_tls_socket") as mock_tls,
            patch(
                "mytools.web.http2abuse._create_h2_connection",
                side_effect=OSError("boom"),
            ),
            patch("mytools.web.http2abuse._CATEGORY_DISPATCH") as mock_dispatch,
            patch("mytools.web.http2abuse.print_results"),
        ):
            mock_tls.return_value.selected_alpn_protocol.return_value = "h2"
            mock_dispatch.get.return_value = AsyncMock(return_value=[])
            result = await run_scan("https://example.com", [], 5.0, None)
            assert result.h2_supported is True
            assert result.server_settings == {}

    @pytest.mark.asyncio
    async def test_invalid_category_is_skipped(self) -> None:
        with (
            patch(
                "mytools.web.http2abuse._create_tls_socket", side_effect=OSError("fail")
            ),
            patch("mytools.web.http2abuse.print_results"),
        ):
            result = await run_scan("https://example.com", ["invalid"], 5.0, None)
            assert result.attempts == []
            assert result.overall_status == "secure"

    @pytest.mark.asyncio
    async def test_tester_exception_adds_error_attempt(self) -> None:
        with (
            patch(
                "mytools.web.http2abuse._create_tls_socket", side_effect=OSError("fail")
            ),
            patch("mytools.web.http2abuse._CATEGORY_DISPATCH") as mock_dispatch,
            patch("mytools.web.http2abuse.print_results"),
        ):
            mock_dispatch.get.return_value = AsyncMock(side_effect=RuntimeError("boom"))
            result = await run_scan("https://example.com", ["h2_downgrade"], 5.0, None)
            assert result.issues == ["Errors: h2_downgrade_error"]


# ─── Create TLS Socket Tests ─────────────────────────────────────────────────


class TestCreateTlsSocket:
    def test_creates_wrapped_socket(self) -> None:
        mock_sock = MagicMock()
        mock_wrapped = MagicMock()
        mock_ctx = MagicMock()
        mock_ctx.wrap_socket.return_value = mock_wrapped
        with (
            patch(
                "mytools.web.http2abuse.socket.create_connection",
                return_value=mock_sock,
            ) as mock_cc,
            patch(
                "mytools.web.http2abuse.ssl.create_default_context",
                return_value=mock_ctx,
            ),
        ):
            result = _create_tls_socket("example.com", 443, 5.0)
        mock_cc.assert_called_once_with(("example.com", 443), timeout=5.0)
        mock_ctx.set_alpn_protocols.assert_called_once_with(["h2", "http/1.1"])
        assert result is mock_wrapped


# ─── Dispatcher Detail Tests ─────────────────────────────────────────────────


class TestDispatcherDetails:
    @pytest.mark.asyncio
    async def test_h2_downgrade_response_received(self) -> None:
        ev = h2.events.ResponseReceived(
            stream_id=1,
            headers=[(":status", "200"), ("x-custom", "1")],  # type: ignore[arg-type]
        )
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(return_value=httpx.Response(200))
        with (
            patch("mytools.web.http2abuse._create_tls_socket") as mock_tls,
            patch("mytools.web.http2abuse._create_h2_connection") as mock_h2,
            patch(
                "mytools.web.http2abuse._recv_events",
                return_value=[ev, h2.events.SettingsAcknowledged()],
            ),
            patch("mytools.web.http2abuse._drain_settings", return_value={}),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            mock_sock = MagicMock()
            mock_tls.return_value = mock_sock
            mock_sock.selected_alpn_protocol.return_value = "h2"
            mock_h2.return_value = (mock_sock, MagicMock())
            results = await _test_h2_downgrade("example.com", 443, "/", 5.0, True, {})
        http1 = [r for r in results if r.technique == "http1_on_h2"]
        connect = [r for r in results if r.technique == "connect_abuse"]
        assert http1 and "Status: 200" in http1[0].details
        assert connect and "CONNECT status: 200" in connect[0].details

    @pytest.mark.asyncio
    async def test_upgrade_h2c_error(self) -> None:
        mock_client = AsyncMock()
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)
        mock_client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))
        with (
            patch("mytools.web.http2abuse._create_tls_socket") as mock_tls,
            patch("mytools.web.http2abuse._create_h2_connection") as mock_h2,
            patch("mytools.web.http2abuse._recv_events", return_value=[]),
            patch("mytools.web.http2abuse._drain_settings", return_value={}),
            patch("httpx.AsyncClient", return_value=mock_client),
        ):
            mock_tls.return_value.selected_alpn_protocol.return_value = "h2"
            mock_h2.return_value = (MagicMock(), MagicMock())
            results = await _test_h2_downgrade("example.com", 443, "/", 5.0, True, {})
        upgrade = [r for r in results if r.technique == "upgrade_h2c"]
        assert upgrade and upgrade[0].error

    @pytest.mark.asyncio
    async def test_window_update_pattern(self) -> None:
        ev = h2.events.WindowUpdated(stream_id=1)
        ev.delta = 100
        with (
            patch("mytools.web.http2abuse._create_tls_socket") as mock_tls,
            patch("mytools.web.http2abuse._create_h2_connection") as mock_h2,
            patch("mytools.web.http2abuse._drain_settings", return_value={}),
            patch(
                "mytools.web.http2abuse._recv_events",
                return_value=[ev, h2.events.SettingsAcknowledged()],
            ),
            patch(
                "mytools.web.http2abuse.time.monotonic",
                side_effect=[0.0, 0.5, 2.0],
            ),
        ):
            mock_tls.return_value = MagicMock()
            mock_h2.return_value = (MagicMock(), MagicMock())
            results = await _test_h2_fingerprint("example.com", 443, "/", 5.0, True, {})
        wu = [r for r in results if r.technique == "window_update_pattern"]
        assert wu and "WINDOW_UPDATEs received: 1" in wu[0].details

    @pytest.mark.asyncio
    async def test_stream_abuse_inner_exceptions(self) -> None:
        with (
            patch("mytools.web.http2abuse._create_h2_connection") as mock_h2,
            patch("mytools.web.http2abuse._drain_settings", return_value={}),
        ):
            mock_conn = MagicMock()
            mock_conn.send_headers.side_effect = Exception("boom")
            mock_h2.return_value = (MagicMock(), mock_conn)
            results = await _test_h2_stream_abuse(
                "example.com", 443, "/", 5.0, True, {}
            )
        cf = [r for r in results if r.technique == "concurrent_flood"]
        ho = [r for r in results if r.technique == "half_open_streams"]
        re = [r for r in results if r.technique == "resource_exhaustion"]
        assert cf and "errors: 1" in cf[0].details
        assert ho and "Half-open streams: 0" in ho[0].details
        assert re and "Rapid cycles: 0" in re[0].details

    @pytest.mark.asyncio
    async def test_large_header_stream_status(self) -> None:
        ev = h2.events.ResponseReceived(
            stream_id=1,
            headers=[(":status", "404"), ("x-custom", "1")],  # type: ignore[arg-type]
        )
        reset = h2.events.StreamReset(stream_id=1, error_code=0, remote_reset=True)
        with (
            patch("mytools.web.http2abuse._create_h2_connection") as mock_h2,
            patch("mytools.web.http2abuse._drain_settings", return_value={}),
            patch(
                "mytools.web.http2abuse._recv_events",
                return_value=[ev, reset, h2.events.SettingsAcknowledged()],
            ),
        ):
            mock_h2.return_value = (MagicMock(), MagicMock())
            results = await _test_h2_stream_abuse(
                "example.com", 443, "/", 5.0, True, {}
            )
        lh = [r for r in results if r.technique == "large_header_stream"]
        assert lh and lh[0].vulnerable is True

    @pytest.mark.asyncio
    async def test_push_abuse_events(self) -> None:
        push = h2.events.PushedStreamReceived()
        push.pushed_stream_id = 5
        push.parent_stream_id = 1
        push.headers = []
        push_none = h2.events.PushedStreamReceived()
        push_none.pushed_stream_id = None
        push_none.parent_stream_id = 1
        push_none.headers = []
        push_headers = h2.events.PushedStreamReceived()
        push_headers.pushed_stream_id = 6
        push_headers.parent_stream_id = 1
        push_headers.headers = [  # type: ignore[assignment]
            (":path", b"/b.css"),
            (":path", "/c.css"),
            ("x-other", "1"),
        ]
        push_empty = h2.events.PushedStreamReceived()
        push_empty.pushed_stream_id = 7
        push_empty.parent_stream_id = 1
        push_empty.headers = []
        data = h2.events.DataReceived(
            stream_id=1, data=b"x" * 10, flow_controlled_length=10
        )
        ack = h2.events.SettingsAcknowledged()
        with (
            patch("mytools.web.http2abuse._create_h2_connection") as mock_h2,
            patch("mytools.web.http2abuse._drain_settings", return_value={}),
            patch(
                "mytools.web.http2abuse._recv_events",
                side_effect=[
                    [push, ack],
                    [push, push_none, ack],
                    [],
                    [push, data],
                    [],
                    [push_headers, push_empty],
                    [],
                ],
            ),
        ):
            mock_h2.return_value = (MagicMock(), MagicMock())
            results = await _test_h2_push_abuse("example.com", 443, "/", 5.0, True, {})
        rst = [r for r in results if r.technique == "rst_consumption"]
        amp = [r for r in results if r.technique == "amplification"]
        pm = [r for r in results if r.technique == "path_manipulation"]
        assert rst and rst[0].vulnerable is True
        assert amp and "data received: 10 bytes" in amp[0].details
        assert pm and "/b.css" in pm[0].details and "/c.css" in pm[0].details

    @pytest.mark.asyncio
    async def test_push_abuse_reset_stream_error(self) -> None:
        push = h2.events.PushedStreamReceived()
        push.pushed_stream_id = 5
        push.parent_stream_id = 1
        push.headers = []
        with (
            patch("mytools.web.http2abuse._create_h2_connection") as mock_h2,
            patch("mytools.web.http2abuse._drain_settings", return_value={}),
            patch(
                "mytools.web.http2abuse._recv_events",
                side_effect=[[push], [push], [], [], [], []],
            ),
        ):
            mock_conn = MagicMock()
            mock_conn.reset_stream.side_effect = Exception("boom")
            mock_h2.return_value = (MagicMock(), mock_conn)
            results = await _test_h2_push_abuse("example.com", 443, "/", 5.0, True, {})
        rst = [r for r in results if r.technique == "rst_consumption"]
        assert rst and rst[0].vulnerable is True

    @pytest.mark.asyncio
    async def test_push_abuse_send_headers_error(self) -> None:
        with (
            patch("mytools.web.http2abuse._create_h2_connection") as mock_h2,
            patch("mytools.web.http2abuse._drain_settings", return_value={}),
            patch("mytools.web.http2abuse._recv_events", return_value=[]),
        ):
            mock_conn = MagicMock()
            mock_conn.send_headers.side_effect = Exception("boom")
            mock_h2.return_value = (MagicMock(), mock_conn)
            results = await _test_h2_push_abuse("example.com", 443, "/", 5.0, True, {})
        amp = [r for r in results if r.technique == "amplification"]
        assert amp and "Pushes: 0" in amp[0].details

    @pytest.mark.asyncio
    async def test_push_loops_exit_by_timeout(self) -> None:
        with (
            patch("mytools.web.http2abuse._create_h2_connection") as mock_h2,
            patch("mytools.web.http2abuse._drain_settings", return_value={}),
            patch("mytools.web.http2abuse._recv_events", return_value=[]),
            patch(
                "mytools.web.http2abuse.time.monotonic",
                side_effect=[0.0, 5.0, 0.0, 5.0, 0.0, 5.0],
            ),
        ):
            mock_h2.return_value = (MagicMock(), MagicMock())
            results = await _test_h2_push_abuse("example.com", 443, "/", 5.0, True, {})
        assert all(r.vulnerable is False for r in results)


# ─── Collect Server Settings Detail ──────────────────────────────────────────


class TestCollectServerSettingsDetail:
    def test_other_events_ignored(self) -> None:
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"data"
        mock_conn = MagicMock()
        mock_conn.receive_data.return_value = [h2.events.SettingsAcknowledged()]
        result = _collect_server_settings(mock_sock, mock_conn, 5.0)
        assert result == {}


# ─── Print Results Secure Category ───────────────────────────────────────────


class TestPrintResultsSecureCategory:
    def test_prints_secure_for_non_vulnerable_attempts(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        attempt = HTTP2Attempt(
            technique="settings_analysis",
            category="h2_fingerprint",
            description="desc",
            h2_supported=True,
            settings_observed={},
            vulnerable=False,
            details="Server fingerprint: nginx",
            error="",
        )
        result = HTTP2Result(
            target="https://example.com",
            host="example.com",
            port=443,
            h2_supported=True,
            server_settings={},
            attempts=[attempt],
            vulnerable_techniques=[],
            issues=[],
            overall_status="secure",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "h2_fingerprint: secure" in output


# ─── run_once / main / guard ────────────────────────────────────────────────


class TestRunOnce:
    def test_vulnerable_returns_1(self) -> None:
        with (
            patch(
                "mytools.web.http2abuse.safe_asyncio_run",
                return_value=_result("vulnerable"),
            ) as mock_run,
            patch("mytools.web.http2abuse.run_scan", new_callable=MagicMock),
        ):
            assert run_once(_ns()) == 1
        mock_run.assert_called_once()

    def test_secure_returns_0(self) -> None:
        with (
            patch(
                "mytools.web.http2abuse.safe_asyncio_run",
                return_value=_result("secure"),
            ),
            patch("mytools.web.http2abuse.run_scan", new_callable=MagicMock),
        ):
            assert run_once(_ns()) == 0


class TestMain:
    def test_main(self) -> None:
        with patch("mytools.web.http2abuse.run_main_loop", return_value=0) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()


class TestMainGuard:
    def test_guard_runs(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.web.http2abuse", run_name="__main__")
