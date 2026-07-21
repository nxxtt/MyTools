"""Testes do modulo http2abuse.py — HTTP/2 Abuse."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import h2.events
import pytest

from mytools.web.http2abuse import (
    _CATEGORY_DISPATCH,
    _CATEGORY_MAP,
    HTTP2Attempt,
    HTTP2Result,
    _collect_server_settings,
    _create_h2_connection,
    _drain_settings,
    _fingerprint_server,
    _parse_url,
    _recv_events,
    build_parser,
    print_results,
    run_scan,
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
        ev.changed_settings = {h2.settings.SettingCodes.MAX_FRAME_SIZE: MagicMock(new_value=16384)}
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
        ev.changed_settings = {h2.settings.SettingCodes.HEADER_TABLE_SIZE: MagicMock(new_value=4096)}
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
    async def test_exception_returns_error(self, cat_name: str, dispatcher: object) -> None:
        with (
            patch("mytools.web.http2abuse._create_tls_socket", side_effect=OSError("fail")),
            patch("mytools.web.http2abuse._create_h2_connection", side_effect=OSError("fail")),
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
            patch("mytools.web.http2abuse._create_tls_socket", side_effect=OSError("conn refused")),
            patch("mytools.web.http2abuse._CATEGORY_DISPATCH") as mock_dispatch,
        ):
            mock_dispatch.get.return_value = AsyncMock(return_value=[])
            result = await run_scan("https://example.com", [], 5.0, None)
            assert result.h2_supported is False

    @pytest.mark.asyncio
    async def test_categories_defaults_to_all(self) -> None:
        with (
            patch("mytools.web.http2abuse._create_tls_socket", side_effect=OSError("fail")),
            patch("mytools.web.http2abuse._CATEGORY_DISPATCH") as mock_dispatch,
        ):
            mock_dispatch.get.return_value = AsyncMock(return_value=[])
            await run_scan("https://example.com", None, 5.0, None)
            assert mock_dispatch.get.call_count == 7

    @pytest.mark.asyncio
    async def test_output_file(self) -> None:
        with (
            patch("mytools.web.http2abuse._create_tls_socket", side_effect=OSError("fail")),
            patch("mytools.web.http2abuse._CATEGORY_DISPATCH") as mock_dispatch,
            patch("mytools.web.http2abuse.write_output") as mock_write,
        ):
            mock_dispatch.get.return_value = AsyncMock(return_value=[])
            await run_scan("https://example.com", [], 5.0, "output.json")
            mock_write.assert_called_once()
