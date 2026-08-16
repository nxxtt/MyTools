import argparse
import socket
from unittest.mock import MagicMock, patch

import pytest

from mytools.network.portscanner import (
    BANNER_PROBES,
    DEFAULT_PORTS,
    TOP_100_PORTS,
    Finding,
    _create_connection,
    build_parser,
    grab_banner,
    ip_sort_key,
    parse_ports,
    print_port_table,
    resolve_targets,
    run_once,
    scan_port,
    scan_targets,
    service_name,
)


class TestParsePorts:
    def test_default_returns_default_ports(self):
        assert parse_ports("default") == sorted(DEFAULT_PORTS)

    def test_top100_returns_top100_ports(self):
        assert parse_ports("top100") == sorted(TOP_100_PORTS)

    def test_all_returns_full_range(self):
        result = parse_ports("all")
        assert result == list(range(1, 65536))

    def test_single_port(self):
        assert parse_ports("80") == [80]

    def test_comma_separated(self):
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_range(self):
        assert parse_ports("80-83") == [80, 81, 82, 83]

    def test_reversed_range(self):
        assert parse_ports("83-80") == [80, 81, 82, 83]

    def test_mixed(self):
        result = parse_ports("22,80-82,443")
        assert result == [22, 80, 81, 82, 443]

    def test_deduplication(self):
        assert parse_ports("80,80,80") == [80]

    def test_invalid_port_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_ports("0")

    def test_empty_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_ports("")

    def test_non_numeric_raises(self):
        with pytest.raises(argparse.ArgumentTypeError) as exc_info:
            parse_ports("abc")
        assert "abc" in str(exc_info.value)

    def test_non_numeric_in_range_raises(self):
        with pytest.raises(argparse.ArgumentTypeError) as exc_info:
            parse_ports("abc-100")
        assert "abc-100" in str(exc_info.value)

    def test_mixed_valid_invalid_raises(self):
        with pytest.raises(argparse.ArgumentTypeError):
            parse_ports("80,abc,443")

    def test_trailing_comma(self):
        assert parse_ports("80,443,") == [80, 443]

    def test_whitespace_parts(self):
        assert parse_ports(" 80 , 443 ") == [80, 443]

    def test_large_port(self):
        assert parse_ports("65535") == [65535]

    def test_port_boundary_one(self):
        assert parse_ports("1") == [1]

    def test_overlapping_ranges(self):
        result = parse_ports("80-82,81-83")
        assert result == [80, 81, 82, 83]


class TestIpSortKey:
    def test_ipv4_returns_zero_version(self):
        key = ip_sort_key("192.168.0.1")
        assert key[0] == 0

    def test_ipv6_returns_one_version(self):
        key = ip_sort_key("::1")
        assert key[0] == 1

    def test_hostname_returns_two_version(self):
        key = ip_sort_key("example.com")
        assert key[0] == 2

    def test_ipv4_before_ipv6(self):
        assert ip_sort_key("10.0.0.1") < ip_sort_key("::1")

    def test_ipv4_ordering(self):
        assert ip_sort_key("10.0.0.1") < ip_sort_key("192.168.0.1")

    def test_ipv4_all_zeros(self):
        key = ip_sort_key("0.0.0.0")
        assert key[0] == 0
        assert key[2] == "00000000"


class TestBannerProbes:
    def test_contains_expected_ports(self):
        assert 80 in BANNER_PROBES
        assert 8080 in BANNER_PROBES
        assert 8000 in BANNER_PROBES
        assert 8443 not in BANNER_PROBES

    def test_probes_are_bytes(self):
        for probe in BANNER_PROBES.values():
            assert isinstance(probe, bytes)
            assert b"HEAD" in probe


class TestFindingDataclass:
    def test_creation(self):
        f = Finding(
            host="localhost", address="127.0.0.1", port=80, state="open", service="http"
        )
        assert f.host == "localhost"
        assert f.port == 80
        assert f.banner == ""

    def test_frozen(self):
        f = Finding(
            host="localhost", address="127.0.0.1", port=80, state="open", service="http"
        )
        with pytest.raises(AttributeError):
            f.port = 443  # type: ignore[reportAttributeAccessIssue]


@pytest.mark.smoke
class TestBuildParser:
    def test_returns_argparse(self):
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_has_targets_argument(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1"])
        assert args.targets == ["127.0.0.1"]

    def test_has_ports_argument(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-p", "80,443"])
        assert args.ports == [80, 443]

    def test_has_banner_flag(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-b"])
        assert args.banner is True

    def test_default_timeout(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1"])
        assert args.timeout == 0.5

    def test_has_verbose_argument(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-v"])
        assert args.verbose is True

    def test_default_verbose_false(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1"])
        assert args.verbose is False

    def test_has_log_file_argument(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "--log-file", "scan.log"])
        assert args.log_file == "scan.log"


@pytest.mark.smoke
class TestBuildParserV3:
    def test_has_list_argument(self):
        parser = build_parser()
        args = parser.parse_args(["-l", "targets.txt"])
        assert args.target_list == "targets.txt"

    def test_has_quiet_flag(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-q"])
        assert args.quiet is True

    def test_default_quiet_false(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1"])
        assert args.quiet is False

    def test_has_threads_alias(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "--threads", "100"])
        assert args.threads == 100

    def test_default_threads_none(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1"])
        assert args.threads is None

    def test_default_workers(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1"])
        assert args.workers == 100


class TestResolveTargetsIPv6:
    def test_ipv4_single(self):
        targets = resolve_targets(["192.168.0.1"])
        assert len(targets) == 1
        assert targets[0][1] == "192.168.0.1"

    def test_ipv6_loopback(self):
        targets = resolve_targets(["::1"])
        assert len(targets) == 1
        assert targets[0][1] == "::1"

    def test_ipv6_full(self):
        targets = resolve_targets(["2001:db8::1"])
        assert len(targets) == 1
        assert targets[0][1] == "2001:db8::1"

    def test_ipv6_cidr(self):
        targets = resolve_targets(["::1/128"])
        assert len(targets) == 1

    def test_ipv4_cidr(self):
        targets = resolve_targets(["192.168.0.0/30"])
        assert len(targets) == 2

    def test_mixed_ipv4_ipv6(self):
        targets = resolve_targets(["192.168.0.1", "::1"])
        assert len(targets) == 2
        addresses = {t[1] for t in targets}
        assert "192.168.0.1" in addresses
        assert "::1" in addresses

    def test_hostname_resolves(self):
        targets = resolve_targets(["localhost"])
        assert len(targets) >= 1

    def test_empty_string_skipped(self):
        targets = resolve_targets(["", "  ", "192.168.0.1"])
        assert len(targets) == 1

    def test_invalid_raises(self):
        import pytest

        with pytest.raises(ValueError, match="nenhum alvo"):
            resolve_targets([])

    def test_unresolvable_hostname_raises(self):
        import pytest

        with pytest.raises(ValueError, match="nao consegui resolver"):
            resolve_targets(["thishostdoesnotexist.invalid"])

    def test_hostname_duplicate_addresses_deduped(self):
        with patch(
            "mytools.network.portscanner.socket.getaddrinfo",
            return_value=[
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.1", 0)),
            ],
        ):
            targets = resolve_targets(["example.com"])
        assert len(targets) == 1
        assert targets[0] == ("example.com", "192.0.2.1")

    def test_overlapping_network_targets_deduped(self):
        targets = resolve_targets(["127.0.0.1", "127.0.0.1/32"])
        assert len(targets) == 1
        assert targets[0] == ("127.0.0.1", "127.0.0.1")


class TestCreateConnection:
    @patch("mytools.network.portscanner.socket.socket")
    def test_ipv4_connection_refused(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError("refused")
        mock_socket_cls.return_value = mock_sock
        with pytest.raises(ConnectionRefusedError):
            _create_connection("192.0.2.1", 1, 0.1)
        mock_sock.close.assert_called_once()

    @patch("mytools.network.portscanner.socket.socket")
    def test_ipv6_connection_refused(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_sock.connect.side_effect = ConnectionRefusedError("refused")
        mock_socket_cls.return_value = mock_sock
        with pytest.raises(ConnectionRefusedError):
            _create_connection("::1", 1, 0.1)
        mock_sock.close.assert_called_once()


class TestDryRun:
    def test_dry_run_flag_exists_in_parser(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "--dry-run"])
        assert args.dry_run is True

    def test_dry_run_default_false(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1"])
        assert args.dry_run is False

    def test_dry_run_returns_zero(self, capsys):
        from mytools.network.portscanner import run_once

        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-p", "80", "--dry-run"])
        result = run_once(args)
        assert result == 0

    def test_dry_run_outputs_info(self, caplog):
        from mytools.network.portscanner import run_once

        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-p", "22,80", "--dry-run"])
        with caplog.at_level("WARNING", logger="mytools.portscanner"):
            run_once(args)
        assert any("Nenhuma conexao" in r.message for r in caplog.records)


class TestMain:
    @patch("mytools.core.utils.run_interactive_shell")
    def test_no_target_shells_interactive(self, mock_shell):
        mock_shell.return_value = 0
        from mytools.network.portscanner import main

        args = argparse.Namespace(
            targets=None,
            target_list=None,
            quiet=False,
            output=None,
            verbose=False,
            color=None,
            log_file=None,
            timeout=0.5,
            ports=[80],
            workers=100,
            threads=None,
            banner=False,
            dry_run=False,
            retries=3,
        )
        with patch(
            "mytools.network.portscanner.argparse.ArgumentParser.parse_args",
            return_value=args,
        ):
            result = main()
            assert result == 0
            mock_shell.assert_called_once()

    def test_quiet_without_output_returns_1(self):
        from mytools.network.portscanner import main

        args = argparse.Namespace(
            targets=["127.0.0.1"],
            target_list=None,
            quiet=True,
            output=None,
            verbose=False,
            color=None,
            log_file=None,
            timeout=0.5,
            ports=[80],
            workers=100,
            threads=None,
            banner=False,
            dry_run=False,
            retries=3,
        )
        with patch(
            "mytools.network.portscanner.argparse.ArgumentParser.parse_args",
            return_value=args,
        ):
            result = main()
            assert result == 1

    @patch("mytools.network.portscanner.run_once")
    def test_valid_target_calls_run_once(self, mock_run_once):
        mock_run_once.return_value = 0
        from mytools.network.portscanner import main

        args = argparse.Namespace(
            targets=["127.0.0.1"],
            target_list=None,
            quiet=False,
            output=None,
            verbose=False,
            color=None,
            log_file=None,
            timeout=0.5,
            ports=[80],
            workers=100,
            threads=None,
            banner=False,
            dry_run=False,
            retries=3,
        )
        with patch(
            "mytools.network.portscanner.argparse.ArgumentParser.parse_args",
            return_value=args,
        ):
            result = main()
            assert result == 0
            mock_run_once.assert_called_once()

    @patch("mytools.network.portscanner.run_once")
    def test_exception_returns_1(self, mock_run_once):
        mock_run_once.side_effect = RuntimeError("fail")
        from mytools.network.portscanner import main

        args = argparse.Namespace(
            targets=["127.0.0.1"],
            target_list=None,
            quiet=False,
            output=None,
            verbose=False,
            color=None,
            log_file=None,
            timeout=0.5,
            ports=[80],
            workers=100,
            threads=None,
            banner=False,
            dry_run=False,
            retries=3,
        )
        with patch(
            "mytools.network.portscanner.argparse.ArgumentParser.parse_args",
            return_value=args,
        ):
            result = main()
            assert result == 1


class TestServiceName:
    @patch("mytools.network.portscanner.socket.getservbyport", return_value="http")
    def test_known_port(self, mock_get):
        assert service_name(80) == "http"
        mock_get.assert_called_once_with(80, "tcp")

    @patch(
        "mytools.network.portscanner.socket.getservbyport",
        side_effect=OSError("no service"),
    )
    def test_unknown_port(self, mock_get):
        assert service_name(59999) == "unknown"


class TestGrabBanner:
    def test_http_probe_sends_head(self):
        sock = MagicMock()
        sock.recv.return_value = b"HTTP/1.1 200 OK\r\n\r\n"
        result = grab_banner(sock, 80, 1.0)
        assert result == "HTTP/1.1 200 OK"
        sock.sendall.assert_called_once_with(BANNER_PROBES[80])
        sock.settimeout.assert_called_once_with(1.0)

    def test_no_probe_still_reads(self):
        sock = MagicMock()
        sock.recv.return_value = b"SSH-2.0-OpenSSH\r\n"
        result = grab_banner(sock, 22, 1.0)
        assert result == "SSH-2.0-OpenSSH"
        sock.sendall.assert_not_called()

    def test_oserror_returns_empty(self):
        sock = MagicMock()
        sock.recv.side_effect = OSError("timeout")
        assert grab_banner(sock, 80, 1.0) == ""


class TestCreateConnectionSuccess:
    @patch("mytools.network.portscanner.socket.socket")
    def test_ipv4_success(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        result = _create_connection("192.0.2.1", 80, 0.5)
        assert result is mock_sock
        mock_sock.connect.assert_called_once_with(("192.0.2.1", 80))
        mock_sock.settimeout.assert_called_once_with(0.5)

    @patch("mytools.network.portscanner.socket.socket")
    def test_ipv6_success(self, mock_socket_cls):
        mock_sock = MagicMock()
        mock_socket_cls.return_value = mock_sock
        result = _create_connection("2001:db8::1", 443, 0.5)
        assert result is mock_sock
        mock_sock.connect.assert_called_once_with(("2001:db8::1", 443))


class TestScanPort:
    @patch("mytools.network.portscanner.service_name", return_value="http")
    @patch("mytools.network.portscanner.grab_banner", return_value="HTTP banner")
    @patch("mytools.network.portscanner._create_connection")
    def test_open_with_banner(self, mock_conn, mock_banner, mock_service):
        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock
        mock_conn.return_value = mock_sock
        result = scan_port("host", "192.0.2.1", 80, 0.5, True)
        assert result is not None
        assert result.state == "open"
        assert result.service == "http"
        assert result.banner == "HTTP banner"
        mock_banner.assert_called_once_with(mock_sock, 80, 0.5)

    @patch("mytools.network.portscanner.service_name", return_value="ssh")
    @patch("mytools.network.portscanner._create_connection")
    def test_open_without_banner(self, mock_conn, mock_service):
        mock_sock = MagicMock()
        mock_sock.__enter__.return_value = mock_sock
        mock_conn.return_value = mock_sock
        result = scan_port("host", "192.0.2.1", 22, 0.5, False)
        assert result is not None
        assert result.banner == ""

    @patch("mytools.network.portscanner._create_connection")
    def test_connection_refused_returns_none(self, mock_conn):
        mock_conn.side_effect = ConnectionRefusedError("refused")
        assert scan_port("h", "192.0.2.1", 22, 0.5, False) is None

    @patch("mytools.network.portscanner._create_connection")
    def test_timeout_returns_none(self, mock_conn):
        mock_conn.side_effect = TimeoutError("timed out")
        assert scan_port("h", "192.0.2.1", 22, 0.5, False) is None

    @patch("mytools.network.portscanner._create_connection")
    def test_oserror_returns_none(self, mock_conn):
        mock_conn.side_effect = OSError("network unreachable")
        assert scan_port("h", "192.0.2.1", 22, 0.5, False) is None


class TestScanTargets:
    def _finding(self, port: int) -> Finding:
        return Finding(
            host="192.0.2.1",
            address="192.0.2.1",
            port=port,
            state="open",
            service="http",
        )

    def test_scans_all_ports(self):
        with patch(
            "mytools.network.portscanner.scan_port",
            side_effect=[self._finding(80), self._finding(443)],
        ):
            findings = scan_targets(
                [("192.0.2.1", "192.0.2.1")], [80, 443], 0.5, 1, False
            )
        assert len(findings) == 2
        assert {f.port for f in findings} == {80, 443}

    def test_flushes_in_batches(self):
        with patch(
            "mytools.network.portscanner.scan_port",
            side_effect=[self._finding(80), self._finding(443), self._finding(8080)],
        ):
            findings = scan_targets(
                [("192.0.2.1", "192.0.2.1")], [80, 443, 8080], 0.5, 1, False
            )
        assert len(findings) == 3

    def test_exception_in_future_logs_warning(self, caplog):
        f = self._finding(443)
        with (
            patch(
                "mytools.network.portscanner.scan_port",
                side_effect=[RuntimeError("boom"), f],
            ),
            caplog.at_level("WARNING", logger="mytools.portscanner"),
        ):
            findings = scan_targets(
                [("192.0.2.1", "192.0.2.1")], [80, 443], 0.5, 1, False
            )
        assert findings == [f]
        assert any("erro no scan_port" in r.message for r in caplog.records)


class TestPrintPortTable:
    def test_empty_message(self, capsys):
        print_port_table([])
        assert "Nenhuma porta aberta" in capsys.readouterr().out

    def test_with_findings(self, capsys):
        f = Finding(
            host="host", address="192.0.2.1", port=80, state="open", service="http"
        )
        print_port_table([f])
        out = capsys.readouterr().out
        assert "192.0.2.1" in out
        assert "http" in out


class TestRunOnce:
    def test_timeout_zero_raises(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "--timeout", "0"])
        with pytest.raises(ValueError, match="timeout"):
            run_once(args)

    def test_workers_zero_raises(self):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "--workers", "0"])
        with pytest.raises(ValueError, match="workers"):
            run_once(args)

    def test_no_targets_raises(self):
        parser = build_parser()
        args = parser.parse_args(["-p", "80"])
        with pytest.raises(ValueError, match="alvo"):
            run_once(args)

    def test_target_list_used(self, tmp_path):
        lst = tmp_path / "targets.txt"
        lst.write_text("127.0.0.1\n")
        parser = build_parser()
        args = parser.parse_args(["-l", str(lst), "-p", "80", "--dry-run"])
        assert run_once(args) == 0

    @pytest.mark.filterwarnings("ignore:.*deprecated.*:DeprecationWarning")
    def test_threads_deprecated(self, caplog):
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-p", "80", "--threads", "5"])
        with caplog.at_level("WARNING", logger="mytools.portscanner"):
            result = run_once(args)
        assert result == 0
        assert args.workers == 5
        assert any("deprecated" in r.message for r in caplog.records)

    def test_full_scan_prints_table(self, capsys):
        f = Finding(
            host="127.0.0.1",
            address="127.0.0.1",
            port=80,
            state="open",
            service="http",
        )
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-p", "80"])
        with patch("mytools.network.portscanner.scan_targets", return_value=[f]):
            assert run_once(args) == 0
        assert "127.0.0.1" in capsys.readouterr().out

    def test_json_output(self, capsys):
        f = Finding(
            host="127.0.0.1",
            address="127.0.0.1",
            port=80,
            state="open",
            service="http",
        )
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-p", "80", "--json"])
        with patch("mytools.network.portscanner.scan_targets", return_value=[f]):
            assert run_once(args) == 0
        assert '"port": 80' in capsys.readouterr().out

    def test_quiet_no_table_no_output(self, capsys):
        f = Finding(
            host="127.0.0.1",
            address="127.0.0.1",
            port=80,
            state="open",
            service="http",
        )
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-p", "80", "--quiet"])
        with patch("mytools.network.portscanner.scan_targets", return_value=[f]):
            assert run_once(args) == 0
        assert capsys.readouterr().out == ""

    def test_output_file(self, tmp_path):
        f = Finding(
            host="127.0.0.1",
            address="127.0.0.1",
            port=80,
            state="open",
            service="http",
        )
        out = tmp_path / "out.json"
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-p", "80", "-o", str(out)])
        with (
            patch("mytools.network.portscanner.scan_targets", return_value=[f]),
            patch("mytools.network.portscanner.write_output") as mock_write,
        ):
            assert run_once(args) == 0
        assert mock_write.call_count == 1

    def test_json_with_output_writes_file(self, capsys, tmp_path):
        f = Finding(
            host="127.0.0.1",
            address="127.0.0.1",
            port=80,
            state="open",
            service="http",
        )
        out = tmp_path / "out.json"
        parser = build_parser()
        args = parser.parse_args(["127.0.0.1", "-p", "80", "--json", "-o", str(out)])
        with (
            patch("mytools.network.portscanner.scan_targets", return_value=[f]),
            patch("mytools.network.portscanner.write_output") as mock_write,
        ):
            assert run_once(args) == 0
        assert mock_write.call_count == 1
        assert '"port": 80' in capsys.readouterr().out


class TestMainValidate:
    def test_validate_no_targets_raises(self):
        from mytools.network.portscanner import main

        args = argparse.Namespace(targets=[], target_list=None)

        def _fake_loop(**kwargs):
            kwargs["validate_fn"](args)
            return 0

        with (
            patch(
                "mytools.network.portscanner.argparse.ArgumentParser.parse_args",
                return_value=args,
            ),
            patch("mytools.network.portscanner.run_main_loop", side_effect=_fake_loop),
            pytest.raises(ValueError, match="pelo menos um alvo"),
        ):
            main()

    def test_validate_with_targets_passes(self):
        from mytools.network.portscanner import main

        args = argparse.Namespace(targets=["127.0.0.1"], target_list=None)

        def _fake_loop(**kwargs):
            kwargs["validate_fn"](args)
            return 0

        with (
            patch(
                "mytools.network.portscanner.argparse.ArgumentParser.parse_args",
                return_value=args,
            ),
            patch("mytools.network.portscanner.run_main_loop", side_effect=_fake_loop),
        ):
            assert main() == 0


class TestMainGuard:
    def test_main_guard(self):
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-port"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.network.portscanner", run_name="__main__")
        assert exc_info.value.code == 0
