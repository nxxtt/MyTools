#!/usr/bin/env python3
"""Testes unitarios do modulo de Email Address Quoting Bypass."""

import asyncio
import runpy
import smtplib
from unittest.mock import MagicMock, patch

import pytest

from mytools.email.emailaddressbypass import (
    _CATEGORY_MAP,
    AddressAttempt,
    AddressResult,
    _async_run_once,
    _build_payloads,
    _connect_smtp,
    _get_banner,
    _test_address,
    banner_art,
    build_parser,
    main,
    print_results,
    run_once,
    scan_address_bypass,
)


class TestAddressAttempt:
    def test_frozen(self) -> None:
        a = AddressAttempt(
            technique="quoted_basic",
            email_address='"user"@test.com',
            status="accepted",
            server_response="250 OK",
            error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(AddressAttempt, "__slots__")


class TestAddressResult:
    def test_frozen(self) -> None:
        r = AddressResult(
            target="mail.test.com",
            port=587,
            tls=False,
            banner="220",
            attempts=[],
            accepted_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(AddressResult, "__slots__")


class TestBuildPayloads:
    def test_all_techniques_present(self) -> None:
        payloads = _build_payloads("test.com")
        assert len(payloads) == 14
        assert "quoted_basic" in payloads
        assert "ip_literal" in payloads

    def test_domain_substituted(self) -> None:
        payloads = _build_payloads("example.com")
        assert "example.com" in payloads["quoted_basic"]
        assert payloads["quoted_basic"] == '"user"@example.com'

    def test_quoted_at_contains_at(self) -> None:
        payloads = _build_payloads("test.com")
        assert payloads["quoted_at"] == '"user@other.com"@test.com'

    def test_null_byte_in_payload(self) -> None:
        payloads = _build_payloads("test.com")
        assert "\x00" in payloads["null_byte"]

    def test_unicode_in_payload(self) -> None:
        payloads = _build_payloads("test.com")
        assert "用户" in payloads["unicode_local"]

    def test_ip_literal(self) -> None:
        payloads = _build_payloads("test.com")
        assert "[127.0.0.1]" in payloads["ip_literal"]


class TestCategoryMap:
    def test_all_categories(self) -> None:
        expected = {"quoted", "special", "encoding", "literal"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_categories_cover_all_payloads(self) -> None:
        all_named = set()
        for names in _CATEGORY_MAP.values():
            all_named.update(names)
        assert len(all_named) == 14


class TestParser:
    def test_default_port(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.test.com"])
        assert args.target == "mail.test.com"
        assert args.port == 587

    def test_custom_port(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.test.com", "--port", "25"])
        assert args.port == 25

    def test_from_addr(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.test.com", "--from-addr", "a@b.com"])
        assert args.from_addr == "a@b.com"

    def test_domain(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.test.com", "--domain", "example.com"])
        assert args.domain == "example.com"

    def test_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.test.com", "--category", "quoted"])
        assert args.category == "quoted"

    def test_all_categories(self) -> None:
        parser = build_parser()
        for cat in _CATEGORY_MAP:
            args = parser.parse_args(["mail.test.com", "--category", cat])
            assert args.category == cat

    def test_dry_run(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--dry-run", "mail.test.com"])
        assert args.dry_run is True


class TestConnectSmtp:
    @patch("mytools.email.emailaddressbypass.smtplib.SMTP")
    def test_connect_ok(self, mock_smtp: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_smtp.return_value = mock_server
        server, tls = _connect_smtp("mail.test.com", 587, 10.0)
        mock_smtp.assert_called_once_with("mail.test.com", 587, timeout=10.0)
        assert server is not None
        assert tls is False

    @patch("mytools.email.emailaddressbypass.smtplib.SMTP_SSL")
    def test_connect_ssl(self, mock_ssl: MagicMock) -> None:
        mock_server = MagicMock()
        mock_ssl.return_value = mock_server
        _server, tls = _connect_smtp("mail.test.com", 465, 10.0)
        mock_ssl.assert_called_once_with("mail.test.com", 465, timeout=10.0)
        assert tls is True

    @patch("mytools.email.emailaddressbypass.smtplib.SMTP")
    def test_connect_fail(self, mock_smtp: MagicMock) -> None:
        mock_smtp.side_effect = ConnectionError("refused")
        with pytest.raises(ConnectionError):
            _connect_smtp("bad.host", 587, 5.0)

    @patch("mytools.email.emailaddressbypass.smtplib.SMTP")
    def test_starttls_attempted(self, mock_smtp: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250-mail\n250-STARTTLS")
        mock_server.starttls.return_value = (220, b"Ready")
        mock_smtp.return_value = mock_server
        _server, _tls = _connect_smtp("mail.test.com", 587, 10.0)
        mock_server.starttls.assert_called_once()

    @patch("mytools.email.emailaddressbypass.smtplib.SMTP")
    def test_connect_smtpconnecterror(self, mock_smtp: MagicMock) -> None:
        mock_smtp.side_effect = smtplib.SMTPConnectError(421, b"refused")
        with pytest.raises(ConnectionError, match="Falha ao conectar"):
            _connect_smtp("bad.host", 587, 5.0)

    @patch("mytools.email.emailaddressbypass.smtplib.SMTP")
    def test_starttls_error_suppressed(self, mock_smtp: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250-mail\n250-STARTTLS")
        mock_server.starttls.side_effect = smtplib.SMTPException("no TLS")
        mock_smtp.return_value = mock_server
        server, tls = _connect_smtp("mail.test.com", 587, 10.0)
        assert server is not None
        assert tls is False


class TestGetBanner:
    def test_banner_ok(self) -> None:
        server = MagicMock()
        server.ehlo.return_value = (250, b"250 mail.example.com")
        assert _get_banner(server) == "250 mail.example.com"

    def test_banner_bytes(self) -> None:
        server = MagicMock()
        server.ehlo.return_value = (250, b"250-\xe9\xe3")
        result = _get_banner(server)
        assert isinstance(result, str)

    def test_banner_exception(self) -> None:
        server = MagicMock()
        server.ehlo.side_effect = smtplib.SMTPException("fail")
        assert _get_banner(server) == ""


class TestTestAddress:
    @patch("mytools.email.emailaddressbypass.smtplib.SMTP")
    def test_address_accepted(self, mock_smtp: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.rcpt.return_value = (250, b"OK")
        mock_smtp.return_value = mock_server
        accepted, details = _test_address(mock_server, "a@b.com", '"user"@b.com')
        assert accepted is True
        assert "250" in details

    @patch("mytools.email.emailaddressbypass.smtplib.SMTP")
    def test_address_rejected(self, mock_smtp: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.rcpt.return_value = (550, b"Rejected")
        mock_smtp.return_value = mock_server
        accepted, details = _test_address(mock_server, "a@b.com", '"user"@b.com')
        assert accepted is False
        assert "550" in details

    @patch("mytools.email.emailaddressbypass.smtplib.SMTP")
    def test_address_251(self, mock_smtp: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.rcpt.return_value = (251, b"User not local")
        mock_smtp.return_value = mock_server
        accepted, _details = _test_address(mock_server, "a@b.com", '"user"@b.com')
        assert accepted is True

    @patch("mytools.email.emailaddressbypass.smtplib.SMTP")
    def test_address_error(self, mock_smtp: MagicMock) -> None:
        from smtplib import SMTPResponseException

        mock_server = MagicMock()
        mock_server.rcpt.side_effect = SMTPResponseException(550, b"fail")
        mock_smtp.return_value = mock_server
        accepted, details = _test_address(mock_server, "a@b.com", '"user"@b.com')
        assert accepted is False
        assert "550" in details

    def test_address_generic_smtpexception(self) -> None:
        mock_server = MagicMock()
        mock_server.rcpt.side_effect = smtplib.SMTPException("boom")
        accepted, details = _test_address(mock_server, "a@b.com", '"user"@b.com')
        assert accepted is False
        assert details == "boom"


class TestScanAddressBypass:
    @patch("mytools.email.emailaddressbypass._connect_smtp")
    @patch("mytools.email.emailaddressbypass._test_address")
    def test_all_accepted(self, mock_test: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)
        mock_test.return_value = (True, "250 OK")

        result = scan_address_bypass("mail.test.com", 587)
        assert result.overall_status == "vulnerable"
        assert len(result.accepted_techniques) == 14

    @patch("mytools.email.emailaddressbypass._connect_smtp")
    @patch("mytools.email.emailaddressbypass._test_address")
    def test_all_rejected(self, mock_test: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)
        mock_test.return_value = (False, "550 Rejected")

        result = scan_address_bypass("mail.test.com", 587)
        assert result.overall_status == "secure"
        assert len(result.blocked_techniques) == 14

    @patch("mytools.email.emailaddressbypass._connect_smtp")
    @patch("mytools.email.emailaddressbypass._test_address")
    def test_partial_accepted(self, mock_test: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, True)

        call_count = 0

        def _side_effect(*args: object, **kwargs: object) -> tuple[bool, str]:
            nonlocal call_count
            call_count += 1
            if call_count <= 3:
                return True, "250 OK"
            return False, "550 Rejected"

        mock_test.side_effect = _side_effect
        result = scan_address_bypass("mail.test.com", 587)
        assert result.overall_status == "vulnerable"
        assert len(result.accepted_techniques) == 3

    @patch("mytools.email.emailaddressbypass._connect_smtp")
    def test_connection_failure(self, mock_conn: MagicMock) -> None:
        mock_conn.side_effect = ConnectionError("refused")
        result = scan_address_bypass("mail.test.com", 587)
        assert result.overall_status == "error"
        assert any("Falha de conexao" in i for i in result.issues)

    @patch("mytools.email.emailaddressbypass._connect_smtp")
    @patch("mytools.email.emailaddressbypass._test_address")
    def test_category_filter(self, mock_test: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)
        mock_test.return_value = (True, "250 OK")

        result = scan_address_bypass("mail.test.com", 587, category="literal")
        assert len(result.attempts) == 1
        assert result.attempts[0].technique == "ip_literal"

    @patch("mytools.email.emailaddressbypass._connect_smtp")
    @patch("mytools.email.emailaddressbypass._test_address")
    def test_tls_detected(self, mock_test: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, True)
        mock_test.return_value = (False, "550 Rejected")

        result = scan_address_bypass("mail.test.com", 587)
        assert result.tls is True

    @patch("mytools.email.emailaddressbypass._connect_smtp")
    @patch("mytools.email.emailaddressbypass._test_address")
    def test_send_error(self, mock_test: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)
        mock_test.side_effect = OSError("timeout")

        result = scan_address_bypass("mail.test.com", 587)
        assert any(a.status == "error" for a in result.attempts)

    @patch("mytools.email.emailaddressbypass._connect_smtp")
    def test_invalid_category(self, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)

        with patch(
            "mytools.email.emailaddressbypass._test_address",
            return_value=(False, "550"),
        ):
            result = scan_address_bypass("mail.test.com", 587, category="invalid")
            assert any("Categoria desconhecida" in i for i in result.issues)

    @patch("mytools.email.emailaddressbypass._connect_smtp")
    @patch("mytools.email.emailaddressbypass._test_address")
    def test_server_quitted(self, mock_test: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)
        mock_test.return_value = (False, "550 Rejected")

        scan_address_bypass("mail.test.com", 587)
        mock_server.quit.assert_called()

    @patch("mytools.email.emailaddressbypass._connect_smtp")
    @patch("mytools.email.emailaddressbypass._test_address")
    def test_result_fields(self, mock_test: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)
        mock_test.return_value = (False, "550 Rejected")

        result = scan_address_bypass("mail.test.com", 25)
        assert result.target == "mail.test.com"
        assert result.port == 25
        assert isinstance(result.banner, str)

    @patch("mytools.email.emailaddressbypass._connect_smtp")
    @patch("mytools.email.emailaddressbypass._test_address")
    def test_custom_domain(self, mock_test: MagicMock, mock_conn: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)
        mock_test.return_value = (True, "250 OK")

        result = scan_address_bypass("mail.test.com", 587, domain="custom.com")
        assert result.overall_status == "vulnerable"
        assert '"user"@custom.com' in result.attempts[0].email_address


class TestPrintResults:
    def test_print_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = AddressResult(
            target="mail.test.com",
            port=587,
            tls=False,
            banner="220",
            attempts=[
                AddressAttempt(
                    technique="quoted_basic",
                    email_address='"user"@test.com',
                    status="accepted",
                    server_response="250 OK",
                    error="",
                )
            ],
            accepted_techniques=["quoted_basic"],
            blocked_techniques=[],
            issues=["1/14 enderecos citados aceitos"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "VULNERAVEL" in captured.out

    def test_print_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = AddressResult(
            target="mail.test.com",
            port=587,
            tls=True,
            banner="220",
            attempts=[
                AddressAttempt(
                    technique="quoted_basic",
                    email_address='"user"@test.com',
                    status="rejected",
                    server_response="550 Rejected",
                    error="",
                )
            ],
            accepted_techniques=[],
            blocked_techniques=["quoted_basic"],
            issues=["Todos os enderecos citados bloqueados"],
            overall_status="secure",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "seguro" in captured.out

    def test_print_error(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = AddressResult(
            target="mail.test.com",
            port=587,
            tls=False,
            banner="",
            attempts=[],
            accepted_techniques=[],
            blocked_techniques=[],
            issues=["Falha de conexao"],
            overall_status="error",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "ERROR" in captured.out

    def test_print_with_errors(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = AddressResult(
            target="mail.test.com",
            port=587,
            tls=False,
            banner="220",
            attempts=[
                AddressAttempt(
                    technique="quoted_at",
                    email_address='"user@other.com"@test.com',
                    status="error",
                    server_response="",
                    error="timeout",
                )
            ],
            accepted_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="warning",
        )
        print_results(result)
        captured = capsys.readouterr()
        assert "timeout" in captured.out


class TestScanWarning:
    @patch("mytools.email.emailaddressbypass._connect_smtp")
    def test_warning_no_attempts(
        self, mock_conn: MagicMock, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"250 OK")
        mock_conn.return_value = (mock_server, False)

        with patch("mytools.email.emailaddressbypass._build_payloads", return_value={}):
            result = scan_address_bypass("mail.test.com", 587)
        assert result.overall_status == "warning"
        assert any("inconclusivo" in i for i in result.issues)
        assert result.attempts == []
        assert result.tool == "swaks"
        assert result.exploit == ""


class TestBanner:
    def test_banner_art(self, capsys: pytest.CaptureFixture[str]) -> None:
        banner_art()
        captured = capsys.readouterr()
        assert "address bypass" in captured.out


class TestRunOnce:
    def test_run_once(self) -> None:
        args = build_parser().parse_args(["mail.test.com"])
        with (
            patch(
                "mytools.email.emailaddressbypass._async_run_once",
                new_callable=MagicMock,
                return_value=0,
            ),
            patch(
                "mytools.email.emailaddressbypass.safe_asyncio_run",
                new_callable=MagicMock,
            ) as mock_safe,
        ):
            mock_safe.return_value = 0
            result = run_once(args)
            assert result == 0
        mock_safe.assert_called_once()


class TestAsyncRunOnce:
    def test_no_target(self) -> None:
        args = build_parser().parse_args([])
        result = asyncio.run(_async_run_once(args))
        assert result == 1

    def test_dry_run(self) -> None:
        args = build_parser().parse_args(["mail.test.com", "--dry-run"])
        result = asyncio.run(_async_run_once(args))
        assert result == 0

    def test_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = AddressResult(
            target="mail.test.com",
            port=587,
            tls=False,
            banner="220",
            attempts=[],
            accepted_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="warning",
        )
        args = build_parser().parse_args(["mail.test.com", "--json"])
        with patch(
            "mytools.email.emailaddressbypass.scan_address_bypass",
            return_value=result,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0
        import json

        data = json.loads(capsys.readouterr().out)
        assert data["target"] == "mail.test.com"

    def test_print_results(self) -> None:
        result = AddressResult(
            target="mail.test.com",
            port=587,
            tls=False,
            banner="220",
            attempts=[],
            accepted_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="warning",
        )
        args = build_parser().parse_args(["mail.test.com"])
        with patch(
            "mytools.email.emailaddressbypass.scan_address_bypass",
            return_value=result,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0

    def test_output_flag(self, tmp_path) -> None:
        result = AddressResult(
            target="mail.test.com",
            port=587,
            tls=False,
            banner="220",
            attempts=[],
            accepted_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="warning",
        )
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(["mail.test.com", "-o", str(out_file)])
        with (
            patch(
                "mytools.email.emailaddressbypass.scan_address_bypass",
                return_value=result,
            ),
            patch("mytools.email.emailaddressbypass.write_output") as mock_write,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0
        mock_write.assert_called_once()

    def test_quiet(self) -> None:
        result = AddressResult(
            target="mail.test.com",
            port=587,
            tls=False,
            banner="220",
            attempts=[],
            accepted_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="warning",
        )
        args = build_parser().parse_args(["mail.test.com", "--quiet"])
        with patch(
            "mytools.email.emailaddressbypass.scan_address_bypass",
            return_value=result,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0


class TestMain:
    def test_main(self) -> None:
        with patch(
            "mytools.email.emailaddressbypass.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-addrbypass", "mail.test.com"]),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.email.emailaddressbypass", run_name="__main__")
