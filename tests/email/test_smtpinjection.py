#!/usr/bin/env python3
"""Testes unitarios do modulo de SMTP Header Injection."""

import asyncio
import runpy
from unittest.mock import MagicMock, patch

import pytest

from mytools.email.smtpinjection import (
    InjectionAttempt,
    InjectionResult,
    _async_run_once,
    _connect_smtp,
    _test_injection,
    banner_art,
    build_parser,
    main,
    print_results,
    run_once,
    scan_smtp_injection,
)


class TestInjectionAttempt:
    def test_frozen(self) -> None:
        a = InjectionAttempt(
            field="To",
            payload_name="crlf",
            payload="x",
            status="blocked",
            server_response="501",
            error="",
        )
        with pytest.raises(AttributeError):
            a.field = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(InjectionAttempt, "__slots__")


class TestInjectionResult:
    def test_frozen(self) -> None:
        r = InjectionResult(
            target="a",
            port=25,
            tls=False,
            banner="",
            ehlo_response="",
            attempts=[],
            vulnerable_fields=[],
            issues=[],
        )
        with pytest.raises(AttributeError):
            r.target = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(InjectionResult, "__slots__")


class TestParser:
    def test_basic(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.example.com"])
        assert args.target == "mail.example.com"

    def test_port(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.example.com", "--port", "25"])
        assert args.port == 25

    def test_from_addr(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.example.com", "--from-addr", "a@b.com"])
        assert args.from_addr == "a@b.com"

    def test_to_addr(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.example.com", "--to-addr", "x@y.com"])
        assert args.to_addr == "x@y.com"

    def test_no_tls(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.example.com", "--no-tls"])
        assert args.no_tls is True

    def test_fields(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.example.com", "--fields", "To,Subject"])
        assert args.fields == "To,Subject"

    def test_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.example.com", "--timeout", "5.0"])
        assert args.timeout == 5.0


class TestConnectSmtp:
    @patch("mytools.email.smtpinjection.smtplib.SMTP")
    def test_connect_ok(self, mock_smtp: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"Hello")
        mock_smtp.return_value = mock_server
        server, _banner, _ehlo = _connect_smtp("mail.test.com", 587, 10.0, False)
        assert server is mock_server
        mock_smtp.assert_called_once_with("mail.test.com", 587, timeout=10.0)

    @patch("mytools.email.smtpinjection.smtplib.SMTP_SSL")
    def test_connect_ssl(self, mock_smtp: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"Hello")
        mock_smtp.return_value = mock_server
        server, _banner, _ehlo = _connect_smtp("mail.test.com", 465, 10.0, False)
        assert server is mock_server
        mock_smtp.assert_called_once_with("mail.test.com", 465, timeout=10.0)

    @patch("mytools.email.smtpinjection.smtplib.SMTP")
    def test_connect_failure(self, mock_smtp: MagicMock) -> None:
        import smtplib

        mock_smtp.side_effect = smtplib.SMTPConnectError(421, b"Service unavailable")
        with pytest.raises(ConnectionError, match="Falha ao conectar"):
            _connect_smtp("bad.host", 25, 5.0, False)

    @patch("mytools.email.smtpinjection.smtplib.SMTP")
    def test_connect_os_error(self, mock_smtp: MagicMock) -> None:
        mock_smtp.side_effect = OSError("Connection refused")
        with pytest.raises(ConnectionError, match="Erro de conexao"):
            _connect_smtp("bad.host", 25, 5.0, False)

    @patch("mytools.email.smtpinjection.smtplib.SMTP")
    def test_connect_starttls(self, mock_smtp: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"Hello")
        mock_server.starttls.return_value = (220, b"Ready")
        mock_smtp.return_value = mock_server
        server, banner, ehlo = _connect_smtp("mail.test.com", 587, 10.0, True)
        assert server is mock_server
        assert "[STARTTLS]" in banner
        assert ehlo == banner

    @patch("mytools.email.smtpinjection.smtplib.SMTP")
    def test_connect_starttls_not_supported(self, mock_smtp: MagicMock) -> None:
        import smtplib

        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"Hello")
        mock_server.starttls.side_effect = smtplib.SMTPNotSupportedError()
        mock_smtp.return_value = mock_server
        server, banner, _ehlo = _connect_smtp("mail.test.com", 587, 10.0, True)
        assert server is mock_server
        assert "[STARTTLS]" not in banner

    @patch("mytools.email.smtpinjection.smtplib.SMTP")
    def test_connect_ehlo_failure(self, mock_smtp: MagicMock) -> None:
        import smtplib

        mock_server = MagicMock()
        mock_server.ehlo.side_effect = smtplib.SMTPException("EHLO failed")
        mock_smtp.return_value = mock_server
        with pytest.raises(ConnectionError, match="Falha no EHLO"):
            _connect_smtp("mail.test.com", 587, 10.0, False)
        mock_server.close.assert_called_once()


class TestTestInjection:
    def _make_server(self, sendmail_exc: Exception | None = None) -> MagicMock:
        server = MagicMock()
        server.ehlo.return_value = (250, b"EHLO")
        server.mail.return_value = (250, b"OK")
        server.rcpt.return_value = (250, b"OK")
        if sendmail_exc is not None:
            server.sendmail.side_effect = sendmail_exc
        return server

    def test_injected(self) -> None:
        server = self._make_server()
        attempt = _test_injection(
            server, "a@b.com", "x@y.com", "To", "crlf_header", "\r\nX-Injected: test"
        )
        assert attempt.status == "injected"

    def test_blocked(self) -> None:
        import smtplib

        exc = smtplib.SMTPDataError(501, b"Bad syntax")
        server = self._make_server(sendmail_exc=exc)
        attempt = _test_injection(
            server, "a@b.com", "x@y.com", "To", "crlf_header", "\r\nX-Injected: test"
        )
        assert attempt.status == "blocked"
        assert "501" in attempt.server_response

    def test_blocked_554(self) -> None:
        import smtplib

        exc = smtplib.SMTPDataError(554, b"Transaction failed")
        server = self._make_server(sendmail_exc=exc)
        attempt = _test_injection(
            server, "a@b.com", "x@y.com", "To", "crlf_header", "\r\nX-Injected: test"
        )
        assert attempt.status == "blocked"
        assert "554" in attempt.server_response

    def test_blocked_556(self) -> None:
        import smtplib

        exc = smtplib.SMTPDataError(556, b"Domain does not accept mail")
        server = self._make_server(sendmail_exc=exc)
        attempt = _test_injection(
            server, "a@b.com", "x@y.com", "To", "crlf_header", "\r\nX-Injected: test"
        )
        assert attempt.status == "blocked"
        assert "556" in attempt.server_response

    def test_smtp_exception(self) -> None:
        import smtplib

        server = self._make_server(sendmail_exc=smtplib.SMTPException("fail"))
        attempt = _test_injection(
            server, "a@b.com", "x@y.com", "Subject", "crlf_bcc", "\r\nBCC: evil@x.com"
        )
        assert attempt.status == "error"
        assert "fail" in attempt.error

    def test_os_error_timeout(self) -> None:
        server = self._make_server(sendmail_exc=OSError("timed out"))
        attempt = _test_injection(
            server, "a@b.com", "x@y.com", "To", "crlf_body", "\r\n\r\nINJECTED"
        )
        assert attempt.status == "timeout"

    def test_error_other_code(self) -> None:
        import smtplib

        exc = smtplib.SMTPDataError(451, b"Local error")
        server = self._make_server(sendmail_exc=exc)
        attempt = _test_injection(
            server, "a@b.com", "x@y.com", "To", "crlf_header", "\r\nX-Injected: test"
        )
        assert attempt.status == "error"
        assert "451" in attempt.server_response

    def test_error_bytes_message(self) -> None:
        import smtplib

        exc = smtplib.SMTPDataError(451, b"\xe9\xe3 bytes")
        server = self._make_server(sendmail_exc=exc)
        attempt = _test_injection(
            server, "a@b.com", "x@y.com", "To", "crlf_header", "\r\nX-Injected: test"
        )
        assert attempt.status == "error"


class TestScanSmtpInjection:
    @patch("mytools.email.smtpinjection._connect_smtp")
    def test_connection_failure(self, mock_connect: MagicMock) -> None:
        mock_connect.side_effect = ConnectionError("refused")
        result = scan_smtp_injection("bad.host", 25)
        assert len(result.attempts) == 0
        assert any("conexao" in i.lower() for i in result.issues)

    @patch("mytools.email.smtpinjection._test_injection")
    @patch("mytools.email.smtpinjection._connect_smtp")
    def test_all_blocked(self, mock_connect: MagicMock, mock_inject: MagicMock) -> None:
        mock_server = MagicMock()
        mock_connect.return_value = (mock_server, "banner", "ehlo")
        mock_inject.return_value = InjectionAttempt(
            field="To",
            payload_name="crlf",
            payload="x",
            status="blocked",
            server_response="501",
            error="",
        )
        result = scan_smtp_injection("safe.host", 587)
        assert len(result.vulnerable_fields) == 0
        assert "seguro" in result.issues[-1].lower()

    @patch("mytools.email.smtpinjection._test_injection")
    @patch("mytools.email.smtpinjection._connect_smtp")
    def test_some_injected(
        self, mock_connect: MagicMock, mock_inject: MagicMock
    ) -> None:
        mock_server = MagicMock()
        mock_connect.return_value = (mock_server, "banner", "ehlo")

        def side_effect(server, from_a, to_a, field, pname, payload):
            if field == "To":
                return InjectionAttempt(
                    field=field,
                    payload_name=pname,
                    payload=payload,
                    status="injected",
                    server_response="250",
                    error="",
                )
            return InjectionAttempt(
                field=field,
                payload_name=pname,
                payload=payload,
                status="blocked",
                server_response="501",
                error="",
            )

        mock_inject.side_effect = side_effect
        result = scan_smtp_injection("vuln.host", 587)
        assert "To" in result.vulnerable_fields
        assert len(result.attempts) > 0

    @patch("mytools.email.smtpinjection._connect_smtp")
    def test_dry_run_fields(self, mock_connect: MagicMock) -> None:
        mock_server = MagicMock()
        mock_server.data.return_value = (250, b"OK")
        mock_connect.return_value = (mock_server, "banner", "ehlo")
        result = scan_smtp_injection("host.com", 587, fields=["Subject"])
        assert result.port == 587

    @patch("mytools.email.smtpinjection._test_injection")
    @patch("mytools.email.smtpinjection._connect_smtp")
    def test_all_timeout(self, mock_connect: MagicMock, mock_inject: MagicMock) -> None:
        mock_server = MagicMock()
        mock_connect.return_value = (mock_server, "banner", "ehlo")
        mock_inject.return_value = InjectionAttempt(
            field="To",
            payload_name="crlf",
            payload="x",
            status="timeout",
            server_response="",
            error="timed out",
        )
        result = scan_smtp_injection("slow.host", 587)
        assert result.overall_status == "warning"
        assert any("erros/timeouts de conexao" in i for i in result.issues)


class TestPrintResults:
    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = InjectionResult(
            target="vuln.host",
            port=587,
            tls=True,
            banner="ESMTP",
            ehlo_response="250-SIZE",
            attempts=[
                InjectionAttempt(
                    "To", "crlf", "\r\nX-Injected: t", "injected", "250", ""
                )
            ],
            vulnerable_fields=["To"],
            issues=["INJECAO DETECTADA"],
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "VULNERAVEL" in out

    def test_safe(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = InjectionResult(
            target="safe.host",
            port=587,
            tls=True,
            banner="ESMTP",
            ehlo_response="250",
            attempts=[InjectionAttempt("To", "crlf", "x", "blocked", "501", "")],
            vulnerable_fields=[],
            issues=["Nenhuma injecao detectada"],
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Nenhuma injecao detectada" in out
        assert "corretamente" in out.lower()

    def test_with_errors(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = InjectionResult(
            target="err.host",
            port=587,
            tls=False,
            banner="ESMTP",
            ehlo_response="250",
            attempts=[
                InjectionAttempt("To", "crlf", "x", "error", "451", "local error"),
                InjectionAttempt("To", "crlf", "y", "timeout", "", "timed out"),
                InjectionAttempt("To", "crlf", "z", "blocked", "501", ""),
            ],
            vulnerable_fields=[],
            issues=["Nenhuma injecao detectada"],
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "Erros/Timeouts" in out
        assert "BLOQUEADO" in out

    def test_no_banner(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = InjectionResult(
            target="nb.host",
            port=587,
            tls=True,
            banner="",
            ehlo_response="250",
            attempts=[InjectionAttempt("To", "crlf", "x", "blocked", "501", "")],
            vulnerable_fields=[],
            issues=["Nenhuma injecao detectada"],
        )
        print_results(result)
        out = capsys.readouterr().out
        assert "BLOQUEADO" in out


class TestBanner:
    def test_banner_art(self, capsys: pytest.CaptureFixture[str]) -> None:
        banner_art()
        captured = capsys.readouterr()
        assert "smtp injection" in captured.out


class TestRunOnce:
    def test_run_once(self) -> None:
        args = build_parser().parse_args(["mail.test.com"])
        with (
            patch(
                "mytools.email.smtpinjection._async_run_once",
                new_callable=MagicMock,
                return_value=0,
            ),
            patch(
                "mytools.email.smtpinjection.safe_asyncio_run",
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

    def test_print_results(self) -> None:
        result = InjectionResult(
            target="mail.test.com",
            port=587,
            tls=False,
            banner="ESMTP",
            ehlo_response="250",
            attempts=[],
            vulnerable_fields=[],
            issues=["Nenhuma injecao detectada"],
        )
        args = build_parser().parse_args(["mail.test.com"])
        with patch(
            "mytools.email.smtpinjection.scan_smtp_injection",
            return_value=result,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0

    def test_output_flag(self, tmp_path) -> None:
        result = InjectionResult(
            target="mail.test.com",
            port=587,
            tls=False,
            banner="ESMTP",
            ehlo_response="250",
            attempts=[],
            vulnerable_fields=[],
            issues=["Nenhuma injecao detectada"],
        )
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(["mail.test.com", "-o", str(out_file)])
        with (
            patch(
                "mytools.email.smtpinjection.scan_smtp_injection",
                return_value=result,
            ),
            patch("mytools.email.smtpinjection.write_output") as mock_write,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0
        mock_write.assert_called_once()

    def test_quiet(self) -> None:
        result = InjectionResult(
            target="mail.test.com",
            port=587,
            tls=False,
            banner="ESMTP",
            ehlo_response="250",
            attempts=[],
            vulnerable_fields=[],
            issues=["Nenhuma injecao detectada"],
        )
        args = build_parser().parse_args(["mail.test.com", "--quiet"])
        with patch(
            "mytools.email.smtpinjection.scan_smtp_injection",
            return_value=result,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0

    def test_json_output(self) -> None:
        result = InjectionResult(
            target="mail.test.com",
            port=587,
            tls=False,
            banner="ESMTP",
            ehlo_response="250",
            attempts=[],
            vulnerable_fields=[],
            issues=["Nenhuma injecao detectada"],
        )
        args = build_parser().parse_args(["mail.test.com", "--json"])
        with (
            patch(
                "mytools.email.smtpinjection.scan_smtp_injection",
                return_value=result,
            ),
            patch("mytools.email.smtpinjection.print_json") as mock_print,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0
        mock_print.assert_called_once()


class TestMain:
    def test_main(self) -> None:
        with patch(
            "mytools.email.smtpinjection.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-smtpinject", "mail.test.com"]),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.email.smtpinjection", run_name="__main__")
