#!/usr/bin/env python3
"""Testes unitarios do modulo de SMTP Downgrade Attack."""

import asyncio
import runpy
from unittest.mock import MagicMock, patch

import pytest

from mytools.email import smtpdowngrade
from mytools.email.smtpdowngrade import (
    DowngradeResult,
    DowngradeTest,
    _async_run_once,
    _check_starttls,
    _connect_smtp,
    _get_banner,
    _test_helo_downgrade,
    _test_plaintext_mail,
    banner_art,
    build_parser,
    main,
    print_results,
    run_once,
    scan_smtp_downgrade,
)


class TestDowngradeTest:
    def test_frozen(self) -> None:
        t = DowngradeTest(name="test", status="pass", description="desc", details="det")
        with pytest.raises(AttributeError):
            t.name = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(DowngradeTest, "__slots__")


class TestDowngradeResult:
    def test_frozen(self) -> None:
        r = DowngradeResult(
            target="mail.test.com",
            port=587,
            banner="220 mail ESMTP",
            ehlo_advertises_starttls=True,
            supports_starttls=True,
            requires_starttls=True,
            plaintext_accepted=False,
            helo_downgrade_accepted=False,
            auth_without_tls=False,
            tests=[],
            issues=[],
            overall_status="secure",
        )
        with pytest.raises(AttributeError):
            r.target = "x"  # type: ignore[misc]

    def test_slots(self) -> None:
        assert hasattr(DowngradeResult, "__slots__")


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

    def test_to_addr(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["mail.test.com", "--to-addr", "c@d.com"])
        assert args.to_addr == "c@d.com"

    def test_dry_run(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["--dry-run", "mail.test.com"])
        assert args.dry_run is True

    def test_timeout(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["-t", "30", "mail.test.com"])
        assert args.timeout == 30.0


class TestConnectSmtp:
    @patch("mytools.email.smtpdowngrade.smtplib.SMTP")
    def test_connect_ok(self, mock_smtp: MagicMock) -> None:
        mock_smtp.return_value = MagicMock()
        result = _connect_smtp("mail.test.com", 587, 10.0)
        mock_smtp.assert_called_once_with("mail.test.com", 587, timeout=10.0)
        assert result is not None

    @patch("mytools.email.smtpdowngrade.smtplib.SMTP")
    def test_connect_error(self, mock_smtp: MagicMock) -> None:
        mock_smtp.side_effect = smtpdowngrade.smtplib.SMTPConnectError(421, b"unavail")
        with pytest.raises(ConnectionError):
            _connect_smtp("mail.test.com", 587, 10.0)

    @patch("mytools.email.smtpdowngrade.smtplib.SMTP")
    def test_connect_os_error(self, mock_smtp: MagicMock) -> None:
        mock_smtp.side_effect = OSError("timeout")
        with pytest.raises(ConnectionError):
            _connect_smtp("mail.test.com", 587, 10.0)


class TestGetBanner:
    def test_ok(self) -> None:
        server = MagicMock()
        server.ehlo.return_value = (250, b"220 mail ESMTP")
        result = _get_banner(server)
        assert "220 mail ESMTP" in result

    def test_smtp_exception(self) -> None:
        server = MagicMock()
        server.ehlo.side_effect = smtpdowngrade.smtplib.SMTPException("fail")
        result = _get_banner(server)
        assert result == ""

    def test_os_error(self) -> None:
        server = MagicMock()
        server.ehlo.side_effect = OSError("timeout")
        result = _get_banner(server)
        assert result == ""


class TestCheckStarttls:
    def test_ok(self) -> None:
        server = MagicMock()
        server.starttls.return_value = (220, b"Ready")
        result = _check_starttls(server)
        assert result is True

    def test_not_supported(self) -> None:
        server = MagicMock()
        server.starttls.side_effect = smtpdowngrade.smtplib.SMTPNotSupportedError()
        result = _check_starttls(server)
        assert result is False

    def test_smtp_exception(self) -> None:
        server = MagicMock()
        server.starttls.side_effect = smtpdowngrade.smtplib.SMTPException("fail")
        result = _check_starttls(server)
        assert result is False


class TestTestPlaintextMail:
    def test_accepted(self) -> None:
        server = MagicMock()
        server.ehlo.return_value = (250, b"OK")
        server.mail.return_value = (250, b"OK")
        server.rcpt.return_value = (250, b"OK")
        accepted, details = _test_plaintext_mail(server, "a@b.com", "c@d.com")
        assert accepted is True
        assert "250" in details

    def test_rejected(self) -> None:
        server = MagicMock()
        server.ehlo.side_effect = smtpdowngrade.smtplib.SMTPResponseException(
            530, b"Auth required"
        )
        accepted, _details = _test_plaintext_mail(server, "a@b.com", "c@d.com")
        assert accepted is False

    def test_smtp_exception(self) -> None:
        server = MagicMock()
        server.mail.side_effect = smtpdowngrade.smtplib.SMTPException("boom")
        accepted, details = _test_plaintext_mail(server, "a@b.com", "c@d.com")
        assert accepted is False
        assert details == "boom"

    def test_partial_accepted(self) -> None:
        server = MagicMock()
        server.ehlo.return_value = (250, b"OK")
        server.mail.return_value = (250, b"OK")
        server.rcpt.return_value = (550, b"Rejected")
        accepted, details = _test_plaintext_mail(server, "a@b.com", "c@d.com")
        assert accepted is False
        assert "RCPT TO=550" in details

    def test_os_error(self) -> None:
        server = MagicMock()
        server.ehlo.return_value = (250, b"OK")
        server.mail.side_effect = OSError("timeout")
        accepted, details = _test_plaintext_mail(server, "a@b.com", "c@d.com")
        assert accepted is False
        assert details == "timeout"


class TestTestHeloDowngrade:
    @patch("mytools.email.smtpdowngrade.smtplib.SMTP")
    def test_accepted(self, mock_smtp: MagicMock) -> None:
        mock_inst = MagicMock()
        mock_inst.helo.return_value = (250, b"Hello")
        mock_inst.quit.return_value = None
        mock_smtp.return_value = mock_inst
        ok, _details = _test_helo_downgrade("mail.test.com", 587, 10.0)
        assert ok is True

    @patch("mytools.email.smtpdowngrade.smtplib.SMTP")
    def test_rejected(self, mock_smtp: MagicMock) -> None:
        mock_inst = MagicMock()
        mock_inst.helo.side_effect = smtpdowngrade.smtplib.SMTPException("fail")
        mock_inst.quit.return_value = None
        mock_smtp.return_value = mock_inst
        ok, _details = _test_helo_downgrade("mail.test.com", 587, 10.0)
        assert ok is False


class TestScanSmtpDowngrade:
    def test_connection_failure(self) -> None:
        with patch(
            "mytools.email.smtpdowngrade._connect_smtp",
            side_effect=ConnectionError("refused"),
        ):
            result = scan_smtp_downgrade("mail.test.com", 587)
            assert result.overall_status == "error"
            assert result.issues

    def test_secure_server(self) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"220 mail\nSTARTTLS")
        mock_server.starttls.return_value = (220, b"Ready")
        mock_server.mail.return_value = (530, b"Auth required")
        mock_server.rcpt.return_value = (530, b"Auth required")
        mock_server.docmd.side_effect = smtpdowngrade.smtplib.SMTPException("fail")

        with (
            patch(
                "mytools.email.smtpdowngrade._connect_smtp", return_value=mock_server
            ),
            patch(
                "mytools.email.smtpdowngrade._get_banner",
                return_value="220 mail\nSTARTTLS",
            ),
            patch("mytools.email.smtpdowngrade._check_starttls", return_value=True),
            patch(
                "mytools.email.smtpdowngrade._test_plaintext_mail",
                return_value=(False, "530"),
            ),
            patch(
                "mytools.email.smtpdowngrade._test_helo_downgrade",
                return_value=(False, "fail"),
            ),
        ):
            result = scan_smtp_downgrade("mail.test.com", 587)
            assert result.overall_status == "secure"
            assert result.ehlo_advertises_starttls is True

    def test_vulnerable_server(self) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"220 mail\nSTARTTLS")
        mock_server.starttls.return_value = (220, b"Ready")
        mock_server.mail.return_value = (250, b"OK")
        mock_server.rcpt.return_value = (250, b"OK")
        mock_server.docmd.return_value = (234, b"Auth")

        with (
            patch(
                "mytools.email.smtpdowngrade._connect_smtp", return_value=mock_server
            ),
            patch(
                "mytools.email.smtpdowngrade._get_banner",
                return_value="220 mail\nSTARTTLS",
            ),
            patch("mytools.email.smtpdowngrade._check_starttls", return_value=True),
            patch(
                "mytools.email.smtpdowngrade._test_plaintext_mail",
                return_value=(True, "250 OK"),
            ),
            patch(
                "mytools.email.smtpdowngrade._test_helo_downgrade",
                return_value=(True, "250"),
            ),
        ):
            result = scan_smtp_downgrade("mail.test.com", 587)
            assert result.overall_status == "vulnerable"
            assert result.plaintext_accepted is True
            assert result.auth_without_tls is True

    def test_no_starttls(self) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"220 mail")
        mock_server.mail.return_value = (250, b"OK")
        mock_server.rcpt.return_value = (250, b"OK")
        mock_server.docmd.side_effect = smtpdowngrade.smtplib.SMTPException("fail")

        with (
            patch(
                "mytools.email.smtpdowngrade._connect_smtp", return_value=mock_server
            ),
            patch("mytools.email.smtpdowngrade._get_banner", return_value="220 mail"),
            patch("mytools.email.smtpdowngrade._check_starttls", return_value=False),
            patch(
                "mytools.email.smtpdowngrade._test_plaintext_mail",
                return_value=(True, "250"),
            ),
            patch(
                "mytools.email.smtpdowngrade._test_helo_downgrade",
                return_value=(True, "250"),
            ),
        ):
            result = scan_smtp_downgrade("mail.test.com", 25)
            assert result.ehlo_advertises_starttls is False
            assert result.supports_starttls is False

    def test_auth_requires_tls(self) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"220 mail\nSTARTTLS")
        mock_server.starttls.return_value = (220, b"Ready")
        mock_server.mail.return_value = (530, b"Auth required")
        mock_server.rcpt.return_value = (530, b"Auth required")
        mock_server.docmd.return_value = (530, b"Must issue STARTTLS first")

        with (
            patch(
                "mytools.email.smtpdowngrade._connect_smtp", return_value=mock_server
            ),
            patch(
                "mytools.email.smtpdowngrade._get_banner",
                return_value="220 mail\nSTARTTLS",
            ),
            patch("mytools.email.smtpdowngrade._check_starttls", return_value=True),
            patch(
                "mytools.email.smtpdowngrade._test_plaintext_mail",
                return_value=(False, "530"),
            ),
            patch(
                "mytools.email.smtpdowngrade._test_helo_downgrade",
                return_value=(False, "fail"),
            ),
        ):
            result = scan_smtp_downgrade("mail.test.com", 587)
            assert result.auth_without_tls is False
            assert not any("MITM possivel" in i for i in result.issues)

    def test_custom_port(self) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"220 mail")
        mock_server.mail.return_value = (250, b"OK")
        mock_server.rcpt.return_value = (250, b"OK")
        mock_server.docmd.side_effect = smtpdowngrade.smtplib.SMTPException("fail")

        with (
            patch(
                "mytools.email.smtpdowngrade._connect_smtp", return_value=mock_server
            ),
            patch("mytools.email.smtpdowngrade._get_banner", return_value="220 mail"),
            patch(
                "mytools.email.smtpdowngrade._test_plaintext_mail",
                return_value=(True, "250"),
            ),
            patch(
                "mytools.email.smtpdowngrade._test_helo_downgrade",
                return_value=(True, "250"),
            ),
        ):
            result = scan_smtp_downgrade("mail.test.com", 25, from_addr="a@b.com")
            assert result.port == 25

    def test_plaintext_connection_failure(self) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"220 mail")
        mock_server.docmd.side_effect = smtpdowngrade.smtplib.SMTPException("fail")

        with (
            patch(
                "mytools.email.smtpdowngrade._connect_smtp",
                side_effect=[mock_server, ConnectionError("refused")],
            ),
            patch("mytools.email.smtpdowngrade._get_banner", return_value="220 mail"),
        ):
            result = scan_smtp_downgrade("mail.test.com", 587)
            assert result.overall_status == "error"
            assert any("teste plaintext" in i for i in result.issues)
            assert result.plaintext_accepted is False

    def test_auth_connection_failure(self) -> None:
        mock_server = MagicMock()
        mock_server.ehlo.return_value = (250, b"220 mail")
        mock_server.mail.return_value = (250, b"OK")
        mock_server.rcpt.return_value = (250, b"OK")
        mock_server.docmd.side_effect = smtpdowngrade.smtplib.SMTPException("fail")

        with (
            patch(
                "mytools.email.smtpdowngrade._connect_smtp",
                side_effect=[
                    mock_server,
                    mock_server,
                    ConnectionError("refused"),
                ],
            ),
            patch("mytools.email.smtpdowngrade._get_banner", return_value="220 mail"),
            patch(
                "mytools.email.smtpdowngrade._test_plaintext_mail",
                return_value=(True, "250"),
            ),
            patch(
                "mytools.email.smtpdowngrade._test_helo_downgrade",
                return_value=(False, "fail"),
            ),
        ):
            result = scan_smtp_downgrade("mail.test.com", 587)
            assert result.overall_status == "error"
            assert any("teste AUTH" in i for i in result.issues)
            assert result.auth_without_tls is False


class TestPrintResults:
    def test_secure(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DowngradeResult(
            target="mail.test.com",
            port=587,
            banner="STARTTLS",
            ehlo_advertises_starttls=True,
            supports_starttls=True,
            requires_starttls=True,
            plaintext_accepted=False,
            helo_downgrade_accepted=False,
            auth_without_tls=False,
            tests=[],
            issues=["OK"],
            overall_status="secure",
        )
        print_results(r)
        out = capsys.readouterr().out
        assert "SECURE" in out

    def test_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DowngradeResult(
            target="mail.test.com",
            port=587,
            banner="STARTTLS",
            ehlo_advertises_starttls=True,
            supports_starttls=True,
            requires_starttls=False,
            plaintext_accepted=True,
            helo_downgrade_accepted=True,
            auth_without_tls=True,
            tests=[],
            issues=["vuln"],
            overall_status="vulnerable",
        )
        print_results(r)
        out = capsys.readouterr().out
        assert "VULNERAVEL" in out

    def test_with_tests(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DowngradeResult(
            target="mail.test.com",
            port=587,
            banner="",
            ehlo_advertises_starttls=False,
            supports_starttls=False,
            requires_starttls=False,
            plaintext_accepted=True,
            helo_downgrade_accepted=True,
            auth_without_tls=False,
            tests=[
                DowngradeTest("T1", "pass", "desc1", "det1"),
                DowngradeTest("T2", "vulnerable", "desc2", "det2"),
            ],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(r)
        out = capsys.readouterr().out
        assert "T1" in out
        assert "T2" in out

    def test_warning(self, capsys: pytest.CaptureFixture[str]) -> None:
        r = DowngradeResult(
            target="mail.test.com",
            port=587,
            banner="",
            ehlo_advertises_starttls=False,
            supports_starttls=False,
            requires_starttls=True,
            plaintext_accepted=False,
            helo_downgrade_accepted=True,
            auth_without_tls=False,
            tests=[
                DowngradeTest("HELO Downgrade", "fail", "desc", "det"),
            ],
            issues=[],
            overall_status="warning",
        )
        print_results(r)
        out = capsys.readouterr().out
        assert "parcial" in out


class TestBanner:
    def test_banner_art(self, capsys: pytest.CaptureFixture[str]) -> None:
        banner_art()
        captured = capsys.readouterr()
        assert "smtp downgrade" in captured.out


class TestRunOnce:
    def test_run_once(self) -> None:
        args = build_parser().parse_args(["mail.test.com"])
        with (
            patch(
                "mytools.email.smtpdowngrade._async_run_once",
                new_callable=MagicMock,
                return_value=0,
            ),
            patch(
                "mytools.email.smtpdowngrade.safe_asyncio_run",
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
        result = DowngradeResult(
            target="mail.test.com",
            port=587,
            banner="",
            ehlo_advertises_starttls=False,
            supports_starttls=False,
            requires_starttls=True,
            plaintext_accepted=False,
            helo_downgrade_accepted=False,
            auth_without_tls=False,
            tests=[],
            issues=[],
            overall_status="secure",
        )
        args = build_parser().parse_args(["mail.test.com"])
        with patch(
            "mytools.email.smtpdowngrade.scan_smtp_downgrade",
            return_value=result,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0

    def test_output_flag(self, tmp_path) -> None:
        result = DowngradeResult(
            target="mail.test.com",
            port=587,
            banner="",
            ehlo_advertises_starttls=False,
            supports_starttls=False,
            requires_starttls=True,
            plaintext_accepted=False,
            helo_downgrade_accepted=False,
            auth_without_tls=False,
            tests=[],
            issues=[],
            overall_status="secure",
        )
        out_file = tmp_path / "out.json"
        args = build_parser().parse_args(["mail.test.com", "-o", str(out_file)])
        with (
            patch(
                "mytools.email.smtpdowngrade.scan_smtp_downgrade",
                return_value=result,
            ),
            patch("mytools.email.smtpdowngrade.write_output") as mock_write,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0
        mock_write.assert_called_once()

    def test_quiet(self) -> None:
        result = DowngradeResult(
            target="mail.test.com",
            port=587,
            banner="",
            ehlo_advertises_starttls=False,
            supports_starttls=False,
            requires_starttls=True,
            plaintext_accepted=False,
            helo_downgrade_accepted=False,
            auth_without_tls=False,
            tests=[],
            issues=[],
            overall_status="secure",
        )
        args = build_parser().parse_args(["mail.test.com", "--quiet"])
        with patch(
            "mytools.email.smtpdowngrade.scan_smtp_downgrade",
            return_value=result,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0

    def test_json_output(self) -> None:
        result = DowngradeResult(
            target="mail.test.com",
            port=587,
            banner="",
            ehlo_advertises_starttls=False,
            supports_starttls=False,
            requires_starttls=True,
            plaintext_accepted=False,
            helo_downgrade_accepted=False,
            auth_without_tls=False,
            tests=[],
            issues=[],
            overall_status="secure",
        )
        args = build_parser().parse_args(["mail.test.com", "--json"])
        with (
            patch(
                "mytools.email.smtpdowngrade.scan_smtp_downgrade",
                return_value=result,
            ),
            patch("mytools.email.smtpdowngrade.print_json") as mock_print,
        ):
            code = asyncio.run(_async_run_once(args))
        assert code == 0
        mock_print.assert_called_once()


class TestMain:
    def test_main(self) -> None:
        with patch(
            "mytools.email.smtpdowngrade.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()

    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-smtpdown", "mail.test.com"]),
            pytest.raises(SystemExit),
        ):
            runpy.run_module("mytools.email.smtpdowngrade", run_name="__main__")
