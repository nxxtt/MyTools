#!/usr/bin/env python3
"""Modulo de deteccao de amplificacao DNS — DNS Amplification Detection.

Verifica se um servidor DNS pode ser abusado para ataques de amplificacao DDoS.
Ferramenta de auditoria defensiva: identifica servidores DNS que podem ser
usados como reflectores em ataques de amplificacao.

Amplificacao DNS ocorre quando:
  1. Atacante envia query com IP fonte spoofado (vitima)
  2. Resolver aberto responde com resposta muito maior que a query
  3. Resposta e enviada para a vitima (amplificacao)

A ferramenta testa:
  - Tamanho de resposta para cada record type (ANY, TXT, A, MX, NS, SOA)
  - Fator de amplificacao (response_bytes / request_bytes)
  - Se recursao esta habilitada (open resolver)
  - Severidade baseada no fator maximo

Fluxo:
  1. Envia query com cada record type para o nameserver
  2. Mede tamanho da resposta em bytes
  3. Calcula amplificacao = response_bytes / ~50 bytes (request)
  4. Testa recursao (rd=1 vs rd=0)
  5. Classifica severidade (critical/high/medium/low/safe)
"""
import argparseimport loggingfrom dataclasses import asdict, dataclassimport dns.exceptionimport dns.flagsimport dns.messageimport dns.nameimport dns.queryimport dns.rdatatypeimport dns.resolverfrom mytools.core.utils import (    Cyber,    add_base_args,    color,    create_banner,    init_scanner,    print_exploit_info,    run_main_loop,    safe_asyncio_run,    write_output,)logger = logging.getLogger("mytools.dnsamplification")

DEFAULT_NAMESERVER = "8.8.8.8"
DEFAULT_TIMEOUT = 3.0
DEFAULT_RECORD_TYPES = ["ANY", "TXT", "A", "MX", "NS", "SOA"]
REQUEST_SIZE_ESTIMATE = 50


@dataclass(frozen=True, slots=True)
class RecordAmplification:
    """Resultado de amplificacao para um record type."""

    record_type: str
    response_bytes: int
    amplification_factor: float
    success: bool
    error: str


@dataclass(frozen=True, slots=True)
class AmplificationResult:
    """Resultado agregado da deteccao de amplificacao."""

    domain: str
    nameserver: str
    recursion_available: bool
    is_open_resolver: bool
    records: list[RecordAmplification]
    max_amplification: float
    severity: str
    request_size: int
    exploit: str = ""
    tool: str = ""


def classify_severity(amplification_factor: float) -> str:
    """Classifica severidade baseado no fator de amplificacao."""
    if amplification_factor >= 10.0:
        return "critical"
    if amplification_factor >= 5.0:
        return "high"
    if amplification_factor >= 2.0:
        return "medium"
    if amplification_factor >= 1.0:
        return "low"
    return "safe"


def _query_record(
    nameserver: str,
    domain: str,
    record_type: str,
    timeout: float,
) -> RecordAmplification:
    """Envia uma query DNS e mede o tamanho da resposta."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    request_bytes = REQUEST_SIZE_ESTIMATE

    try:
        answer = resolver.resolve(domain, record_type)
        response_bytes = len(answer.response.to_wire())
        amp_factor = round(response_bytes / request_bytes, 2) if request_bytes > 0 else 0.0

        return RecordAmplification(
            record_type=record_type,
            response_bytes=response_bytes,
            amplification_factor=amp_factor,
            success=True,
            error="",
        )
    except dns.resolver.NXDOMAIN:
        return RecordAmplification(
            record_type=record_type, response_bytes=0,
            amplification_factor=0.0, success=False, error="NXDOMAIN",
        )
    except dns.resolver.NoAnswer:
        return RecordAmplification(
            record_type=record_type, response_bytes=0,
            amplification_factor=0.0, success=False, error="NOANSWER",
        )
    except dns.resolver.NoNameservers:
        return RecordAmplification(
            record_type=record_type, response_bytes=0,
            amplification_factor=0.0, success=False, error="NAMESERVERS",
        )
    except dns.exception.Timeout:
        return RecordAmplification(
            record_type=record_type, response_bytes=0,
            amplification_factor=0.0, success=False, error="TIMEOUT",
        )
    except dns.exception.DNSException as e:
        return RecordAmplification(
            record_type=record_type, response_bytes=0,
            amplification_factor=0.0, success=False, error=str(e)[:50],
        )


def _check_recursion(nameserver: str, domain: str, timeout: float) -> bool:
    """Testa se o nameserver permite recursao (open resolver)."""
    try:
        msg = dns.message.make_query(
            dns.name.from_text(domain),
            dns.rdatatype.A,
            use_edns=False,
        )
        msg.flags |= dns.flags.RD
        response = dns.query.udp(msg, nameserver, timeout=timeout)
        rd_set = bool(response.flags & dns.flags.RA)
        return rd_set
    except Exception:
        return False


def scan_amplification(
    domain: str,
    nameserver: str = DEFAULT_NAMESERVER,
    record_types: list[str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
) -> AmplificationResult:
    """Executa o scan de amplificacao DNS."""
    types_to_test = record_types or DEFAULT_RECORD_TYPES

    records = []
    for rt in types_to_test:
        result = _query_record(nameserver, domain, rt, timeout)
        records.append(result)

    recursion = _check_recursion(nameserver, domain, timeout)

    amp_values = [r.amplification_factor for r in records if r.success and r.amplification_factor > 0]
    max_amp = max(amp_values) if amp_values else 0.0

    is_open = recursion and max_amp >= 2.0
    severity = classify_severity(max_amp) if recursion else "safe"

    return AmplificationResult(
        domain=domain,
        nameserver=nameserver,
        recursion_available=recursion,
        is_open_resolver=is_open,
        records=records,
        max_amplification=max_amp,
        severity=severity,
        request_size=REQUEST_SIZE_ESTIMATE,
        exploit="open_resolver_abuse" if is_open else "",
        tool="hping3",
    )


def print_results(result: AmplificationResult) -> None:
    """Exibe o relatorio de amplificacao de forma colorida."""
    print(color("\n[+] DNS Amplification Detection — Relatorio:", Cyber.GREEN, Cyber.BOLD))
    print(f"  Dominio: {color(result.domain, Cyber.WHITE, Cyber.BOLD)}")
    print(f"  Nameserver: {color(result.nameserver, Cyber.CYAN)}")
    print()

    sev_colors = {
        "critical": (Cyber.RED, Cyber.BOLD),
        "high": (Cyber.RED, ""),
        "medium": (Cyber.YELLOW, Cyber.BOLD),
        "low": (Cyber.YELLOW, ""),
        "safe": (Cyber.GREEN, Cyber.BOLD),
    }
    sev_color = sev_colors.get(result.severity, (Cyber.WHITE, ""))
    print(f"  Severidade: {color(result.severity.upper(), *sev_color)}")
    print(f"  Recursao: {color('SIM', Cyber.RED) if result.recursion_available else color('NAO', Cyber.GREEN)}")
    print(f"  Open Resolver: {color('SIM', Cyber.RED, Cyber.BOLD) if result.is_open_resolver else color('NAO', Cyber.GREEN)}")
    print()

    print(color("  Record Types:", Cyber.YELLOW, Cyber.BOLD))
    for rec in result.records:
        if rec.success:
            amp_color = Cyber.RED if rec.amplification_factor >= 5.0 else (Cyber.YELLOW if rec.amplification_factor >= 2.0 else Cyber.GREEN)
            print(f"    {rec.record_type:>4}: {color(f'{rec.response_bytes:>6} bytes', Cyber.WHITE)} | "
                  f"amp={color(f'{rec.amplification_factor:.1f}x', amp_color, Cyber.BOLD)}")
        else:
            print(f"    {rec.record_type:>4}: {color('FALHA', Cyber.RED)} ({rec.error})")

    print()
    print(f"  Request estimado: {color(f'{result.request_size} bytes', Cyber.WHITE)}")
    print(f"  Amplificacao max: {color(f'{result.max_amplification:.1f}x', Cyber.RED if result.max_amplification >= 5.0 else Cyber.WHITE, Cyber.BOLD)}")

    if result.is_open_resolver:
        print(color("\n  [!] SERVIDOR ABERTO — pode ser abusado para amplificacao DDoS!", Cyber.RED, Cyber.BOLD))
        print(color("  [!] Recomendacao: desabilitar recursao ou restringir acesso", Cyber.YELLOW))
    elif result.recursion_available and result.max_amplification >= 2.0:
        print(color("\n  [!] Recursao habilitada com amplificacao potencial", Cyber.YELLOW))
        print(color("  [!] Considere restringir recursao a redes internas", Cyber.YELLOW))
    elif result.max_amplification >= 5.0:
        print(color("\n  [!] Alta amplificacao detectada, mas recursao desabilitada", Cyber.YELLOW))
    else:
        print(color("\n  [+] Servidor seguro — baixa amplificacao", Cyber.GREEN))

    print_exploit_info(result.exploit, result.tool)


def banner() -> None:
    """Exibe o banner do DNS Amplification Detection."""
    art = r"""
    __  _______  __       __             __
   /  |/  / __ \/ /__  __/ /____  _____/ /_
  / /|_/ / / / / / _ \/ / __/ _ \/ ___/ __/
 / /  / / /_/ / /  __/ / /_/  __/ /__/ /_
/_/  /_/\____/_/\___/_/\__/\___/\___/\__/
"""
    create_banner(art, "   amplification detection: auditoria de amplificacao DNS")()


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="DNS Amplification Detection — verifica se servidor pode ser usado para amplificacao DDoS.",
        epilog="Use apenas em servidores que voce possui ou tem autorizacao para auditar.",
    )
    add_base_args(parser)
    parser.add_argument("domain", nargs="?", help="Dominio ou IP do nameserver a auditar.")
    parser.add_argument(
        "--nameserver", "-s",
        default=DEFAULT_NAMESERVER,
        help=f"Nameserver a testar. Padrao: {DEFAULT_NAMESERVER}",
    )
    parser.add_argument(
        "--record-types", "-r",
        default=",".join(DEFAULT_RECORD_TYPES),
        help=f"Record types para testar (separados por virgula). Padrao: {','.join(DEFAULT_RECORD_TYPES)}",
    )
    parser.add_argument(
        "--query-timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help=f"Timeout por query em segundos. Padrao: {DEFAULT_TIMEOUT}",
    )
    return parser


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)

    domain = getattr(args, "domain", None)
    if not domain:
        print(color("[!] Informe um dominio ou nameserver.", Cyber.RED))
        return 1

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma query DNS sera enviada.")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(domain, Cyber.WHITE, Cyber.BOLD)}")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Nameserver: {args.nameserver}")
        return 0

    record_types = [rt.strip().upper() for rt in args.record_types.split(",") if rt.strip()]

    result = scan_amplification(
        domain=domain,
        nameserver=args.nameserver,
        record_types=record_types,
        timeout=args.query_timeout,
    )

    if not quiet:
        print_results(result)

    if args.output:
        write_output(
            args.output,
            [asdict(result)],
            ["domain", "nameserver", "recursion_available", "is_open_resolver",
             "max_amplification", "severity", "request_size"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do DNS Amplification Detection."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.domain),
        prompt="amp> ",
        description="DNS Amplification Detection interativo.",
        example="example.com --record-types ANY,TXT,MX",
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  8.8.8.8 --nameserver 1.1.1.1\n"
            "  example.com --record-types ANY,TXT,MX"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
