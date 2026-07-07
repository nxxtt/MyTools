#!/usr/bin/env python3
"""Modulo de validacao DNSSEC — DNSSEC Validation.

Verifica se DNSSEC esta configurado corretamente em um dominio:
  - Cadeia de confianca (DS → DNSKEY → RRSIG)
  - Assinaturas RRSIG validas (inception/expiry)
  - Forca dos algoritmos (RSA/ECDSA/ED25519)
  - Configuracao NSEC/NSEC3

DNSSEC adiciona assinaturas cryptographicas aos registros DNS para
prevenir spoofing e tampering.

Fluxo:
  1. Consulta DNSKEY (chaves publicas da zona)
  2. Consulta DS (delegacao signer no parent)
  3. Consulta RRSIG (assinaturas)
  4. Verifica cadeia de confianca
  5. Avalia forca dos algoritmos
  6. Retorna status geral (secure/insecure/broken)
"""
import argparse
import datetime
import logging
from dataclasses import asdict, dataclass

import dns.dnssec
import dns.exception
import dns.flags
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver

from mytools.core.utils import (
    Cyber,
    add_base_args,
    color,
    create_banner,
    init_scanner,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.dnssecvalidation")

WEAK_ALGORITHMS = {5, 7}  # RSASHA1, RSASHA1-NSEC3-SHA1
MEDIUM_ALGORITHMS = {8, 10}  # RSASHA256, RSASHA512
STRONG_ALGORITHMS = {13, 14, 15, 16}  # ECDSA, ED25519, ED448

ALGORITHM_NAMES = {
    1: "RSAMD5", 3: "DSA", 5: "RSASHA1", 6: "DSA-NSEC3-SHA1",
    7: "RSASHA1-NSEC3-SHA1", 8: "RSASHA256", 10: "RSASHA512",
    12: "ECC-GOST", 13: "ECDSAP256SHA256", 14: "ECDSAP384SHA384",
    15: "ED25519", 16: "ED448",
}


@dataclass(frozen=True, slots=True)
class DnssecCheck:
    """Check individual de DNSSEC."""

    check: str
    status: str  # pass, warn, fail, missing
    detail: str
    severity: str


@dataclass(frozen=True, slots=True)
class DnssecResult:
    """Resultado agregado da validacao DNSSEC."""

    domain: str
    nameserver: str
    is_signed: bool
    has_ds: bool
    has_dnskey: bool
    has_rrsig: bool
    chain_valid: bool
    algorithm_strength: str
    checks: list[DnssecCheck]
    overall_status: str  # secure, insecure, broken


def _check_dnskey(domain: str, resolver: dns.resolver.Resolver) -> tuple[bool, list[DnssecCheck]]:
    """Verifica registros DNSKEY."""
    checks: list[DnssecCheck] = []
    has_dnskey = False

    try:
        answer = resolver.resolve(domain, "DNSKEY")
        has_dnskey = True

        zsk_count = 0
        ksk_count = 0
        algorithms = set()

        for rr in answer:
            flags = rr.flags
            algorithm = rr.algorithm
            algorithms.add(algorithm)

            if flags == 256:
                zsk_count += 1
            elif flags == 257:
                ksk_count += 1

        if ksk_count == 0:
            checks.append(DnssecCheck(
                check="dnskey_ksk",
                status="warn",
                detail="Nenhuma KSK (flags=257) encontrada",
                severity="medium",
            ))
        else:
            checks.append(DnssecCheck(
                check="dnskey_ksk",
                status="pass",
                detail=f"{ksk_count} KSK encontrada(s)",
                severity="low",
            ))

        if zsk_count == 0:
            checks.append(DnssecCheck(
                check="dnskey_zsk",
                status="warn",
                detail="Nenhuma ZSK (flags=256) encontrada",
                severity="medium",
            ))
        else:
            checks.append(DnssecCheck(
                check="dnskey_zsk",
                status="pass",
                detail=f"{zsk_count} ZSK encontrada(s)",
                severity="low",
            ))

        algo_strs = [ALGORITHM_NAMES.get(a, f"algo-{a}") for a in sorted(algorithms)]
        checks.append(DnssecCheck(
            check="dnskey_algorithms",
            status="pass",
            detail=f"Algoritmos: {', '.join(algo_strs)}",
            severity="low",
        ))

    except dns.resolver.NXDOMAIN:
        checks.append(DnssecCheck(
            check="dnskey", status="fail",
            detail="Dominio nao existe", severity="high",
        ))
    except dns.resolver.NoAnswer:
        checks.append(DnssecCheck(
            check="dnskey", status="missing",
            detail="Nenhum registro DNSKEY encontrado — zona nao assinada",
            severity="high",
        ))
    except dns.exception.Timeout:
        checks.append(DnssecCheck(
            check="dnskey", status="fail",
            detail="Timeout ao consultar DNSKEY", severity="medium",
        ))
    except dns.exception.DNSException as e:
        checks.append(DnssecCheck(
            check="dnskey", status="fail",
            detail=f"Erro DNS: {str(e)[:60]}", severity="medium",
        ))

    return has_dnskey, checks


def _check_ds(domain: str, resolver: dns.resolver.Resolver) -> tuple[bool, list[DnssecCheck]]:
    """Verifica registros DS (delegacao signer)."""
    checks: list[DnssecCheck] = []
    has_ds = False

    try:
        answer = resolver.resolve(domain, "DS")
        has_ds = True

        ds_count = len(list(answer))
        checks.append(DnssecCheck(
            check="ds_record",
            status="pass",
            detail=f"{ds_count} DS record(s) encontrado(s)",
            severity="low",
        ))

    except dns.resolver.NoAnswer:
        checks.append(DnssecCheck(
            check="ds_record", status="missing",
            detail="Nenhum registro DS — zona pode nao ter delegacao DNSSEC",
            severity="medium",
        ))
    except dns.resolver.NXDOMAIN:
        checks.append(DnssecCheck(
            check="ds_record", status="fail",
            detail="Dominio nao existe", severity="high",
        ))
    except dns.exception.Timeout:
        checks.append(DnssecCheck(
            check="ds_record", status="fail",
            detail="Timeout ao consultar DS", severity="medium",
        ))
    except dns.exception.DNSException as e:
        checks.append(DnssecCheck(
            check="ds_record", status="fail",
            detail=f"Erro DNS: {str(e)[:60]}", severity="medium",
        ))

    return has_ds, checks


def _check_rrsig(domain: str, resolver: dns.resolver.Resolver) -> tuple[bool, list[DnssecCheck]]:
    """Verifica registros RRSIG (assinaturas)."""
    checks: list[DnssecCheck] = []
    has_rrsig = False

    try:
        answer = resolver.resolve(domain, "RRSIG")
        has_rrsig = True

        now = datetime.datetime.now(datetime.UTC)
        expired = 0
        valid = 0

        for rr in answer:
            try:
                expiry = rr.expiration
                exp_ts = dns.dnssec.to_timestamp(expiry)
                exp_dt = datetime.datetime.fromtimestamp(exp_ts, tz=datetime.UTC)
                if exp_dt < now:
                    expired += 1
                else:
                    valid += 1
            except Exception:
                valid += 1

        if expired > 0:
            checks.append(DnssecCheck(
                check="rrsig_expiry",
                status="warn",
                detail=f"{expired} assinatura(s) expirada(s), {valid} valida(s)",
                severity="high",
            ))
        else:
            checks.append(DnssecCheck(
                check="rrsig_expiry",
                status="pass",
                detail=f"{valid} assinatura(s) valida(s)",
                severity="low",
            ))

    except dns.resolver.NoAnswer:
        checks.append(DnssecCheck(
            check="rrsig", status="missing",
            detail="Nenhum registro RRSIG — zona nao assinada",
            severity="high",
        ))
    except dns.resolver.NXDOMAIN:
        checks.append(DnssecCheck(
            check="rrsig", status="fail",
            detail="Dominio nao existe", severity="high",
        ))
    except dns.exception.Timeout:
        checks.append(DnssecCheck(
            check="rrsig", status="fail",
            detail="Timeout ao consultar RRSIG", severity="medium",
        ))
    except dns.exception.DNSException as e:
        checks.append(DnssecCheck(
            check="rrsig", status="fail",
            detail=f"Erro DNS: {str(e)[:60]}", severity="medium",
        ))

    return has_rrsig, checks


def _check_nsec(domain: str, resolver: dns.resolver.Resolver) -> list[DnssecCheck]:
    """Verifica registros NSEC/NSEC3."""
    checks: list[DnssecCheck] = []

    try:
        answer = resolver.resolve(domain, "NSEC")
        nsec_count = len(list(answer))
        checks.append(DnssecCheck(
            check="nsec",
            status="pass",
            detail=f"{nsec_count} NSEC record(s) encontrado(s)",
            severity="low",
        ))
    except dns.resolver.NoAnswer:
        try:
            answer = resolver.resolve(domain, "NSEC3")
            nsec3_count = len(list(answer))
            checks.append(DnssecCheck(
                check="nsec3",
                status="pass",
                detail=f"{nsec3_count} NSEC3 record(s) encontrado(s)",
                severity="low",
            ))
        except dns.resolver.NoAnswer:
            checks.append(DnssecCheck(
                check="nsec", status="missing",
                detail="Nenhum NSEC/NSEC3 encontrado",
                severity="low",
            ))
        except dns.exception.DNSException:
            checks.append(DnssecCheck(
                check="nsec3", status="fail",
                detail="Erro ao consultar NSEC3", severity="low",
            ))
    except dns.exception.DNSException:
        checks.append(DnssecCheck(
            check="nsec", status="fail",
            detail="Erro ao consultar NSEC", severity="low",
        ))

    return checks


def _evaluate_algorithm_strength(domain: str, resolver: dns.resolver.Resolver) -> str:
    """Avalia a forca dos algoritmos DNSSEC."""
    try:
        answer = resolver.resolve(domain, "DNSKEY")
        algorithms = set()
        for rr in answer:
            algorithms.add(rr.algorithm)

        if algorithms & STRONG_ALGORITHMS:
            return "strong"
        if algorithms & MEDIUM_ALGORITHMS:
            return "medium"
        if algorithms & WEAK_ALGORITHMS:
            return "weak"
        return "unknown"
    except Exception:
        return "unknown"


def scan_dnssec(
    domain: str,
    nameserver: str = "8.8.8.8",
    timeout: float = 5.0,
) -> DnssecResult:
    """Executa a validacao DNSSEC."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    all_checks: list[DnssecCheck] = []

    has_dnskey, dnskey_checks = _check_dnskey(domain, resolver)
    all_checks.extend(dnskey_checks)

    has_ds, ds_checks = _check_ds(domain, resolver)
    all_checks.extend(ds_checks)

    has_rrsig, rrsig_checks = _check_rrsig(domain, resolver)
    all_checks.extend(rrsig_checks)

    nsec_checks = _check_nsec(domain, resolver)
    all_checks.extend(nsec_checks)

    algo_strength = _evaluate_algorithm_strength(domain, resolver)

    if algo_strength == "weak":
        all_checks.append(DnssecCheck(
            check="algorithm_strength",
            status="warn",
            detail="Algoritmos fracos detectados (SHA-1/DSA)",
            severity="medium",
        ))
    elif algo_strength == "strong":
        all_checks.append(DnssecCheck(
            check="algorithm_strength",
            status="pass",
            detail="Algoritmos fortes (ECDSA/ED25519)",
            severity="low",
        ))

    chain_valid = has_dnskey and has_ds and has_rrsig
    is_signed = has_dnskey and has_rrsig

    if chain_valid and algo_strength != "weak":
        overall = "secure"
    elif is_signed and not has_ds:
        overall = "insecure"
    elif is_signed:
        overall = "partial"
    else:
        overall = "unsigned"

    return DnssecResult(
        domain=domain,
        nameserver=nameserver,
        is_signed=is_signed,
        has_ds=has_ds,
        has_dnskey=has_dnskey,
        has_rrsig=has_rrsig,
        chain_valid=chain_valid,
        algorithm_strength=algo_strength,
        checks=all_checks,
        overall_status=overall,
    )


def print_results(result: DnssecResult) -> None:
    """Exibe o relatorio de validacao DNSSEC."""
    print(color("\n[+] DNSSEC Validation — Relatorio:", Cyber.GREEN, Cyber.BOLD))
    print(f"  Dominio: {color(result.domain, Cyber.WHITE, Cyber.BOLD)}")
    print(f"  Nameserver: {color(result.nameserver, Cyber.CYAN)}")
    print()

    status_colors = {
        "secure": (Cyber.GREEN, Cyber.BOLD),
        "insecure": (Cyber.YELLOW, Cyber.BOLD),
        "partial": (Cyber.YELLOW, ""),
        "unsigned": (Cyber.RED, ""),
    }
    sc = status_colors.get(result.overall_status, (Cyber.WHITE, ""))
    print(f"  Status: {color(result.overall_status.upper(), *sc)}")
    print(f"  Assinado: {color('SIM', Cyber.GREEN) if result.is_signed else color('NAO', Cyber.RED)}")
    print(f"  DS Record: {color('SIM', Cyber.GREEN) if result.has_ds else color('NAO', Cyber.RED)}")
    print(f"  DNSKEY: {color('SIM', Cyber.GREEN) if result.has_dnskey else color('NAO', Cyber.RED)}")
    print(f"  RRSIG: {color('SIM', Cyber.GREEN) if result.has_rrsig else color('NAO', Cyber.RED)}")
    print(f"  Cadeia: {color('VALIDA', Cyber.GREEN, Cyber.BOLD) if result.chain_valid else color('INVALIDA', Cyber.RED, Cyber.BOLD)}")

    algo_colors = {"strong": (Cyber.GREEN, Cyber.BOLD), "medium": (Cyber.YELLOW, ""), "weak": (Cyber.RED, ""), "unknown": (Cyber.WHITE, "")}
    ac = algo_colors.get(result.algorithm_strength, (Cyber.WHITE, ""))
    print(f"  Algoritmos: {color(result.algorithm_strength.upper(), *ac)}")
    print()

    print(color("  Checks:", Cyber.YELLOW, Cyber.BOLD))
    status_icons = {"pass": color("[+]", Cyber.GREEN), "warn": color("[!]", Cyber.YELLOW), "fail": color("[-]", Cyber.RED), "missing": color("[?]", Cyber.GRAY)}
    for check in result.checks:
        icon = status_icons.get(check.status, color("[?]", Cyber.WHITE))
        print(f"    {icon} {check.check}: {check.detail}")

    print()
    if result.overall_status == "secure":
        print(color("  [+] DNSSEC configurado corretamente — zona segura", Cyber.GREEN, Cyber.BOLD))
    elif result.overall_status == "insecure":
        print(color("  [!] Zona parcialmente assinada — sem delegacao DS", Cyber.YELLOW))
        print(color("  [!] Considere configurar DNSSEC no parent zone", Cyber.YELLOW))
    elif result.overall_status == "partial":
        print(color("  [!] DNSSEC parcialmente configurado — cadeia incompleta", Cyber.YELLOW))
    else:
        print(color("  [-] DNSSEC nao configurado — zona nao assinada", Cyber.RED))
        print(color("  [-] Recomendacao: implementar DNSSEC para protecao contra spoofing", Cyber.YELLOW))


def banner() -> None:
    """Exibe o banner do DNSSEC Validation."""
    art = r"""
    __  _______  __        _____ __             __
   /  |/  / __ \/ /__  __/_  _(_)___  ____    / /____
  / /|_/ / / / / / _ \/ / / / / / __ \/ __ \  / / ___/
 / /  / / /_/ / /  __/ / / / / / / / / /_/ / / (__  )
/_/  /_/\____/_/\___/_/ /_/_/_/_/ /_/\____/ /_/____/
"""
    create_banner(art, "   dnssec validation: verifica se DNSSEC esta configurado corretamente")()


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="DNSSEC Validation — verifica se DNSSEC esta configurado corretamente.",
        epilog="Verifica cadeia de confianca, assinaturas, algoritmos e configuracao NSEC/NSEC3.",
    )
    add_base_args(parser)
    parser.add_argument("domain", nargs="?", help="Dominio alvo para validacao DNSSEC.")
    parser.add_argument(
        "--nameserver", "-s",
        default="8.8.8.8",
        help="Nameserver para queries. Padrao: 8.8.8.8",
    )
    parser.add_argument(
        "--query-timeout",
        type=float,
        default=5.0,
        help="Timeout por query em segundos. Padrao: 5",
    )
    return parser


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)

    domain = getattr(args, "domain", None)
    if not domain:
        print(color("[!] Informe um dominio.", Cyber.RED))
        return 1

    if getattr(args, "dry_run", False):
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Nenhuma query DNS sera enviada.")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Dominio: {color(domain, Cyber.WHITE, Cyber.BOLD)}")
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Nameserver: {args.nameserver}")
        return 0

    result = scan_dnssec(
        domain=domain,
        nameserver=args.nameserver,
        timeout=args.query_timeout,
    )

    if not quiet:
        print_results(result)

    if args.output:
        write_output(
            args.output,
            [asdict(result)],
            ["domain", "nameserver", "is_signed", "has_ds", "has_dnskey",
             "has_rrsig", "chain_valid", "algorithm_strength", "overall_status"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do DNSSEC Validation."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.domain),
        prompt="dnssec> ",
        description="DNSSEC Validation interativo.",
        example="example.com --nameserver 8.8.8.8",
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --nameserver 1.1.1.1\n"
            "  example.com --query-timeout 10"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
