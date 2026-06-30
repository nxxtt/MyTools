#!/usr/bin/env python3
"""Modulo de verificacao de email security — DMARC/SPF/DKIM.

Verifica a configuracao de email security de um dominio:
  - SPF (Sender Policy Framework): quais IPs podem enviar email
  - DKIM (DomainKeys Identified Mail): chaves publicas para verificacao
  - DMARC (Domain-based Message Authentication): politica de alinhamento

Fluxo:
  1. Consulta TXT record SPF (v=spf1...)
  2. Consulta TXT record DMARC (_dmarc.dominio)
  3. Consulta TXT records DKIM (seletores comuns)
  4. Analisa mecanismos e qualificadores
  5. Classifica severidade geral
"""
import argparse
import logging
import re
from dataclasses import asdict, dataclass

import dns.exception
import dns.resolver

from utils import (
    Cyber,
    add_base_args,
    color,
    create_banner,
    init_scanner,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.emailsecurity")

DEFAULT_SELECTORS = ["default", "google", "selector1", "selector2", "s1", "s2", "dkim", "mail"]

SPF_ALL_PATTERN = re.compile(r"\+all|~all|\-all|\?all|all")
DMARC_POLICY_PATTERN = re.compile(r"p=(none|quarantine|reject)")
DMARC_SP_PATTERN = re.compile(r"sp=(none|quarantine|reject)")
DMARC_PCT_PATTERN = re.compile(r"pct=(\d+)")
DMARC_RUA_PATTERN = re.compile(r"rua=([^;\s]+)")


@dataclass(frozen=True, slots=True)
class SpfRecord:
    """Registro SPF parsed."""

    raw: str
    version: str
    mechanisms: list[str]
    has_all: bool
    all_qualifier: str
    includes: list[str]


@dataclass(frozen=True, slots=True)
class DmarcRecord:
    """Registro DMARC parsed."""

    raw: str
    policy: str
    sp: str
    rua: str
    pct: int


@dataclass(frozen=True, slots=True)
class EmailSecurityResult:
    """Resultado da verificacao de email security."""

    domain: str
    spf: SpfRecord | None
    dkim_selectors: list[str]
    dmarc: DmarcRecord | None
    overall_status: str  # secure, good, warning, critical, missing
    issues: list[str]


def _query_txt(domain: str, resolver: dns.resolver.Resolver) -> str | None:
    """Consulta TXT record de um dominio e retorna a primeira string."""
    try:
        answer = resolver.resolve(domain, "TXT")
        for rr in answer:
            for txt in rr.strings:
                if isinstance(txt, bytes):
                    return txt.decode("utf-8", errors="ignore")
                return str(txt)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        pass
    except dns.exception.Timeout:
        pass
    except dns.exception.DNSException:
        pass
    return None


def _parse_spf(raw: str) -> SpfRecord:
    """Parse do registro SPF."""
    mechanisms = []
    includes = []
    has_all = False
    all_qualifier = ""

    parts = raw.split()
    for part in parts:
        clean = part.strip('"').lower()
        if clean.startswith("include:"):
            includes.append(clean[8:])
        elif "all" in clean:
            has_all = True
            match = SPF_ALL_PATTERN.search(clean)
            if match:
                all_qualifier = match.group(0).replace("all", "")
        elif clean.startswith(("a", "mx", "ptr", "ip4", "ip6", "exists:")):
            mechanisms.append(clean)

    return SpfRecord(
        raw=raw,
        version="spf1",
        mechanisms=mechanisms,
        has_all=has_all,
        all_qualifier=all_qualifier,
        includes=includes,
    )


def _parse_dmarc(raw: str) -> DmarcRecord:
    """Parse do registro DMARC."""
    policy_match = DMARC_POLICY_PATTERN.search(raw)
    policy = policy_match.group(1) if policy_match else "none"

    sp_match = DMARC_SP_PATTERN.search(raw)
    sp = sp_match.group(1) if sp_match else policy

    pct_match = DMARC_PCT_PATTERN.search(raw)
    pct = int(pct_match.group(1)) if pct_match else 100

    rua_match = DMARC_RUA_PATTERN.search(raw)
    rua = rua_match.group(1) if rua_match else ""

    return DmarcRecord(
        raw=raw,
        policy=policy,
        sp=sp,
        rua=rua,
        pct=pct,
    )


def scan_email_security(
    domain: str,
    nameserver: str = "8.8.8.8",
    selectors: list[str] | None = None,
    timeout: float = 5.0,
) -> EmailSecurityResult:
    """Executa a verificacao de email security."""
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    issues: list[str] = []

    spf_raw = _query_txt(domain, resolver)
    spf = None
    if spf_raw and "v=spf1" in spf_raw.lower():
        spf = _parse_spf(spf_raw)
        if spf.all_qualifier == "+" and spf.has_all:
            issues.append("SPF usa +all — qualquer IP pode enviar email (critico)")
        elif spf.has_all and spf.all_qualifier == "":
            issues.append("SPF usa all sem qualificador — equivalente a +all")
    elif spf_raw:
        issues.append(f"TXT record encontrado mas nao e SPF: {spf_raw[:50]}")
    else:
        issues.append("Nenhum registro SPF encontrado")

    dmarc_raw = _query_txt(f"_dmarc.{domain}", resolver)
    dmarc = None
    if dmarc_raw and "v=DMARC1" in dmarc_raw:
        dmarc = _parse_dmarc(dmarc_raw)
        if dmarc.policy == "none":
            issues.append("DMARC p=none — nao rejeita emails falhos (fraco)")
        if dmarc.pct < 100:
            issues.append(f"DMARC pct={dmarc.pct} — nao aplica a todos os emails")
        if not dmarc.rua:
            issues.append("DMARC sem rua — sem relatorios de aggregate")
    elif dmarc_raw:
        issues.append(f"DMARC record invalido: {dmarc_raw[:50]}")
    else:
        issues.append("Nenhum registro DMARC encontrado")

    dkim_selectors: list[str] = []
    for sel in (selectors or DEFAULT_SELECTORS):
        dkim_raw = _query_txt(f"{sel}._domainkey.{domain}", resolver)
        if dkim_raw and ("v=DKIM1" in dkim_raw or "p=" in dkim_raw):
            dkim_selectors.append(sel)

    if not dkim_selectors:
        issues.append("Nenhum registro DKIM encontrado (seletores testados: " +
                       ", ".join(selectors or DEFAULT_SELECTORS) + ")")

    # Critico: ausencia total, sem DMARC, DMARC none sem SPF, ou SPF +all
    if (not spf and not dmarc and not dkim_selectors) or \
       (not dmarc) or \
       (dmarc and dmarc.policy == "none" and not spf) or \
       (spf and spf.has_all and spf.all_qualifier == "+"):
        status = "critical"
    elif dmarc and dmarc.policy == "reject" and spf and dkim_selectors:
        status = "secure"
    elif dmarc and dmarc.policy in ("quarantine", "reject") and spf:
        status = "good"
    elif (dmarc and dmarc.policy == "none") or spf or dmarc:
        status = "warning"
    else:
        status = "missing"

    return EmailSecurityResult(
        domain=domain,
        spf=spf,
        dkim_selectors=dkim_selectors,
        dmarc=dmarc,
        overall_status=status,
        issues=issues,
    )


def print_results(result: EmailSecurityResult) -> None:
    """Exibe o relatorio de email security."""
    print(color("\n[+] Email Security (DMARC/SPF/DKIM) — Relatorio:", Cyber.GREEN, Cyber.BOLD))
    print(f"  Dominio: {color(result.domain, Cyber.WHITE, Cyber.BOLD)}")
    print()

    status_colors = {
        "secure": (Cyber.GREEN, Cyber.BOLD),
        "good": (Cyber.GREEN, ""),
        "warning": (Cyber.YELLOW, ""),
        "critical": (Cyber.RED, Cyber.BOLD),
        "missing": (Cyber.RED, ""),
    }
    sc = status_colors.get(result.overall_status, (Cyber.WHITE, ""))
    print(f"  Status: {color(result.overall_status.upper(), *sc)}")
    print()

    if result.spf:
        spf_icon = color("[!]", Cyber.RED) if result.spf.all_qualifier == "+" else color("[+]", Cyber.GREEN)
        print(f"  SPF: {spf_icon} {result.spf.raw[:80]}")
        if result.spf.includes:
            print(f"       Includes: {', '.join(result.spf.includes)}")
    else:
        print(f"  SPF: {color('[-]', Cyber.RED)} Nao encontrado")

    if result.dmarc:
        dmarc_icon = color("[+]", Cyber.GREEN) if result.dmarc.policy in ("quarantine", "reject") else color("[!]", Cyber.YELLOW)
        print(f"  DMARC: {dmarc_icon} {result.dmarc.raw[:80]}")
        print(f"         p={result.dmarc.policy} sp={result.dmarc.sp} pct={result.dmarc.pct}")
        if result.dmarc.rua:
            print(f"         rua={result.dmarc.rua}")
    else:
        print(f"  DMARC: {color('[-]', Cyber.RED)} Nao encontrado")

    if result.dkim_selectors:
        print(f"  DKIM: {color('[+]', Cyber.GREEN)} Seletores: {', '.join(result.dkim_selectors)}")
    else:
        print(f"  DKIM: {color('[-]', Cyber.RED)} Nenhum seletor encontrado")

    if result.issues:
        print()
        print(color("  Problemas:", Cyber.YELLOW, Cyber.BOLD))
        for issue in result.issues:
            print(f"    {color('[!]', Cyber.YELLOW)} {issue}")

    print()
    if result.overall_status == "secure":
        print(color("  [+] Email security configurado corretamente", Cyber.GREEN, Cyber.BOLD))
    elif result.overall_status == "good":
        print(color("  [+] Email security razoavel — melhorias possiveis", Cyber.GREEN))
    elif result.overall_status == "warning":
        print(color("  [!] Email security com problemas — revise a configuracao", Cyber.YELLOW))
    elif result.overall_status == "critical":
        print(color("  [-] Email security critico — vulneravel a spoofing", Cyber.RED, Cyber.BOLD))
    else:
        print(color("  [-] Nenhum registro de email security encontrado", Cyber.RED))


def banner() -> None:
    """Exibe o banner do Email Security."""
    art = r"""
    __  _______  __       _____ __             __
   /  |/  / __ \/ /__  __/ ___// /_  ______   / /____
  / /|_/ / / / / / _ \/ /\__ \/ __ \/ ___/  / / ___/
 / /  / / /_/ / /  __/ /___/ / / / (__  )  / (__  )
/_/  /_/\____/_/\___/_/____/_/_/ /_/____/ /_/____/
"""
    create_banner(art, "   email security: verifica DMARC, SPF e DKIM")()


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Email Security — verifica DMARC, SPF e DKIM de um dominio.",
        epilog="Analiza configuracao de email security para protecao contra spoofing.",
    )
    add_base_args(parser)
    parser.add_argument("domain", nargs="?", help="Dominio alvo para verificacao.")
    parser.add_argument(
        "--nameserver", "-s",
        default="8.8.8.8",
        help="Nameserver para queries. Padrao: 8.8.8.8",
    )
    parser.add_argument(
        "--selectors",
        default=",".join(DEFAULT_SELECTORS),
        help=f"Seletores DKIM (separados por virgula). Padrao: {','.join(DEFAULT_SELECTORS)}",
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
        return 0

    selectors = [s.strip() for s in args.selectors.split(",") if s.strip()]

    result = scan_email_security(
        domain=domain,
        nameserver=args.nameserver,
        selectors=selectors,
        timeout=args.query_timeout,
    )

    if not quiet:
        print_results(result)

    if args.output:
        write_output(
            args.output,
            [asdict(result)],
            ["domain", "overall_status", "issues"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do Email Security."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.domain),
        prompt="secemail> ",
        description="Email Security interativo — verifica DMARC/SPF/DKIM.",
        example="example.com --selectors default,google",
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --selectors default,google,s1\n"
            "  example.com --nameserver 1.1.1.1"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
