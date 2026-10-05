#!/usr/bin/env python3

"""Scanner de DNS Zone Transfer (AXFR) para detecção de configurações inseguras.



Fluxo principal:

  1. Consulta registros NS do dominio (dns.resolver.resolve)

  2. Resolve cada NS em IP (dns.resolver.resolve A record)

  3. Tenta AXFR (zone transfer) contra cada NS

  4. Retorna todos os registros DNS se bem-sucedido



O que e zone transfer (AXFR)?

  Protocolo DNS que permite copiar toda a zona DNS de um servidor.

  Se habilitado indevidamente, revela todos os registros (subdominios,

  IPs, MX, etc.) para qualquer pessoa que consulte.



Vulnerabilidade:

  Nameservers mal configurados permitem AXFR de qualquer IP.

  Isso expoe a estrutura interna da rede para enumeracao.



Uso do dnspython:

  - dns.resolver.resolve: consultas DNS standard

  - dns.query.inbound_xfr: tentativa de zone transfer AXFR

  - dns.zone: parsing da zona transferida

"""

import argparse
import logging
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

import dns.exception
import dns.name
import dns.query
import dns.rdatatype
import dns.resolver
import dns.zone

from mytools.core.base import BaseScanner, ScanGroup
from mytools.core.utils import (
    Cyber,
    color,
    create_banner,
    ensure_output_dir,
    print_exploit_info,
    print_json,
    run_main_loop,
    write_output,
)

logger = logging.getLogger("mytools.dnstransfer")


BANNER_ART = r"""

 ____  _   _ _____     _   ___  _  __

|  _ \| | | |  ___|   | \ | \ \/ /

| | | | | | | |_ ______|  \| |\  /

| |_| | |_| |  _|_____| |\  / /  \

|____/ \___/|_|       |_| \_/_/\_\

"""


AXFR_TIMEOUT = 10


banner = create_banner(BANNER_ART, "   DNS zone transfer (AXFR) scanner")


@dataclass(frozen=True, slots=True)
class XfrResult:
    """Resultado de uma tentativa de zone transfer contra um nameserver."""

    domain: str

    nameserver: str

    ns_ip: str

    zone_transferred: bool

    record_count: int = 0

    records: list[str] = field(default_factory=list)

    error: str = ""

    elapsed: float = 0.0

    exploit: str = ""

    tool: str = ""


def get_nameservers(domain: str) -> list[str]:
    """Consulta os nameservers (NS) autoritativos para um domínio.



    Args:

        domain: Nome de domínio alvo (ex: "example.com").



    Returns:

        Lista de hostnames de nameservers.

    """

    try:
        answer = dns.resolver.resolve(domain, "NS")

        return sorted(str(rr.target).rstrip(".") for rr in answer)

    except dns.resolver.NoAnswer:
        logger.debug("nenhum registro NS encontrado para %s", domain)

        return []

    except dns.resolver.NXDOMAIN:
        logger.debug("dominio %s nao existe (NXDOMAIN)", domain)

        return []

    except dns.exception.DNSException as error:
        logger.debug("erro ao resolver NS para %s: %s", domain, error)

        return []


def resolve_ns_to_ip(ns_hostname: str) -> str:
    """Resolve o hostname de um nameserver em seu endereço IP.



    Args:

        ns_hostname: Hostname do nameserver (ex: "ns1.example.com").



    Returns:

        Endereço IP resolvido.



    Raises:

        ValueError: Se não for possível resolver o hostname.

    """

    try:
        answers = dns.resolver.resolve(ns_hostname, "A")

        return str(answers[0])

    except dns.exception.DNSException as error:
        raise ValueError(f"nao foi possivel resolver {ns_hostname}: {error}") from error


def try_zone_transfer(
    domain: str,
    ns_hostname: str,
    ns_ip: str,
    timeout: float = AXFR_TIMEOUT,
) -> XfrResult:
    """Tenta realizar um zone transfer (AXFR) contra um nameserver.



    Args:

        domain: Domínio alvo.

        ns_hostname: Hostname do nameserver.

        ns_ip: Endereço IP do nameserver.

        timeout: Timeout em segundos para a operação AXFR.



    Returns:

        XfrResult com o resultado da tentativa.

    """

    start = time.monotonic()

    try:
        zone = dns.zone.Zone(dns.name.from_text(domain))
        dns.query.inbound_xfr(
            ns_ip,
            zone,
            timeout=timeout,
            lifetime=timeout,
        )

        elapsed = time.monotonic() - start

        records: list[str] = []

        for name, node in zone.nodes.items():  # pyright: ignore[reportGeneralTypeIssues]
            for rdataset in node.rdatasets:
                records.extend(
                    f"{name} {dns.rdatatype.to_text(rdataset.rdtype)} {rdata}"
                    for rdata in rdataset
                )

        return XfrResult(
            domain=domain,
            nameserver=ns_hostname,
            ns_ip=ns_ip,
            zone_transferred=True,
            record_count=len(records),
            records=sorted(records),
            elapsed=elapsed,
            exploit=f"dig axfr {domain} @{ns_hostname}",
            tool="dig",
        )

    except dns.exception.FormError as error:
        elapsed = time.monotonic() - start

        return XfrResult(
            domain=domain,
            nameserver=ns_hostname,
            ns_ip=ns_ip,
            zone_transferred=False,
            error=f"AXFR recusado (FormError): {error}",
            elapsed=elapsed,
            exploit="",
            tool="",
        )
    except dns.exception.Timeout as error:
        elapsed = time.monotonic() - start

        return XfrResult(
            domain=domain,
            nameserver=ns_hostname,
            ns_ip=ns_ip,
            zone_transferred=False,
            error=f"timeout apos {timeout}s: {error}",
            elapsed=elapsed,
            exploit="",
            tool="",
        )
    except dns.exception.DNSException as error:
        elapsed = time.monotonic() - start

        return XfrResult(
            domain=domain,
            nameserver=ns_hostname,
            ns_ip=ns_ip,
            zone_transferred=False,
            error=f"erro DNS: {error}",
            elapsed=elapsed,
            exploit="",
            tool="",
        )
    except Exception as error:
        elapsed = time.monotonic() - start

        return XfrResult(
            domain=domain,
            nameserver=ns_hostname,
            ns_ip=ns_ip,
            zone_transferred=False,
            error=f"erro inesperado: {error}",
            elapsed=elapsed,
            exploit="",
        )


def run_xfr_scan(
    domain: str,
    timeout: float = AXFR_TIMEOUT,
) -> list[XfrResult]:
    """Executa o scan completo de zone transfer para todas as nameservers de um domínio.



    Args:

        domain: Domínio alvo.

        timeout: Timeout em segundos para cada tentativa AXFR.



    Returns:

        Lista de XfrResult, uma entrada por nameserver testado.

    """

    domain = domain.strip().lower()

    if not domain:
        raise ValueError("informe um dominio valido")

    ns_list = get_nameservers(domain)

    if not ns_list:
        logger.error("Nenhum nameserver encontrado para %s", domain)

        return []
    logger.info("Nameservers encontrados: %d", len(ns_list))

    for ns in ns_list:
        logger.info("    -> %s", ns)

    print()

    results: list[XfrResult] = []

    for ns in ns_list:
        try:
            ns_ip = resolve_ns_to_ip(ns)

        except ValueError as error:
            logger.error("%s: %s", ns, error)
            results.append(
                XfrResult(
                    domain=domain,
                    nameserver=ns,
                    ns_ip="",
                    zone_transferred=False,
                    error=str(error),
                    exploit="",
                )
            )

            continue

        logger.info("Testando AXFR em %s (%s)...", ns, ns_ip)
        result = try_zone_transfer(domain, ns, ns_ip, timeout)
        results.append(result)

        if result.zone_transferred:
            logger.warning("VULNERAVEL!")

        else:
            logger.info("recusado")

    return results


def _print_results(results: list[XfrResult]) -> None:
    """Exibe os resultados em formato de tabela no terminal."""

    vulnerable = [r for r in results if r.zone_transferred]

    if vulnerable:
        print()

        print(
            color("[!]", Cyber.RED, Cyber.BOLD),
            color(
                f"ZONA TRANSFER PERMITIDA! {len(vulnerable)} nameserver(s) vulneravel(is)!",
                Cyber.RED,
                Cyber.BOLD,
            ),
        )

        for result in vulnerable:
            print()

            print(
                color("  Nameserver:", Cyber.CYAN, Cyber.BOLD),
                color(result.nameserver, Cyber.WHITE),
            )

            print(
                color("  IP:", Cyber.CYAN, Cyber.BOLD), color(result.ns_ip, Cyber.WHITE)
            )

            print(
                color("  Registros:", Cyber.CYAN, Cyber.BOLD),
                color(str(result.record_count), Cyber.YELLOW, Cyber.BOLD),
            )

            print(
                color("  Tempo:", Cyber.CYAN, Cyber.BOLD),
                color(f"{result.elapsed:.2f}s", Cyber.YELLOW),
            )

            if result.records:
                print(color("  Primeiros registros:", Cyber.CYAN))

                for record in result.records[:20]:
                    print(color(f"    {record}", Cyber.GRAY))

                if len(result.records) > 20:
                    print(
                        color(
                            f"    ... e mais {len(result.records) - 20} registros",
                            Cyber.GRAY,
                        )
                    )

            print_exploit_info(result.exploit, result.tool)

    else:
        print()

        print(
            color("[*]", Cyber.GREEN, Cyber.BOLD),
            color(
                "Nenhum nameserver permitiu zone transfer.",
                Cyber.GREEN,
            ),
        )


async def run_scan(
    domain: str,
    timeout: float,
    quiet: bool = False,
    output: str | None = None,
    json_output: bool = False,
    output_dir: str | None = None,
) -> int:
    """Executa uma unica varredura de zone transfer (wrap do run_once original)."""

    domain = domain.strip().lower()

    start = time.monotonic()

    results = run_xfr_scan(domain, timeout=timeout)

    elapsed = time.monotonic() - start

    if not quiet:
        _print_results(results)

        logger.info(
            "Finalizado em %.2fs. Nameservers: %d. Vulneraveis: %d.",
            elapsed,
            len(results),
            sum(1 for r in results if r.zone_transferred),
        )

    if output:
        rows = [asdict(r) for r in results]

        write_output(
            output,
            rows,
            [
                "domain",
                "nameserver",
                "ns_ip",
                "zone_transferred",
                "record_count",
                "records",
                "error",
                "elapsed",
            ],
            quiet=quiet,
        )

    if json_output:
        print_json([asdict(r) for r in results])

    if output_dir:
        ensure_output_dir(output_dir)

        write_output(
            f"{output_dir}/{domain}.json",
            [asdict(r) for r in results],
            [
                "domain",
                "nameserver",
                "ns_ip",
                "zone_transferred",
                "record_count",
                "records",
                "error",
                "elapsed",
            ],
            quiet=quiet,
        )

    failed = not results or any(r.error for r in results)

    return 1 if failed or any(r.zone_transferred for r in results) else 0


class DnstransferScanner(BaseScanner):
    """Scanner de DNS Zone Transfer (AXFR) — dispatcher BaseScanner (Grupo A)."""

    prog = "mytools-dnsxfer"
    description = (
        "Scanner de DNS Zone Transfer (AXFR) para detecção de configurações inseguras."
    )
    prompt = "dnsxfer> "
    module_name = "mytools.dnstransfer"
    module_type = "core"
    group = ScanGroup.A
    scan_fn = staticmethod(run_scan)

    @staticmethod
    def _get_target(args: argparse.Namespace) -> str | None:
        return getattr(args, "domain", None)

    def build_parser(self) -> argparse.ArgumentParser:
        # O parser original chamava add_base_args(timeout_default=AXFR_TIMEOUT);
        # add_common_args usa o default 5.0 — restaura o default do modulo.
        parser = super().build_parser()
        parser.set_defaults(timeout=AXFR_TIMEOUT)
        return parser

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "domain",
            nargs="?",
            help="Domínio alvo. Ex: example.com",
        )

    def _pre_scan(self, args: argparse.Namespace) -> int | None:
        if args.timeout <= 0:
            raise ValueError("timeout precisa ser maior que zero")
        return None

    def _describe_plan(self, args: argparse.Namespace) -> int:
        domain = (self._get_target(args) or "").strip().lower()
        logger.warning("Nenhuma consulta DNS sera realizada.")
        logger.info("Dominio: %s", domain)
        logger.info("Nameservers: serao consultados na execucao real")
        return 0

    def _build_run_once_kwargs(self, args: argparse.Namespace) -> dict[str, Any]:
        return {
            "domain": self._get_target(args),
            "timeout": args.timeout,
            "quiet": bool(getattr(args, "quiet", False)),
            "output": getattr(args, "output", None),
            "json_output": getattr(args, "json_output", False),
            "output_dir": getattr(args, "output_dir", None),
        }

    async def run_scan(self, **kwargs: Any) -> Any:
        return await run_scan(**kwargs)  # type: ignore[override]

    def print_results(self, result: object) -> None:
        _print_results(result)  # type: ignore[arg-type]

    def _make_banner(self) -> Callable[[], None]:
        return banner

    def main(self) -> int:
        """Ponto de entrada principal (mantem validacao de dominio original)."""

        def _validate(args: argparse.Namespace) -> None:
            if not args.domain:
                raise ValueError("Informe um dominio alvo.")

        return run_main_loop(
            parser=self.build_parser(),
            banner_fn=self._make_banner(),
            run_fn=self.run_once,
            has_target=lambda a: bool(self._get_target(a)),
            prompt=self.prompt,
            description=f"{self.description.strip()} interativo.",
            example=self._example(),
            validate_fn=_validate,
            contextual_help=self._help(),
        )

    def _example(self) -> str:
        return "example.com -t 15"

    def _help(self) -> str:
        return (
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com -t 15 -o xfr.json"
        )


scanner = DnstransferScanner()
main = scanner.main
run_once = scanner.run_once
build_parser = scanner.build_parser

if __name__ == "__main__":
    raise SystemExit(main())
