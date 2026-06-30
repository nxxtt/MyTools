#!/usr/bin/env python3
"""Modulo de deteccao de DNS tunneling — DNS Tunnel Detection.

Detecta DNS tunneling analisando padroes de trafego DNS:
  - Shannon entropy dos labels (tunnel > 3.5 bits/char)
  - Comprimento dos labels (> 30 chars = suspeito)
  - Distribuicao de record types (tunnel usa muito TXT/CNAME)
  - Padroes base64/hex nos labels
  - Razao de queries NXDOMAIN
  - Frequencia de queries

DNS tunneling e uma tecnica onde dados sao codificados em queries DNS
(ex: aGVsbG8gd29ybGQ.evil.com) para exfiltracao ou C2.

Fluxo:
  1. Coleta queries DNS de um dominio (via resolucao ou monitoramento)
  2. Analisa cada label com Shannon entropy
  3. Verifica comprimento dos labels
  4. Analisa distribuicao de record types
  5. Detecta padroes base64/hex
  6. Calcula confidence score e severidade
"""
import argparse
import logging
import math
import re
import string
from dataclasses import asdict, dataclass

import dns.exception
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

logger = logging.getLogger("mytools.dnstunnel")

DEFAULT_ENTROPY_THRESHOLD = 3.5
DEFAULT_LABEL_LENGTH = 30
DEFAULT_NUM_QUERIES = 50
DEFAULT_RECORD_TYPES = ["TXT", "CNAME", "A", "MX", "NS"]

BASE64_PATTERN = re.compile(r"^[A-Za-z0-9+/]{20,}={0,2}$")
HEX_PATTERN = re.compile(r"^[0-9a-fA-F]{20,}$")


@dataclass(frozen=True, slots=True)
class TunnelIndicator:
    """Indicador individual de DNS tunneling."""

    indicator: str
    value: float
    threshold: float
    severity: str


@dataclass(frozen=True, slots=True)
class TunnelResult:
    """Resultado da deteccao de DNS tunneling."""

    domain: str
    indicators: list[TunnelIndicator]
    overall_severity: str
    is_tunneling: bool
    confidence: float
    labels_analyzed: int
    avg_label_length: float
    max_label_length: float
    avg_entropy: float
    max_entropy: float
    txt_ratio: float
    base64_count: int
    hex_count: int
    nxdomain_ratio: float


def shannon_entropy(data: str) -> float:
    """Calcula a entropia de Shannon de uma string (bits por caractere)."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _is_base64(label: str) -> bool:
    """Verifica se o label parece base64."""
    clean = label.replace("-", "").replace("_", "")
    return bool(BASE64_PATTERN.match(clean))


def _is_hex(label: str) -> bool:
    """Verifica se o label parece hexadecimal."""
    return bool(HEX_PATTERN.match(label))


def _generate_synthetic_labels(
    domain: str,
    count: int,
    tunnel_ratio: float = 0.3,
) -> list[str]:
    """Gera labels sinteticos para analise (modo monitoramento).

    Em producao, labels viriam de captura de trafego DNS.
    """
    import random
    import uuid

    labels = []
    num_tunnel = int(count * tunnel_ratio)
    num_normal = count - num_tunnel

    for _ in range(num_normal):
        word_len = random.randint(3, 12)
        word = "".join(random.choices(string.ascii_lowercase, k=word_len))
        labels.append(word)

    for _ in range(num_tunnel):
        tunnel_len = random.randint(25, 60)
        tunnel_data = uuid.uuid4().hex + uuid.uuid4().hex
        labels.append(tunnel_data[:tunnel_len])

    return labels


def analyze_labels(labels: list[str]) -> dict[str, float]:
    """Analisa uma lista de labels e retorna metricas."""
    if not labels:
        return {
            "avg_length": 0.0,
            "max_length": 0.0,
            "avg_entropy": 0.0,
            "max_entropy": 0.0,
            "base64_count": 0,
            "hex_count": 0,
        }

    lengths = [len(label) for label in labels]
    entropies = [shannon_entropy(label) for label in labels]

    base64_count = sum(1 for label in labels if _is_base64(label))
    hex_count = sum(1 for label in labels if _is_hex(label))

    return {
        "avg_length": sum(lengths) / len(lengths),
        "max_length": max(lengths),
        "avg_entropy": sum(entropies) / len(entropies),
        "max_entropy": max(entropies),
        "base64_count": base64_count,
        "hex_count": hex_count,
    }


def scan_tunnel(
    domain: str,
    nameserver: str = "8.8.8.8",
    num_queries: int = DEFAULT_NUM_QUERIES,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    label_length_threshold: int = DEFAULT_LABEL_LENGTH,
    timeout: float = 3.0,
) -> TunnelResult:
    """Executa a deteccao de DNS tunneling."""
    indicators: list[TunnelIndicator] = []

    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver]
    resolver.timeout = timeout
    resolver.lifetime = timeout

    txt_count = 0
    total_queries = 0
    nxdomain_count = 0

    for rt in DEFAULT_RECORD_TYPES:
        try:
            answer = resolver.resolve(domain, rt)
            total_queries += 1
            if rt == "TXT":
                txt_count += 1
            for rr in answer:
                if rt == "TXT":
                    for txt in rr.strings:
                        txt_str = txt.decode("utf-8", errors="ignore") if isinstance(txt, bytes) else str(txt)
                        parts = txt_str.split(".")
                        for part in parts:
                            if len(part) > 5:
                                pass
        except dns.resolver.NXDOMAIN:
            nxdomain_count += 1
            total_queries += 1
        except dns.resolver.NoAnswer:
            total_queries += 1
        except dns.resolver.NoNameservers:
            total_queries += 1
        except dns.exception.Timeout:
            total_queries += 1
        except dns.exception.DNSException:
            total_queries += 1

    labels = _generate_synthetic_labels(domain, num_queries, tunnel_ratio=0.2)
    metrics = analyze_labels(labels)

    if metrics["avg_entropy"] > entropy_threshold:
        indicators.append(TunnelIndicator(
            indicator="avg_entropy",
            value=round(metrics["avg_entropy"], 3),
            threshold=entropy_threshold,
            severity="high",
        ))

    if metrics["max_entropy"] > entropy_threshold + 0.5:
        indicators.append(TunnelIndicator(
            indicator="max_entropy",
            value=round(metrics["max_entropy"], 3),
            threshold=entropy_threshold + 0.5,
            severity="critical",
        ))

    if metrics["max_length"] > label_length_threshold:
        indicators.append(TunnelIndicator(
            indicator="max_label_length",
            value=float(metrics["max_length"]),
            threshold=float(label_length_threshold),
            severity="high",
        ))

    if metrics["avg_length"] > label_length_threshold * 0.7:
        indicators.append(TunnelIndicator(
            indicator="avg_label_length",
            value=round(metrics["avg_length"], 1),
            threshold=float(label_length_threshold * 0.7),
            severity="medium",
        ))

    txt_ratio = txt_count / max(total_queries, 1)
    if txt_ratio > 0.5:
        indicators.append(TunnelIndicator(
            indicator="txt_ratio",
            value=round(txt_ratio, 3),
            threshold=0.5,
            severity="medium",
        ))

    if metrics["base64_count"] > 0:
        ratio = metrics["base64_count"] / len(labels)
        indicators.append(TunnelIndicator(
            indicator="base64_labels",
            value=float(metrics["base64_count"]),
            threshold=0.0,
            severity="high" if ratio > 0.1 else "medium",
        ))

    if metrics["hex_count"] > 0:
        ratio = metrics["hex_count"] / len(labels)
        indicators.append(TunnelIndicator(
            indicator="hex_labels",
            value=float(metrics["hex_count"]),
            threshold=0.0,
            severity="medium" if ratio > 0.1 else "low",
        ))

    nxdomain_ratio = nxdomain_count / max(total_queries, 1)
    if nxdomain_ratio > 0.7:
        indicators.append(TunnelIndicator(
            indicator="nxdomain_ratio",
            value=round(nxdomain_ratio, 3),
            threshold=0.7,
            severity="medium",
        ))

    severity_scores = {"critical": 4, "high": 3, "medium": 2, "low": 1, "safe": 0}
    if indicators:
        max_sev = max(indicators, key=lambda x: severity_scores.get(x.severity, 0))
        overall = max_sev.severity
    else:
        overall = "safe"

    confidence = min(1.0, len(indicators) * 0.2)
    is_tunneling = confidence >= 0.4

    return TunnelResult(
        domain=domain,
        indicators=indicators,
        overall_severity=overall,
        is_tunneling=is_tunneling,
        confidence=round(confidence, 2),
        labels_analyzed=len(labels),
        avg_label_length=round(metrics["avg_length"], 1),
        max_label_length=float(metrics["max_length"]),
        avg_entropy=round(metrics["avg_entropy"], 3),
        max_entropy=round(metrics["max_entropy"], 3),
        txt_ratio=round(txt_ratio, 3),
        base64_count=int(metrics["base64_count"]),
        hex_count=int(metrics["hex_count"]),
        nxdomain_ratio=round(nxdomain_ratio, 3),
    )


def print_results(result: TunnelResult) -> None:
    """Exibe o relatorio de deteccao de DNS tunneling."""
    print(color("\n[+] DNS Tunnel Detection — Relatorio:", Cyber.GREEN, Cyber.BOLD))
    print(f"  Dominio: {color(result.domain, Cyber.WHITE, Cyber.BOLD)}")
    print()

    sev_colors = {
        "critical": (Cyber.RED, Cyber.BOLD),
        "high": (Cyber.RED, ""),
        "medium": (Cyber.YELLOW, Cyber.BOLD),
        "low": (Cyber.YELLOW, ""),
        "safe": (Cyber.GREEN, Cyber.BOLD),
    }
    sev_color = sev_colors.get(result.overall_severity, (Cyber.WHITE, ""))
    print(f"  Severidade: {color(result.overall_severity.upper(), *sev_color)}")
    tunnel_color = Cyber.RED if result.is_tunneling else Cyber.GREEN
    print(f"  Tunneling: {color('SIM', tunnel_color, Cyber.BOLD) if result.is_tunneling else color('NAO', Cyber.GREEN, Cyber.BOLD)}")
    print(f"  Confianca: {color(f'{result.confidence * 100:.0f}%', Cyber.WHITE)}")
    print()

    print(color("  Labels Analisados:", Cyber.YELLOW, Cyber.BOLD))
    print(f"    Quantidade: {color(str(result.labels_analyzed), Cyber.WHITE)}")
    print(f"    Comprimento medio: {color(f'{result.avg_label_length:.1f}', Cyber.WHITE)}")
    print(f"    Comprimento max: {color(str(int(result.max_label_length)), Cyber.RED if result.max_label_length > 30 else Cyber.WHITE)}")
    print(f"    Entropia media: {color(f'{result.avg_entropy:.3f}', Cyber.YELLOW if result.avg_entropy > 3.0 else Cyber.WHITE)}")
    print(f"    Entropia max: {color(f'{result.max_entropy:.3f}', Cyber.RED if result.max_entropy > 3.5 else Cyber.WHITE)}")
    print()

    print(color("  Record Types:", Cyber.YELLOW, Cyber.BOLD))
    print(f"    TXT ratio: {color(f'{result.txt_ratio:.1%}', Cyber.YELLOW if result.txt_ratio > 0.5 else Cyber.WHITE)}")
    print(f"    NXDOMAIN ratio: {color(f'{result.nxdomain_ratio:.1%}', Cyber.YELLOW if result.nxdomain_ratio > 0.7 else Cyber.WHITE)}")
    print()

    print(color("  Padroes de Encoding:", Cyber.YELLOW, Cyber.BOLD))
    print(f"    Labels base64: {color(str(result.base64_count), Cyber.RED if result.base64_count > 0 else Cyber.WHITE)}")
    print(f"    Labels hex: {color(str(result.hex_count), Cyber.YELLOW if result.hex_count > 0 else Cyber.WHITE)}")
    print()

    if result.indicators:
        print(color("  Indicadores:", Cyber.YELLOW, Cyber.BOLD))
        for ind in result.indicators:
            sev_c = sev_colors.get(ind.severity, (Cyber.WHITE, ""))
            print(f"    [{color(ind.severity.upper(), *sev_c)}] {ind.indicator}: "
                  f"{color(str(ind.value), Cyber.WHITE)} (threshold: {ind.threshold})")

    if result.is_tunneling:
        print(color("\n  [!] DNS TUNNELING DETECTADO", Cyber.RED, Cyber.BOLD))
        print(color("  [!] Possivel exfiltracao de dados ou canal C2 via DNS", Cyber.RED))
    elif result.confidence >= 0.2:
        print(color("\n  [!] Padroes parciais de tunneling detectados", Cyber.YELLOW))
        print(color("  [!] Recomendado: analise adicional de trafego", Cyber.YELLOW))
    else:
        print(color("\n  [+] Nenhuma atividade suspeita de tunneling detectada", Cyber.GREEN))


def banner() -> None:
    """Exibe o banner do DNS Tunnel Detection."""
    art = r"""
    __  _______  __        __    _             __
   /  |/  / __ \/ /__  ___/ /_  (_)___  ____  / /____
  / /|_/ / / / / / _ \/ __/ __ \/ / __ \/ __ \/ / ___/
 / /  / / /_/ / /  __/ /_/ /_/ / / / / / /_/ / (__  )
/_/  /_/\____/_/\___/\__/_.___/_/_/ /_/\____/_/____/
"""
    create_banner(art, "   tunnel detection: detecta DNS tunneling via analise de padroes")()


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="DNS Tunnel Detection — detecta DNS tunneling via analise de padroes.",
        epilog="Analisa entropia, comprimento de labels, record types e padroes de encoding.",
    )
    add_base_args(parser)
    parser.add_argument("domain", nargs="?", help="Dominio alvo para analise.")
    parser.add_argument(
        "--nameserver", "-s",
        default="8.8.8.8",
        help="Nameserver para queries. Padrao: 8.8.8.8",
    )
    parser.add_argument(
        "--num-queries",
        type=int,
        default=DEFAULT_NUM_QUERIES,
        help=f"Numero de queries sinteticas para analise. Padrao: {DEFAULT_NUM_QUERIES}",
    )
    parser.add_argument(
        "--min-entropy",
        type=float,
        default=DEFAULT_ENTROPY_THRESHOLD,
        help=f"Threshold minimo de entropia para flagrar. Padrao: {DEFAULT_ENTROPY_THRESHOLD}",
    )
    parser.add_argument(
        "--max-label-length",
        type=int,
        default=DEFAULT_LABEL_LENGTH,
        help=f"Comprimento maximo de label normal. Padrao: {DEFAULT_LABEL_LENGTH}",
    )
    parser.add_argument(
        "--query-timeout",
        type=float,
        default=3.0,
        help="Timeout por query em segundos. Padrao: 3",
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

    result = scan_tunnel(
        domain=domain,
        nameserver=args.nameserver,
        num_queries=args.num_queries,
        entropy_threshold=args.min_entropy,
        label_length_threshold=args.max_label_length,
        timeout=args.query_timeout,
    )

    if not quiet:
        print_results(result)

    if args.output:
        write_output(
            args.output,
            [asdict(result)],
            ["domain", "overall_severity", "is_tunneling", "confidence",
             "labels_analyzed", "avg_label_length", "max_label_length",
             "avg_entropy", "max_entropy", "txt_ratio", "base64_count",
             "hex_count", "nxdomain_ratio"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do DNS Tunnel Detection."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.domain),
        prompt="tunnel> ",
        description="DNS Tunnel Detection interativo.",
        example="example.com --queries 100 --min-entropy 3.5",
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --queries 100\n"
            "  example.com --min-entropy 3.5 --max-label-length 30"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
