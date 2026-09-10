"""PCAP Analysis — analise de capturas de rede com dpkt."""

from __future__ import annotations

import argparse
import logging
import re
from collections import Counter
from pathlib import Path
from typing import Any

from anyio import Path as AsyncPath

from mytools.core.base import BaseScanner, ScanGroup
from mytools.core.utils import Cyber, color, create_banner
from mytools.network._pcap_common import (
    PCAP_SECRET_PATTERNS,
    PcapAttempt,
    PcapResult,
)

logger = logging.getLogger(__name__)

_BANNER_TEXT = (
    "  _____          _       __  __            _ _             \n"
    " |  __ \\        | |     |  \\/  |          (_) |            \n"
    " | |__) |__  ___| |_ ___| \\  / | __ _ _ __ _| |_ _   _ ___ \n"
    " |  _ ___/ _ \\/ __/ __| |\\/| |/ _` | '__| | | | | | |/ _ \\\n"
    " | |_) |  __/\\__ \\__ \\ | |  | | (_| | |  | | | | |_| |  __/\n"
    " |____/ \\___||___/___/ |_|  |_|\\__,_|_|  |_|_|_|\\__,_|\\___|\n"
)


def _detect_file_format(file_path: Path) -> str:
    try:
        with file_path.open("rb") as f:
            magic = f.read(4)
        if magic == b"\xd4\xc3\xb2\xa1":
            return "pcap_le"
        if magic == b"\xa1\xb2\xc3\xd4":
            return "pcap_be"
        if magic == b"\x0a\x0d\x0d\x0a":
            return "pcapng"
    except OSError, PermissionError:
        pass
    return "unknown"


def _parse_pcap(file_path: Path) -> tuple[int, list[str], list[bytes]]:
    total = 0
    protos: Counter[str] = Counter()
    payloads: list[bytes] = []

    try:
        import dpkt

        with file_path.open("rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
            except ValueError:
                f.seek(0)
                try:
                    pcap = dpkt.pcapng.Reader(f)
                except ValueError:
                    return 0, [], []

            for _ts, buf in pcap:
                total += 1
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                except dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError:
                    continue

                if not isinstance(eth.data, dpkt.ip.IP):
                    if isinstance(eth.data, dpkt.sll.SLL):
                        ip = eth.data.data
                        if not isinstance(ip, dpkt.ip.IP):
                            continue
                    else:
                        continue
                else:
                    ip = eth.data

                proto_name = _proto_name(ip.p)  # type: ignore[attr-defined]
                protos[proto_name] += 1

                if isinstance(ip.data, dpkt.tcp.TCP):
                    tcp = ip.data
                    if tcp.data:
                        payloads.append(bytes(tcp.data))
                elif isinstance(ip.data, dpkt.udp.UDP):
                    udp = ip.data
                    if udp.data:
                        payloads.append(bytes(udp.data))

    except Exception as exc:
        logger.debug("Failed to parse PCAP: %s", exc)
        return 0, [], []

    sorted_protos = sorted(protos.keys(), key=lambda p: -protos[p])
    return total, sorted_protos, payloads


def _proto_name(ip_proto: int) -> str:
    names = {1: "ICMP", 6: "TCP", 17: "UDP", 47: "GRE", 50: "ESP"}
    return names.get(ip_proto, f"IP-{ip_proto}")


def _check_protocol_anomalies(
    protos: list[str],
    total: int,
) -> list[PcapAttempt]:
    attempts: list[PcapAttempt] = []

    proto_counts = Counter(protos)

    if "ICMP" in proto_counts and total > 0:
        icmp_ratio = proto_counts["ICMP"] / total
        if icmp_ratio > 0.3:
            attempts.append(
                PcapAttempt(
                    check_name="icmp_flood",
                    vulnerable=True,
                    severity="medium",
                    description=f"Alta proporcao ICMP: {icmp_ratio:.1%} dos pacotes",
                )
            )

    if "GRE" in proto_counts:
        attempts.append(
            PcapAttempt(
                check_name="gre_tunnel",
                vulnerable=False,
                severity="low",
                description="Protocolo GRE detectado (possivel tunel)",
            )
        )

    if "ESP" in proto_counts:
        attempts.append(
            PcapAttempt(
                check_name="ipsec_traffic",
                vulnerable=False,
                severity="low",
                description="Trafego IPsec/ESP detectado",
            )
        )

    return attempts


def _check_secrets_in_payloads(
    payloads: list[bytes],
    patterns: dict[str, re.Pattern[bytes]] | None = None,
) -> list[PcapAttempt]:
    attempts: list[PcapAttempt] = []
    effective = patterns or PCAP_SECRET_PATTERNS

    for i, payload in enumerate(payloads):
        clean = payload.replace(b"\x00", b" ")
        for pat_name, pattern in effective.items():
            match = pattern.search(clean)
            if match:
                preview = match.group(0)[:80]
                attempts.append(
                    PcapAttempt(
                        check_name=f"secret_{pat_name}",
                        vulnerable=True,
                        severity="high",
                        description=f"Segredo no pacote #{i}: {pat_name}",
                        details=preview.decode("utf-8", errors="replace"),
                    )
                )

    return attempts


def _check_dns_tunneling(
    payloads: list[bytes],
) -> list[PcapAttempt]:
    attempts: list[PcapAttempt] = []

    try:
        import dpkt

        for i, payload in enumerate(payloads):
            try:
                dns = dpkt.dns.DNS(payload)
                if dns.qr == 0 and len(dns.qd) > 0:
                    qname = dns.qd[0].name if dns.qd else b""
                    if isinstance(qname, bytes) and len(qname) > 50:
                        attempts.append(
                            PcapAttempt(
                                check_name="dns_tunnel",
                                vulnerable=True,
                                severity="high",
                                description=f"DNS query异常 long ({len(qname)} bytes) no pacote #{i}",
                                details=qname[:60].decode("utf-8", errors="replace"),
                            )
                        )
            except dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError:
                continue
    except Exception as exc:
        logger.debug("DNS tunnel check failed: %s", exc)

    return attempts


def _check_large_payloads(
    payloads: list[bytes],
    threshold: int = 8192,
) -> list[PcapAttempt]:
    attempts: list[PcapAttempt] = []

    large = [(i, len(p)) for i, p in enumerate(payloads) if len(p) > threshold]
    if large:
        total_bytes = sum(sz for _, sz in large)
        attempts.append(
            PcapAttempt(
                check_name="large_payloads",
                vulnerable=False,
                severity="low",
                description=f"{len(large)} payloads grandes (>{threshold} bytes)",
                details=f"Total: {total_bytes:,} bytes nos payloads grandes",
            )
        )

    return attempts


async def run_pcap_analysis(
    target: str,
    checks: list[str] | None = None,
) -> PcapResult:
    file_path = await AsyncPath(target).resolve()
    if not await file_path.exists():
        return PcapResult(
            target=target,
            file_size=0,
            total_packets=0,
            issues=[f"Target not found: {target}"],
            overall_status="error",
        )

    if not await file_path.is_file():
        return PcapResult(
            target=target,
            file_size=0,
            total_packets=0,
            issues=["Target is not a file"],
            overall_status="error",
        )
    stat_info = await file_path.stat()
    file_size = stat_info.st_size
    pathlib_file = Path(str(file_path))

    fmt = _detect_file_format(pathlib_file)
    if fmt == "unknown":
        return PcapResult(
            target=target,
            file_size=file_size,
            total_packets=0,
            issues=["Formato de arquivo nao reconhecido (use .pcap ou .pcapng)"],
            overall_status="error",
        )

    total, protos, payloads = _parse_pcap(pathlib_file)

    effective_checks = (
        set(checks)
        if checks
        else {
            "protocols",
            "secrets",
            "dns_tunnel",
            "large",
        }
    )

    all_attempts: list[PcapAttempt] = []

    if "protocols" in effective_checks:
        all_attempts.extend(_check_protocol_anomalies(protos, total))

    if "secrets" in effective_checks:
        all_attempts.extend(_check_secrets_in_payloads(payloads))

    if "dns_tunnel" in effective_checks:
        all_attempts.extend(_check_dns_tunneling(payloads))

    if "large" in effective_checks:
        all_attempts.extend(_check_large_payloads(payloads))

    issues: list[str] = []
    overall = "clean"
    if all_attempts:
        overall = "found"
        sev_counts: dict[str, int] = {}
        for a in all_attempts:
            sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
        issues.extend(
            f"{sev_counts[s]} {s} issue(s)"
            for s in ("critical", "high", "medium", "low")
            if s in sev_counts
        )

    return PcapResult(
        target=target,
        file_size=file_size,
        total_packets=total,
        protocols=protos,
        attempts=all_attempts,
        issues=issues,
        overall_status=overall,
    )


class PcapAnalysisScanner(BaseScanner):
    prog = "mytools-pcap"
    description = "PCAP Analysis — analise de capturas de rede (.pcap, .pcapng)"
    prompt = "pcap> "
    module_name = "mytools.network"
    banner_text = _BANNER_TEXT
    group = ScanGroup.B

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "target",
            nargs="?",
            help="Arquivo PCAP/PCAPNG para analisar",
        )
        parser.add_argument(
            "-c",
            "--checks",
            nargs="+",
            choices=["protocols", "secrets", "dns_tunnel", "large", "all"],
            default=["protocols", "secrets", "dns_tunnel", "large"],
            help="Tipos de check para executar",
        )

    @staticmethod
    def _get_target(args: argparse.Namespace) -> str | None:
        return getattr(args, "target", None)

    def _build_run_once_kwargs(self, args: argparse.Namespace) -> dict[str, Any]:
        checks = getattr(args, "checks", None)
        if checks and "all" in checks:
            checks = ["protocols", "secrets", "dns_tunnel", "large"]
        return {
            "target": self._get_target(args) or ".",
            "checks": checks,
        }

    async def run_scan(
        self,
        target: str = ".",
        checks: list[str] | None = None,
        **_kwargs: Any,
    ) -> PcapResult:
        return await run_pcap_analysis(target=target, checks=checks)

    def print_results(self, result: object) -> None:
        assert isinstance(result, PcapResult)

        status_color = Cyber.RED if result.overall_status == "found" else Cyber.GREEN
        status_text = (
            "PROBLEMAS ENCONTRADOS" if result.overall_status == "found" else "LIMPO"
        )
        print(f"\n{color(status_color, status_text)}")
        print(
            f"  Pacotes: {result.total_packets:,} | Tamanho: {result.file_size:,} bytes"
        )

        if result.protocols:
            print(f"  Protocolos: {', '.join(result.protocols)}")

        if result.issues:
            print(f"\n  {color(Cyber.YELLOW, 'Resumo:')}")
            for issue in result.issues:
                print(f"    - {issue}")

        if result.attempts:
            print(f"\n  {color(Cyber.RED, 'Problemas encontrados:')}")
            for att in result.attempts:
                sev_color = {
                    "critical": Cyber.RED,
                    "high": Cyber.RED,
                    "medium": Cyber.YELLOW,
                    "low": Cyber.CYAN,
                }.get(att.severity, Cyber.WHITE)
                print(
                    f"    {color(sev_color, att.severity.upper()):>10} "
                    f" [{att.check_name}] {att.description}"
                )
                if att.details:
                    print(f"             {color(Cyber.GRAY, att.details)}")

    def _example(self) -> str:
        return "scan capture.pcap"

    def _help(self) -> str:
        return (
            "PCAP Analysis — analise de capturas de rede\n\n"
            "Analisa arquivos .pcap e .pcapng em busca de:\n"
            "  protocols: anomalias de protocolo (ICMP flood, GRE, ESP)\n"
            "  secrets: credenciais e chaves em payloads HTTP\n"
            "  dns_tunnel: queries DNS anormalmente longas\n"
            "  large: payloads grandes suspeitos\n\n"
            "Formatos suportados:\n"
            "  .pcap: formato classico (little/big endian)\n"
            "  .pcapng: formato next generation\n"
        )


_scanner = PcapAnalysisScanner()
main = _scanner.main
run_once = _scanner.run_once
banner_art = create_banner(_BANNER_TEXT, _scanner.description)
build_parser = _scanner.build_parser
