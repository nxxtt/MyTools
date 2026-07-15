#!/usr/bin/env python3
"""DNS-over-TLS (DoT) Scan — Resolucao DNS via TLS.

Testa resolucao DNS via protocolo DoT (RFC 7858):
  - Envia queries DNS via TLS socket (porta 853)
  - Frame com 2-byte length prefix (RFC 7858)
  - Verifica TLS certificate (issuer, expiry, SAN)
  - Compara com DNS tradicional para detectar filtering/blocking
  - Testa multiplos resolvers DoT (Google, Cloudflare, Quad9)

DoT criptografa queries DNS em TLS, prevenindo monitoring
e manipulation de trafego DNS em ambientes corporativos.
"""

from __future__ import annotations

import argparse
import socket
import ssl
import struct
import time
from dataclasses import asdict, dataclass
from typing import Any

import dns.exception
import dns.message
import dns.name
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

_BANNER_LINES: str = (
    "  _____ ____   ____     _    _   _\n"
    " |_   _/ ___| |  _ \\   / \\  | \\ | |\n"
    "   | || |  _  | | | | / _ \\ |  \\| |\n"
    "   | || |_| | | |_| |/ ___ \\| |\\  |\n"
    "   |_| \\____| |____//_/   \\_\\_| \\_|\n"
)

_DOT_RESOLVERS: dict[str, dict[str, Any]] = {
    "google": {
        "name": "Google DNS",
        "host": "dns.google",
        "port": 853,
    },
    "cloudflare": {
        "name": "Cloudflare DNS",
        "host": "one.one.one.one",
        "port": 853,
    },
    "quad9": {
        "name": "Quad9 DNS",
        "host": "dns.quad9.net",
        "port": 853,
    },
}

_RDTYPE_MAP: dict[str, int] = {
    "A": dns.rdatatype.A,
    "AAAA": dns.rdatatype.AAAA,
    "MX": dns.rdatatype.MX,
    "NS": dns.rdatatype.NS,
    "TXT": dns.rdatatype.TXT,
    "CNAME": dns.rdatatype.CNAME,
    "SOA": dns.rdatatype.SOA,
    "SRV": dns.rdatatype.SRV,
    "CAA": dns.rdatatype.CAA,
}


@dataclass(frozen=True, slots=True)
class DotRecord:
    name: str
    rdtype: str
    ttl: int
    rdata: str


@dataclass(frozen=True, slots=True)
class DotTlsInfo:
    issuer: str
    subject: str
    not_before: str
    not_after: str
    san: list[str]
    serial: str
    version: str


@dataclass(frozen=True, slots=True)
class DotResolverResult:
    resolver: str
    resolver_name: str
    host: str
    port: int
    records: list[DotRecord]
    tls_info: DotTlsInfo
    latency_ms: float
    error: str


@dataclass(frozen=True, slots=True)
class DotScanResult:
    domain: str
    query_type: str
    resolvers: list[DotResolverResult]
    traditional_records: list[DotRecord]
    traditional_latency_ms: float
    filtering_detected: bool
    inconsistencies: list[str]
    dot_supported: bool
    overall_status: str
    error: str


def _build_dns_query(domain: str, rdtype_str: str) -> bytes:
    query = dns.message.make_query(domain, rdtype_str.upper())
    return query.to_wire()


def _parse_dns_response(wire_data: bytes) -> list[DotRecord]:
    records: list[DotRecord] = []
    try:
        response = dns.message.from_wire(wire_data)
        for rrset in response.answer:
            for rdata in rrset:
                records.append(DotRecord(
                    name=str(rrset.name),
                    rdtype=dns.rdatatype.to_text(rrset.rdtype),
                    ttl=rrset.ttl,
                    rdata=str(rdata),
                ))
    except Exception:
        pass
    return records


def _extract_tls_info(ssl_sock: ssl.SSLSocket) -> DotTlsInfo:
    cert = ssl_sock.getpeercert()
    if not cert:
        return DotTlsInfo(issuer="", subject="", not_before="", not_after="", san=[], serial="", version="")
    issuer_parts = []
    for rdn in cert.get("issuer", ()):
        for attr, val in rdn:
            issuer_parts.append(f"{attr}={val}")
    subject_parts = []
    for rdn in cert.get("subject", ()):
        for attr, val in rdn:
            subject_parts.append(f"{attr}={val}")
    san_list = []
    for _san_type, san_val in cert.get("subjectAltName", ()):
        san_list.append(san_val)
    return DotTlsInfo(
        issuer=", ".join(issuer_parts),
        subject=", ".join(subject_parts),
        not_before=str(cert.get("notBefore", "")),
        not_after=str(cert.get("notAfter", "")),
        san=san_list,
        serial=str(cert.get("serialNumber", "")),
        version=str(ssl_sock.version()) if ssl_sock.version() else "",
    )


def _traditional_resolve(domain: str, rdtype_str: str, timeout: float) -> tuple[list[DotRecord], float, str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    records: list[DotRecord] = []
    error = ""
    start = time.monotonic()
    try:
        answer = resolver.resolve(domain, rdtype_str.upper())
        for rdata in answer:
            records.append(DotRecord(
                name=str(answer.qname),
                rdtype=rdtype_str.upper(),
                ttl=answer.rrset.ttl if answer.rrset else 0,
                rdata=str(rdata),
            ))
    except dns.resolver.NoAnswer:
        error = "no_answer"
    except dns.resolver.NXDOMAIN:
        error = "nxdomain"
    except dns.resolver.NoNameservers:
        error = "no_nameservers"
    except dns.exception.Timeout:
        error = "timeout"
    except dns.exception.DNSException as e:
        error = str(e)[:100]
    elapsed = (time.monotonic() - start) * 1000
    return records, elapsed, error


def _dot_query(
    host: str, port: int, wire_query: bytes, timeout: float,
) -> tuple[bytes, DotTlsInfo, str]:
    tls_info = DotTlsInfo(issuer="", subject="", not_before="", not_after="", san=[], serial="", version="")
    try:
        ctx = ssl.create_default_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection((host, port), timeout=timeout) as sock, ctx.wrap_socket(sock, server_hostname=host) as ssock:
            tls_info = _extract_tls_info(ssock)
            length_prefix = struct.pack("!H", len(wire_query))
            ssock.sendall(length_prefix + wire_query)
            resp_data = b""
            while len(resp_data) < 2:
                chunk = ssock.recv(2 - len(resp_data))
                if not chunk:
                    break
                resp_data += chunk
            if len(resp_data) < 2:
                return b"", tls_info, "incomplete_length"
            resp_len = struct.unpack("!H", resp_data)[0]
            while len(resp_data) < 2 + resp_len:
                chunk = ssock.recv(2 + resp_len - len(resp_data))
                if not chunk:
                    break
                resp_data += chunk
            return resp_data[2:], tls_info, ""
    except ssl.SSLCertVerificationError as e:
        return b"", tls_info, f"cert_error: {e}"
    except ssl.SSLError as e:
        return b"", tls_info, f"tls_error: {e}"
    except TimeoutError:
        return b"", tls_info, "timeout"
    except ConnectionRefusedError:
        return b"", tls_info, "connection_refused"
    except OSError as e:
        return b"", tls_info, f"os_error: {e}"
    except Exception as e:
        return b"", tls_info, str(e)[:100]


def _compare_records(
    dot_records: list[DotRecord], trad_records: list[DotRecord],
) -> tuple[bool, list[str]]:
    inconsistencies: list[str] = []
    dot_rdata = sorted(r.rdata for r in dot_records)
    trad_rdata = sorted(r.rdata for r in trad_records)
    filtering = False
    if dot_rdata != trad_rdata:
        filtering = True
        missing_in_dot = set(trad_rdata) - set(dot_rdata)
        extra_in_dot = set(dot_rdata) - set(trad_rdata)
        if missing_in_dot:
            inconsistencies.append(f"missing_in_dot: {', '.join(list(missing_in_dot)[:3])}")
        if extra_in_dot:
            inconsistencies.append(f"extra_in_dot: {', '.join(list(extra_in_dot)[:3])}")
    return filtering, inconsistencies


async def scan_dot(
    domain: str,
    rdtype: str = "A",
    resolvers: list[str] | None = None,
    timeout: float = 5.0,
) -> DotScanResult:
    selected = resolvers or list(_DOT_RESOLVERS.keys())
    wire_query = _build_dns_query(domain, rdtype)
    trad_records, trad_latency, trad_error = _traditional_resolve(domain, rdtype, timeout)
    resolver_results: list[DotResolverResult] = []
    for rk in selected:
        prov = _DOT_RESOLVERS.get(rk)
        if prov is None:
            continue
        start = time.monotonic()
        data, tls_info, error = _dot_query(prov["host"], prov["port"], wire_query, timeout)
        elapsed = (time.monotonic() - start) * 1000
        records = _parse_dns_response(data) if data else []
        resolver_results.append(DotResolverResult(
            resolver=rk,
            resolver_name=prov["name"],
            host=prov["host"],
            port=prov["port"],
            records=records,
            tls_info=tls_info,
            latency_ms=round(elapsed, 2),
            error=error,
        ))
    all_filtering = False
    all_inconsistencies: list[str] = []
    for rr in resolver_results:
        if rr.records and trad_records:
            filt, incons = _compare_records(rr.records, trad_records)
            if filt:
                all_filtering = True
            all_inconsistencies.extend(incons)
    successful = [rr for rr in resolver_results if not rr.error and rr.records]
    dot_supported = len(successful) > 0
    if trad_error == "nxdomain":
        overall = "nxdomain"
    elif not dot_supported and trad_records:
        overall = "no_dot_support"
    elif all_filtering:
        overall = "filtering_detected"
    elif dot_supported:
        overall = "resolved"
    else:
        overall = "error"
    return DotScanResult(
        domain=domain,
        query_type=rdtype.upper(),
        resolvers=resolver_results,
        traditional_records=trad_records,
        traditional_latency_ms=round(trad_latency, 2),
        filtering_detected=all_filtering,
        inconsistencies=list(set(all_inconsistencies)),
        dot_supported=dot_supported,
        overall_status=overall,
        error=trad_error,
    )


def print_results(result: DotScanResult) -> None:
    print(color("\n[+] DNS-over-TLS (DoT) Scan — Relatorio:", Cyber.GREEN, Cyber.BOLD))
    print(f"  Dominio: {color(result.domain, Cyber.WHITE, Cyber.BOLD)}")
    print(f"  Query Type: {color(result.query_type, Cyber.CYAN)}")
    print()

    if result.traditional_records:
        print(color("  DNS Tradicional:", Cyber.YELLOW, Cyber.BOLD))
        print(f"    Latencia: {result.traditional_latency_ms:.1f}ms")
        print(f"    Registros: {len(result.traditional_records)}")
    elif result.error:
        print(color("  DNS Tradicional:", Cyber.YELLOW, Cyber.BOLD))
        print(f"    Erro: {color(result.error, Cyber.RED)}")
    print()

    print(color("  Resolvers DoT:", Cyber.YELLOW, Cyber.BOLD))
    for rr in result.resolvers:
        status_color = Cyber.GREEN if not rr.error else Cyber.RED
        status_text = f"{len(rr.records)} registros" if rr.records else rr.error
        print(f"    {color(rr.resolver_name, Cyber.WHITE)}: {color(status_text, status_color)} ({rr.latency_ms:.1f}ms)")
        if rr.tls_info.issuer:
            print(f"      TLS: {rr.tls_info.version} | {rr.tls_info.issuer}")
    print()

    if result.filtering_detected:
        print(color("  [!] FILTERING DETECTADO", Cyber.RED, Cyber.BOLD))
        for inc in result.inconsistencies:
            print(color("    -", Cyber.RED), inc)
    elif result.dot_supported:
        print(color("  [+] DoT funcionando corretamente", Cyber.GREEN))
    else:
        print(color("  [!] DoT nao suportado ou sem resposta", Cyber.YELLOW))
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mytools-dot",
        description="DNS-over-TLS (DoT) Scan — Resolucao DNS via TLS",
    )
    parser.add_argument("domain", help="Dominio alvo")
    parser.add_argument(
        "-T", "--type", default="A",
        choices=["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA"],
        help="Tipo de registro DNS (default: A)",
    )
    parser.add_argument(
        "-r", "--resolvers", nargs="+",
        choices=list(_DOT_RESOLVERS.keys()),
        default=None,
        help="Resolvers DoT para testar (default: todos)",
    )
    add_base_args(parser)
    return parser


async def _run_scan(args: argparse.Namespace) -> DotScanResult:
    domain = str(getattr(args, "domain", ""))
    rdtype = str(getattr(args, "type", "A"))
    resolvers = getattr(args, "resolvers", None)
    timeout = float(getattr(args, "timeout", 5.0))
    return await scan_dot(domain, rdtype, resolvers, timeout)


def banner() -> None:
    """Exibe o banner do DoT Scan."""
    art = r"""
  _____ ____   ____     _    _   _
 |_   _/ ___| |  _ \   / \  | \ | |
   | || |  _  | | | | / _ \ |  \| |
   | || |_| | | |_| |/ ___ \| |\  |
   |_| \____| |____//_/   \_\_| \_|
"""
    create_banner(art, "DNS-over-TLS Scan — resolucao DNS via TLS")()


def main() -> int:
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=_safe_run,
        has_target=lambda a: bool(getattr(a, "domain", None)),
        prompt="dot> ",
        description="DNS-over-TLS (DoT) Scan — Resolucao DNS via TLS",
        example="mytools-dot example.com",
        contextual_help="dot: testa resolucao DNS via TLS contra multiplos resolvers",
    )


def _safe_run(args: argparse.Namespace) -> int:
    result = safe_asyncio_run(_run_scan(args))
    quiet = init_scanner(args)
    if not quiet:
        print_results(result)
    if getattr(args, "output", None):
        write_output(args.output, [asdict(result)])
    return 0 if result.overall_status in ("resolved", "nxdomain") else 1


if __name__ == "__main__":
    raise SystemExit(main())
