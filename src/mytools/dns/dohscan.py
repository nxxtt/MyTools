#!/usr/bin/env python3
"""DNS-over-HTTPS (DoH) Scan — Resolucao DNS via HTTPS.

Testa resolucao DNS via protocolo DoH (RFC 8484):
  - Envia queries DNS via POST/GET para providers DoH
  - Compara com DNS tradicional para detectar filtering/blocking
  - Verifica suporte a DoH em domain via content-type negotiation
  - Testa multiplos providers (Google, Cloudflare, Quad9, AdGuard)
  - Analisa latencia e consistencia de respostas

DoH encapsula queries DNS em HTTPS, permitindo bypass de
DNS filtering/monitoring em ambientes corporativos.
"""

from __future__ import annotations

import argparse
import base64
import time
from dataclasses import asdict, dataclass
from typing import Any

import dns.exception
import dns.message
import dns.name
import dns.rdatatype
import dns.resolver
import httpx

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
    "  ____   ___  ____  _____    _    _   _\n"
    " |  _ \\ / _ \\|  _ \\| ____|  / \\  | \\ | |\n"
    " | | | | | | | | | |  _|   / _ \\ |  \\| |\n"
    " | |_| | |_| | |_| | |___ / ___ \\| |\\  |\n"
    " |____/ \\___/|____/|_____/_/   \\_\\_| \\_|\n"
)

_DOH_PROVIDERS: dict[str, dict[str, Any]] = {
    "google": {
        "name": "Google DNS",
        "url": "https://dns.google/dns-query",
        "method": "GET",
    },
    "cloudflare": {
        "name": "Cloudflare DNS",
        "url": "https://cloudflare-dns.com/dns-query",
        "method": "GET",
    },
    "quad9": {
        "name": "Quad9 DNS",
        "url": "https://dns.quad9.net/dns-query",
        "method": "GET",
    },
    "adguard": {
        "name": "AdGuard DNS",
        "url": "https://dns.adguard.com/dns-query",
        "method": "GET",
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
class DohRecord:
    name: str
    rdtype: str
    ttl: int
    rdata: str


@dataclass(frozen=True, slots=True)
class DohProviderResult:
    provider: str
    provider_name: str
    url: str
    records: list[DohRecord]
    latency_ms: float
    status_code: int
    error: str
    query_method: str


@dataclass(frozen=True, slots=True)
class DohScanResult:
    domain: str
    query_type: str
    providers: list[DohProviderResult]
    traditional_records: list[DohRecord]
    traditional_latency_ms: float
    filtering_detected: bool
    inconsistencies: list[str]
    doh_supported: bool
    overall_status: str
    error: str


def _build_dns_query(domain: str, rdtype_str: str) -> bytes:
    query = dns.message.make_query(domain, rdtype_str.upper())
    return query.to_wire()


def _parse_dns_response(wire_data: bytes) -> list[DohRecord]:
    records: list[DohRecord] = []
    try:
        response = dns.message.from_wire(wire_data)
        for rrset in response.answer:
            for rdata in rrset:
                records.append(DohRecord(
                    name=str(rrset.name),
                    rdtype=dns.rdatatype.to_text(rrset.rdtype),
                    ttl=rrset.ttl,
                    rdata=str(rdata),
                ))
    except Exception:
        pass
    return records


def _traditional_resolve(domain: str, rdtype_str: str, timeout: float) -> tuple[list[DohRecord], float, str]:
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    records: list[DohRecord] = []
    error = ""
    start = time.monotonic()
    try:
        answer = resolver.resolve(domain, rdtype_str.upper())
        for rdata in answer:
            records.append(DohRecord(
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


async def _doh_query_post(
    url: str, wire_query: bytes, timeout: float,
) -> tuple[bytes, int, str]:
    headers = {"Content-Type": "application/dns-message", "Accept": "application/dns-message"}
    try:
        async with httpx.AsyncClient(http2=True, timeout=timeout, verify=True) as client:
            resp = await client.post(url, content=wire_query, headers=headers)
            if resp.status_code == 200 and resp.headers.get("content-type", "").startswith("application/dns-message"):
                return resp.content, resp.status_code, ""
            return b"", resp.status_code, f"unexpected_content_type: {resp.headers.get('content-type', 'none')}"
    except httpx.TimeoutException:
        return b"", 0, "timeout"
    except httpx.ConnectError as e:
        return b"", 0, f"connect_error: {e}"
    except Exception as e:
        return b"", 0, str(e)[:100]


async def _doh_query_get(
    url: str, wire_query: bytes, timeout: float,
) -> tuple[bytes, int, str]:
    b64 = base64.urlsafe_b64encode(wire_query).rstrip(b"=").decode("ascii")
    full_url = f"{url}?dns={b64}"
    headers = {"Accept": "application/dns-message"}
    try:
        async with httpx.AsyncClient(http2=True, timeout=timeout, verify=True) as client:
            resp = await client.get(full_url, headers=headers)
            if resp.status_code == 200 and resp.headers.get("content-type", "").startswith("application/dns-message"):
                return resp.content, resp.status_code, ""
            return b"", resp.status_code, f"unexpected_content_type: {resp.headers.get('content-type', 'none')}"
    except httpx.TimeoutException:
        return b"", 0, "timeout"
    except httpx.ConnectError as e:
        return b"", 0, f"connect_error: {e}"
    except Exception as e:
        return b"", 0, str(e)[:100]


def _compare_records(
    doh_records: list[DohRecord], trad_records: list[DohRecord],
) -> tuple[bool, list[str]]:
    inconsistencies: list[str] = []
    doh_rdata = sorted(r.rdata for r in doh_records)
    trad_rdata = sorted(r.rdata for r in trad_records)
    filtering = False
    if doh_rdata != trad_rdata:
        filtering = True
        missing_in_doh = set(trad_rdata) - set(doh_rdata)
        extra_in_doh = set(doh_rdata) - set(trad_rdata)
        if missing_in_doh:
            inconsistencies.append(f"missing_in_doh: {', '.join(list(missing_in_doh)[:3])}")
        if extra_in_doh:
            inconsistencies.append(f"extra_in_doh: {', '.join(list(extra_in_doh)[:3])}")
    return filtering, inconsistencies


async def _test_provider(
    provider_key: str, provider: dict[str, Any],
    wire_query: bytes, domain: str, rdtype: str, timeout: float,
) -> DohProviderResult:
    start = time.monotonic()
    if provider["method"] == "POST":
        data, status, error = await _doh_query_post(provider["url"], wire_query, timeout)
    else:
        data, status, error = await _doh_query_get(provider["url"], wire_query, timeout)
    elapsed = (time.monotonic() - start) * 1000
    records = _parse_dns_response(data) if data else []
    return DohProviderResult(
        provider=provider_key,
        provider_name=provider["name"],
        url=provider["url"],
        records=records,
        latency_ms=round(elapsed, 2),
        status_code=status,
        error=error,
        query_method=provider["method"],
    )


async def scan_doh(
    domain: str,
    rdtype: str = "A",
    providers: list[str] | None = None,
    timeout: float = 5.0,
) -> DohScanResult:
    selected = providers or list(_DOH_PROVIDERS.keys())
    wire_query = _build_dns_query(domain, rdtype)
    trad_records, trad_latency, trad_error = _traditional_resolve(domain, rdtype, timeout)
    provider_results: list[DohProviderResult] = []
    for pk in selected:
        prov = _DOH_PROVIDERS.get(pk)
        if prov is None:
            continue
        result = await _test_provider(pk, prov, wire_query, domain, rdtype, timeout)
        provider_results.append(result)
    all_filtering = False
    all_inconsistencies: list[str] = []
    for pr in provider_results:
        if pr.records and trad_records:
            filt, incons = _compare_records(pr.records, trad_records)
            if filt:
                all_filtering = True
            all_inconsistencies.extend(incons)
    successful = [pr for pr in provider_results if not pr.error and pr.records]
    doh_supported = len(successful) > 0
    if trad_error == "nxdomain":
        overall = "nxdomain"
    elif not doh_supported and trad_records:
        overall = "no_doh_support"
    elif all_filtering:
        overall = "filtering_detected"
    elif doh_supported:
        overall = "resolved"
    else:
        overall = "error"
    return DohScanResult(
        domain=domain,
        query_type=rdtype.upper(),
        providers=provider_results,
        traditional_records=trad_records,
        traditional_latency_ms=round(trad_latency, 2),
        filtering_detected=all_filtering,
        inconsistencies=list(set(all_inconsistencies)),
        doh_supported=doh_supported,
        overall_status=overall,
        error=trad_error,
    )


def print_results(result: DohScanResult) -> None:
    print(color("\n[+] DNS-over-HTTPS (DoH) Scan — Relatorio:", Cyber.GREEN, Cyber.BOLD))
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

    print(color("  Providers DoH:", Cyber.YELLOW, Cyber.BOLD))
    for pr in result.providers:
        status_color = Cyber.GREEN if not pr.error else Cyber.RED
        status_text = f"{len(pr.records)} registros" if pr.records else pr.error
        print(f"    {color(pr.provider_name, Cyber.WHITE)}: {color(status_text, status_color)} ({pr.latency_ms:.1f}ms)")

    print()
    if result.filtering_detected:
        print(color("  [!] FILTERING DETECTADO", Cyber.RED, Cyber.BOLD))
        for inc in result.inconsistencies:
            print(color("    -", Cyber.RED), inc)
    elif result.doh_supported:
        print(color("  [+] DoH funcionando corretamente", Cyber.GREEN))
    else:
        print(color("  [!] DoH nao suportado ou sem resposta", Cyber.YELLOW))
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mytools-doh",
        description="DNS-over-HTTPS (DoH) Scan — Resolucao DNS via HTTPS",
    )
    parser.add_argument("domain", help="Dominio alvo")
    parser.add_argument(
        "-T", "--type", default="A",
        choices=["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV", "CAA"],
        help="Tipo de registro DNS (default: A)",
    )
    parser.add_argument(
        "-p", "--providers", nargs="+",
        choices=list(_DOH_PROVIDERS.keys()),
        default=None,
        help="Providers DoH para testar (default: todos)",
    )
    add_base_args(parser)
    return parser


async def _run_scan(args: argparse.Namespace) -> DohScanResult:
    domain = str(getattr(args, "domain", ""))
    rdtype = str(getattr(args, "type", "A"))
    providers = getattr(args, "providers", None)
    timeout = float(getattr(args, "timeout", 5.0))
    return await scan_doh(domain, rdtype, providers, timeout)


def banner() -> None:
    """Exibe o banner do DoH Scan."""
    art = r"""
  ____   ___  ____  _____    _    _   _
 |  _ \ / _ \|  _ \| ____|  / \  | \ | |
 | | | | | | | | | |  _|   / _ \ |  \| |
 | |_| | |_| | |_| | |___ / ___ \| |\  |
 |____/ \___/|____/|_____/_/   \_\_| \_|
"""
    create_banner(art, "DNS-over-HTTPS Scan — resolucao DNS via HTTPS")()


def main() -> int:
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=_safe_run,
        has_target=lambda a: bool(getattr(a, "domain", None)),
        prompt="doh> ",
        description="DNS-over-HTTPS (DoH) Scan — Resolucao DNS via HTTPS",
        example="mytools-doh example.com",
        contextual_help="doh: testa resolucao DNS via HTTPS contra multiplos providers",
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
