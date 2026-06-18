#!/usr/bin/env python3
"""Wrapper que executa todos os modulos MyTools contra um alvo de uma vez."""
from __future__ import annotations

import argparse
import os
import time

import attackaudit
import dirscanner
import dnstransfer
import portscanner
import subdomainenum
import webrecon
from utils import (
    Cyber,
    color,
    create_banner,
    setup_logging,
    __version__,
)

"""Recon completo: executa portscanner, dirscanner, webrecon, attackaudit, dnstransfer e subenum contra um alvo."""


def banner() -> None:
    art = r"""
    __  ___        ______            __
   /  |/  /_  __  /_  __/___  ____  / /____
  / /|_/ / / / /   / / / __ \/ __ \/ / ___/
 / /  / / /_/ /   / / / /_/ / /_/ / (__  )
/_/  /_/\__, /   /_/  \____/\____/_/____/
       /____/
"""
    create_banner(art, "   recon all-in-one: port + dir + web + audit + dns + subenum")()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mytools-reconall",
        description="Executa todos os modulos MyTools contra um alvo.",
    )
    parser.add_argument("target", help="Alvo: dominio (example.com) ou URL (https://example.com)")
    parser.add_argument("--deep", action="store_true", help="Modo profundo (crawl, path probing)")
    parser.add_argument("--test-vulns", action="store_true", help="Testa XSS/SQLi no attackaudit")
    parser.add_argument("--test-methods", action="store_true", help="Testa metodos HTTP (PUT/DELETE/PATCH)")
    parser.add_argument("--cve", action="store_true", help="Busca CVEs no webrecon")
    parser.add_argument("-p", "--ports", default="top100", help="Portas para portscanner. Padrao: top100")
    parser.add_argument("-o", "--output-dir", help="Diretorio para salvar resultados JSON de cada modulo")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Timeout em segundos. Padrao: 5")
    parser.add_argument("-v", "--verbose", action="store_true", help="Mostra mensagens de debug")
    parser.add_argument("-q", "--quiet", action="store_true", help="Modo silencioso")
    parser.add_argument("--dry-run", action="store_true", help="Mostra o que faria sem executar nada")
    parser.add_argument("--skip", action="append", default=[], help="Modulo para pular (pode usar mais de um)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _is_url(target: str) -> bool:
    return target.startswith("http://") or target.startswith("https://")


def _extract_domain(target: str) -> str:
    if _is_url(target):
        from urllib.parse import urlparse
        parsed = urlparse(target)
        return parsed.hostname or target
    return target


def _make_args(target: str, extra: dict, base_args: argparse.Namespace) -> argparse.Namespace:
    ns = argparse.Namespace(**vars(base_args))
    for k, v in extra.items():
        setattr(ns, k, v)
    return ns


def _run_module(name: str, fn, args: argparse.Namespace) -> int:
    color_name = color(f"[{name}]", Cyber.CYAN, Cyber.BOLD)
    print(f"\n{'='*60}")
    print(f" {color_name} Iniciando {name}")
    print(f"{'='*60}")
    start = time.monotonic()
    try:
        result = fn(args)
    except Exception as exc:
        print(color(f"  Erro em {name}: {exc}", Cyber.RED))
        return 1
    elapsed = time.monotonic() - start
    status = color("OK", Cyber.GREEN, Cyber.BOLD) if result == 0 else color(f"FALHA ({result})", Cyber.RED, Cyber.BOLD)
    print(f" {color_name} {status} ({elapsed:.1f}s)")
    return result


def run_all(args: argparse.Namespace) -> int:
    skipped = {s.lower() for s in args.skip}
    target = args.target
    is_url = _is_url(target)
    domain = _extract_domain(target)
    total_errors = 0

    base_ns = argparse.Namespace(
        timeout=args.timeout,
        output=None,
        verbose=args.verbose,
        log_file=None,
        quiet=True,
        color=None,
        retries=3,
        dry_run=args.dry_run,
        target_list=None,
    )

    if args.output_dir:
        os.makedirs(args.output_dir, exist_ok=True)

    def _out(module_name: str) -> str | None:
        if not args.output_dir:
            return None
        return os.path.join(args.output_dir, f"{module_name}.json")

    # --- DNS modules (domain only) ---
    if not is_url:
        if "dnstransfer" not in skipped:
            dns_args = _make_args(domain, {"domain": domain, "output": _out("dnstransfer")}, base_ns)
            total_errors += _run_module("dnstransfer", dnstransfer.run_once, dns_args)

        if "subenum" not in skipped:
            sub_args = _make_args(domain, {"domain": domain, "output": _out("subenum")}, base_ns)
            total_errors += _run_module("subenum", subdomainenum.run_once, sub_args)

    # --- PortScanner ---
    if "portscanner" not in skipped:
        port_args = _make_args(target, {"targets": [domain], "ports": args.ports, "banner": False, "workers": 200, "output": _out("portscanner")}, base_ns)
        total_errors += _run_module("portscanner", portscanner.run_once, port_args)

    # --- HTTP modules (URL only) ---
    if is_url:
        if "dirscanner" not in skipped:
            dir_args = _make_args(target, {"url": target, "output": _out("dirscanner"), "extensions": "php,txt,bak,html"}, base_ns)
            total_errors += _run_module("dirscanner", dirscanner.run_once, dir_args)

        if "webrecon" not in skipped:
            web_args = _make_args(target, {"url": target, "output": _out("webrecon"), "cve": args.cve, "deep": args.deep}, base_ns)
            total_errors += _run_module("webrecon", webrecon.run_once, web_args)

        if "attackaudit" not in skipped:
            audit_args = _make_args(target, {
                "url": target,
                "output": _out("attackaudit"),
                "deep": args.deep,
                "test_vulns": args.test_vulns,
                "test_methods": args.test_methods,
            }, base_ns)
            total_errors += _run_module("attackaudit", attackaudit.run_once, audit_args)

    return total_errors


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(verbose=args.verbose)

    if args.dry_run:
        print(color("[DRY-RUN]", Cyber.YELLOW, Cyber.BOLD), "Modo dry-run ativado")
        print(color("  Alvo:", Cyber.CYAN), args.target)
        print(color("  Modulos:", Cyber.CYAN), ", ".join(m for m in ["portscanner", "dnstransfer", "subenum", "dirscanner", "webrecon", "attackaudit"] if m not in args.skip))
        if args.deep:
            print(color("  Flags:", Cyber.CYAN), "--deep")
        if args.test_vulns:
            print(color("  Flags:", Cyber.CYAN), "--test-vulns")
        if args.cve:
            print(color("  Flags:", Cyber.CYAN), "--cve")
        return 0

    banner()
    print(color(f"  Alvo: {args.target}", Cyber.WHITE, Cyber.BOLD))
    print(color(f"  Modulos: {', '.join(m for m in ['portscanner', 'dnstransfer', 'subenum', 'dirscanner', 'webrecon', 'attackaudit'] if m not in args.skip)}", Cyber.WHITE))

    start = time.monotonic()
    errors = run_all(args)
    elapsed = time.monotonic() - start

    print(f"\n{'='*60}")
    if errors == 0:
        print(color("  Recon concluido com sucesso!", Cyber.GREEN, Cyber.BOLD))
    else:
        print(color(f"  Recon concluido com {errors} erro(s)", Cyber.YELLOW, Cyber.BOLD))
    print(color(f"  Tempo total: {elapsed:.1f}s", Cyber.WHITE))
    print(f"{'='*60}")
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
