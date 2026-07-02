#!/usr/bin/env python3
"""Modulo de deteccao de Web Cache Deception.

Testa se o servidor e vulneravel a cache deception via:
  - Extension — extensions cacheaveis em paths sensiveis (.css, .js, .png)
  - Path — truques de path que confundem cache vs app routing
  - Parameter — parametros cacheaveis em URLs sensiveis
  - Framework — tricks especificos (Django, Flask, Express, Rails)
  - Bypass — encoding e normalizacao para contornar filtros

Fluxo:
  1. Envia requisicao baseline para detectar cache
  2. Envia paths com extensions/parametros que o cache pode armazenar
  3. Verifica se resposta foi cacheada (X-Cache: HIT)
  4. Classifica: detectado, blocked, error
  5. Retorna resultado consolidado com severidade
"""
import argparse
import logging
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

logger = logging.getLogger("mytools.cachedeception")

_CATEGORY_MAP: dict[str, list[str]] = {
    "extension": ["css_ext", "js_ext", "png_ext", "gif_ext", "ico_ext"],
    "path": ["trailing_slash", "double_slash", "semicolon_path", "fragment_bypass", "case_path"],
    "parameter": ["cache_param", "utm_source", "cb_param", "nocache_bypass", "version_param"],
    "framework": ["django_static", "flask_static", "express_static", "rails_asset", "spring_static"],
    "bypass": ["double_encode", "null_byte", "unicode_path", "backslash_path", "case_extension"],
}

_EXTENSION_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "css_ext",
        "/admin.css",
        ["admin", "css", "cache", "static"],
    ),
    (
        "js_ext",
        "/secret.js",
        ["secret", "js", "cache", "static"],
    ),
    (
        "png_ext",
        "/profile.png",
        ["profile", "png", "cache", "image"],
    ),
    (
        "gif_ext",
        "/data.gif",
        ["data", "gif", "cache", "image"],
    ),
    (
        "ico_ext",
        "/auth.ico",
        ["auth", "ico", "cache", "favicon"],
    ),
]

_PATH_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "trailing_slash",
        "/admin/",
        ["admin", "cache", "static"],
    ),
    (
        "double_slash",
        "/admin//",
        ["admin", "cache", "double"],
    ),
    (
        "semicolon_path",
        "/admin;.css",
        ["admin", "css", "semicolon", "cache"],
    ),
    (
        "fragment_bypass",
        "/admin#.css",
        ["admin", "css", "fragment", "cache"],
    ),
    (
        "case_path",
        "/Admin/",
        ["Admin", "cache", "case"],
    ),
]

_PARAMETER_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "cache_param",
        "?cache=1",
        ["cache", "param", "static"],
    ),
    (
        "utm_source",
        "?utm_source=test",
        ["utm_source", "cache", "param"],
    ),
    (
        "cb_param",
        "?cb=12345",
        ["cb", "cache", "param", "callback"],
    ),
    (
        "nocache_bypass",
        "?nocache=0",
        ["nocache", "cache", "param"],
    ),
    (
        "version_param",
        "?v=1.0",
        ["v=", "cache", "param", "version"],
    ),
]

_FRAMEWORK_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "django_static",
        "/static/admin.css",
        ["static", "admin", "css", "django"],
    ),
    (
        "flask_static",
        "/static/secret.js",
        ["static", "secret", "js", "flask"],
    ),
    (
        "express_static",
        "/public/admin.css",
        ["public", "admin", "css", "express"],
    ),
    (
        "rails_asset",
        "/assets/admin.css",
        ["assets", "admin", "css", "rails"],
    ),
    (
        "spring_static",
        "/resources/admin.css",
        ["resources", "admin", "css", "spring"],
    ),
]

_BYPASS_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "double_encode",
        "/%2561dmin.css",
        ["admin", "css", "double", "encode"],
    ),
    (
        "null_byte",
        "/admin%00.css",
        ["admin", "css", "null", "bypass"],
    ),
    (
        "unicode_path",
        "/%E0%80%80admin.css",
        ["admin", "css", "unicode", "bypass"],
    ),
    (
        "backslash_path",
        "/\\admin.css",
        ["admin", "css", "backslash", "bypass"],
    ),
    (
        "case_extension",
        "/admin.CSS",
        ["admin", "CSS", "case", "extension"],
    ),
]

_SENSITIVE_PATHS: list[str] = [
    "/admin", "/secret", "/profile", "/dashboard", "/settings",
    "/api/keys", "/api/users", "/internal", "/debug", "/config",
]


@dataclass(frozen=True, slots=True)
class DeceptionAttempt:
    """Tentativa individual de Web Cache Deception."""
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
class DeceptionResult:
    """Resultado consolidado do scan de Web Cache Deception."""
    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[DeceptionAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


def _check_deception_response(
    body: bytes,
    status: int,
    headers: dict[str, str],
    indicators: list[str],
) -> bool:
    """Verifica se a resposta indica cache deception."""
    if status == 0:
        return False
    cache_hit = headers.get("x-cache", "").lower()
    cache_control = headers.get("cache-control", "").lower()
    text = body.decode("utf-8", errors="ignore").lower()
    combined = text + " " + cache_hit + " " + cache_control
    return any(ind.lower() in combined for ind in indicators)


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia request baseline para obter tamanho e status de referencia."""
    try:
        resp = await client.get(url, follow_redirects=True)
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


async def _test_extension(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[DeceptionAttempt]:
    """Testa payloads de extension cacheavel."""
    b_status, b_size, _ = baseline
    results: list[DeceptionAttempt] = []

    for technique, ext_payload, indicators in _EXTENSION_PAYLOADS:
        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path + ext_payload
                resp = await client.get(test_url, follow_redirects=True)
                headers_dict = dict(resp.headers)
                vulnerable = _check_deception_response(
                    resp.content, resp.status_code, headers_dict, indicators,
                )
                results.append(DeceptionAttempt(
                    technique=technique,
                    category="extension",
                    payload=f"{path}{ext_payload}",
                    param=path,
                    method="get_path",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"path={path}, indicators={indicators}" if vulnerable else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(DeceptionAttempt(
                    technique=technique,
                    category="extension",
                    payload=f"{path}{ext_payload}",
                    param=path,
                    method="get_path",
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


async def _test_path(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[DeceptionAttempt]:
    """Testa payloads de path deception."""
    b_status, b_size, _ = baseline
    results: list[DeceptionAttempt] = []

    for technique, path_payload, indicators in _PATH_PAYLOADS:
        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path + path_payload
                resp = await client.get(test_url, follow_redirects=True)
                headers_dict = dict(resp.headers)
                vulnerable = _check_deception_response(
                    resp.content, resp.status_code, headers_dict, indicators,
                )
                results.append(DeceptionAttempt(
                    technique=technique,
                    category="path",
                    payload=f"{path}{path_payload}",
                    param=path,
                    method="get_path",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"path={path}, indicators={indicators}" if vulnerable else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(DeceptionAttempt(
                    technique=technique,
                    category="path",
                    payload=f"{path}{path_payload}",
                    param=path,
                    method="get_path",
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


async def _test_parameter(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[DeceptionAttempt]:
    """Testa payloads de parameter cacheavel."""
    b_status, b_size, _ = baseline
    results: list[DeceptionAttempt] = []

    for technique, param_payload, indicators in _PARAMETER_PAYLOADS:
        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path + param_payload
                resp = await client.get(test_url, follow_redirects=True)
                headers_dict = dict(resp.headers)
                vulnerable = _check_deception_response(
                    resp.content, resp.status_code, headers_dict, indicators,
                )
                results.append(DeceptionAttempt(
                    technique=technique,
                    category="parameter",
                    payload=f"{path}{param_payload}",
                    param=path,
                    method="get_path",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"path={path}, indicators={indicators}" if vulnerable else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(DeceptionAttempt(
                    technique=technique,
                    category="parameter",
                    payload=f"{path}{param_payload}",
                    param=path,
                    method="get_path",
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


async def _test_framework(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[DeceptionAttempt]:
    """Testa payloads de framework-specific deception."""
    b_status, b_size, _ = baseline
    results: list[DeceptionAttempt] = []

    for technique, fw_payload, indicators in _FRAMEWORK_PAYLOADS:
        try:
            test_url = url.rstrip("/") + fw_payload
            resp = await client.get(test_url, follow_redirects=True)
            headers_dict = dict(resp.headers)
            vulnerable = _check_deception_response(
                resp.content, resp.status_code, headers_dict, indicators,
            )
            results.append(DeceptionAttempt(
                technique=technique,
                category="framework",
                payload=fw_payload,
                param=fw_payload,
                method="get_path",
                status_baseline=b_status,
                status_test=resp.status_code,
                size_baseline=b_size,
                size_test=len(resp.content),
                status_changed=resp.status_code != b_status,
                size_changed=len(resp.content) != b_size,
                vulnerable=vulnerable,
                details=f"payload={fw_payload}, indicators={indicators}" if vulnerable else "",
                error="",
            ))
        except httpx.RequestError as e:
            results.append(DeceptionAttempt(
                technique=technique,
                category="framework",
                payload=fw_payload,
                param=fw_payload,
                method="get_path",
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
) -> list[DeceptionAttempt]:
    """Testa payloads de bypass de normalizacao."""
    b_status, b_size, _ = baseline
    results: list[DeceptionAttempt] = []

    for technique, bypass_payload, indicators in _BYPASS_PAYLOADS:
        for path in _SENSITIVE_PATHS[:4]:
            try:
                test_url = url.rstrip("/") + path + bypass_payload
                resp = await client.get(test_url, follow_redirects=True)
                headers_dict = dict(resp.headers)
                vulnerable = _check_deception_response(
                    resp.content, resp.status_code, headers_dict, indicators,
                )
                results.append(DeceptionAttempt(
                    technique=technique,
                    category="bypass",
                    payload=f"{path}{bypass_payload}",
                    param=path,
                    method="get_path",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"path={path}, indicators={indicators}" if vulnerable else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(DeceptionAttempt(
                    technique=technique,
                    category="bypass",
                    payload=f"{path}{bypass_payload}",
                    param=path,
                    method="get_path",
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


def print_results(result: DeceptionResult) -> None:
    """Exibe os resultados do scan de Web Cache Deception."""
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
        print(color("\n  [+] Nenhuma Web Cache Deception detectada", Cyber.GREEN, Cyber.BOLD))

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
    """Executa o scan de Web Cache Deception."""
    logger.info("Web Cache Deception scan para %s", target)

    async with create_async_client(timeout=timeout) as client:
        b_status, b_size, _ = await _test_baseline(client, target)
        if b_status == 0:
            print(color("[-] Nao foi possivel conectar ao alvo", Cyber.RED))
            return 1

        print(color(f"[*] Baseline: status={b_status}, size={b_size}", Cyber.CYAN))

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())
        all_attempts: list[DeceptionAttempt] = []

        for cat in test_categories:
            if cat == "extension":
                attempts = await _test_extension(client, target, (b_status, b_size, b""))
            elif cat == "path":
                attempts = await _test_path(client, target, (b_status, b_size, b""))
            elif cat == "parameter":
                attempts = await _test_parameter(client, target, (b_status, b_size, b""))
            elif cat == "framework":
                attempts = await _test_framework(client, target, (b_status, b_size, b""))
            elif cat == "bypass":
                attempts = await _test_bypass(client, target, (b_status, b_size, b""))
            else:
                continue
            all_attempts.extend(attempts)

        vulnerable = [a for a in all_attempts if a.vulnerable]
        blocked = [a for a in all_attempts if a.error and "403" in a.error]
        issues = [f"VULN: {a.technique} via {a.param}" for a in vulnerable]

        result = DeceptionResult(
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
    _ __  _ __ ___   _ __   __ _ _ __   __ _ _ __  _   ___  __
   | '_ \| '__/ _ \ | '_ \ / _` | '_ \ / _` | '_ \| | | \ \/ /
   | |_) | | | (_) || | | | (_| | | | | (_| | | | | |_| |>  <
   | .__/|_|  \___/ |_| |_|\__,_|_| |_|\__,_|_| |_|\__,_/_/\_\
   |_|
"""
    create_banner(art, "   web cache deception: extensions, paths, parameters")()


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-cachedec",
        description="Web Cache Deception — detecta paths que o cache armazena mas a app nao deveria",
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
    """Executa um scan Web Cache Deception a partir de argumentos parseados."""
    logger.info("Web Cache Deception scan iniciado para %s", args.url)
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
        prompt="cachedec> ",
        description="Web Cache Deception interativo.",
        example="https://target.com -c extension",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c extension\n"
            "  https://target.com -c path\n"
            "  https://target.com -c framework\n"
            "  https://target.com -c bypass --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
