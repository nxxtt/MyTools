#!/usr/bin/env python3
"""Modulo de auditoria de Cookie Domain Boundary.

Verifica se cookies de uma aplicacao web vazam para subdominios maliciosos,
analisando atributos Domain, Path, Secure, HttpOnly e SameSite.

Categorias de teste:
  - domain: Analise do attribute Domain (overly broad, mismatch, wildcard)
  - flags: Flags Secure, HttpOnly, SameSite
  - path: Analise do attribute Path
  - all: Todas as categorias

Fluxo:
  1. Envia request para a URL alvo
  2. Extrai todos os headers Set-Cookie
  3. Parseia atributos de cada cookie
  4. Verifica boundary de dominio e flags de seguranca
  5. Retorna resultado consolidado com severidade
"""
import argparse
import logging
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    fetch,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.cookieboundary")

_CATEGORY_MAP: dict[str, list[str]] = {
    "domain": [
        "domain_absent",
        "domain_wildcard",
        "domain_overly_broad",
        "domain_mismatch",
        "domain_public_suffix",
    ],
    "flags": [
        "flag_no_httponly",
        "flag_no_secure",
        "flag_no_samesite",
        "flag_samesite_none",
    ],
    "path": [
        "path_absent",
        "path_overly_broad",
    ],
}


@dataclass(frozen=True, slots=True)
class CookieInfo:
    """Informacoes parseadas de um cookie Set-Cookie."""

    name: str
    value: str
    domain: str
    path: str
    secure: bool
    httponly: bool
    samesite: str
    raw: str


@dataclass(frozen=True, slots=True)
class CookieBoundaryAttempt:
    """Tentativa individual de Cookie Domain Boundary."""

    technique: str
    category: str
    cookie_name: str
    attribute_tested: str
    attribute_value: str
    vulnerable: bool
    details: str
    error: str


@dataclass(frozen=True, slots=True)
class CookieBoundaryResult:
    """Resultado consolidado do scan de Cookie Domain Boundary."""

    target: str
    target_domain: str
    tls: bool
    cookies_found: list[CookieInfo]
    attempts: list[CookieBoundaryAttempt]
    vulnerable_techniques: list[str]
    protected_techniques: list[str]
    issues: list[str]
    overall_status: str


def _parse_cookie(raw: str) -> CookieInfo:
    """Parseia um header Set-Cookie em CookieInfo."""
    parts = raw.split(";")
    first = parts[0].strip()
    if "=" not in first:
        return CookieInfo(
            name=first, value="", domain="", path="",
            secure=False, httponly=False, samesite="", raw=raw,
        )
    name, value = first.split("=", 1)
    domain = ""
    path = ""
    secure = False
    httponly = False
    samesite = ""
    for part in parts[1:]:
        part = part.strip().lower()
        if part == "httponly":
            httponly = True
        elif part == "secure":
            secure = True
        elif part.startswith("domain="):
            domain = part.split("=", 1)[1].strip().strip('"')
        elif part.startswith("path="):
            path = part.split("=", 1)[1].strip().strip('"')
        elif part.startswith("samesite="):
            samesite = part.split("=", 1)[1].strip()
    return CookieInfo(
        name=name.strip(), value=value, domain=domain, path=path,
        secure=secure, httponly=httponly, samesite=samesite, raw=raw,
    )


def _extract_target_domain(url: str) -> str:
    """Extrai o dominio base de uma URL."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    parts = host.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host


def _is_public_suffix(domain: str) -> bool:
    """Verifica se o dominio e um public suffix simplificado."""
    public_suffixes = {
        "com", "org", "net", "edu", "gov", "mil", "int",
        "co.uk", "co.jp", "co.kr", "co.za", "com.au", "com.br",
        "com.cn", "com.mx", "com.tw", "org.uk", "net.au",
    }
    return domain.lower() in public_suffixes


def _test_domain_attributes(
    cookies: list[CookieInfo],
    target_domain: str,
) -> list[CookieBoundaryAttempt]:
    """Testa atributos Domain de cada cookie."""
    results: list[CookieBoundaryAttempt] = []
    for cookie in cookies:
        if not cookie.domain:
            results.append(CookieBoundaryAttempt(
                technique="domain_absent", category="domain",
                cookie_name=cookie.name, attribute_tested="Domain",
                attribute_value="ausente", vulnerable=True,
                details=f"Cookie '{cookie.name}' sem attribute Domain",
                error="",
            ))
            continue

        cookie_domain = cookie.domain.lstrip(".")
        target_base = target_domain.lstrip(".")

        if cookie.domain == "." or cookie.domain == ".*":
            results.append(CookieBoundaryAttempt(
                technique="domain_wildcard", category="domain",
                cookie_name=cookie.name, attribute_tested="Domain",
                attribute_value=cookie.domain, vulnerable=True,
                details=f"Cookie '{cookie.name}' com Domain wildcard: {cookie.domain}",
                error="",
            ))
        elif _is_public_suffix(cookie_domain):
            results.append(CookieBoundaryAttempt(
                technique="domain_public_suffix", category="domain",
                cookie_name=cookie.name, attribute_tested="Domain",
                attribute_value=cookie.domain, vulnerable=True,
                details=f"Cookie '{cookie.name}' em public suffix: {cookie.domain}",
                error="",
            ))
        elif not cookie_domain.endswith(target_base) and not target_base.endswith(cookie_domain):
            results.append(CookieBoundaryAttempt(
                technique="domain_mismatch", category="domain",
                cookie_name=cookie.name, attribute_tested="Domain",
                attribute_value=cookie.domain, vulnerable=True,
                details=f"Cookie '{cookie.name}' domain mismatch: {cookie.domain} vs {target_domain}",
                error="",
            ))
        elif cookie_domain != target_base and target_base.endswith(cookie_domain):
            results.append(CookieBoundaryAttempt(
                technique="domain_overly_broad", category="domain",
                cookie_name=cookie.name, attribute_tested="Domain",
                attribute_value=cookie.domain, vulnerable=True,
                details=f"Cookie '{cookie.name}' domain amplo: {cookie.domain} (vaza para subdominios)",
                error="",
            ))
        else:
            results.append(CookieBoundaryAttempt(
                technique="domain_mismatch", category="domain",
                cookie_name=cookie.name, attribute_tested="Domain",
                attribute_value=cookie.domain, vulnerable=False,
                details=f"Cookie '{cookie.name}' domain correto: {cookie.domain}",
                error="",
            ))
    return results


def _test_flag_attributes(
    cookies: list[CookieInfo],
) -> list[CookieBoundaryAttempt]:
    """Testa flags Secure, HttpOnly e SameSite de cada cookie."""
    results: list[CookieBoundaryAttempt] = []
    for cookie in cookies:
        results.append(CookieBoundaryAttempt(
            technique="flag_no_httponly", category="flags",
            cookie_name=cookie.name, attribute_tested="HttpOnly",
            attribute_value=str(cookie.httponly), vulnerable=not cookie.httponly,
            details=f"Cookie '{cookie.name}' sem HttpOnly" if not cookie.httponly else "",
            error="",
        ))
        results.append(CookieBoundaryAttempt(
            technique="flag_no_secure", category="flags",
            cookie_name=cookie.name, attribute_tested="Secure",
            attribute_value=str(cookie.secure), vulnerable=not cookie.secure,
            details=f"Cookie '{cookie.name}' sem Secure" if not cookie.secure else "",
            error="",
        ))
        has_samesite = bool(cookie.samesite)
        samesite_none = cookie.samesite.lower() == "none"
        results.append(CookieBoundaryAttempt(
            technique="flag_no_samesite", category="flags",
            cookie_name=cookie.name, attribute_tested="SameSite",
            attribute_value=cookie.samesite or "ausente",
            vulnerable=not has_samesite,
            details=f"Cookie '{cookie.name}' sem SameSite" if not has_samesite else "",
            error="",
        ))
        if has_samesite:
            results.append(CookieBoundaryAttempt(
                technique="flag_samesite_none", category="flags",
                cookie_name=cookie.name, attribute_tested="SameSite",
                attribute_value=cookie.samesite, vulnerable=samesite_none,
                details=f"Cookie '{cookie.name}' SameSite=None (permite cross-site)" if samesite_none else "",
                error="",
            ))
    return results


def _test_path_attributes(
    cookies: list[CookieInfo],
) -> list[CookieBoundaryAttempt]:
    """Testa atributos Path de cada cookie."""
    results: list[CookieBoundaryAttempt] = []
    for cookie in cookies:
        if not cookie.path:
            results.append(CookieBoundaryAttempt(
                technique="path_absent", category="path",
                cookie_name=cookie.name, attribute_tested="Path",
                attribute_value="ausente", vulnerable=True,
                details=f"Cookie '{cookie.name}' sem attribute Path (default: /)",
                error="",
            ))
        elif cookie.path == "/":
            results.append(CookieBoundaryAttempt(
                technique="path_overly_broad", category="path",
                cookie_name=cookie.name, attribute_tested="Path",
                attribute_value=cookie.path, vulnerable=True,
                details=f"Cookie '{cookie.name}' com Path=/ (amplo)",
                error="",
            ))
        else:
            results.append(CookieBoundaryAttempt(
                technique="path_overly_broad", category="path",
                cookie_name=cookie.name, attribute_tested="Path",
                attribute_value=cookie.path, vulnerable=False,
                details=f"Cookie '{cookie.name}' com Path={cookie.path}",
                error="",
            ))
    return results


def print_results(result: CookieBoundaryResult) -> None:
    """Exibe os resultados do scan de Cookie Domain Boundary."""
    vuln = [a for a in result.attempts if a.vulnerable]
    protected = [a for a in result.attempts if not a.vulnerable and not a.error]
    errors = [a for a in result.attempts if a.error]

    print(color("\n--- Cookie Domain Boundary Audit ---", Cyber.CYAN, Cyber.BOLD))
    print(color(f"  Alvo:          {result.target}", Cyber.WHITE))
    print(color(f"  Dominio:       {result.target_domain}", Cyber.WHITE))
    print(color(f"  TLS:           {'sim' if result.tls else 'nao'}", Cyber.WHITE))
    print(color(f"  Cookies:       {len(result.cookies_found)}", Cyber.WHITE))
    print(color(f"  Testes:        {len(result.attempts)}", Cyber.WHITE))
    print(color(f"  Vulneraveis:   {len(vuln)}", Cyber.RED if vuln else Cyber.GRAY))
    print(color(f"  Protegidos:    {len(protected)}", Cyber.GREEN if protected else Cyber.GRAY))
    print(color(f"  Erros:         {len(errors)}", Cyber.RED if errors else Cyber.GRAY))

    if result.cookies_found:
        print(color("\n  [*] Cookies detectados:", Cyber.CYAN))
        for c in result.cookies_found:
            attrs = []
            if c.domain:
                attrs.append(f"Domain={c.domain}")
            if c.path:
                attrs.append(f"Path={c.path}")
            if c.secure:
                attrs.append("Secure")
            if c.httponly:
                attrs.append("HttpOnly")
            if c.samesite:
                attrs.append(f"SameSite={c.samesite}")
            attr_str = "; ".join(attrs) if attrs else "sem atributos"
            print(color(f"    {c.name}={c.value[:30]}{'...' if len(c.value) > 30 else ''}", Cyber.WHITE))
            print(color(f"      {attr_str}", Cyber.GRAY))

    if vuln:
        print(color("\n  [!] Vulnerabilidades detectadas:", Cyber.RED, Cyber.BOLD))
        seen: set[str] = set()
        for a in vuln:
            key = f"{a.technique}:{a.cookie_name}"
            if key in seen:
                continue
            seen.add(key)
            print(color(f"    [{a.category}] {a.technique}", Cyber.RED))
            print(color(f"      Cookie: {a.cookie_name}", Cyber.WHITE))
            print(color(f"      Atributo: {a.attribute_tested} = {a.attribute_value}", Cyber.WHITE))
            if a.details:
                print(color(f"      Detalhes: {a.details}", Cyber.GRAY))
        print(color(f"\n  Total: {len(result.attempts)} testes, {len(vuln)} vulneraveis", Cyber.WHITE))
    else:
        print(color("\n  [+] Nenhuma vulnerabilidade de Cookie Domain Boundary detectada", Cyber.GREEN))

    if result.issues:
        print(color("\n  [!] Observacoes:", Cyber.YELLOW))
        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))


async def run_scan(
    target: str,
    categories: list[str],
    timeout: float,
    output_file: str | None,
) -> int:
    """Executa o scan de Cookie Domain Boundary."""
    logger.info("Cookie Domain Boundary scan para %s", target)
    tls = target.startswith("https://")
    target_domain = _extract_target_domain(target)

    async with create_async_client(timeout=timeout) as client:
        try:
            _status, _headers, _body, raw_headers = await fetch(client, target, timeout=timeout)
        except Exception as e:
            print(color(f"Erro ao acessar {target}: {e}", Cyber.RED))
            return 1

        set_cookies = raw_headers.get("set-cookie", [])
        cookies = [_parse_cookie(sc) for sc in set_cookies]

        all_attempts: list[CookieBoundaryAttempt] = []
        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        for cat in test_categories:
            if cat == "domain":
                all_attempts.extend(_test_domain_attributes(cookies, target_domain))
            elif cat == "flags":
                all_attempts.extend(_test_flag_attributes(cookies))
            elif cat == "path":
                all_attempts.extend(_test_path_attributes(cookies))

        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})
        protected_techs = list({a.technique for a in all_attempts if not a.vulnerable and not a.error})
        issues: list[str] = []

        if not cookies:
            issues.append("Nenhum Set-Cookie detectado na resposta")
        if not vuln_techs and not protected_techs:
            issues.append("Nenhum teste retornou resultado claro")

        result = CookieBoundaryResult(
            target=target, target_domain=target_domain, tls=tls,
            cookies_found=cookies, attempts=all_attempts,
            vulnerable_techniques=vuln_techs, protected_techniques=protected_techs,
            issues=issues,
            overall_status="vulnerable" if vuln_techs else ("safe" if protected_techs else "unknown"),
        )

        print_results(result)
        logger.info(
            "Cookie Domain Boundary scan concluido: %d cookies, %d testes, %d vulneraveis",
            len(cookies), len(all_attempts), len(vuln_techs),
        )

        if output_file:
            write_output(output_file, asdict(result))
            logger.info("Resultados salvos em %s", output_file)

        return 1 if vuln_techs else 0


def banner_art() -> None:
    """Exibe a banner do modulo."""
    art = r"""
    ___            _            __   ____ ____
   / __/_ _  ___ (_)__ __ ___ / /  / __// __ \
  / _//  ' \/ -_)/ // //(_-</ /__ _\ \ / /_/ /
 /___/_/_/_/\__//_/\_, //___/____/___/\___\_\
                  /___/
"""
    create_banner(art, "   cookieboundary: domain, flags, path")()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""
    parser = argparse.ArgumentParser(
        prog="mytools-cookieboundary",
        description="Cookie Domain Boundary — audita cookies para leakage via subdominios.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-cookieboundary https://target.com\n"
            "  mytools-cookieboundary https://target.com -c domain\n"
            "  mytools-cookieboundary https://target.com -c flags\n"
            "  mytools-cookieboundary https://target.com --proxy http://127.0.0.1:8080"
        ),
    )
    parser.add_argument("url", help="URL alvo para o scan")
    parser.add_argument(
        "-c", "--category",
        default="all",
        choices=["all", "domain", "flags", "path"],
        help="Categoria de testes (default: todas)",
    )
    add_common_args(parser)
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan Cookie Domain Boundary a partir de argumentos parseados."""
    logger.info("Cookie Domain Boundary scan iniciado para %s", args.url)
    categories: list[str] = []
    if getattr(args, "category", None) and args.category != "all":
        categories = [args.category]
    return safe_asyncio_run(
        run_scan(
            target=args.url,
            categories=categories,
            timeout=getattr(args, "timeout", 10),
            output_file=getattr(args, "output", None),
        ),
    )


def main() -> int:
    """Entry point do modulo Cookie Domain Boundary."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None) or getattr(a, "target", None)),
        prompt="cookieboundary> ",
        description="Cookie Domain Boundary interativo.",
        example="https://target.com -c domain",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c domain\n"
            "  https://target.com -c flags\n"
            "  https://target.com -c path\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )
