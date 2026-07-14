#!/usr/bin/env python3
"""Modulo de auditoria de Cookie Security (Domain + Path + CSRF + SameSite DNS + Quoting).

Verifica se cookies de uma aplicacao web vazam para subdominios maliciosos,
entre paths diferentes, sao bypassaveis via Double Submit Cookie, ou podem
ser bypassados via DNS rebinding em SameSite=Lax.

Categorias de teste:
  - domain: Analise do attribute Domain (overly broad, mismatch, wildcard)
  - flags: Flags Secure, HttpOnly, SameSite
  - path: Analise do attribute Path (estatica)
  - path_traversal: Testes ativos de bypass de Path (encoding, case, traversal)
  - double_submit: Analise de Double Submit Cookie pattern (CSRF bypass)
  - samesite_dns: SameSite=Lax + DNS rebinding feasibility
  - csrf_subdomain: CSRF bypass via subdominios (cookie scope, takeover risk)
  - cookie_quoting: Edge cases de quoting (aspas, backslashes, null bytes, separadores)
  - all: Todas as categorias

Fluxo:
  1. Envia request para a URL alvo
  2. Extrai todos os headers Set-Cookie
  3. Parseia atributos de cada cookie (RFC 6265 compliant)
  4. Verifica boundary de dominio, flags e path
  5. Para path_traversal: testa bypasses ativos com requests HTTP
  6. Para double_submit: analisa cookies CSRF para bypass
  7. Para samesite_dns: verifica se SameSite=Lax e bypassavel via DNS rebinding
  8. Para csrf_subdomain: verifica se protecao CSRF e bypassavel via subdominio
  9. Para cookie_quoting: verifica edge cases de parsing (aspas, null bytes, etc)
  10. Retorna resultado consolidado com severidade
"""
import argparse
import asyncio
import contextlib
import logging
from dataclasses import asdict, dataclass
from urllib.parse import urlparse

import httpx

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
    "path_traversal": [
        "traversal_url_encoded",
        "traversal_double_encoded",
        "traversal_semicolon",
        "traversal_backslash",
        "traversal_case_variation",
        "traversal_trailing_slash",
        "traversal_prefix_match",
        "traversal_overlong_utf8",
        "traversal_tab_injection",
    ],
    "double_submit": [
        "ds_cookie_no_httponly",
        "ds_cookie_no_samesite",
        "ds_cookie_overly_broad_domain",
        "ds_cookie_no_secure",
        "ds_token_in_cookie_vs_field",
    ],
    "samesite_dns": [
        "samesite_lax_detected",
        "samesite_missing_detected",
        "dns_rebindable_ttl",
        "dns_rebindable_wildcard",
        "dns_rebindable_ip_flip",
        "samesite_dns_bypass_risk",
    ],
    "csrf_subdomain": [
        "csrf_subdomain_cookie_scope",
        "csrf_subdomain_no_httponly",
        "csrf_subdomain_wildcard_domain",
        "csrf_subdomain_samesite_none",
        "csrf_subdomain_takeover_risk",
        "csrf_subdomain_combined_risk",
    ],
    "cookie_quoting": [
        "quoting_semicolon_in_value",
        "quoting_backslash_escape",
        "quoting_null_byte",
        "quoting_comma_separator",
        "quoting_unbalanced_quotes",
        "quoting_whitespace_in_value",
    ],
}

_CSRF_COOKIE_NAMES: frozenset[str] = frozenset({
    "csrf_token", "_csrf", "csrf", "csrftoken", "xsrf-token",
    "_xsrf", "_csrf_token", "csrfmiddlewaretoken",
    "__requestverificationtoken", "x-csrf-token",
    "x-xsrf-token", "csrf_secret", "csrf_protection",
})

_CSRF_FIELD_NAMES: frozenset[str] = frozenset({
    "csrf_token", "_csrf", "csrf", "csrftoken", "_token",
    "authenticity_token", "xsrf-token", "_xsrf", "_csrf_token",
    "csrfmiddlewaretoken", "__requestverificationtoken",
})

_COOKIE_PATH_TRAVERSAL_PAYLOADS: list[tuple[str, str, str]] = [
    ("traversal_url_encoded", "/..%2f", "URL-encoded slash traversal"),
    ("traversal_double_encoded", "/..%252f", "Double-encoded slash traversal"),
    ("traversal_semicolon", "/..;/", "Semicolon bypass"),
    ("traversal_backslash", "/..%5c", "Backslash traversal"),
    ("traversal_overlong_utf8", "/..%c0%af", "Overlong UTF-8 traversal"),
    ("traversal_tab_injection", "/..%09", "Tab character injection"),
]


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
    """Parseia um header Set-Cookie em CookieInfo (RFC 6265 compliant)."""
    pos = 0
    length = len(raw)

    while pos < length and raw[pos] in (' ', '\t'):
        pos += 1

    name_start = pos
    while pos < length and raw[pos] not in ('=', ';', ' ', '\t'):
        pos += 1
    name = raw[name_start:pos]

    if pos >= length or raw[pos] != '=':
        return CookieInfo(
            name=name, value="", domain="", path="",
            secure=False, httponly=False, samesite="", raw=raw,
        )
    pos += 1

    value = ""
    if pos < length and raw[pos] == '"':
        pos += 1
        value_parts: list[str] = []
        while pos < length:
            ch = raw[pos]
            if ch == '\\' and pos + 1 < length:
                value_parts.append(raw[pos + 1])
                pos += 2
            elif ch == '"':
                pos += 1
                break
            else:
                value_parts.append(ch)
                pos += 1
        value = ''.join(value_parts)
        while pos < length and raw[pos] != ';':
            pos += 1
    else:
        value_start = pos
        while pos < length and raw[pos] != ';':
            pos += 1
        value = raw[value_start:pos]

    domain = ""
    path = ""
    secure = False
    httponly = False
    samesite = ""

    while pos < length:
        while pos < length and raw[pos] == ';':
            pos += 1
        while pos < length and raw[pos] in (' ', '\t'):
            pos += 1

        attr_start = pos
        while pos < length and raw[pos] not in ('=', ';', ' ', '\t'):
            pos += 1
        attr_name = raw[attr_start:pos].lower()

        if pos < length and raw[pos] == '=':
            pos += 1
            if pos < length and raw[pos] == '"':
                pos += 1
                val_parts = []
                while pos < length:
                    ch = raw[pos]
                    if ch == '\\' and pos + 1 < length:
                        val_parts.append(raw[pos + 1])
                        pos += 2
                    elif ch == '"':
                        pos += 1
                        break
                    else:
                        val_parts.append(ch)
                        pos += 1
                attr_value = ''.join(val_parts)
            else:
                val_start = pos
                while pos < length and raw[pos] != ';':
                    pos += 1
                attr_value = raw[val_start:pos].strip()
        else:
            attr_value = ""

        if attr_name == "httponly":
            httponly = True
        elif attr_name == "secure":
            secure = True
        elif attr_name == "domain":
            domain = attr_value
        elif attr_name == "path":
            path = attr_value
        elif attr_name == "samesite":
            samesite = attr_value.lower()

    return CookieInfo(
        name=name, value=value, domain=domain, path=path,
        secure=secure, httponly=httponly, samesite=samesite, raw=raw,
    )


def _extract_target_domain(url: str) -> str:
    """Extrai o dominio base de uma URL, lidando com TLDs compostos."""
    parsed = urlparse(url)
    host = parsed.hostname or ""
    parts = host.split(".")
    if len(parts) >= 2:
        # Pula partes de TLD composto (ex: co.uk, com.br)
        for i in range(2, len(parts) + 1):
            candidate = ".".join(parts[-i:])
            if _is_public_suffix(candidate):
                continue
            return ".".join(parts[-i:])
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


async def _test_path_traversal_active(
    client: httpx.AsyncClient,
    target: str,
    cookies: list[CookieInfo],
) -> list[CookieBoundaryAttempt]:
    """Testa bypasses ativos de Path em cookies com escopo restrito."""
    results: list[CookieBoundaryAttempt] = []
    scoped = [c for c in cookies if c.path and c.path != "/"]
    if not scoped:
        return results

    parsed = urlparse(target)
    base = f"{parsed.scheme}://{parsed.netloc}"

    for cookie in scoped:
        cookie_path = cookie.path.rstrip("/")

        for tech, suffix, desc in _COOKIE_PATH_TRAVERSAL_PAYLOADS:
            bypass_url = f"{base}{cookie_path}{suffix}"
            try:
                resp = await client.get(bypass_url, follow_redirects=False)
                resp_cookies = resp.headers.get_list("set-cookie")
                leaked = any(cookie.name in sc for sc in resp_cookies)
                results.append(CookieBoundaryAttempt(
                    technique=tech, category="path_traversal",
                    cookie_name=cookie.name, attribute_tested="Path",
                    attribute_value=cookie.path, vulnerable=leaked,
                    details=f"{desc}: {bypass_url}" if leaked else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(CookieBoundaryAttempt(
                    technique=tech, category="path_traversal",
                    cookie_name=cookie.name, attribute_tested="Path",
                    attribute_value=cookie.path, vulnerable=False,
                    details="", error=str(e)[:100],
                ))

        upper_path = cookie_path.upper()
        if upper_path != cookie_path:
            bypass_url = f"{base}{upper_path}"
            try:
                resp = await client.get(bypass_url, follow_redirects=False)
                resp_cookies = resp.headers.get_list("set-cookie")
                leaked = any(cookie.name in sc for sc in resp_cookies)
                results.append(CookieBoundaryAttempt(
                    technique="traversal_case_variation", category="path_traversal",
                    cookie_name=cookie.name, attribute_tested="Path",
                    attribute_value=cookie.path, vulnerable=leaked,
                    details=f"Case variation: {bypass_url}" if leaked else "",
                    error="",
                ))
            except httpx.RequestError as e:
                results.append(CookieBoundaryAttempt(
                    technique="traversal_case_variation", category="path_traversal",
                    cookie_name=cookie.name, attribute_tested="Path",
                    attribute_value=cookie.path, vulnerable=False,
                    details="", error=str(e)[:100],
                ))

        trailing_url = f"{base}{cookie_path}/"
        try:
            resp = await client.get(trailing_url, follow_redirects=False)
            resp_cookies = resp.headers.get_list("set-cookie")
            leaked = any(cookie.name in sc for sc in resp_cookies)
            results.append(CookieBoundaryAttempt(
                technique="traversal_trailing_slash", category="path_traversal",
                cookie_name=cookie.name, attribute_tested="Path",
                attribute_value=cookie.path, vulnerable=leaked,
                details=f"Trailing slash: {trailing_url}" if leaked else "",
                error="",
            ))
        except httpx.RequestError as e:
            results.append(CookieBoundaryAttempt(
                technique="traversal_trailing_slash", category="path_traversal",
                cookie_name=cookie.name, attribute_tested="Path",
                attribute_value=cookie.path, vulnerable=False,
                details="", error=str(e)[:100],
            ))

        prefix_url = f"{base}{cookie_path}2"
        try:
            resp = await client.get(prefix_url, follow_redirects=False)
            resp_cookies = resp.headers.get_list("set-cookie")
            leaked = any(cookie.name in sc for sc in resp_cookies)
            results.append(CookieBoundaryAttempt(
                technique="traversal_prefix_match", category="path_traversal",
                cookie_name=cookie.name, attribute_tested="Path",
                attribute_value=cookie.path, vulnerable=leaked,
                details=f"Prefix match (RFC 6265): {prefix_url}" if leaked else "",
                error="",
            ))
        except httpx.RequestError as e:
            results.append(CookieBoundaryAttempt(
                technique="traversal_prefix_match", category="path_traversal",
                cookie_name=cookie.name, attribute_tested="Path",
                attribute_value=cookie.path, vulnerable=False,
                details="", error=str(e)[:100],
            ))

    return results


def _is_csrf_cookie(cookie_name: str) -> bool:
    """Verifica se o nome do cookie indica um token CSRF."""
    lower = cookie_name.lower()
    return any(csrf in lower for csrf in _CSRF_COOKIE_NAMES)


async def _test_double_submit(
    client: httpx.AsyncClient,
    target: str,
    cookies: list[CookieInfo],
) -> list[CookieBoundaryAttempt]:
    """Testa se o padrao Double Submit Cookie e bypassavel."""
    results: list[CookieBoundaryAttempt] = []
    csrf_cookies = [c for c in cookies if _is_csrf_cookie(c.name)]

    if not csrf_cookies:
        return results

    for cookie in csrf_cookies:
        results.append(CookieBoundaryAttempt(
            technique="ds_cookie_no_httponly", category="double_submit",
            cookie_name=cookie.name, attribute_tested="HttpOnly",
            attribute_value=str(cookie.httponly), vulnerable=not cookie.httponly,
            details=f"Cookie CSRF '{cookie.name}' legivel via JS (sem HttpOnly)"
                    if not cookie.httponly else "",
            error="",
        ))

        has_samesite = bool(cookie.samesite)
        samesite_none = cookie.samesite.lower() == "none"
        results.append(CookieBoundaryAttempt(
            technique="ds_cookie_no_samesite", category="double_submit",
            cookie_name=cookie.name, attribute_tested="SameSite",
            attribute_value=cookie.samesite or "ausente",
            vulnerable=not has_samesite or samesite_none,
            details=f"Cookie CSRF '{cookie.name}' enviado cross-site"
                    if not has_samesite or samesite_none else "",
            error="",
        ))

        has_domain = bool(cookie.domain)
        overly_broad = has_domain and cookie.domain.lstrip(".").count(".") <= 1
        results.append(CookieBoundaryAttempt(
            technique="ds_cookie_overly_broad_domain", category="double_submit",
            cookie_name=cookie.name, attribute_tested="Domain",
            attribute_value=cookie.domain or "ausente",
            vulnerable=overly_broad,
            details=f"Cookie CSRF '{cookie.name}' em domain amplo: {cookie.domain}"
                    if overly_broad else "",
            error="",
        ))

        results.append(CookieBoundaryAttempt(
            technique="ds_cookie_no_secure", category="double_submit",
            cookie_name=cookie.name, attribute_tested="Secure",
            attribute_value=str(cookie.secure), vulnerable=not cookie.secure,
            details=f"Cookie CSRF '{cookie.name}' sem Secure" if not cookie.secure else "",
            error="",
        ))

    try:
        _status, _headers, body, _raw = await fetch(client, target, timeout=10)
        body_text = body.decode("utf-8", errors="replace").lower()
        has_form = "<form" in body_text
        has_csrf_field = any(
            f'name="{field}"' in body_text or f"name='{field}'" in body_text
            for field in _CSRF_FIELD_NAMES
        )
        pattern_confirmed = has_form and has_csrf_field
        results.append(CookieBoundaryAttempt(
            technique="ds_token_in_cookie_vs_field", category="double_submit",
            cookie_name=csrf_cookies[0].name, attribute_tested="Pattern",
            attribute_value="confirmed" if pattern_confirmed else "not_detected",
            vulnerable=pattern_confirmed,
            details="Double Submit Cookie pattern confirmado (cookie + campo hidden)"
                    if pattern_confirmed else "",
            error="",
        ))
    except Exception as e:
        results.append(CookieBoundaryAttempt(
            technique="ds_token_in_cookie_vs_field", category="double_submit",
            cookie_name=csrf_cookies[0].name, attribute_tested="Pattern",
            attribute_value="error", vulnerable=False,
            details="", error=str(e)[:100],
        ))

    return results


async def _test_samesite_dns_bypass(
    client: httpx.AsyncClient,
    target: str,
    cookies: list[CookieInfo],
) -> list[CookieBoundaryAttempt]:
    """Testa se SameSite=Lax e bypassavel via DNS rebinding."""
    results: list[CookieBoundaryAttempt] = []
    lax_cookies = [
        c for c in cookies
        if c.samesite.lower() == "lax" or not c.samesite
    ]

    if not lax_cookies:
        return results

    for cookie in lax_cookies:
        is_missing = not cookie.samesite
        results.append(CookieBoundaryAttempt(
            technique="samesite_lax_detected" if not is_missing else "samesite_missing_detected",
            category="samesite_dns",
            cookie_name=cookie.name, attribute_tested="SameSite",
            attribute_value=cookie.samesite or "ausente",
            vulnerable=True,
            details=f"Cookie '{cookie.name}' SameSite={'Lax (bypassavel via top-level GET)' if not is_missing else 'ausente (default Lax)'}",
            error="",
        ))

    parsed = urlparse(target)
    domain = parsed.hostname or ""
    if not domain:
        return results

    try:
        from mytools.dns.dnsrebinding import scan_rebinding

        rebinding_results = await asyncio.to_thread(scan_rebinding, domain)
    except Exception as e:
        results.append(CookieBoundaryAttempt(
            technique="samesite_dns_bypass_risk", category="samesite_dns",
            cookie_name=lax_cookies[0].name, attribute_tested="DNS",
            attribute_value="error", vulnerable=False,
            details="", error=str(e)[:100],
        ))
        return results

    has_low_ttl = any(
        r.check == "ttl" and r.severity in {"critical", "high", "medium"}
        for r in rebinding_results
    )
    has_wildcard = any(
        r.check == "wildcard" and r.severity in {"critical", "high", "medium"}
        for r in rebinding_results
    )
    has_ip_flip = any(
        r.check == "ip_flip" and r.severity == "critical"
        for r in rebinding_results
    )

    if has_low_ttl:
        results.append(CookieBoundaryAttempt(
            technique="dns_rebindable_ttl", category="samesite_dns",
            cookie_name=lax_cookies[0].name, attribute_tested="DNS TTL",
            attribute_value="low", vulnerable=True,
            details="TTL baixo detectado — DNS rebinding factivel",
            error="",
        ))

    if has_wildcard:
        results.append(CookieBoundaryAttempt(
            technique="dns_rebindable_wildcard", category="samesite_dns",
            cookie_name=lax_cookies[0].name, attribute_tested="DNS Wildcard",
            attribute_value="detected", vulnerable=True,
            details="Wildcard DNS detectado — subdominios aleatorios resolvem",
            error="",
        ))

    if has_ip_flip:
        results.append(CookieBoundaryAttempt(
            technique="dns_rebindable_ip_flip", category="samesite_dns",
            cookie_name=lax_cookies[0].name, attribute_tested="DNS IP Flip",
            attribute_value="detected", vulnerable=True,
            details="IP flip detectado — alternancia entre IPs publicos e privados",
            error="",
        ))

    rebindable = has_low_ttl or has_wildcard or has_ip_flip
    if rebindable:
        cookie_names = ", ".join(c.name for c in lax_cookies)
        results.append(CookieBoundaryAttempt(
            technique="samesite_dns_bypass_risk", category="samesite_dns",
            cookie_name=lax_cookies[0].name, attribute_tested="Combined Risk",
            attribute_value="high" if has_ip_flip else "medium",
            vulnerable=True,
            details=(
                f"SameSite=Lax cookies ({cookie_names}) bypassaveis via DNS rebinding. "
                f"Indicadores: {'TTL baixo' if has_low_ttl else ''}"
                f"{' | Wildcard DNS' if has_wildcard else ''}"
                f"{' | IP flip' if has_ip_flip else ''}"
            ),
            error="",
        ))

    return results


async def _test_csrf_subdomain(
    client: httpx.AsyncClient,
    target: str,
    cookies: list[CookieInfo],
) -> list[CookieBoundaryAttempt]:
    """Testa se protecao CSRF e bypassavel via subdominios."""
    results: list[CookieBoundaryAttempt] = []
    csrf_cookies = [c for c in cookies if _is_csrf_cookie(c.name)]

    if not csrf_cookies:
        return results

    parsed = urlparse(target)
    domain = parsed.hostname or ""
    base_domain = _extract_target_domain(target)

    for cookie in csrf_cookies:
        if cookie.domain:
            is_wildcard = cookie.domain.startswith(".")
            is_broad = is_wildcard or (base_domain in cookie.domain and cookie.domain != domain)
            if is_wildcard:
                results.append(CookieBoundaryAttempt(
                    technique="csrf_subdomain_wildcard_domain", category="csrf_subdomain",
                    cookie_name=cookie.name, attribute_tested="Domain",
                    attribute_value=cookie.domain, vulnerable=True,
                    details=f"Cookie '{cookie.name}' com Domain wildcard {cookie.domain} — acessivel por qualquer subdominio",
                    error="",
                ))
            elif is_broad:
                results.append(CookieBoundaryAttempt(
                    technique="csrf_subdomain_cookie_scope", category="csrf_subdomain",
                    cookie_name=cookie.name, attribute_tested="Domain",
                    attribute_value=cookie.domain, vulnerable=True,
                    details=f"Cookie '{cookie.name}' com Domain {cookie.domain} — compartilhado entre subdominios",
                    error="",
                ))

        if not cookie.httponly:
            results.append(CookieBoundaryAttempt(
                technique="csrf_subdomain_no_httponly", category="csrf_subdomain",
                cookie_name=cookie.name, attribute_tested="HttpOnly",
                attribute_value="ausente", vulnerable=True,
                details=f"Cookie '{cookie.name}' sem HttpOnly — JavaScript em subdominio pode ler token CSRF",
                error="",
            ))

        if cookie.samesite.lower() == "none":
            results.append(CookieBoundaryAttempt(
                technique="csrf_subdomain_samesite_none", category="csrf_subdomain",
                cookie_name=cookie.name, attribute_tested="SameSite",
                attribute_value="None", vulnerable=True,
                details=f"Cookie '{cookie.name}' SameSite=None — requests cross-site de subdominio permitidos",
                error="",
            ))

    if not domain:
        return results

    try:
        from mytools.dns.subdomainenum import passive_enumeration

        subdomains = await asyncio.to_thread(
            passive_enumeration, domain, ["crtsh", "otx", "urlscan"],
        )
    except Exception as e:
        results.append(CookieBoundaryAttempt(
            technique="csrf_subdomain_takeover_risk", category="csrf_subdomain",
            cookie_name=csrf_cookies[0].name, attribute_tested="Subdomains",
            attribute_value="error", vulnerable=False,
            details="", error=str(e)[:100],
        ))
        return results

    own_subdomains = [
        s for s in subdomains
        if s.subdomain.endswith(f".{domain}") and s.subdomain != domain
    ]

    if own_subdomains:
        sub_list = ", ".join(s.subdomain for s in own_subdomains[:5])
        more = f" (+{len(own_subdomains) - 5} mais)" if len(own_subdomains) > 5 else ""
        results.append(CookieBoundaryAttempt(
            technique="csrf_subdomain_takeover_risk", category="csrf_subdomain",
            cookie_name=csrf_cookies[0].name, attribute_tested="Subdomains",
            attribute_value=f"{len(own_subdomains)} found", vulnerable=True,
            details=f"Subdominios descobertos: {sub_list}{more} — potencial para takeover/CSRF",
            error="",
        ))

    has_cookie_scope = any(
        a.technique in {"csrf_subdomain_cookie_scope", "csrf_subdomain_wildcard_domain"}
        for a in results
    )
    has_no_httponly = any(a.technique == "csrf_subdomain_no_httponly" for a in results)
    has_samesite_none = any(a.technique == "csrf_subdomain_samesite_none" for a in results)
    has_subdomains = any(a.technique == "csrf_subdomain_takeover_risk" and a.vulnerable for a in results)

    risk_count = sum([has_cookie_scope, has_no_httponly, has_samesite_none, has_subdomains])
    if risk_count >= 2:
        cookie_names = ", ".join(c.name for c in csrf_cookies)
        indicators = []
        if has_cookie_scope:
            indicators.append("Domain broad/wildcard")
        if has_no_httponly:
            indicators.append("sem HttpOnly")
        if has_samesite_none:
            indicators.append("SameSite=None")
        if has_subdomains:
            indicators.append("subdominios descobertos")
        results.append(CookieBoundaryAttempt(
            technique="csrf_subdomain_combined_risk", category="csrf_subdomain",
            cookie_name=csrf_cookies[0].name, attribute_tested="Combined Risk",
            attribute_value="high" if risk_count >= 3 else "medium",
            vulnerable=True,
            details=(
                f"CSRF cookies ({cookie_names}) com {risk_count} indicadores de bypass via subdominio: "
                f"{', '.join(indicators)}"
            ),
            error="",
        ))

    return results


def _test_cookie_quoting(cookies: list[CookieInfo]) -> list[CookieBoundaryAttempt]:
    """Testa edge cases de quoting em cookies (aspas, backslashes, null bytes, separadores)."""
    results: list[CookieBoundaryAttempt] = []

    for cookie in cookies:
        raw = cookie.raw
        value = cookie.value

        if ';' in value:
            results.append(CookieBoundaryAttempt(
                technique="quoting_semicolon_in_value", category="cookie_quoting",
                cookie_name=cookie.name, attribute_tested="Value",
                attribute_value=value[:50], vulnerable=True,
                details=f"Cookie '{cookie.name}' contem ';' no valor — parsers podem dividir incorretamente",
                error="",
            ))

        if '\\' in raw:
            results.append(CookieBoundaryAttempt(
                technique="quoting_backslash_escape", category="cookie_quoting",
                cookie_name=cookie.name, attribute_tested="Raw",
                attribute_value=raw[:50], vulnerable=True,
                details=f"Cookie '{cookie.name}' contem backslash no header raw — risco de confusao de escape",
                error="",
            ))

        if '\x00' in value:
            results.append(CookieBoundaryAttempt(
                technique="quoting_null_byte", category="cookie_quoting",
                cookie_name=cookie.name, attribute_tested="Value",
                attribute_value="contains \\x00", vulnerable=True,
                details=f"Cookie '{cookie.name}' contem null byte — risco de truncamento entre parsers",
                error="",
            ))

        if ',' in raw and ';' not in raw.split('=', 1)[-1] if '=' in raw else True:
            name_value = raw.split('=', 1)[0] if '=' in raw else raw
            rest = raw[len(name_value):] if '=' in raw else ""
            if ',' in rest and ';' not in rest:
                results.append(CookieBoundaryAttempt(
                    technique="quoting_comma_separator", category="cookie_quoting",
                    cookie_name=cookie.name, attribute_tested="Separator",
                    attribute_value=",", vulnerable=True,
                    details=f"Cookie '{cookie.name}' usa ',' como separador — nao conforme RFC 6265",
                    error="",
                ))

        quote_count = raw.count('"')
        if quote_count % 2 != 0:
            results.append(CookieBoundaryAttempt(
                technique="quoting_unbalanced_quotes", category="cookie_quoting",
                cookie_name=cookie.name, attribute_tested="Quotes",
                attribute_value=f"{quote_count} quotes", vulnerable=True,
                details=f"Cookie '{cookie.name}' tem {quote_count} aspas (impar) — aspas desbalanceadas",
                error="",
            ))

        if value != value.strip() and value.strip():
            results.append(CookieBoundaryAttempt(
                technique="quoting_whitespace_in_value", category="cookie_quoting",
                cookie_name=cookie.name, attribute_tested="Value",
                attribute_value=value[:50], vulnerable=True,
                details=f"Cookie '{cookie.name}' tem whitespace no inicio/fim do valor",
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
            elif cat == "path_traversal":
                with contextlib.suppress(Exception):
                    all_attempts.extend(
                        await _test_path_traversal_active(client, target, cookies),
                    )
            elif cat == "double_submit":
                with contextlib.suppress(Exception):
                    all_attempts.extend(
                        await _test_double_submit(client, target, cookies),
                    )
            elif cat == "samesite_dns":
                with contextlib.suppress(Exception):
                    all_attempts.extend(
                        await _test_samesite_dns_bypass(client, target, cookies),
                    )
            elif cat == "csrf_subdomain":
                with contextlib.suppress(Exception):
                    all_attempts.extend(
                        await _test_csrf_subdomain(client, target, cookies),
                    )
            elif cat == "cookie_quoting":
                all_attempts.extend(_test_cookie_quoting(cookies))

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
    create_banner(art, "   cookieboundary: domain, flags, path, path_traversal, double_submit, samesite_dns, csrf_subdomain, cookie_quoting")()


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
            "  mytools-cookieboundary https://target.com -c path_traversal\n"
            "  mytools-cookieboundary https://target.com -c double_submit\n"
            "  mytools-cookieboundary https://target.com -c samesite_dns\n"
            "  mytools-cookieboundary https://target.com -c csrf_subdomain\n"
            "  mytools-cookieboundary https://target.com -c cookie_quoting\n"
            "  mytools-cookieboundary https://target.com --proxy http://127.0.0.1:8080"
        ),
    )
    parser.add_argument("url", help="URL alvo para o scan")
    parser.add_argument(
        "-c", "--category",
        default="all",
        choices=["all", "domain", "flags", "path", "path_traversal", "double_submit", "samesite_dns", "csrf_subdomain", "cookie_quoting"],
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
            "  https://target.com -c path_traversal\n"
            "  https://target.com -c double_submit\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )
