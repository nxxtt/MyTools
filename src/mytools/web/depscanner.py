"""Dependency Scanner — deteccao de libs front-end/back-end + verificacao CVE.

Modulo inspirado em retire.js / WPScan lite. Detecta bibliotecas via:
  - Tags HTML (script src, link href, meta tags)
  - Headers HTTP (X-Powered-By, Server, X-AspNet-Version)
  - Cookies (PHPSESSID, JSESSIONID, connect.sid, etc.)
  - Manifest files (/package.json, /composer.json, /Gemfile.lock)
  - Error pages (stack traces por framework)
  - Sourcemap probing (extrair versao de .map)

Apos deteccao, compara versoes com CVE database embutida (offline) e
marca dependencias desatualizadas.

Limitacoes conhecidas:
  - Extracao de versao e imprecisa em libs compiladas/minificadas.
    CDN paths sem versao no path retornam version="" sem sourcemap.
  - Sourcemap probing so funciona para libs que publicam sourcemaps
    em producao (~20% dos casos). React, Vue, Angular sim;
    jQuery, Bootstrap geralmente nao.
  - Manifest probing depende de arquivos acessivel publicamente.
    Muitos servidores bloqueiam acesso a /package.json.
  - CVE database e estatica e precisa de atualizacoes manuais.
"""
from __future__ import annotations

import argparse
import json
import logging
import re
from dataclasses import asdict, dataclass
from typing import Any

import httpx

from mytools.core.utils import (
    Cyber,
    FetchError,
    add_base_args,
    add_http_args,
    color,
    create_async_client,
    create_banner,
    fetch,
    init_scanner,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.depscanner")

BANNER_ART = r"""
  ____       _              _____
 |  _ \  ___| |_ ___  _ __|  ___|__  _ __ ___ ___  ___  _ __
 | | | |/ _ \ __/ _ \| '__| |_ / _ \| '__/ __/ _ \/ _ \| '_ \
 | |_| |  __/ || (_) | |  |  _| (_) | | | (_|  __/ (_) | | | |
 |____/ \___|\__\___/|_|  |_|  \___/|_|  \___\___|\___/|_| |_|
"""

DEFAULT_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------

_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "frontend_deps": ["frontend_probe"],
    "backend_deps": ["backend_probe"],
    "cve_check": ["cve_match"],
    "outdated_check": ["outdated_match"],
}

_FRONTEND_LIBS_DEFAULT: dict[str, Any] = {
    "jquery": {
        "patterns": [
            r"/jquery[@. -]([\d]+\.[\d]+\.[\d]+)",
            r"/jquery\.min\.js\?v=([\d]+\.[\d]+\.[\d]+)",
        ],
        "latest_known": "3.7.1",
        "cves": [
            {
                "id": "CVE-2020-11022",
                "affected": "<3.5.0",
                "severity": "medium",
                "description": "XSS in jQuery.htmlPrefilter",
            },
        ],
    },
    "react": {
        "patterns": [r"/react@([\d]+\.[\d]+\.[\d]+)"],
        "sourcemap": True,
        "latest_known": "18.3.1",
        "cves": [
            {
                "id": "CVE-2024-2858",
                "affected": "<18.2.0",
                "severity": "medium",
                "description": "Server-Side Rendering DoS",
            },
        ],
    },
}

_BACKEND_LIBS_DEFAULT: dict[str, Any] = {
    "express": {
        "headers": ["X-Powered-By: Express"],
        "cookies": ["connect.sid"],
        "error_patterns": ["at Layer.handle", "at Router.handle"],
        "manifest_paths": ["/package.json"],
        "manifest_key_pattern": r'"express":\s*"(\\^?\d+\.\d+\.\d+)"',
        "latest_known": "4.21.0",
        "cves": [
            {
                "id": "CVE-2024-29041",
                "affected": "<4.19.2",
                "severity": "high",
                "description": "Open redirect via URL parsing",
            },
        ],
    },
}


def _load_dep_data() -> tuple[dict[str, list[str]], dict[str, Any], dict[str, Any]]:
    from mytools.data import load_payloads

    data = load_payloads("web", "dependency_scan", default={
        "category_map": _CATEGORY_MAP_DEFAULT,
        "frontend_libraries": _FRONTEND_LIBS_DEFAULT,
        "backend_libraries": _BACKEND_LIBS_DEFAULT,
    })
    return (
        data.get("category_map", _CATEGORY_MAP_DEFAULT),
        data.get("frontend_libraries", _FRONTEND_LIBS_DEFAULT),
        data.get("backend_libraries", _BACKEND_LIBS_DEFAULT),
    )


_CATEGORY_MAP, _FRONTEND_LIBS, _BACKEND_LIBS = _load_dep_data()


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DepScanAttempt:
    """Resultado de uma tentativa de deteccao/check de dependencia."""

    technique: str
    category: str
    library: str
    version: str
    source: str
    severity: str
    details: str
    error: str


@dataclass(frozen=True, slots=True)
class DepScanResult:
    """Resultado consolidado do scan de dependencias."""

    target: str
    attempts: list[DepScanAttempt]
    vulnerable_deps: list[str]
    outdated_deps: list[str]
    overall_status: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _parse_manifest_version(body: str, pattern: str) -> str:
    """Extrai versao de manifest JSON via regex. Retorna '' se nao encontrar."""
    m = re.search(pattern, body)
    if m:
        ver = m.group(1)
        return re.sub(r"^[~^>=<]+", "", ver)
    return ""


async def _try_sourcemap_version(
    client: httpx.AsyncClient,
    base_url: str,
    script_src: str,
) -> str:
    """Tenta extrair versao de sourcemap. Retorna '' se falhar."""
    src = script_src.rstrip("/")
    map_url = f"{base_url.rstrip('/')}{src}.map"
    try:
        status, _headers, body_bytes, _raw = await fetch(client, map_url)
        if status != 200:
            return ""
        data = json.loads(body_bytes)
        return str(data.get("version", ""))
    except (json.JSONDecodeError, Exception):
        return ""


async def _check_url(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
) -> tuple[int, str]:
    """Faz GET e retorna (status_code, body_text)."""
    url = f"{base_url.rstrip('/')}{path}"
    try:
        status, _headers, body_bytes, _raw = await fetch(client, url)
        body = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
        return status, body
    except FetchError:
        return 0, ""
    except Exception as exc:
        logger.debug("check_url failed for %s: %s", url, exc)
        return 0, ""


# ---------------------------------------------------------------------------
# Frontend detection
# ---------------------------------------------------------------------------

_SCRIPT_RE = re.compile(
    r"""<script[^>]+src=["']([^"']+)["']""",
    re.IGNORECASE,
)
_LINK_RE = re.compile(
    r"""<link[^>]+href=["']([^"']+\.css[^"']*)["']""",
    re.IGNORECASE,
)
_META_RE = re.compile(
    r"""<meta[^>]+(?:name|property)=["']([^"']+)["'][^>]+content=["']([^"']+)["']""",
    re.IGNORECASE,
)


async def _detect_frontend_deps(
    client: httpx.AsyncClient,
    base_url: str,
) -> list[DepScanAttempt]:
    """Detecta libs front-end de HTML + sourcemaps."""
    attempts: list[DepScanAttempt] = []
    status, body = await _check_url(client, base_url, "/")
    if status == 0 or not body:
        return attempts

    detected: dict[str, str] = {}

    # Scan script tags
    for m in _SCRIPT_RE.finditer(body):
        src = m.group(1)
        for lib_name, sig in _FRONTEND_LIBS.items():
            if lib_name in detected:
                continue
            for pat in sig.get("patterns", []):
                vm = re.search(pat, src, re.IGNORECASE)
                if vm:
                    detected[lib_name] = vm.group(1)
                    break

    # Scan link tags
    for m in _LINK_RE.finditer(body):
        href = m.group(1)
        for lib_name, sig in _FRONTEND_LIBS.items():
            if lib_name in detected:
                continue
            for pat in sig.get("patterns", []):
                vm = re.search(pat, href, re.IGNORECASE)
                if vm:
                    detected[lib_name] = vm.group(1)
                    break

    # Scan meta tags
    for m in _META_RE.finditer(body):
        content = m.group(2)
        for lib_name, sig in _FRONTEND_LIBS.items():
            if lib_name in detected:
                continue
            for pat in sig.get("patterns", []):
                vm = re.search(pat, content, re.IGNORECASE)
                if vm:
                    detected[lib_name] = vm.group(1)
                    break

    # Sourcemap probing for libs without version
    for lib_name, sig in _FRONTEND_LIBS.items():
        if lib_name in detected:
            continue
        if not sig.get("sourcemap"):
            continue
        for m in _SCRIPT_RE.finditer(body):
            src = m.group(1)
            for pat in sig.get("patterns", []):
                if re.search(pat, src, re.IGNORECASE):
                    ver = await _try_sourcemap_version(client, base_url, src)
                    if ver:
                        detected[lib_name] = ver
                        break
            if lib_name in detected:
                break

    # Build attempts
    for lib_name, version in detected.items():
        attempts.append(DepScanAttempt(
            technique="frontend_probe",
            category="frontend_deps",
            library=lib_name,
            version=version,
            source="script_src",
            severity="",
            details="Detected in HTML source",
            error="",
        ))

    # Log libs found without version
    attempts.extend(
        DepScanAttempt(
                technique="frontend_probe",
                category="frontend_deps",
                library=lib_name,
                version="",
                source="",
                severity="",
                details="Not detected",
                error="",
            )
            for lib_name in _FRONTEND_LIBS
            if lib_name not in detected
            )

    return attempts


# ---------------------------------------------------------------------------
# Backend detection
# ---------------------------------------------------------------------------


async def _detect_backend_deps(
    client: httpx.AsyncClient,
    base_url: str,
) -> list[DepScanAttempt]:
    """Detecta libs back-end de headers, cookies, manifests, error pages."""
    attempts: list[DepScanAttempt] = []

    # Fetch main page for headers + body
    try:
        _status, headers, body_bytes, _raw = await fetch(client, base_url)
        body = body_bytes.decode("utf-8", errors="replace") if body_bytes else ""
        headers_dict = dict(headers) if hasattr(headers, "items") else {}
        headers_lower = {k.lower(): v for k, v in headers_dict.items()}
    except (FetchError, Exception):
        return attempts

    cookies_raw = ""
    try:
        resp = await client.get(base_url)
        cookies_raw = "; ".join(f"{c.name}={c.value}" for c in resp.cookies.jar)
    except Exception:
        pass

    detected: dict[str, str] = {}

    for lib_name, sig in _BACKEND_LIBS.items():
        # Check headers
        for header_pat in sig.get("headers", []):
            key, _, val = header_pat.partition(":")
            key = key.strip().lower()
            val = val.strip()
            actual = headers_lower.get(key, "")
            if val.lower() in actual.lower():
                detected[lib_name] = actual
                break

        if lib_name in detected:
            continue

        # Check cookies
        for cookie_pat in sig.get("cookies", []):
            if cookie_pat.lower() in cookies_raw.lower():
                detected[lib_name] = f"Cookie: {cookie_pat}"
                break

        if lib_name in detected:
            continue

        # Check error patterns
        for err_pat in sig.get("error_patterns", []):
            if err_pat in body:
                detected[lib_name] = f"Error page pattern: {err_pat}"
                break

    # Manifest probing
    for lib_name, sig in _BACKEND_LIBS.items():
        if lib_name in detected:
            continue
        for path in sig.get("manifest_paths", []):
            mstatus, mbody = await _check_url(client, base_url, path)
            if mstatus == 200 and mbody:
                pat = sig.get("manifest_key_pattern", "")
                if pat:
                    ver = _parse_manifest_version(mbody, pat)
                    if ver:
                        detected[lib_name] = f"Manifest: {path}"
                        # Store version for later
                        attempts.append(DepScanAttempt(
                            technique="backend_probe",
                            category="backend_deps",
                            library=lib_name,
                            version=ver,
                            source="manifest",
                            severity="",
                            details=f"Detected via {path}",
                            error="",
                        ))
                        break

    # Add detected entries without version from manifest
    for lib_name, detail in detected.items():
        already = any(a.library == lib_name for a in attempts)
        if not already:
            attempts.append(DepScanAttempt(
                technique="backend_probe",
                category="backend_deps",
                library=lib_name,
                version="",
                source="header",
                severity="",
                details=detail,
                error="",
            ))

    return attempts


# ---------------------------------------------------------------------------
# CVE + Outdated checking
# ---------------------------------------------------------------------------


def _parse_version_list(version_str: str) -> list[int]:
    """Converte versao em lista de inteiros para comparacao."""
    return [int(x) for x in re.findall(r"\d+", version_str)]


def _version_in_range(
    version: str,
    affected: str,
) -> bool:
    """Verifica se versao esta dentro do range afetado.

    Suporta: <3.5.0, <=3.5.0, >=3.0.0, >3.0.0, ==3.5.0
    """
    if not version:
        return False

    affected = affected.strip()
    ver_parts = _parse_version_list(version)

    if affected.startswith("<="):
        bound = _parse_version_list(affected[2:])
        return ver_parts <= bound
    if affected.startswith("<"):
        bound = _parse_version_list(affected[1:])
        return ver_parts < bound
    if affected.startswith(">="):
        bound = _parse_version_list(affected[2:])
        return ver_parts >= bound
    if affected.startswith(">"):
        bound = _parse_version_list(affected[1:])
        return ver_parts > bound
    if affected.startswith("=="):
        bound = _parse_version_list(affected[2:])
        return ver_parts == bound

    return False


def _check_cves(deps: list[DepScanAttempt]) -> list[DepScanAttempt]:
    """Cross-reference libs detectadas com CVE database (offline)."""
    results: list[DepScanAttempt] = []

    detected = {a.library.lower(): a for a in deps if a.version}

    # Check frontend CVEs
    results.extend(
        DepScanAttempt(
                    technique="cve_match",
                    category="cve_check",
                    library=lib_name,
                    version=dep.version,
                    source=dep.source,
                    severity=cve["severity"],
                    details=f"{cve['id']}: {cve['description']} (affected: {cve['affected']})",
                    error="",
                )
        for lib_name, sig in _FRONTEND_LIBS.items()
        if (dep := detected.get(lib_name))
        for cve in sig.get("cves", [])
        if _version_in_range(dep.version, cve["affected"])
    )
    # Check backend CVEs
    results.extend(
     DepScanAttempt(
        technique="cve_match",
        category="cve_check",
        library=lib_name,
        version=dep.version,
        source=dep.source,
        severity=cve["severity"],
        details=f"{cve['id']}: {cve['description']} (affected: {cve['affected']})",
        error="",
    )
    for lib_name, sig in _BACKEND_LIBS.items()
    if (dep := detected.get(lib_name))
    for cve in sig.get("cves", [])
    if _version_in_range(dep.version, cve["affected"])
)
    return results


def _check_outdated(deps: list[DepScanAttempt]) -> list[DepScanAttempt]:
    """Compara versoes detectadas com latest_known (offline)."""
    results: list[DepScanAttempt] = []

    detected = {a.library.lower(): a for a in deps if a.version}

    all_libs: dict[str, dict[str, Any]] = {}
    all_libs.update(_FRONTEND_LIBS)
    all_libs.update(_BACKEND_LIBS)

    for lib_name, sig in all_libs.items():
        dep = detected.get(lib_name)
        if not dep:
            continue
        latest = sig.get("latest_known", "")
        if not latest:
            continue
        if dep.version != latest:
            results.append(DepScanAttempt(
                technique="outdated_match",
                category="outdated_check",
                library=lib_name,
                version=dep.version,
                source=dep.source,
                severity="info",
                details=f"Latest: {latest} (detected: {dep.version})",
                error="",
            ))

    return results


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------


async def scan_dependency(
    base_url: str,
    categories: list[str] | None,
    timeout: float,
) -> DepScanResult:
    """Executa scan de dependencias."""

    all_attempts: list[DepScanAttempt] = []
    vulnerable_deps: list[str] = []
    outdated_deps: list[str] = []

    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())

    async with create_async_client(timeout=timeout) as client:
        # Frontend detection
        frontend_deps: list[DepScanAttempt] = []
        if "frontend_deps" in cats:
            frontend_deps = await _detect_frontend_deps(client, base_url)
            all_attempts.extend(frontend_deps)

        # Backend detection
        backend_deps: list[DepScanAttempt] = []
        if "backend_deps" in cats:
            backend_deps = await _detect_backend_deps(client, base_url)
            all_attempts.extend(backend_deps)

        all_deps = frontend_deps + backend_deps

    # CVE check (offline)
    if "cve_check" in cats:
        cve_results = _check_cves(all_deps)
        all_attempts.extend(cve_results)
        vulnerable_deps = list({
            f"{a.library} {a.version}" for a in cve_results
        })

    # Outdated check (offline)
    if "outdated_check" in cats:
        outdated_results = _check_outdated(all_deps)
        all_attempts.extend(outdated_results)
        outdated_deps = list({
            f"{a.library} {a.version}" for a in outdated_results
        })

    # Determine overall status
    if vulnerable_deps:
        overall = "vulnerable"
    elif outdated_deps:
        overall = "outdated"
    else:
        overall = "secure"

    return DepScanResult(
        target=base_url,
        attempts=all_attempts,
        vulnerable_deps=vulnerable_deps,
        outdated_deps=outdated_deps,
        overall_status=overall,
    )


# ---------------------------------------------------------------------------
# Print results
# ---------------------------------------------------------------------------


def print_results(result: DepScanResult) -> None:
    """Imprime resultados formatados no terminal."""
    print()
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Dependency Scanner")
    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")
    print()

    if result.vulnerable_deps:
        print(color("[!]", Cyber.RED, Cyber.BOLD), "Vulnerable dependencies:")
        for dep in result.vulnerable_deps:
            print(color("    -", Cyber.RED), dep)
        print()

    if result.outdated_deps:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Outdated dependencies:")
        for dep in result.outdated_deps:
            print(color("    -", Cyber.YELLOW), dep)
        print()

    # Group by category
    categories: dict[str, list[DepScanAttempt]] = {}
    for attempt in result.attempts:
        categories.setdefault(attempt.category, []).append(attempt)

    for cat, attempts in categories.items():
        if cat in ("cve_check", "outdated_check"):
            continue
        found = [a for a in attempts if a.version]
        if found:
            print(color("[*]", Cyber.GREEN, Cyber.BOLD), f"{cat}:")
            for a in found:
                ver_str = f" v{a.version}" if a.version else ""
                print(color("    -", Cyber.GREEN), f"{a.library}{ver_str} ({a.source})")
        else:
            print(color("[*]", Cyber.GREEN), f"{cat}: no dependencies found")

    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Constroi parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-depscan",
        description="Dependency Scanner — deteccao de libs + verificacao CVE + outdated",
    )
    parser.add_argument("url", help="URL alvo (ex: https://example.com)")
    parser.add_argument(
        "-c", "--categories",
        nargs="+",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categorias para testar (default: todas)",
    )
    add_base_args(parser)
    add_http_args(parser)
    return parser


def _async_run_once(args: argparse.Namespace) -> DepScanResult:
    """Executa scan uma vez."""
    init_scanner(args)

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    categories = getattr(args, "categories", None)
    timeout = getattr(args, "timeout", DEFAULT_TIMEOUT)

    result = safe_asyncio_run(scan_dependency(
        base_url=url,
        categories=categories,
        timeout=timeout,
    ))

    print_results(result)

    if getattr(args, "output", None):
        write_output(args.output, [asdict(a) for a in result.attempts])

    return result


def run_once(args: argparse.Namespace) -> int:
    """Wrapper sincrono."""
    _async_run_once(args)
    return 0


def main() -> int:
    """Entry point CLI."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=create_banner(BANNER_ART, "Dependency Scanner"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="depscan> ",
        description="Dependency Scanner — deteccao de libs front-end/back-end + CVE + outdated.",
        example="https://example.com -c frontend_deps cve_check",
        contextual_help=(
            "Categorias disponiveis:\n"
            "  frontend_deps   — detectar libs front-end (HTML + sourcemaps)\n"
            "  backend_deps    — detectar libs back-end (headers + manifests)\n"
            "  cve_check       — verificar CVEs conhecidas\n"
            "  outdated_check  — verificar versoes desatualizadas\n"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
