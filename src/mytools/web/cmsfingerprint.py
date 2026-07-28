#!/usr/bin/env python3
"""CMS Fingerprinting — deteccao ativa de CMS, plugins, temas e usuarios.

Testa endpoints HTTP para identificar CMS (WordPress, Joomla, Drupal,
Magento, PrestaShop, OpenCart) via probing de paths especificos.

Detecta:
  - Versao do CMS
  - Plugins/temas instalados
  - Enumeracao de usuarios (WordPress)
  - Extensoes de terceiros (Joomla)

IMPORTANTE: Diferente do techfingerprint (passivo), este modulo faz probing
ativo de paths especificos do CMS.

Fluxo:
  1. cms_detect — identifica CMS via probing de paths caracteristicos
  2. wp_version — extrai versao do WordPress
  3. wp_plugins — detecta plugins via /wp-content/plugins/{plugin}/readme.txt
  4. wp_themes — detecta temas via /wp-content/themes/{theme}/style.css
  5. wp_users — enumera usuarios via author param + WP REST API
  6. joomla_info — versao + extensoes de terceiros Joomla
"""

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
    print_exploit_info,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.cmsfingerprint")

BANNER_ART = r"""
  _____ ___  ____   ___  __  __ ___ _   _    _    _
 / ____/ _ \|  _ \ / _ \|  \/  |_ _| \ | |  / \  | |
| |   | | | | |_) | | | | |\/| || ||  \| | / _ \ | |
| |___| |_| |  __/| |_| | |  | || || |\  |/ ___ \| |___
 \_____\___/|_|    \___/|_|  |_|___|_| \_/_/   \_\_____|
"""

DEFAULT_TIMEOUT = 10.0


# ---------------------------------------------------------------------------
# YAML loading
# ---------------------------------------------------------------------------

_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "cms_detect": ["cms_identify"],
    "wp_version": ["wp_version_probe"],
    "wp_plugins": ["wp_plugin_probe"],
    "wp_themes": ["wp_theme_probe"],
    "wp_users": ["wp_user_enum"],
    "joomla_info": ["joomla_version_probe"],
}

_CMS_SIGNATURES_DEFAULT: dict[str, Any] = {
    "wordpress": {
        "detect_paths": ["/wp-login.php", "/wp-admin/", "/wp-includes/"],
        "version_paths": ["/readme.html", "/feed/", "/wp-includes/version.php"],
        "plugins": [
            "akismet",
            "contact-form-7",
            "wordfence",
            "yoast-seo",
            "woocommerce",
        ],
        "themes": ["twentytwentythree", "twentytwentytwo", "astra", "generatepress"],
        "user_paths": ["/?author=1", "/wp-json/wp/v2/users", "/xmlrpc.php"],
    },
    "joomla": {
        "detect_paths": ["/administrator/", "/configuration.php", "/components/"],
        "version_paths": [
            "/language/en-GB/en-GB.xml",
            "/administrator/manifests/files/joomla.xml",
        ],
        "third_party_extensions": [
            "com_hikashop",
            "com_jce",
            "com_k2",
            "com_virtuemart",
        ],
    },
    "drupal": {
        "detect_paths": ["/core/", "/sites/default/", "/CHANGELOG.txt"],
        "version_paths": ["/core/CHANGELOG.txt"],
        "modules": ["views", "pathauto", "token", "webform"],
    },
    "magento": {
        "detect_paths": ["/magento_version", "/skin/frontend/", "/pub/static/"],
        "version_paths": ["/magento_version"],
    },
    "prestashop": {
        "detect_paths": ["/admin-dev/", "/themes/", "/modules/"],
        "version_paths": ["/install-dev/install_version.php"],
    },
    "opencart": {
        "detect_paths": ["/admin/", "/catalog/", "/system/"],
    },
}


def _load_cms_data() -> tuple[dict[str, list[str]], dict[str, Any]]:
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "cms_fingerprint",
        default={
            "category_map": _CATEGORY_MAP_DEFAULT,
            "cms_signatures": _CMS_SIGNATURES_DEFAULT,
        },
    )
    return (
        data.get("category_map", _CATEGORY_MAP_DEFAULT),
        data.get("cms_signatures", _CMS_SIGNATURES_DEFAULT),
    )


_CATEGORY_MAP, _CMS_SIGNATURES = _load_cms_data()


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CmsAttempt:
    """Resultado de uma tentativa de CMS fingerprinting."""

    technique: str
    category: str
    description: str
    status_code: int
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class CmsResult:
    """Resultado consolidado do scan."""

    target: str
    cms_detected: str
    version: str
    attempts: list[CmsAttempt]
    issues: list[str]
    overall_status: str


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------


async def _check_path(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
) -> tuple[int, str]:
    """Faz GET e retorna (status_code, body_text)."""
    url = f"{base_url.rstrip('/')}{path}"
    try:
        status, _headers, body_bytes, _raw = await fetch(client, url)
        return status, body_bytes.decode("utf-8", errors="replace")
    except FetchError:
        return 0, ""


# ---------------------------------------------------------------------------
# CMS Detection
# ---------------------------------------------------------------------------


async def _detect_cms(
    client: httpx.AsyncClient,
    base_url: str,
) -> str:
    """Identifica CMS via probing de paths caracteristicos. Retorna nome do CMS ou ""."""
    for cms_name, sigs in _CMS_SIGNATURES.items():
        detect_paths = sigs.get("detect_paths", [])
        hits = 0
        for path in detect_paths[:2]:
            status, _ = await _check_path(client, base_url, path)
            if status in (200, 301, 302, 403):
                hits += 1
        if hits >= 2:
            return cms_name
    return ""


# ---------------------------------------------------------------------------
# WordPress detection
# ---------------------------------------------------------------------------


async def _detect_wp_version(
    client: httpx.AsyncClient,
    base_url: str,
) -> tuple[str, str]:
    """Detecta versao do WordPress. Retorna (version, evidence)."""
    # 1. readme.html
    status, body = await _check_path(client, base_url, "/readme.html")
    if status == 200:
        m = re.search(r"Version\s+([\d.]+)", body, re.IGNORECASE)
        if m:
            return m.group(1), f"readme.html: {m.group(0)}"

    # 2. generator meta tag
    status, body = await _check_path(client, base_url, "/")
    if status == 200:
        m = re.search(r'content="WordPress\s+([\d.]+)"', body, re.IGNORECASE)
        if m:
            return m.group(1), f"generator meta: {m.group(0)}"

    # 3. wp-includes/version.php
    status, body = await _check_path(client, base_url, "/wp-includes/version.php")
    if status == 200:
        m = re.search(r"\$wp_version\s*=\s*['\"]([\d.]+)['\"]", body)
        if m:
            return m.group(1), f"version.php: $wp_version = {m.group(1)}"

    return "", ""


async def _detect_wp_plugins(
    client: httpx.AsyncClient,
    base_url: str,
    plugin_list: list[str],
) -> list[str]:
    """Detecta plugins via probing de /wp-content/plugins/{plugin}/readme.txt."""
    found: list[str] = []
    for plugin in plugin_list:
        path = f"/wp-content/plugins/{plugin}/readme.txt"
        status, _ = await _check_path(client, base_url, path)
        if status == 200:
            found.append(plugin)
    return found


async def _detect_wp_themes(
    client: httpx.AsyncClient,
    base_url: str,
    theme_list: list[str],
) -> list[str]:
    """Detecta temas via probing de /wp-content/themes/{theme}/style.css."""
    found: list[str] = []
    for theme in theme_list:
        path = f"/wp-content/themes/{theme}/style.css"
        status, body = await _check_path(client, base_url, path)
        if status == 200 and "Theme Name:" in body:
            found.append(theme)
    return found


async def _detect_wp_users(
    client: httpx.AsyncClient,
    base_url: str,
) -> list[str]:
    """Enumera usuarios WordPress via author param + REST API."""
    users: list[str] = []

    # 1. /?author=1 → redirect reveals username
    for i in range(1, 4):
        status, body = await _check_path(client, base_url, f"/?author={i}")
        if status in (301, 302):
            m = re.search(r"/author/([^/\"'&]+)", body, re.IGNORECASE)
            if not m:
                # Check Location header via fetch redirect handling
                m = re.search(r"/author/([^/\"'&]+)", body)
            if m:
                users.append(m.group(1))

    # 2. WP REST API
    status, body = await _check_path(client, base_url, "/wp-json/wp/v2/users")
    if status == 200:
        try:
            data = json.loads(body)
            if isinstance(data, list):
                for u in data:
                    name = u.get("name", "")
                    if name and name not in users:
                        users.append(name)
        except json.JSONDecodeError, TypeError:
            pass

    return users


# ---------------------------------------------------------------------------
# Joomla detection
# ---------------------------------------------------------------------------


async def _detect_joomla_info(
    client: httpx.AsyncClient,
    base_url: str,
    extension_list: list[str],
) -> tuple[str, list[str]]:
    """Detecta versao Joomla e extensoes de terceiros. Retorna (version, extensions)."""
    version = ""

    # Version via language file
    status, body = await _check_path(client, base_url, "/language/en-GB/en-GB.xml")
    if status == 200:
        m = re.search(r"<version>([\d.]+)</version>", body)
        if m:
            version = m.group(1)

    # Version via manifests
    if not version:
        status, body = await _check_path(
            client, base_url, "/administrator/manifests/files/joomla.xml"
        )
        if status == 200:
            m = re.search(r"<version>([\d.]+)</version>", body)
            if m:
                version = m.group(1)

    # Third-party extensions
    extensions: list[str] = []
    for ext in extension_list:
        path = f"/administrator/components/com_{ext.replace('com_', '')}/"
        status, _ = await _check_path(client, base_url, path)
        if status in (200, 301, 302, 403):
            extensions.append(ext)

    return version, extensions


# ---------------------------------------------------------------------------
# Main scan
# ---------------------------------------------------------------------------


async def scan_cms_fingerprint(
    base_url: str,
    categories: list[str] | None,
    timeout: float,
    plugin_limit: int,
    theme_limit: int,
) -> CmsResult:
    """Executa CMS fingerprinting ativo."""

    all_attempts: list[CmsAttempt] = []
    issues: list[str] = []
    cms_detected = ""
    version = ""

    cats = categories if categories is not None else list(_CATEGORY_MAP.keys())

    async with create_async_client(timeout=timeout) as client:
        # Step 1: CMS detection (always runs)
        if "cms_detect" in cats:
            cms_detected = await _detect_cms(client, base_url)
            if cms_detected:
                all_attempts.append(
                    CmsAttempt(
                        technique="cms_identify",
                        category="cms_detect",
                        description=f"CMS detected: {cms_detected}",
                        status_code=200,
                        vulnerable=True,
                        details=f"CMS: {cms_detected}",
                        error="",
                    )
                )
                issues.append(f"CMS detected: {cms_detected}")
            else:
                all_attempts.append(
                    CmsAttempt(
                        technique="cms_identify",
                        category="cms_detect",
                        description="No CMS detected",
                        status_code=0,
                        vulnerable=False,
                        details="",
                        error="",
                    )
                )

        # Step 2: WordPress-specific checks
        if (
            cms_detected == "wordpress"
            or "wp_version" in cats
            or "wp_plugins" in cats
            or "wp_themes" in cats
            or "wp_users" in cats
        ):
            sigs = _CMS_SIGNATURES.get("wordpress", {})

            # Version
            if "wp_version" in cats:
                version, evidence = await _detect_wp_version(client, base_url)
                if version:
                    all_attempts.append(
                        CmsAttempt(
                            technique="wp_version_probe",
                            category="wp_version",
                            description=f"WordPress version: {version}",
                            status_code=200,
                            vulnerable=True,
                            details=evidence,
                            error="",
                        )
                    )
                else:
                    all_attempts.append(
                        CmsAttempt(
                            technique="wp_version_probe",
                            category="wp_version",
                            description="WordPress version not detected",
                            status_code=0,
                            vulnerable=False,
                            details="",
                            error="",
                        )
                    )

            # Plugins
            if "wp_plugins" in cats:
                plugins = await _detect_wp_plugins(
                    client,
                    base_url,
                    sigs.get("plugins", [])[:plugin_limit],
                )
                if plugins:
                    all_attempts.append(
                        CmsAttempt(
                            technique="wp_plugin_probe",
                            category="wp_plugins",
                            description=f"{len(plugins)} plugin(s) found",
                            status_code=200,
                            vulnerable=True,
                            details=", ".join(plugins),
                            error="",
                        )
                    )
                else:
                    all_attempts.append(
                        CmsAttempt(
                            technique="wp_plugin_probe",
                            category="wp_plugins",
                            description="No plugins detected",
                            status_code=0,
                            vulnerable=False,
                            details="",
                            error="",
                        )
                    )

            # Themes
            if "wp_themes" in cats:
                themes = await _detect_wp_themes(
                    client,
                    base_url,
                    sigs.get("themes", [])[:theme_limit],
                )
                if themes:
                    all_attempts.append(
                        CmsAttempt(
                            technique="wp_theme_probe",
                            category="wp_themes",
                            description=f"{len(themes)} theme(s) found",
                            status_code=200,
                            vulnerable=True,
                            details=", ".join(themes),
                            error="",
                        )
                    )
                else:
                    all_attempts.append(
                        CmsAttempt(
                            technique="wp_theme_probe",
                            category="wp_themes",
                            description="No themes detected",
                            status_code=0,
                            vulnerable=False,
                            details="",
                            error="",
                        )
                    )

            # Users (auto when WordPress detected, or explicit -c wp_users)
            if cms_detected == "wordpress" or "wp_users" in cats:
                users = await _detect_wp_users(client, base_url)
                if users:
                    all_attempts.append(
                        CmsAttempt(
                            technique="wp_user_enum",
                            category="wp_users",
                            description=f"{len(users)} user(s) found",
                            status_code=200,
                            vulnerable=True,
                            details=", ".join(users),
                            error="",
                        )
                    )
                    issues.append(f"WordPress users enumerated: {', '.join(users)}")

        # Step 3: Joomla-specific checks
        if cms_detected == "joomla" or "joomla_info" in cats:
            sigs = _CMS_SIGNATURES.get("joomla", {})
            joomla_version, extensions = await _detect_joomla_info(
                client,
                base_url,
                sigs.get("third_party_extensions", []),
            )
            if joomla_version:
                version = joomla_version
            details_parts = []
            if joomla_version:
                details_parts.append(f"Version: {joomla_version}")
            if extensions:
                details_parts.append(f"Extensions: {', '.join(extensions)}")
            all_attempts.append(
                CmsAttempt(
                    technique="joomla_version_probe",
                    category="joomla_info",
                    description=f"Joomla info: {joomla_version or 'unknown'}",
                    status_code=200 if joomla_version else 0,
                    vulnerable=bool(extensions),
                    details="; ".join(details_parts) or "No info found",
                    error="",
                )
            )

    # Overall status
    vuln_cats = {a.category for a in all_attempts if a.vulnerable}
    overall = "vulnerable" if vuln_cats else "secure"

    return CmsResult(
        target=base_url,
        cms_detected=cms_detected,
        version=version,
        attempts=all_attempts,
        issues=issues,
        overall_status=overall,
    )


# ---------------------------------------------------------------------------
# Print results
# ---------------------------------------------------------------------------


def print_results(result: CmsResult) -> None:
    """Imprime resultados formatados no terminal."""
    print()
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), "CMS Fingerprinting")
    print(color("[*]", Cyber.CYAN), f"Target: {result.target}")

    if result.cms_detected:
        print(
            color("[*]", Cyber.CYAN),
            f"CMS: {result.cms_detected} {result.version}".strip(),
        )
    else:
        print(color("[*]", Cyber.CYAN), "CMS: not detected")

    print()

    if result.issues:
        print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")
        for issue in result.issues:
            print(color("    -", Cyber.YELLOW), issue)
        print()

    # Group by category
    categories: dict[str, list[CmsAttempt]] = {}
    for attempt in result.attempts:
        categories.setdefault(attempt.category, []).append(attempt)

    for cat, attempts in categories.items():
        vuln_in_cat = [a for a in attempts if a.vulnerable]
        if vuln_in_cat:
            print(color("[!]", Cyber.RED, Cyber.BOLD), f"{cat}:")
            for a in vuln_in_cat:
                print(color("    -", Cyber.RED), a.details or a.description)
        else:
            print(color("[*]", Cyber.GREEN), f"{cat}: no findings")

    print()

    for a in result.attempts:
        print_exploit_info(a.exploit, a.tool)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Constrói parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-cmsfp",
        description="CMS Fingerprinting — deteccao ativa de CMS, plugins, temas e usuarios",
    )
    parser.add_argument("url", help="URL alvo (ex: https://example.com)")
    parser.add_argument(
        "-c",
        "--categories",
        nargs="+",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categorias para testar (default: todas)",
    )
    parser.add_argument(
        "--plugin-limit",
        type=int,
        default=15,
        help="Maximo de plugins WordPress para testar (default: 15)",
    )
    parser.add_argument(
        "--theme-limit",
        type=int,
        default=10,
        help="Maximo de temas WordPress para testar (default: 10)",
    )
    add_base_args(parser)
    add_http_args(parser)
    return parser


def _async_run_once(args: argparse.Namespace) -> CmsResult:
    """Executa scan uma vez."""
    init_scanner(args)

    url = args.url
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    categories = getattr(args, "categories", None)
    timeout = getattr(args, "timeout", DEFAULT_TIMEOUT)
    plugin_limit = getattr(args, "plugin_limit", 15)
    theme_limit = getattr(args, "theme_limit", 10)

    result = safe_asyncio_run(
        scan_cms_fingerprint(
            base_url=url,
            categories=categories,
            timeout=timeout,
            plugin_limit=plugin_limit,
            theme_limit=theme_limit,
        )
    )

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
        banner_fn=create_banner(BANNER_ART, "CMS Fingerprinting"),
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None)),
        prompt="cmsfp> ",
        description="CMS Fingerprinting — deteccao ativa de CMS, plugins, temas e usuarios.",
        example="https://example.com -c cms_detect wp_version",
        contextual_help=(
            "Categorias disponiveis:\n"
            "  cms_detect   — identificar CMS\n"
            "  wp_version   — versao do WordPress\n"
            "  wp_plugins   — plugins WordPress\n"
            "  wp_themes    — temas WordPress\n"
            "  wp_users     — enumerar usuarios WP\n"
            "  joomla_info  — versao + extensoes Joomla\n"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
