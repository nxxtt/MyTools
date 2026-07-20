#!/usr/bin/env python3
"""Modulo de monitoramento de pastes e leaks (Paste/Leak Monitoring).

Monitora pastes e repositorios publicos por credenciais e dados sensiveis
do alvo usando multiplas fontes:
  - GitHub Gists — monitora gists publicos por palavras-chave (gratis, 60 req/h)
  - Pastebin RSS — busca pastes via feed RSS (gratis, sem API key)
  - GitLab Snippets — monitora snippets publicos (gratis, 60 req/min)
  - GitHub Code Search — busca em codigo-fonte (opcional, requer GITHUB_TOKEN)

Padroes de detecao:
  - Chaves AWS (AKIA...), GitHub (ghp_...), Slack (xoxb-...), Stripe (sk-...)
  - Chaves privadas RSA/DSA/EC
  - Padroes genericos: password=, api_key=, secret=, token=
  - Combinações email+senha

Fluxo:
  1. Coleta pastes/gists/snippets de cada fonte
  2. Busca padroes de credenciais no conteudo
  3. Dedup por (fonte, url, padrao)
  4. Mascara trechos sensiveis na exibicao
"""
import argparse
import json
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from urllib.parse import quote

import httpx
from anyio import Path

from mytools.core.utils import (
    Cyber,
    FetchError,
    RateLimiter,
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

logger = logging.getLogger("mytools.pasteleak")

STATUS_OK = frozenset({200})

GITHUB_API = "https://api.github.com"
GITLAB_API = "https://gitlab.com/api/v4"
PASTEBIN_FEED = "https://pastebin.com/feed.php"

DEFAULT_SOURCES: list[str] = ["github_gists", "pastebin_rss", "gitlab_snippets"]

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("github_token", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("slack_token", re.compile(r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,36}")),
    ("stripe_key", re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("private_key", re.compile(r"-----BEGIN\s+(RSA|DSA|EC)\s+PRIVATE\s+KEY-----")),
    ("password_assign", re.compile(r"""(?:password|passwd|pwd)\s*[:=]\s*['"]?([^\s'"<>]{4,80})['"]?""", re.IGNORECASE)),
    ("api_key_assign", re.compile(r"""(?:api[_-]?key|apikey)\s*[:=]\s*['"]?([^\s'"<>]{8,80})['"]?""", re.IGNORECASE)),
    ("secret_assign", re.compile(r"""(?:secret|secret[_-]?key)\s*[:=]\s*['"]?([^\s'"<>]{8,80})['"]?""", re.IGNORECASE)),
    ("token_assign", re.compile(r"""(?:auth[_-]?token|access[_-]?token)\s*[:=]\s*['"]?([^\s'"<>]{8,80})['"]?""", re.IGNORECASE)),
    ("connection_string", re.compile(
        r"(?:mysql|postgres|mongodb|redis)://[^\s\"'<>]{10,}", re.IGNORECASE)),
]


@dataclass(frozen=True, slots=True)
class LeakRecord:
    """Representa uma credencial ou dado sensivel encontrado."""

    source: str
    url: str
    filename: str
    matched_pattern: str
    matched_text: str
    found_at: str
    exploit: str = ""
    tool: str = ""


def _mask_secret(text: str) -> str:
    """Mascara o texto sensivel, preservando apenas primeiros/ultimos chars."""
    if len(text) <= 8:
        return text[:2] + "***"
    return text[:4] + "***" + text[-4:]


def _scan_content(content: str, source: str, url: str, filename: str) -> list[LeakRecord]:
    """Busca padroes de credenciais no conteudo de um paste/gist/snippet."""
    leaks: list[LeakRecord] = []
    now = datetime.now(UTC).isoformat()

    for pattern_name, pattern in _SECRET_PATTERNS:
        for match in pattern.finditer(content):
            matched_text = match.group(0) if not match.groups() else match.group(1)
            leaks.append(
                LeakRecord(
                    source=source,
                    url=url,
                    filename=filename,
                    matched_pattern=pattern_name,
                    matched_text=_mask_secret(matched_text),
                    found_at=now,
                    exploit=f"curl {url}",
                    tool="curl",
                )
            )
    return leaks


def _dedup_leaks(leaks: list[LeakRecord]) -> list[LeakRecord]:
    """Remove duplicatas por (source, url, matched_pattern, matched_text)."""
    seen: set[tuple[str, str, str, str]] = set()
    result: list[LeakRecord] = []
    for leak in leaks:
        key = (leak.source, leak.url, leak.matched_pattern, leak.matched_text)
        if key not in seen:
            seen.add(key)
            result.append(leak)
    return result


def _contains_domain(content: str, domain: str) -> bool:
    """Verifica se o conteudo menciona o dominio alvo (word boundary)."""
    pattern = re.compile(rf"\b{re.escape(domain)}\b", re.IGNORECASE)
    return bool(pattern.search(content))


async def _query_github_gists(
    client: httpx.AsyncClient,
    domain: str,
    timeout: float,
    rate_limiter: RateLimiter,
    max_results: int = 30,
) -> list[LeakRecord]:
    """Busca gists publicos do GitHub por palavras-chave do dominio."""
    leaks: list[LeakRecord] = []

    url = f"{GITHUB_API}/gists/public?per_page={min(max_results, 100)}"
    try:
        await rate_limiter.wait()
        status, _h, body, _ = await fetch(
            client, url, timeout=timeout, max_retries=2, rate_limiter=rate_limiter,
        )
    except FetchError as e:
        logger.debug("GitHub Gists fetch error: %s", e)
        return leaks

    if status not in STATUS_OK:
        logger.debug("GitHub Gists status %d", status)
        return leaks

    try:
        gists = json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return leaks
    for gist in gists[:max_results]:
            description = gist.get("description", "") or ""
            files = gist.get("files", {})
            gist_url = gist.get("html_url", "")

            if _contains_domain(description, domain):
                for fname, fdata in files.items():
                    raw_url = fdata.get("raw_url", "")
                    if raw_url:
                        try:
                            await rate_limiter.wait()
                            s2, _, c, _ = await fetch(
                                client, raw_url, timeout=timeout, max_retries=1, rate_limiter=rate_limiter,
                            )
                            if s2 == 200:
                                content = c.decode("utf-8", errors="replace")
                                leaks.extend(_scan_content(content, "github_gists", gist_url, fname))
                        except FetchError:
                            pass

            if len(leaks) >= max_results:
                break

    return leaks


async def _query_pastebin_rss(
    client: httpx.AsyncClient,
    domain: str,
    timeout: float,
    rate_limiter: RateLimiter,
    max_results: int = 30,
) -> list[LeakRecord]:
    """Busca pastes no Pastebin via feed RSS."""
    leaks: list[LeakRecord] = []
    url = f"{PASTEBIN_FEED}?q={quote(domain)}"

    try:
        await rate_limiter.wait()
        status, _h, body, _ = await fetch(
            client, url, timeout=timeout, max_retries=2, rate_limiter=rate_limiter,
        )
    except FetchError as e:
        logger.debug("Pastebin RSS fetch error: %s", e)
        return leaks

    if status not in STATUS_OK:
        logger.debug("Pastebin RSS status %d", status)
        return leaks

    xml_text = body.decode("utf-8", errors="replace")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        logger.debug("Pastebin RSS parse error")
        return leaks

    ns = {"atom": "http://www.w3.org/2005/Atom"}
    entries = root.findall("atom:entry", ns) or root.findall("entry")

    for entry in entries[:max_results]:
        title_el = entry.find("atom:title", ns)
        if title_el is None:
            title_el = entry.find("title")
        link_el = entry.find("atom:link", ns)
        if link_el is None:
            link_el = entry.find("link")

        title = title_el.text if title_el is not None and title_el.text else ""
        link = link_el.get("href", "") if link_el is not None else ""

        if not link:
            continue

        paste_url = link
        try:
            await rate_limiter.wait()
            s2, _, c, _ = await fetch(
                client, paste_url, timeout=timeout, max_retries=1, rate_limiter=rate_limiter,
            )
            if s2 == 200:
                content = c.decode("utf-8", errors="replace")
                leaks.extend(_scan_content(content, "pastebin_rss", paste_url, title))
        except FetchError:
            pass

        if len(leaks) >= max_results:
            break

    return leaks


async def _query_gitlab_snippets(
    client: httpx.AsyncClient,
    domain: str,
    timeout: float,
    rate_limiter: RateLimiter,
    max_results: int = 30,
) -> list[LeakRecord]:
    """Busca snippets publicos do GitLab."""
    leaks: list[LeakRecord] = []
    url = f"{GITLAB_API}/snippets/public?per_page={min(max_results, 100)}"

    try:
        await rate_limiter.wait()
        status, _h, body, _ = await fetch(
            client, url, timeout=timeout, max_retries=2, rate_limiter=rate_limiter,
        )
    except FetchError as e:
        logger.debug("GitLab Snippets fetch error: %s", e)
        return leaks

    if status not in STATUS_OK:
        logger.debug("GitLab Snippets status %d", status)
        return leaks

    snippets = json.loads(body)
    for snippet in snippets[:max_results]:
        snippet_url = snippet.get("web_url", "")
        files = snippet.get("files", {})

        for fname, fdata in files.items():
            raw_url = fdata.get("raw_url", "")
            if raw_url:
                try:
                    await rate_limiter.wait()
                    s2, _, c, _ = await fetch(
                        client, raw_url, timeout=timeout, max_retries=1, rate_limiter=rate_limiter,
                    )
                    if s2 == 200:
                        content = c.decode("utf-8", errors="replace")
                        leaks.extend(_scan_content(content, "gitlab_snippets", snippet_url, fname))
                except FetchError:
                    pass

        if len(leaks) >= max_results:
            break

    return leaks


async def _query_github_code(
    client: httpx.AsyncClient,
    domain: str,
    timeout: float,
    rate_limiter: RateLimiter,
    token: str,
    max_results: int = 30,
) -> list[LeakRecord]:
    """Busca codigo no GitHub (requer autenticacao)."""
    if not token:
        return []

    leaks: list[LeakRecord] = []
    queries = [
        f'"{domain}" password',
        f'"{domain}" api_key OR secret OR token',
        f'"{domain}" "AKIA" OR "ghp_" OR "sk_"',
    ]

    auth_headers = {"Authorization": f"token {token}"}

    for q in queries:
        url = f"{GITHUB_API}/search/code?q={quote(q)}&per_page={min(max_results, 30)}"

        try:
            await rate_limiter.wait()
            status, _h, body, _ = await fetch(
                client, url, timeout=timeout, max_retries=2, rate_limiter=rate_limiter,
                headers=auth_headers,
            )
        except FetchError as e:
            logger.debug("GitHub Code Search error: %s", e)
            continue

        if status not in STATUS_OK:
            logger.debug("GitHub Code Search status %d", status)
            continue

        try:
            items = json.loads(body).get("items", [])
        except (json.JSONDecodeError, ValueError):
            items = []
        for item in items[:max_results]:
            file_path = item.get("path", "")
            html_url = item.get("html_url", "")
            download_url = item.get("download_url", "")

            if download_url:
                try:
                    await rate_limiter.wait()
                    s2, _, c, _ = await fetch(
                        client, download_url, timeout=timeout, max_retries=1, rate_limiter=rate_limiter,
                    )
                    if s2 == 200:
                        content = c.decode("utf-8", errors="replace")
                        leaks.extend(_scan_content(content, "github_code", html_url, file_path))
                except FetchError:
                    pass

            if len(leaks) >= max_results:
                break

    return leaks


async def scan_leaks(
    domain: str,
    sources: list[str],
    api_keys: dict[str, str | None],
    timeout: float = 5.0,
    user_agent: str = "",
    proxy: str | None = None,
    verify: bool = False,
    requests_per_second: float = 2.0,
    max_results: int = 30,
) -> list[LeakRecord]:
    """Executa scan de leaks em todas as fontes configuradas."""
    rate_limiter = RateLimiter(requests_per_second)
    client = create_async_client(
        user_agent=user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) MyTools",
        proxy=proxy,
        verify=verify,
    )

    all_leaks: list[LeakRecord] = []

    try:
        for source in sources:
            if source == "github_gists":
                found = await _query_github_gists(client, domain, timeout, rate_limiter, max_results)
                all_leaks.extend(found)
                logger.info("[%s] %d leaks encontrados", source, len(found))
            elif source == "pastebin_rss":
                found = await _query_pastebin_rss(client, domain, timeout, rate_limiter, max_results)
                all_leaks.extend(found)
                logger.info("[%s] %d leaks encontrados", source, len(found))
            elif source == "gitlab_snippets":
                found = await _query_gitlab_snippets(client, domain, timeout, rate_limiter, max_results)
                all_leaks.extend(found)
                logger.info("[%s] %d leaks encontrados", source, len(found))
            elif source == "github_code":
                token = api_keys.get("github_token") or ""
                found = await _query_github_code(client, domain, timeout, rate_limiter, token, max_results)
                all_leaks.extend(found)
                logger.info("[%s] %d leaks encontrados", source, len(found))
    finally:
        await client.aclose()

    return _dedup_leaks(all_leaks)


def print_results(leaks: list[LeakRecord]) -> None:
    """Exibe os leaks encontrados de forma colorida."""
    if not leaks:
        print(color("[*] Nenhum leak encontrado.", Cyber.GREEN))
        return

    by_source: dict[str, list[LeakRecord]] = {}
    for leak in leaks:
        by_source.setdefault(leak.source, []).append(leak)

    total = len(leaks)
    sources_count = len(by_source)
    print(
        color(f"\n[+] {total} leak(s) encontrado(s) em {sources_count} fonte(s):", Cyber.GREEN, Cyber.BOLD)
    )

    for source, source_leaks in by_source.items():
        print(color(f"\n  Fonte: {source}", Cyber.CYAN, Cyber.BOLD))
        for leak in source_leaks:
            print(
                f"    {color(leak.matched_pattern, Cyber.RED, Cyber.BOLD)}"
                f" | {color(leak.filename, Cyber.YELLOW)}"
                f" | {leak.matched_text}"
            )
            print(f"      {color(leak.url, Cyber.GRAY)}")
            print_exploit_info(leak.exploit, leak.tool)


def banner() -> None:
    """Exibe o banner do Paste/Leak Monitoring."""
    art = r"""
    __  _______  ______            __
   /  |/  / __ \/ ____/___  ____  / /____
  / /|_/ / / / / __/ / __ \/ __ \/ / ___/
 / /  / / /_/ / /___/ /_/ / /_/ / (__  )
/_/  /_/\____/_____/\____/\____/_/____/
"""
    create_banner(art, "   paste/leak monitoring: github gists + pastebin + gitlab snippets")()


def build_parser() -> argparse.ArgumentParser:
    """Construi o parser de argumentos da linha de comandos."""
    parser = argparse.ArgumentParser(
        description="Monitoramento de pastes e leaks — busca credenciais em pastes e repos publicos.",
    )
    add_base_args(parser)
    add_http_args(parser)
    parser.add_argument("domain", nargs="?", help="Dominio alvo para monitorar (ex: example.com).")
    parser.add_argument("-l", "--list", dest="target_list", help="Arquivo com dominios (um por linha).")
    parser.add_argument(
        "--source",
        action="append",
        choices=["github_gists", "pastebin_rss", "gitlab_snippets", "github_code"],
        dest="sources",
        help="Fonte para monitoramento (pode repetir). Padrao: github_gists,pastebin_rss,gitlab_snippets.",
    )
    parser.add_argument(
        "--github-token",
        dest="github_token",
        help="Token do GitHub (obrigatorio para --source github_code).",
    )
    parser.add_argument(
        "--max-results",
        type=int,
        default=30,
        dest="max_results",
        help="Max resultados por fonte. Padrao: 30",
    )
    return parser


async def _async_run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan (async)."""
    quiet = init_scanner(args)

    domain = getattr(args, "domain", None)
    target_list = getattr(args, "target_list", None)

    if not domain and target_list:
        try:
            async with await Path(target_list).open(encoding="utf-8") as f:
                domains = [line.strip() async for line in f if line.strip()]
        except FileNotFoundError:
            logger.error("Arquivo nao encontrado: %s", target_list)
            return 1
    elif domain:
        domains = [domain]
    else:
        logger.error("Informe um dominio ou use -l <arquivo>.")
        return 1

    if getattr(args, "dry_run", False):
        logger.warning("Nenhuma requisicao HTTP sera enviada.")
        for d in domains:
            logger.info("Dominio: %s", d)
        return 0

    sources = args.sources or list(DEFAULT_SOURCES)
    api_keys: dict[str, str | None] = {
        "github_token": getattr(args, "github_token", None),
    }

    for s in sources:
        if s == "github_code" and not api_keys.get("github_token"):
            logger.warning("github_code requer token (use --github-token)")

    all_leaks: list[LeakRecord] = []
    for d in domains:
        leaks = await scan_leaks(
            domain=d,
            sources=sources,
            api_keys=api_keys,
            timeout=args.timeout,
            user_agent=args.user_agent,
            proxy=args.proxy,
            verify=getattr(args, "verify", False),
            requests_per_second=args.delay,
            max_results=getattr(args, "max_results", 30),
        )
        all_leaks.extend(leaks)

    all_leaks = _dedup_leaks(all_leaks)

    if not quiet:
        print_results(all_leaks)

    if args.output:
        write_output(
            args.output,
            [asdict(leak) for leak in all_leaks],
            ["source", "url", "filename", "matched_pattern", "matched_text", "found_at"],
            quiet=quiet,
        )
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Executa um unico scan com os argumentos fornecidos."""
    return safe_asyncio_run(_async_run_once(args))


def main() -> int:
    """Ponto de entrada principal do Paste/Leak Monitoring."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner,
        run_fn=run_once,
        has_target=lambda a: bool(a.domain or getattr(a, "target_list", None)),
        prompt="leak> ",
        description="Paste/Leak Monitoring interativo.",
        example="example.com --source github_gists",
        contextual_help=(
            "Uso: <dominio> [opcoes]\n"
            "Exemplos:\n"
            "  example.com\n"
            "  example.com --source github_gists --source pastebin_rss\n"
            "  example.com --github-token ghp_xxx\n"
            "  -l domains.txt -o results.json"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
