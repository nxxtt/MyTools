#!/usr/bin/env python3
"""Modulo principal que integra as ferramentas de seguranca.

Painel interativo central com menu dinamico em 2 niveis:
  Nivel 1: categorias (CONFIG, CORE, DNS, EMAIL, MOBILE, NETWORK,
           OSINT, VCS, WEB, WHOIS)
  Nivel 2: ferramentas da categoria, paginadas (10 por pagina),
           com navegacao [n]/[p] e retorno [0] as categorias.

As ferramentas sao descobertas via entry points (importlib.metadata),
entao qualquer novo modulo registrado no pyproject aparece no menu
automaticamente. Digite o nome do modulo, do script ou um alias a
qualquer momento para lancar a ferramenta direto.
"""

import importlib
import importlib.metadata as im
import logging
import sys
import tomllib
from pathlib import Path

from mytools.core.utils import Cyber, __version__, clear_console, color, create_banner

logger = logging.getLogger("mytools.main")

PAGE_SIZE = 10

_CATEGORY_LABELS = {
    "config": "CONFIG",
    "core": "CORE",
    "dns": "DNS",
    "email": "EMAIL",
    "mobile": "MOBILE",
    "network": "NETWORK",
    "osint": "OSINT",
    "vcs": "VCS",
    "web": "WEB",
    "whois": "WHOIS",
}

_CATEGORY_ORDER = [
    "config",
    "core",
    "dns",
    "email",
    "mobile",
    "network",
    "osint",
    "vcs",
    "web",
    "whois",
]

_DISPLAY_NAMES = {
    # CONFIG
    "backupfiledetect": "Backup File Detect",
    "configfiledetect": "Config File Detect",
    # CORE
    "batch": "Batch Runner",
    "cred": "Credential Checker",
    "reconall": "Full Recon",
    "report": "HTML Report",
    # DNS
    "caacheck": "CAA Check",
    "dnsamplification": "DNS Amplification",
    "dnshistory": "DNS History",
    "dnsrebinding": "DNS Rebinding",
    "dnssecvalidation": "DNSSEC Validation",
    "dnstransfer": "DNS Zone Transfer",
    "dnstunnel": "DNS Tunnel",
    "dnswatorture": "DNS Water Torture",
    "dohscan": "DoH Scan",
    "dotscan": "DoT Scan",
    "nsecwalking": "NSEC Walking",
    "subdomainenum": "Subdomain Enumeration",
    # EMAIL
    "emailaddressbypass": "Email Address Bypass",
    "emailattachmentbypass": "Email Attachment Bypass",
    "emaillinktracking": "Email Link Tracking",
    "emailsecurity": "Email Security (SPF/DMARC/DKIM)",
    "emailspoof": "Email Spoofing",
    "emailtemplateinject": "Email Template Injection",
    "smtpdowngrade": "SMTP Downgrade",
    "smtpinjection": "SMTP Injection",
    # MOBILE
    "mobile_audit": "Mobile Audit",
    # NETWORK
    "dirscanner": "Directory Scanner",
    "portscanner": "Port Scanner",
    # OSINT
    "darkwebmonitor": "Dark Web Monitor",
    "emailbreachcheck": "Email Breach Check",
    "googledorking": "Google Dorking",
    "ipasninfo": "IP/ASN Info",
    "pasteleak": "Paste Leak Monitor",
    "socialengrecon": "Social Engineering Recon",
    # VCS
    "vcsleak": "VCS Leak",
    # WHOIS
    "whoishistory": "Whois History",
    # WEB
    "accountabuse": "Account Abuse",
    "attackanalysis": "Attack Analysis",
    "attackaudit": "Attack Audit",
    "blindxss": "Blind XSS",
    "bominjection": "BOM Injection",
    "businesslogic": "Business Logic Abuse",
    "cachedeception": "Cache Deception",
    "cachepoisoning": "Cache Poisoning",
    "certcheck": "Certificate Check",
    "charsetbypass": "Charset Bypass",
    "clickjacking": "Clickjacking",
    "cloudbucketenum": "Cloud Bucket Enumeration",
    "cmdinject": "Command Injection",
    "cmsfingerprint": "CMS Fingerprinting",
    "cookieboundary": "Cookie Boundary",
    "corsmisconfig": "CORS Misconfiguration",
    "crlfinjection": "CRLF Injection",
    "csrfscan": "CSRF Scan",
    "cssinject": "CSS Injection",
    "depscanner": "Dependency Scanner",
    "deserialinject": "Deserialization Injection",
    "dockerattack": "Docker Attack",
    "domclobbering": "DOM Clobbering",
    "doubleurlencode": "Double URL Encoding",
    "edgefunctions": "Edge Functions",
    "fileupload": "File Upload Abuse",
    "graphqlattack": "GraphQL Attack",
    "graphqlplayground": "GraphQL Playground",
    "grpcattack": "gRPC Attack",
    "headeredge": "Header Edge",
    "headerinject": "Header Injection",
    "hostheaderinject": "Host Header Injection",
    "httpparampollution": "HTTP Parameter Pollution",
    "http2abuse": "HTTP/2 Abuse",
    "httsmuggle": "HTTP Smuggling",
    "infraattack": "Infra Attack",
    "iotattack": "IoT Attack",
    "jwtanalysis": "JWT Analysis",
    "k8sattack": "K8s Attack",
    "lambdaattack": "Lambda Attack",
    "ldapiinject": "LDAP Injection",
    "lfidetect": "LFI Detect",
    "log4shell": "Log4Shell",
    "loginbruteforce": "Login Bruteforce",
    "loginjection": "Login Injection",
    "methodoverride": "Method Override",
    "multitenant": "Multi-Tenant Abuse",
    "mxss": "Mutable XSS (mXSS)",
    "nosqliinject": "NoSQL Injection",
    "nullbyteinject": "Null Byte Injection",
    "oauth": "OAuth Abuse",
    "oidc": "OIDC Abuse",
    "openapidiscovery": "OpenAPI Discovery",
    "openredirect": "Open Redirect",
    "overlongencoding": "Overlong Encoding",
    "pathtraversal": "Path Traversal",
    "prototypepollution": "Prototype Pollution",
    "restapifuzz": "REST API Fuzzer",
    "rtloverride": "RTL Override",
    "saml": "SAML Abuse",
    "serverlessattack": "Serverless Attack",
    "sourcemapdiscovery": "Source Map Discovery",
    "sqliscan": "SQL Injection",
    "ssiinject": "SSI Injection",
    "ssrfdetect": "SSRF Detect",
    "sstidetect": "SSTI Detect",
    "subdomaintakeover": "Subdomain Takeover",
    "techfingerprint": "Tech Fingerprint",
    "thriftattack": "Thrift Attack",
    "timingattack": "Timing Attack",
    "tlsfingerprint": "TLS Fingerprint",
    "webrecon": "Web Recon",
    "websocketattack": "WebSocket Attack",
    "xpathinject": "XPath Injection",
    "xssvectors": "XSS Vectors",
    "xxedetect": "XXE Detect",
}

_ALIASES = {
    "port": "portscanner",
    "ports": "portscanner",
    "dir": "dirscanner",
    "dirs": "dirscanner",
    "web": "webrecon",
    "audit": "attackaudit",
    "attack": "attackaudit",
    "redblue": "attackaudit",
    "dns": "dnstransfer",
    "xfer": "dnstransfer",
    "dnsxfer": "dnstransfer",
    "sub": "subdomainenum",
    "subenum": "subdomainenum",
    "dns-history": "dnshistory",
    "history": "dnshistory",
    "whois": "whoishistory",
    "whois-history": "whoishistory",
    "ip-asn": "ipasninfo",
    "asn": "ipasninfo",
    "tech": "techfingerprint",
    "fingerprint": "techfingerprint",
    "openapi": "openapidiscovery",
    "swagger": "openapidiscovery",
    "graphql": "graphqlplayground",
    "playground": "graphqlplayground",
    "sourcemap": "sourcemapdiscovery",
    "sourcemaps": "sourcemapdiscovery",
    "git": "vcsleak",
    "svn": "vcsleak",
    "hg": "vcsleak",
    "config": "configfiledetect",
    "cfg": "configfiledetect",
    "env": "configfiledetect",
    "backup": "backupfiledetect",
    "google": "googledorking",
    "email": "emailbreachcheck",
    "hibp": "emailbreachcheck",
    "soceng": "socialengrecon",
    "social": "socialengrecon",
    "employee": "socialengrecon",
    "paste": "pasteleak",
    "monitor": "pasteleak",
    "dark": "darkwebmonitor",
    "darkweb": "darkwebmonitor",
    "rebinding": "dnsrebinding",
    "watorture": "dnswatorture",
    "amplification": "dnsamplification",
    "dmarc": "emailsecurity",
    "spf": "emailsecurity",
    "dkim": "emailsecurity",
    "spoofing": "emailspoof",
    "smtp": "smtpinjection",
    "downgrade": "smtpdowngrade",
    "template": "emailtemplateinject",
    "templatinject": "emailtemplateinject",
    "attachment": "emailattachmentbypass",
    "attach": "emailattachmentbypass",
    "address": "emailaddressbypass",
    "addr": "emailaddressbypass",
    "quoting": "emailaddressbypass",
    "linktracking": "emaillinktracking",
    "tracking": "emaillinktracking",
    "null": "nullbyteinject",
    "nullinject": "nullbyteinject",
    "doubleurl": "doubleurlencode",
    "doubleencode": "doubleurlencode",
    "traversalenc": "pathtraversal",
    "rfi": "lfidetect",
    "overlongenc": "overlongencoding",
    "command": "cmdinject",
    "csrfdetect": "csrfscan",
    "sqliinject": "sqliscan",
    "bom": "bominjection",
    "charset": "charsetbypass",
    "charsets": "charsetbypass",
    "rtl": "rtloverride",
    "redirect": "openredirect",
    "oredir": "openredirect",
    "crlf": "crlfinjection",
    "ssti": "sstidetect",
    "ssrf": "ssrfdetect",
    "xxe": "xxedetect",
    "nosql": "nosqliinject",
    "ldapi": "ldapiinject",
    "xpathi": "xpathinject",
    "ssi": "ssiinject",
    "ppoll": "prototypepollution",
    "deserialization": "deserialinject",
    "cpcache": "cachepoisoning",
    "deception": "cachedeception",
    "moverride": "methodoverride",
    "parampollution": "httpparampollution",
    "blindexss": "blindxss",
    "corsmis": "corsmisconfig",
    "cj": "clickjacking",
    "hhi": "hostheaderinject",
    "hdrinject": "headerinject",
    "hdr": "headerinject",
    "loginject": "loginjection",
    "log": "loginjection",
    "l4s": "log4shell",
    "jndi": "log4shell",
    "brute": "loginbruteforce",
    "login": "loginbruteforce",
    "cloudbucket": "cloudbucketenum",
    "s3": "cloudbucketenum",
    "takeover": "subdomaintakeover",
    "subdomain": "subdomaintakeover",
    "restapi": "restapifuzz",
    "apifuzz": "restapifuzz",
    "all": "reconall",
    "full": "reconall",
}


def banner() -> None:
    """Exibe o banner artistico e informacoes do projeto."""
    art = r"""
    __  ___        ______            __
   /  |/  /_  __  /_  __/___  ____  / /____
  / /|_/ / / / /   / / / __ \/ __ \/ / ___/
 / /  / / /_/ /   / / / /_/ / /_/ / (__  )
/_/  /_/\__, /   /_/  \____/\____/_/____/
       /____/
"""
    create_banner(
        art,
        "port scanner + dir scanner + web recon + attack audit + dns xfer + subenum + dnshistory + whoishistory + oas + bak + dork + breach + soceng",
        extra=lambda: print(color("   by Default\n", Cyber.GRAY)),
    )()


def _load_tools() -> list[tuple[str, str, str]]:
    """Descobre as ferramentas via entry points.

    Retorna lista de (script, categoria, modulo) ordenada por
    (categoria, modulo). Usa importlib.metadata; se vier vazia
    (instalacao sem metadata), le o pyproject.toml como fallback.
    """
    tools: list[tuple[str, str, str]] = []
    try:
        eps = im.entry_points(group="console_scripts")
    except Exception:
        eps = ()
    for ep in eps:
        name = ep.name
        if not name.startswith("mytools-") or name == "mytools":
            continue
        mod_path = ep.value.partition(":")[0]
        parts = mod_path.split(".")
        if len(parts) < 3:
            continue
        tools.append((name, parts[1], parts[-1]))
    if not tools:
        tools = _load_tools_from_pyproject()
    return sorted(tools, key=lambda t: (t[1], t[2]))


def _find_pyproject() -> Path | None:
    """Sobe a arvore procurando pyproject.toml."""
    path = Path(__file__).resolve().parent
    for _ in range(6):
        if (path / "pyproject.toml").exists():
            return path / "pyproject.toml"
        path = path.parent
    return None


def _load_tools_from_pyproject() -> list[tuple[str, str, str]]:
    """Fallback: le [project.scripts] do pyproject.toml."""
    pyproject = _find_pyproject()
    if pyproject is None:
        return []
    tools: list[tuple[str, str, str]] = []
    try:
        with pyproject.open("rb") as fh:
            data = tomllib.load(fh)
        for name, value in data.get("project", {}).get("scripts", {}).items():
            if not name.startswith("mytools-") or name == "mytools":
                continue
            mod_path = value.partition(":")[0]
            parts = mod_path.split(".")
            if len(parts) < 3:
                continue
            tools.append((name, parts[1], parts[-1]))
    except OSError, tomllib.TOMLDecodeError:
        pass
    return tools


def _tools_by_category() -> dict[str, list[tuple[str, str]]]:
    """Agrupa ferramentas por categoria, ordenadas por modulo."""
    by_cat: dict[str, list[tuple[str, str]]] = {}
    for script, cat, mod in _load_tools():
        by_cat.setdefault(cat, []).append((script, mod))
    return by_cat


def _display_name(mod: str) -> str:
    """Nome de exibicao (bonito) de um modulo, com fallback no nome cru."""
    return _DISPLAY_NAMES.get(mod, mod.replace("_", " ").title())


def _resolve_tool(text: str) -> tuple[str, str] | None:
    """Resolve texto (modulo, script ou alias) para (categoria, modulo)."""
    text = text.strip().lower()
    for script, cat, mod in _load_tools():
        if mod == text or script == f"mytools-{text}" or script == text:
            return cat, mod
    target = _ALIASES.get(text)
    if target:
        for _, cat, mod in _load_tools():
            if mod == target:
                return cat, mod
    return None


def menu_root(tools_by_cat: dict[str, list[tuple[str, str]]]) -> None:
    """Exibe o nivel 1: categorias numeradas com contagem."""
    print(color("Escolha uma categoria:", Cyber.WHITE, Cyber.BOLD))
    for idx, cat in enumerate(_CATEGORY_ORDER, 1):
        count = len(tools_by_cat.get(cat, []))
        label = _CATEGORY_LABELS.get(cat, cat.upper())
        print(
            f"  {color(str(idx), Cyber.GREEN, Cyber.BOLD)} "
            f"{color(label, Cyber.CYAN)}  {color(f'({count})', Cyber.GRAY)}"
        )
    print(
        f"  {color('h', Cyber.GREEN, Cyber.BOLD)} "
        f"{color('Ajuda / Exemplos', Cyber.CYAN)}"
    )
    print(f"  {color('0', Cyber.RED, Cyber.BOLD)} {color('Sair', Cyber.CYAN)}")


def menu_category(
    cat: str,
    items: list[tuple[str, str]],
    page: int,
    pages: int,
) -> None:
    """Exibe o nivel 2: ferramentas da categoria, paginadas."""
    label = _CATEGORY_LABELS.get(cat, cat.upper())
    print(color(f"{label} — Pagina {page + 1}/{pages}", Cyber.WHITE, Cyber.BOLD))
    start = page * PAGE_SIZE
    for idx, (script, mod) in enumerate(items[start : start + PAGE_SIZE], 1):
        script_short = script.removeprefix("mytools-")
        print(
            f"  {color(str(idx), Cyber.GREEN, Cyber.BOLD)} "
            f"{color(_display_name(mod), Cyber.CYAN)}  "
            f"{color(f'({script_short})', Cyber.GRAY)}"
        )
    nav = "  [n] Proxima  [p] Anterior  [0] Categorias  [q] Sair"
    print(color(nav, Cyber.YELLOW))


def help_screen(tools_by_cat: dict[str, list[tuple[str, str]]]) -> None:
    """Exibe exemplos rapidos gerados a partir das ferramentas."""
    print(color("\nExemplos:", Cyber.WHITE, Cyber.BOLD))
    for cat in _CATEGORY_ORDER:
        items = tools_by_cat.get(cat, [])
        if not items:
            continue
        label = _CATEGORY_LABELS.get(cat, cat.upper())
        print(color(f"\n{label}:", Cyber.CYAN))
        for script, _ in items[:4]:
            print(f"  mytools-{script.removeprefix('mytools-')} --help")
    print(color("\nDentro do menu:", Cyber.CYAN))
    print(
        "  escolha uma categoria, depois uma tool, e digite os argumentos como faria depois do nome do script."
    )
    print("  use 'exit' dentro de cada scanner para voltar a selecao de categorias.")
    print("  digite 'n'/'p' para navegar entre paginas e '0' para voltar.\n")


def _run_tool(cat: str, mod: str) -> None:
    """Importa o modulo (lazy) e chama seu main()."""
    try:
        module = importlib.import_module(f"mytools.{cat}.{mod}")
    except Exception as error:
        logger.debug("Falha ao importar mytools.%s.%s: %s", cat, mod, error)
        print(color(f"Erro ao carregar o modulo: {error}", Cyber.RED))
        input(color("Enter para continuar...", Cyber.GRAY))
        return
    main_fn = getattr(module, "main", None)
    if not callable(main_fn):
        print(color(f"Modulo {mod} nao possui main() callable.", Cyber.RED))
        input(color("Enter para continuar...", Cyber.GRAY))
        return
    try:
        main_fn()
    except EOFError, KeyboardInterrupt:
        print()
    except SystemExit:
        pass
    except Exception as error:
        logger.debug("Falha em mytools.%s.%s: %s", cat, mod, error)
        print(color(f"Erro: {error}", Cyber.RED))
        input(color("Enter para continuar...", Cyber.GRAY))


def main() -> int:
    """Loop principal do menu interativo em 2 niveis. Retorna 0 ao sair."""
    if "--version" in sys.argv or "-V" in sys.argv:
        print(f"mytools {__version__}")
        return 0

    tools_by_cat = _tools_by_category()
    if not tools_by_cat:
        print(color("Nenhuma ferramenta encontrada nos entry points.", Cyber.RED))
        return 1

    while True:
        banner()
        menu_root(tools_by_cat)
        try:
            choice = (
                input(color("\nuser-agent> ", Cyber.GREEN, Cyber.BOLD)).strip().lower()
            )
        except EOFError, KeyboardInterrupt:
            print()
            return 0

        if choice in {"0", "q", "quit", "exit"}:
            print(color("bye bye user!", Cyber.MAGENTA))
            return 0
        if choice in {"h", "help", "ajuda"}:
            help_screen(tools_by_cat)
            input(color("Enter para voltar...", Cyber.GRAY))
            clear_console()
            continue
        if choice in {"clear", "limpar", "cls"}:
            clear_console()
            continue

        cat = None
        if choice.isdigit():
            idx = int(choice)
            if 1 <= idx <= len(_CATEGORY_ORDER):
                cat = _CATEGORY_ORDER[idx - 1]
        else:
            for _, name in enumerate(_CATEGORY_ORDER, 1):
                if choice == _CATEGORY_LABELS.get(name, name).lower() or choice == name:
                    cat = name
                    break
        if cat is None:
            resolved = _resolve_tool(choice)
            if resolved:
                _run_tool(*resolved)
                clear_console()
                continue
            print(color("Categoria invalida.", Cyber.RED))
            input(color("Enter para continuar...", Cyber.GRAY))
            continue

        items = tools_by_cat.get(cat, [])
        pages = max(1, (len(items) + PAGE_SIZE - 1) // PAGE_SIZE)
        page = 0
        while True:
            clear_console()
            menu_category(cat, items, page, pages)
            try:
                sub = (
                    input(color(f"\n{cat}> ", Cyber.GREEN, Cyber.BOLD)).strip().lower()
                )
            except EOFError, KeyboardInterrupt:
                print()
                return 0

            if sub in {"0", "back"}:
                break
            if sub in {"q", "quit", "exit"}:
                print(color("bye bye user!", Cyber.MAGENTA))
                return 0
            if sub in {"n", "next"}:
                page = (page + 1) % pages
                continue
            if sub in {"p", "prev", "previous"}:
                page = (page - 1) % pages
                continue
            if sub in {"h", "help"}:
                help_screen(tools_by_cat)
                input(color("Enter para continuar...", Cyber.GRAY))
                continue
            if sub in {"clear", "limpar", "cls"}:
                continue

            if sub.isdigit():
                idx = int(sub)
                start = page * PAGE_SIZE
                if 1 <= idx <= len(items[start : start + PAGE_SIZE]):
                    _, mod = items[start + idx - 1]
                    _run_tool(cat, mod)
                    break
                print(color("Opcao invalida.", Cyber.RED))
                input(color("Enter para continuar...", Cyber.GRAY))
                continue

            resolved = _resolve_tool(sub)
            if resolved:
                _run_tool(*resolved)
                break
            print(color("Opcao invalida.", Cyber.RED))
            input(color("Enter para continuar...", Cyber.GRAY))


if __name__ == "__main__":
    raise SystemExit(main())
