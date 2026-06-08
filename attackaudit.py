#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
import json
import os
import shlex
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request

from utils import (
    Cyber,
    NoRedirectHandler,
    NO_REDIRECT_OPENER,
    clear_console,
    color,
    header_get,
    status_color,
)


SECURITY_HEADERS = {
    "strict-transport-security": "Ative HSTS com max-age alto e includeSubDomains quando fizer sentido.",
    "content-security-policy": "Defina CSP para reduzir XSS e carregamento de recursos nao confiaveis.",
    "x-frame-options": "Use DENY/SAMEORIGIN ou frame-ancestors via CSP contra clickjacking.",
    "x-content-type-options": "Use nosniff para impedir MIME sniffing.",
    "referrer-policy": "Use politica restritiva, como strict-origin-when-cross-origin.",
    "permissions-policy": "Desabilite APIs do browser que a aplicacao nao usa.",
}

INTERESTING_PATHS = [
    ".env", ".git/HEAD", "backup.zip", "backup.tar.gz", "dump.sql", "db.sql",
    "config.php", "phpinfo.php", "server-status", "actuator", "actuator/env",
    "swagger.json", "swagger-ui/", "api-docs", "openapi.json", "robots.txt",
    "sitemap.xml", "admin", "login", "wp-admin", "phpmyadmin",
]

RISK_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
    "info": 0,
}


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms = 0
        self.password_inputs = 0
        self.external_scripts: set[str] = set()
        self.comments: list[str] = []
        self._title = False
        self.title_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "title":
            self._title = True
        if tag.lower() == "form":
            self.forms += 1
        if tag.lower() == "input" and attrs_dict.get("type", "").lower() == "password":
            self.password_inputs += 1
        if tag.lower() == "script" and attrs_dict.get("src"):
            self.external_scripts.add(attrs_dict["src"])

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._title = False

    def handle_data(self, data: str) -> None:
        if self._title:
            self.title_parts.append(data.strip())

    def handle_comment(self, data: str) -> None:
        text = " ".join(data.split())
        if text:
            self.comments.append(text[:120])

    @property
    def title(self) -> str:
        return " ".join(part for part in self.title_parts if part)[:100]


@dataclass(frozen=True)
class Probe:
    url: str
    status: int
    size: int
    location: str


@dataclass(frozen=True)
class Finding:
    severity: str
    category: str
    item: str
    evidence: str
    recommendation: str


@dataclass(frozen=True)
class AuditResult:
    target: str
    final_url: str
    status: int
    title: str
    ip: str
    tls_subject: str
    tls_issuer: str
    tls_not_after: str
    allowed_methods: list[str]
    forms: int
    password_inputs: int
    probes: list[Probe]
    findings: list[Finding]
    risk_score: int
    elapsed: float


def banner() -> None:
    art = r"""
    ___   __  __             __      ___             ___ __ 
   /   | / /_/ /_____ ______/ /__   /   | __  ______/ (_) /_
  / /| |/ __/ __/ __ `/ ___/ //_/  / /| |/ / / / __  / / __/
 / ___ / /_/ /_/ /_/ / /__/ ,<    / ___ / /_/ / /_/ / / /_  
/_/  |_\__/\__/\__,_/\___/_/|_|  /_/  |_\__,_/\__,_/_/\__/  
"""
    print(color(art.rstrip(), Cyber.CYAN, Cyber.BOLD))
    print(color("   red/blue web audit | ofensivo autorizado + hardening defensivo\n", Cyber.MAGENTA))


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url:
        raise ValueError("informe uma URL alvo")
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError(f"URL invalida: {url}")
    return url.rstrip("/")


def fetch(url: str, timeout: float, user_agent: str, method: str = "GET") -> tuple[int, dict[str, str], bytes]:
    request = Request(url, headers={"User-Agent": user_agent}, method=method)
    try:
        response = NO_REDIRECT_OPENER.open(request, timeout=timeout)
        return response.status, dict(response.headers.items()), response.read()
    except HTTPError as error:
        return error.code, dict(error.headers.items()), error.read()
    except (URLError, TimeoutError, OSError, ssl.SSLError) as error:
        raise ValueError(f"falha ao acessar {url}: {error}") from error


def resolve_ip(hostname: str) -> str:
    try:
        return socket.gethostbyname(hostname)
    except OSError:
        return ""


def tls_info(url: str, timeout: float) -> tuple[str, str, str]:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        return "", "", ""
    port = parsed.port or 443
    context = ssl.create_default_context()
    try:
        with socket.create_connection((parsed.hostname or "", port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=parsed.hostname) as tls:
                cert = tls.getpeercert()
    except (OSError, ssl.SSLError, TimeoutError):
        return "", "", ""

    def flatten_name(rows: tuple[tuple[tuple[str, str], ...], ...]) -> str:
        parts = []
        for row in rows:
            for key, value in row:
                if key in {"commonName", "organizationName"}:
                    parts.append(value)
        return ", ".join(parts)

    return (
        flatten_name(cert.get("subject", ())),
        flatten_name(cert.get("issuer", ())),
        cert.get("notAfter", ""),
    )


def parse_allowed_methods(url: str, timeout: float, user_agent: str) -> list[str]:
    try:
        _, headers, _ = fetch(url, timeout, user_agent, method="OPTIONS")
    except ValueError:
        return []
    allow = header_get(headers, "allow") or header_get(headers, "access-control-allow-methods")
    return sorted({item.strip().upper() for item in allow.split(",") if item.strip()})


def probe_path(base_url: str, path: str, timeout: float, user_agent: str) -> Probe | None:
    url = urljoin(base_url.rstrip("/") + "/", path)
    try:
        status, headers, body = fetch(url, timeout, user_agent)
    except ValueError:
        return None
    if status in {200, 204, 301, 302, 307, 308, 401, 403}:
        return Probe(url, status, len(body), header_get(headers, "location"))
    return None


def scan_paths(base_url: str, timeout: float, user_agent: str, threads: int) -> list[Probe]:
    probes: list[Probe] = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [
            executor.submit(probe_path, base_url, path, timeout, user_agent)
            for path in INTERESTING_PATHS
        ]
        for future in as_completed(futures):
            try:
                probe = future.result()
            except Exception:
                continue
            if probe:
                probes.append(probe)
                print(
                    f"{color('[+]', Cyber.GREEN, Cyber.BOLD)} "
                    f"{color(str(probe.status).ljust(3), status_color(probe.status), Cyber.BOLD)} "
                    f"{color(str(probe.size).rjust(7), Cyber.YELLOW)}B "
                    f"{color(probe.url, Cyber.CYAN)}"
                )
    return sorted(probes, key=lambda item: (item.status, item.url))


def build_findings(
    url: str,
    status: int,
    headers: dict[str, str],
    parser: PageParser,
    methods: list[str],
    probes: list[Probe],
    tls_subject: str,
) -> list[Finding]:
    findings: list[Finding] = []
    parsed = urlparse(url)
    lower_headers = {key.lower(): value for key, value in headers.items()}

    if parsed.scheme == "http":
        findings.append(Finding(
            "high", "transport", "HTTP sem TLS",
            "A pagina principal respondeu sem HTTPS.",
            "Force HTTPS, redirecione HTTP para HTTPS e use HSTS.",
        ))
    elif not tls_subject:
        findings.append(Finding(
            "medium", "transport", "TLS nao validado pela ferramenta",
            "Nao foi possivel coletar certificado TLS.",
            "Verifique validade, cadeia, hostname e protocolos aceitos.",
        ))

    for header, recommendation in SECURITY_HEADERS.items():
        if header not in lower_headers:
            findings.append(Finding(
                "medium", "headers", f"Header ausente: {header}",
                "Header nao apareceu na resposta principal.",
                recommendation,
            ))

    server = header_get(headers, "server")
    powered_by = header_get(headers, "x-powered-by")
    if server:
        findings.append(Finding("low", "fingerprint", "Server exposto", server, "Reduza versao/banner quando possivel."))
    if powered_by:
        findings.append(Finding("low", "fingerprint", "X-Powered-By exposto", powered_by, "Remova o header para reduzir fingerprinting."))

    cors = header_get(headers, "access-control-allow-origin")
    if cors == "*":
        findings.append(Finding(
            "medium", "cors", "CORS permissivo",
            "Access-Control-Allow-Origin: *",
            "Restrinja origens permitidas e revise credenciais CORS.",
        ))

    cookies = [value for key, value in headers.items() if key.lower() == "set-cookie"]
    for cookie in cookies:
        lowered = cookie.lower()
        missing = [flag for flag in ("httponly", "secure", "samesite") if flag not in lowered]
        if missing:
            findings.append(Finding(
                "medium", "cookies", "Cookie sem flags fortes",
                f"faltando: {', '.join(missing)}",
                "Use Secure, HttpOnly e SameSite em cookies sensiveis.",
            ))

    dangerous_methods = [method for method in methods if method in {"PUT", "DELETE", "TRACE", "CONNECT"}]
    if dangerous_methods:
        findings.append(Finding(
            "high", "methods", "Metodos HTTP perigosos habilitados",
            ", ".join(dangerous_methods),
            "Desabilite metodos nao usados no servidor, proxy e aplicacao.",
        ))

    if parser.password_inputs and parsed.scheme == "http":
        findings.append(Finding(
            "critical", "auth", "Senha em pagina sem HTTPS",
            f"{parser.password_inputs} campo(s) password detectado(s).",
            "Nunca sirva formularios de autenticacao via HTTP.",
        ))
    elif parser.password_inputs:
        findings.append(Finding(
            "info", "auth", "Formulario de login detectado",
            f"{parser.password_inputs} campo(s) password detectado(s).",
            "Revise MFA, rate limit, lockout e protecao contra credential stuffing.",
        ))

    if parser.comments:
        findings.append(Finding(
            "low", "content", "Comentarios HTML presentes",
            parser.comments[0],
            "Remova comentarios com detalhes internos, rotas, tokens ou tecnologia.",
        ))

    sensitive_hits = [
        probe for probe in probes
        if probe.status in {200, 401, 403} and any(token in probe.url for token in (".env", ".git", "dump", "backup", "config", "phpinfo", "actuator"))
    ]
    for probe in sensitive_hits:
        severity = "high" if probe.status == 200 else "medium"
        findings.append(Finding(
            severity, "exposure", "Endpoint/arquivo sensivel exposto",
            f"{probe.status} {probe.url}",
            "Remova arquivos sensiveis do webroot e restrinja endpoints administrativos.",
        ))

    if 500 <= status < 600:
        findings.append(Finding(
            "medium", "stability", "Erro 5xx na pagina principal",
            f"HTTP {status}",
            "Investigue logs e tratamento de erro para evitar vazamento e indisponibilidade.",
        ))

    return findings


def risk_score(findings: list[Finding]) -> int:
    return sum(RISK_WEIGHTS.get(finding.severity, 0) for finding in findings)


def severity_color(severity: str) -> str:
    return {
        "critical": Cyber.RED,
        "high": Cyber.RED,
        "medium": Cyber.YELLOW,
        "low": Cyber.BLUE,
        "info": Cyber.GRAY,
    }.get(severity, Cyber.WHITE)


def run_audit(url: str, timeout: float, user_agent: str, threads: int, deep: bool) -> AuditResult:
    started = time.monotonic()
    target = normalize_url(url)
    parsed = urlparse(target)
    ip = resolve_ip(parsed.hostname or "")

    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Alvo: {color(target, Cyber.WHITE, Cyber.BOLD)}")
    if ip:
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"IP: {color(ip, Cyber.YELLOW)}")

    status, headers, body = fetch(target, timeout, user_agent)
    content_type = header_get(headers, "content-type")
    text = body.decode("utf-8", errors="replace") if "text/html" in content_type.lower() else ""
    parser = PageParser()
    if text:
        parser.feed(text)

    tls_subject, tls_issuer, tls_not_after = tls_info(target, timeout)
    methods = parse_allowed_methods(target, timeout, user_agent)
    probes = scan_paths(target, timeout, user_agent, threads) if deep else []
    findings = build_findings(target, status, headers, parser, methods, probes, tls_subject)

    return AuditResult(
        target=url,
        final_url=target,
        status=status,
        title=parser.title,
        ip=ip,
        tls_subject=tls_subject,
        tls_issuer=tls_issuer,
        tls_not_after=tls_not_after,
        allowed_methods=methods,
        forms=parser.forms,
        password_inputs=parser.password_inputs,
        probes=probes,
        findings=findings,
        risk_score=risk_score(findings),
        elapsed=time.monotonic() - started,
    )


def print_result(result: AuditResult) -> None:
    print()
    print(color("Resumo", Cyber.CYAN, Cyber.BOLD))
    print(f"{color('[*]', Cyber.CYAN, Cyber.BOLD)} URL: {color(result.final_url, Cyber.WHITE, Cyber.BOLD)}")
    print(f"{color('[*]', Cyber.CYAN, Cyber.BOLD)} Status: {color(str(result.status), status_color(result.status), Cyber.BOLD)} | Score: {color(str(result.risk_score), Cyber.YELLOW, Cyber.BOLD)} | Tempo: {color(f'{result.elapsed:.2f}s', Cyber.YELLOW)}")
    if result.title:
        print(f"{color('[T]', Cyber.MAGENTA, Cyber.BOLD)} Title: {color(result.title, Cyber.WHITE)}")
    if result.tls_subject:
        print(f"{color('[*]', Cyber.CYAN, Cyber.BOLD)} TLS: {color(result.tls_subject, Cyber.GREEN)} | expira: {color(result.tls_not_after, Cyber.YELLOW)}")
    if result.allowed_methods:
        print(f"{color('[*]', Cyber.CYAN, Cyber.BOLD)} Metodos: {color(', '.join(result.allowed_methods), Cyber.WHITE)}")
    print(f"{color('[*]', Cyber.CYAN, Cyber.BOLD)} Forms: {color(str(result.forms), Cyber.WHITE)} | Password inputs: {color(str(result.password_inputs), Cyber.WHITE)}")

    print(color("\nFindings red/blue", Cyber.CYAN, Cyber.BOLD))
    if not result.findings:
        print(color("Nenhum finding relevante com os checks atuais.", Cyber.GREEN))
        return

    for finding in sorted(result.findings, key=lambda item: -RISK_WEIGHTS.get(item.severity, 0)):
        sev = color(finding.severity.upper().ljust(8), severity_color(finding.severity), Cyber.BOLD)
        print(f"{sev} {color(finding.category.ljust(11), Cyber.GRAY)} {color(finding.item, Cyber.WHITE, Cyber.BOLD)}")
        print(f"         evidencia: {color(finding.evidence, Cyber.YELLOW)}")
        print(f"         defesa:    {color(finding.recommendation, Cyber.GREEN)}")


def write_output(path: str, result: AuditResult) -> None:
    extension = os.path.splitext(path)[1].lower()
    data = asdict(result)
    with open(path, "w", encoding="utf-8", newline="") as file_handle:
        if extension == ".csv":
            writer = csv.DictWriter(
                file_handle,
                fieldnames=["severity", "category", "item", "evidence", "recommendation"],
            )
            writer.writeheader()
            for finding in data["findings"]:
                writer.writerow(finding)
        else:
            json.dump(data, file_handle, indent=2)
            file_handle.write("\n")
    print(color("[*]", Cyber.CYAN, Cyber.BOLD), f"Resultado salvo em {color(path, Cyber.GREEN)}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Auditoria web red/blue para laboratorios e alvos autorizados."
    )
    parser.add_argument("url", nargs="?", help="URL alvo. Ex: https://example.com")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Timeout em segundos. Padrao: 5")
    parser.add_argument("--threads", type=int, default=20, help="Threads para probes de paths. Padrao: 20")
    parser.add_argument("--deep", action="store_true", help="Ativa probes de arquivos/endpoints comuns.")
    parser.add_argument(
        "-A",
        "--user-agent",
        default="Mozilla/5.0 (X11; Linux x86_64) AttackAudit/1.0",
        help="User-Agent usado nas requests.",
    )
    parser.add_argument("-o", "--output", help="Salva resultado em .json ou .csv.")
    return parser


def run_once(args: argparse.Namespace) -> int:
    if not args.url:
        raise ValueError("informe uma URL alvo")
    if args.timeout <= 0:
        raise ValueError("timeout precisa ser maior que zero")
    if args.threads < 1:
        raise ValueError("threads precisa ser maior que zero")

    result = run_audit(args.url, args.timeout, args.user_agent, args.threads, args.deep)
    print_result(result)
    if args.output:
        write_output(args.output, result)
    return 0


def interactive_shell(parser: argparse.ArgumentParser) -> int:
    banner()
    print(color("AttackAudit interativo.", Cyber.WHITE, Cyber.BOLD), "Digite 'help', 'clear' ou 'exit'.")
    print(color("Ex:", Cyber.CYAN), "https://example.com --deep -o audit.json")

    while True:
        try:
            raw = input(color("audit> ", Cyber.GREEN, Cyber.BOLD)).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

        if not raw:
            continue
        if raw in {"exit", "quit"}:
            return 0
        if raw == "clear":
            clear_console()
            continue
        if raw == "help":
            parser.print_help()
            continue

        try:
            args = parser.parse_args(shlex.split(raw))
            run_once(args)
        except SystemExit:
            continue
        except Exception as error:
            print(color(f"Erro: {error}", Cyber.RED))


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not args.url:
        return interactive_shell(parser)

    try:
        banner()
        return run_once(args)
    except Exception as error:
        print(color(f"Erro: {error}", Cyber.RED), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
