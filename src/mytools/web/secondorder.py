"""Verificacao de Segunda Ordem — reduz falsos positivos em injecao por conteudo.

Quando um modulo de injecao detecta positivo (conteudo, erro DB, leak),
esta logica faz segundo request com payload DIFERENTE para confirmar.
Se o segundo payload tambem confirma → true positive.
Se nao → falso positivo (marcado como tal).

Aplicavel para:
  - CMD injection (content-based): ; id → uid= then ; whoami → www-data
  - SQL injection (error-based): ' → MySQL error then " → different error
  - LFI detection: ../../etc/passwd → root:x: then ../../etc/hostname → hostname
  - SSTI detection: {{7*7}} → 49 then {{7*8}} → 56

NAO aplica para:
  - Timing-based (blind injection) — mesmo ruído afeta ambos requests
  - SSRF — segundo payload nao adiciona evidencia independente sem callback
"""

from __future__ import annotations

import logging

import httpx

logger = logging.getLogger("mytools.secondorder")


def check_indicators(body: bytes, indicators: list[bytes]) -> tuple[bool, str]:
    """Verifica se body contem algum dos indicadores.

    Args:
        body: Corpo da resposta HTTP
        indicators: Lista de bytes que confirmam positivo

    Returns:
        (found, matched_indicator) — indicator decodificado como string
    """
    for ind in indicators:
        if ind in body:
            return True, ind.decode("utf-8", errors="replace")
    return False, ""


# ---------------------------------------------------------------------------
# Verification payloads: module -> category -> (payload, indicators)
# Modulos usam como fallback; podem sobrescrever se precisar.
# ---------------------------------------------------------------------------

VERIFY_PAYLOADS: dict[str, dict[str, tuple[str, list[bytes]]]] = {
    "cmdinject": {
        "os_command": ("; whoami", [b"www-data", b"root", b"nobody", b"nginx"]),
        "bypass": ("%0a whoami", [b"www-data", b"root", b"nobody"]),
    },
    "sqliscan": {
        "error": (
            '" OR 1=1--',
            [b"error", b"warning", b"mysql", b"sqlite", b"postgresql"],
        ),
    },
    "lfidetect": {
        "lfi": ("../../../../etc/hostname", [b"\n"]),
        "rfi": ("http://httpbin.org/robots.txt", [b"User-agent"]),
    },
    "sstidetect": {
        "detect": ("{{7*8}}", [b"56"]),
        "exploit": ("{{7*9}}", [b"63"]),
        "bypass": ("${7*8}", [b"56"]),
    },
}


def get_verify_payload(module: str, category: str) -> tuple[str, list[bytes]] | None:
    """Retorna (payload, indicators) para verificacao, ou None se nao aplicavel.

    NOTA: A construcao de inject_url e responsabilidade do modulo caller.
    Exemplos de construcao:
      - GET param: f"{url}?{param}={verify_payload}"
      - Path-based: f"{url}/{verify_payload}"
      - POST: usar httpx diretamente e chamar check_indicators()
    """
    mod = VERIFY_PAYLOADS.get(module, {})
    return mod.get(category)


async def verify_positive(
    client: httpx.AsyncClient,
    inject_url: str,
    indicators: list[bytes],
) -> tuple[bool, str]:
    """Faz GET na inject_url e verifica indicadores no body.

    NOTA: A construcao de inject_url e responsabilidade do modulo caller.

    Args:
        client: AsyncClient (reutiliza o do modulo)
        inject_url: URL completa com payload de verificacao ja embutido
        indicators: Lista de bytes que confirmam positivo

    Returns:
        (confirmed, matched_indicator)
    """
    try:
        resp = await client.get(inject_url, follow_redirects=False, timeout=10.0)
        return check_indicators(resp.content, indicators)
    except httpx.RequestError:
        return False, ""
