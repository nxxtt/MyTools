#!/usr/bin/env python3
"""Utilitários gerais para formatação, cores e manipulação de dados."""
from __future__ import annotations

import os
import sys
from urllib.request import HTTPRedirectHandler, build_opener


USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


class Cyber:
    """Constantes de cores ANSI para formatação de terminal."""

    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[38;5;203m"
    GREEN = "\033[38;5;46m"
    CYAN = "\033[38;5;51m"
    BLUE = "\033[38;5;39m"
    MAGENTA = "\033[38;5;201m"
    YELLOW = "\033[38;5;226m"
    WHITE = "\033[38;5;255m"
    GRAY = "\033[38;5;244m"


def color(text: str, *styles: str) -> str:
    """Aplica estilos de cor ANSI ao texto."""
    if not USE_COLOR:
        return text
    return "".join(styles) + text + Cyber.RESET


def clear_console() -> None:
    """Limpa a tela do console."""
    os.system("cls" if os.name == "nt" else "clear")


class NoRedirectHandler(HTTPRedirectHandler):
    """Handler que impede redirecionamento automático em requisições HTTP."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


NO_REDIRECT_OPENER = build_opener(NoRedirectHandler)


def status_color(status: int) -> str:
    """Retorna a cor ANSI correspondente ao código de status HTTP."""
    if 200 <= status < 300:
        return Cyber.GREEN
    if 300 <= status < 400:
        return Cyber.YELLOW
    if status in {401, 403}:
        return Cyber.MAGENTA
    if 400 <= status < 500:
        return Cyber.RED
    return Cyber.GRAY


def header_get(headers: dict[str, str], name: str) -> str:
    """Obtém o valor de um header HTTP, ignorando maiúsculas/minúsculas."""
    for key, value in headers.items():
        if key.lower() == name.lower():
            return value
    return ""


def extract_title(text: str) -> str:
    """Extrai o conteúdo da tag <title> de um HTML."""
    lower = text.lower()
    start = lower.find("<title>")
    end = lower.find("</title>", start + 7)
    if start == -1 or end == -1:
        return ""
    return " ".join(text[start + 7:end].strip().split())[:100]
