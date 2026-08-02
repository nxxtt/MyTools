"""Headless browser helpers via Playwright (import lazy).

Fornece:
- ``browser_available`` — detecta playwright + chromium instalados
- ``evaluate`` — executa JavaScript no contexto de uma pagina real
- ``HeadlessError`` — erro amigavel quando o browser nao esta instalado

O playwright so e importado quando ``evaluate`` e chamado, entao o resto do
projeto nao paga custo de import nem exige o browser instalado.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

__all__ = ["HeadlessError", "browser_available", "confirm_js_execution", "evaluate"]


class HeadlessError(RuntimeError):
    """Browser headless indisponivel (playwright ou chromium ausente)."""


def _browser_dir() -> Path | None:
    """Retorna o diretorio de browsers do playwright, se existir."""
    env = os.environ.get("PLAYWRIGHT_BROWSERS_PATH")
    if env:
        base = Path(env)
    else:
        home = Path.home()
        base = home / ".cache" / "ms-playwright"
        if not base.is_dir():
            base = home / "AppData" / "Local" / "ms-playwright"
    if base.is_dir():
        return base
    return None


def browser_available() -> bool:
    """True se playwright importa e um chromium foi baixado.

    Cobre ``playwright install chromium`` (diretorios ``chromium-*`` e
    ``chromium_headless_shell-*``) e o override ``PLAYWRIGHT_BROWSERS_PATH``.
    """
    try:
        import playwright  # noqa: F401
    except ImportError:
        return False
    base = _browser_dir()
    if base is None:
        return False
    return any(p.name.startswith("chromium") for p in base.iterdir() if p.is_dir())


async def evaluate(
    url: str,
    script: str,
    arg: Any = None,
    *,
    timeout: float = 10.0,
    proxy: str | None = None,
    verify: bool = False,
) -> Any:
    """Carrega ``url`` num chromium headless e avalia ``script`` na pagina.

    Args:
        url: URL alvo (a pagina e renderizada de verdade, com JS).
        script: JavaScript a executar via ``page.evaluate``. Pode ser uma
            funcao ``(arg) => ...``; ``arg`` e passado como argumento.
        arg: valor serializavel passado para ``script``.
        timeout: timeout do page.goto em segundos.
        proxy: proxy HTTP/SOCKS no formato ``http://host:port``.
        verify: False ignora erros de certificado (padrao do projeto).

    Raises:
        HeadlessError: se playwright ou o chromium nao estao instalados.
    """
    if not browser_available():
        raise HeadlessError(
            "browser chromium nao instalado. Rode: uv run playwright install chromium"
        )
    from playwright.async_api import async_playwright

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            context_kwargs: dict[str, Any] = {"ignore_https_errors": not verify}
            if proxy:
                context_kwargs["proxy"] = {"server": proxy}
            context = await browser.new_context(**context_kwargs)
            page = await context.new_page()
            await page.goto(
                url, timeout=int(timeout * 1000), wait_until="domcontentloaded"
            )
            return await page.evaluate(script, arg)
        finally:
            await browser.close()


# Seletores de elementos que podem disparar JS por interacao do usuario.
_CLICKABLE_SELECTOR = (
    "a[href], area[href], button, "
    "input[type=submit], input[type=button], input[type=image], "
    "[onclick], [onerror], [onload], [onmouseover], "
    "svg a, use, select, option"
)


async def confirm_js_execution(
    url: str,
    *,
    timeout: float = 10.0,
    proxy: str | None = None,
    verify: bool = False,
) -> bool:
    """Confirma que o JavaScript de ``url`` executa de fato.

    Carrega ``url`` num chromium headless, captura dialogs (``alert``,
    ``confirm``, ``prompt``) disparados durante o load — inclusive os de
    iframes srcdoc/data — e depois clica nos elementos clicaveis para
    disparar vetores acionados por interacao (ex.: ``javascript:`` URI).

    Retorna ``True`` se qualquer dialog foi disparado antes de fechar o
    browser. Usa 1 page.goto. Lazy import de playwright.

    Raises:
        HeadlessError: se playwright ou o chromium nao estao instalados.
    """
    if not browser_available():
        raise HeadlessError(
            "browser chromium nao instalado. Rode: uv run playwright install chromium"
        )
    from playwright.async_api import async_playwright

    fired = False

    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        try:
            context_kwargs: dict[str, Any] = {"ignore_https_errors": not verify}
            if proxy:
                context_kwargs["proxy"] = {"server": proxy}
            context = await browser.new_context(**context_kwargs)
            page = await context.new_page()

            def _on_dialog(_dialog: Any) -> None:
                nonlocal fired
                fired = True

            page.on("dialog", _on_dialog)
            await page.goto(
                url, timeout=int(timeout * 1000), wait_until="domcontentloaded"
            )

            clickables = page.locator(_CLICKABLE_SELECTOR)
            count = await clickables.count()
            for i in range(count):
                if fired:
                    break
                try:
                    await clickables.nth(i).click(timeout=2000)
                except Exception:
                    continue
            return fired
        finally:
            await browser.close()
