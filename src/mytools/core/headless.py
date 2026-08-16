"""Headless browser helpers via Playwright (import lazy).

Fornece:
- ``browser_available`` — detecta playwright + chromium instalados
- ``evaluate`` — executa JavaScript no contexto de uma pagina real
- ``HeadlessError`` — erro amigavel quando o browser nao esta instalado

O playwright so e importado quando ``evaluate`` e chamado, entao o resto do
projeto nao paga custo de import nem exige o browser instalado.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import os
from pathlib import Path
from typing import Any

__all__ = ["HeadlessError", "browser_available", "confirm_js_execution", "evaluate"]


class HeadlessError(RuntimeError):
    """Browser headless indisponivel (playwright ou chromium ausente)."""


def _timeout_ms(timeout: float) -> int:
    """Converte segundos em ms para o playwright, garantindo timeout ativo."""
    return max(1, int(timeout * 1000))


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


@functools.lru_cache(maxsize=1)
def browser_available() -> bool:
    """True se playwright importa e um chromium foi baixado.

    Resultado cacheado (lru_cache): a deteccao so roda uma vez por processo.
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
    browser: Any = None,
) -> Any:
    """Carrega ``url`` num chromium headless e avalia ``script`` na pagina.

    Args:
        url: URL alvo (a pagina e renderizada de verdade, com JS).
        script: JavaScript a executar via ``page.evaluate``. Pode ser uma
            funcao ``(arg) => ...``; ``arg`` e passado como argumento.
        arg: valor serializavel passado para ``script``.
        timeout: timeout do page.goto e do evaluate em segundos.
        proxy: proxy HTTP/SOCKS no formato ``http://host:port``.
        verify: False ignora erros de certificado (padrao do projeto).
        browser: browser playwright ja iniciado para reuso (economiza um
            launch por chamada). Se ``None``, um browser novo e criado e
            fechado ao final.

    Raises:
        HeadlessError: se playwright ou o chromium nao estao instalados.
    """
    if not browser_available():
        raise HeadlessError(
            "browser chromium nao instalado. Rode: uv run playwright install chromium"
        )
    from playwright.async_api import async_playwright

    owns_playwright = browser is None
    pm: Any = None
    if owns_playwright:
        p = async_playwright()
        pm = await p.start()
        browser = await pm.chromium.launch(headless=True)
    try:
        context_kwargs: dict[str, Any] = {"ignore_https_errors": not verify}
        if proxy:
            context_kwargs["proxy"] = {"server": proxy}
        context = await browser.new_context(**context_kwargs)
        page = await context.new_page()
        await page.goto(
            url, timeout=_timeout_ms(timeout), wait_until="domcontentloaded"
        )
        return await asyncio.wait_for(page.evaluate(script, arg), timeout=timeout)
    finally:
        if owns_playwright:
            await browser.close()
            if pm is not None:
                await pm.stop()


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
    browser: Any = None,
) -> bool:
    """Confirma que o JavaScript de ``url`` executa de fato.

    Carrega ``url`` num chromium headless, captura dialogs (``alert``,
    ``confirm``, ``prompt``) disparados durante o load — inclusive os de
    iframes srcdoc/data — e depois clica nos elementos clicaveis para
    disparar vetores acionados por interacao (ex.: ``javascript:`` URI).

    Retorna ``True`` se qualquer dialog foi disparado antes de fechar o
    browser. Usa 1 page.goto. Lazy import de playwright.

    Args:
        browser: browser playwright ja iniciado para reuso. Se ``None``,
            um browser novo e criado e fechado ao final.

    Raises:
        HeadlessError: se playwright ou o chromium nao estao instalados.
    """
    if not browser_available():
        raise HeadlessError(
            "browser chromium nao instalado. Rode: uv run playwright install chromium"
        )
    from playwright.async_api import async_playwright

    owns_playwright = browser is None
    pm: Any = None
    if owns_playwright:
        p = async_playwright()
        pm = await p.start()
        browser = await pm.chromium.launch(headless=True)

    fired = False
    deadline = asyncio.get_event_loop().time() + timeout
    try:
        context_kwargs: dict[str, Any] = {"ignore_https_errors": not verify}
        if proxy:
            context_kwargs["proxy"] = {"server": proxy}
        context = await browser.new_context(**context_kwargs)
        page = await context.new_page()

        async def _on_dialog(dialog: Any) -> None:
            nonlocal fired
            fired = True
            with contextlib.suppress(Exception):
                await dialog.dismiss()

        page.on("dialog", _on_dialog)
        await page.goto(
            url, timeout=_timeout_ms(timeout), wait_until="domcontentloaded"
        )

        clickables = page.locator(_CLICKABLE_SELECTOR)
        count = await clickables.count()
        for i in range(count):
            if fired or asyncio.get_event_loop().time() > deadline:
                break
            try:
                await clickables.nth(i).click(timeout=2000)
            except Exception:
                continue
        return fired
    finally:
        if owns_playwright:
            await browser.close()
            if pm is not None:
                await pm.stop()
