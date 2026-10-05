"""BaseScanner — elimina boilerplate comum em modulos.

Fornece:
- ``ScanGroup`` enum para select do dispatch de ``run_once``
- ``BaseScanner`` ABC com template de ``build_parser``, ``main``, ``run_once``
- Hooks sobrescreviveis: ``_add_arguments``, ``_build_run_once_kwargs``,
  ``_get_return_code``, ``_describe_plan``, ``_example``, ``_help``
- ``scan_fn`` (attr opcional): funcao module-level alvo da delegacao —
  permite filtrar kwargs default pela assinatura real do scan

Logger fica module-level em cada arquivo (compativel com codigo existente).

Adocao: todos os 97 modulos-ferramenta usam este template. Excecao unica:
``core/reconall.py`` (orquestrador que chama ``run_once`` dos modulos — nao e
CLI individual, fica de fora por design).
"""

from __future__ import annotations

import argparse
import inspect
import logging
from abc import ABC, abstractmethod
from collections.abc import Callable
from dataclasses import asdict
from enum import Enum, auto
from pathlib import Path
from typing import Any

from mytools.core.utils import (
    Cyber,
    add_common_args,
    color,
    create_banner,
    ensure_output_dir,
    get_dry_run,
    init_scanner,
    print_json,
    run_main_loop,
    safe_asyncio_run,
    workspace_path,
    write_output,
)

__all__ = ["BaseScanner", "ScanGroup"]

logger = logging.getLogger("mytools.base")


class ScanGroup(Enum):
    """Grupo arquitetural do modulo."""

    A = auto()  # run_scan() retorna int; output gerenciado internamente
    B = auto()  # run_scan() retorna Result dataclass; output em run_once


class BaseScanner(ABC):
    """Classe base para modulos de scan.

    Subclasses definem:
        prog, description, prompt, module_name, banner_text, group

    E implementam:
        _add_arguments, run_scan, print_results, _example, _help
    """

    # --- Subclasses definem estas strings ---
    prog: str = ""
    description: str = ""
    prompt: str = ""
    module_name: str = ""
    banner_text: str = ""
    banner_fn: Callable[[], None] | None = None
    epilog: str = ""
    group: ScanGroup = ScanGroup.B
    module_type: str = "core"

    # Funcao module-level de scan (ex.: staticmethod(scan_caa)). Quando
    # definida, os kwargs default sao filtrados pela assinatura dela.
    scan_fn: Callable[..., Any] | None = None

    # ------------------------------------------------------------------
    # Parser
    # ------------------------------------------------------------------

    def build_parser(self) -> argparse.ArgumentParser:
        """Template: cria parser base e chama hook _add_arguments."""
        parser = argparse.ArgumentParser(
            prog=self.prog,
            description=self.description,
            epilog=self.epilog or None,
            formatter_class=argparse.RawDescriptionHelpFormatter,
        )
        self._add_arguments(parser)
        add_common_args(parser, self.module_type)
        return parser

    @abstractmethod
    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        """Subclasses adicionam args especificos (url, category, etc)."""
        ...

    # ------------------------------------------------------------------
    # Scan
    # ------------------------------------------------------------------

    @abstractmethod
    async def run_scan(self, **kwargs: Any) -> int | object:
        """Logica de scan. Grupo A retorna int, Grupo B retorna Result."""
        ...

    @abstractmethod
    def print_results(self, result: object) -> None:
        """Formata e imprime resultados."""
        ...

    # ------------------------------------------------------------------
    # Target resolution
    # ------------------------------------------------------------------

    @staticmethod
    def _get_target(args: argparse.Namespace) -> str | None:
        """Resolve target de args.url OU args.target."""
        return getattr(args, "url", None) or getattr(args, "target", None)

    # ------------------------------------------------------------------
    # run_once dispatch
    # ------------------------------------------------------------------

    def run_once(self, args: argparse.Namespace) -> int:
        """Dispatch para grupo A ou B."""
        if self.group == ScanGroup.A:
            return self._run_once_a(args)
        return self._run_once_b(args)

    def _run_once_a(self, args: argparse.Namespace) -> int:
        """Grupo A: run_scan retorna int, output gerenciado internamente."""
        init_scanner(args)
        early = self._pre_scan(args)
        if early is not None:
            return early
        if get_dry_run():
            return self._describe_plan(args)
        kwargs = self._build_run_once_kwargs(args)
        return safe_asyncio_run(self.run_scan(**kwargs))

    def _run_once_b(self, args: argparse.Namespace) -> int:
        """Grupo B: scan retorna Result, output gerenciado em run_once."""
        quiet = init_scanner(args)
        early = self._pre_scan(args)
        if early is not None:
            return early
        if get_dry_run():
            return self._describe_plan(args)
        kwargs = self._build_run_once_kwargs(args)
        if not self._get_target(args):
            print(color("Especifique um alvo.", Cyber.RED))
            return 1
        result = safe_asyncio_run(self.run_scan(**kwargs))
        if getattr(args, "json_output", False):
            print_json(asdict(result))
        elif not quiet:
            self.print_results(result)
        payload = asdict(result)
        output_path = getattr(args, "output", None)
        if output_path:
            write_output(output_path, payload)
        output_dir = getattr(args, "output_dir", None)
        if output_dir:
            ws = workspace_path(output_dir, self._get_target(args) or "")
            ensure_output_dir(str(ws.parent))
            write_output(str(ws), payload, quiet=True)
        return self._get_return_code(result)

    # ------------------------------------------------------------------
    # Hooks sobrescreviveis
    # ------------------------------------------------------------------

    def _pre_scan(self, args: argparse.Namespace) -> int | None:
        """Hook opcional executado antes do dry-run/scan (Grupos A e B).

        Retorne um int para abortar com esse codigo de saida (validacoes
        de argumentos como nameserver invalido). Retorne ``None`` para
        continuar normalmente (padrao)."""
        return None

    def _build_run_once_kwargs(self, args: argparse.Namespace) -> dict[str, Any]:
        """Kwargs passados ao scan. Grupo A: target/categories/timeout/...;
        Grupo B: url/timeout/user_agent/.... Sobrescrever para modulos que
        usam parametros diferentes (domain, wordlist, etc).

        Quando ``scan_fn`` esta definida, os kwargs default sao filtrados
        pela assinatura da funcao de scan (evita TypeError em scans que nao
        aceitam proxy/headless/json_output/etc)."""
        if self.group == ScanGroup.A:
            target = self._get_target(args)
            output_file = getattr(args, "output", None)
            if not output_file:
                output_dir = getattr(args, "output_dir", None)
                if output_dir and target:
                    output_file = str(workspace_path(output_dir, target))
                    ensure_output_dir(str(Path(output_file).parent))
            kwargs: dict[str, Any] = {
                "target": target,
                "categories": self._get_categories(args),
                "timeout": getattr(args, "timeout", 10),
                "output_file": output_file,
                "json_output": getattr(args, "json_output", False),
                "proxy": getattr(args, "proxy", None),
                "headless": getattr(args, "headless", False),
            }
        else:
            kwargs = {
                "url": self._get_target(args),
                "timeout": getattr(args, "timeout", 10.0),
                "user_agent": getattr(args, "user_agent", None),
                "proxy": getattr(args, "proxy", None),
                "verify": getattr(args, "verify", False),
                "confirm": getattr(args, "confirm", True),
                "category": getattr(args, "category", None),
                "concurrency": getattr(args, "concurrency", 5),
            }
        if self.scan_fn is not None:
            kwargs = self._filter_kwargs(self.scan_fn, kwargs)
        return kwargs

    @staticmethod
    def _filter_kwargs(
        fn: Callable[..., Any], kwargs: dict[str, Any]
    ) -> dict[str, Any]:
        """Mantem apenas kwargs aceitos pela assinatura de ``fn``.

        Se ``fn`` declara ``**kwargs`` (ou a assinatura e inacessivel),
        devolve ``kwargs`` intactos."""
        try:
            params = inspect.signature(fn).parameters
        except TypeError, ValueError:
            return kwargs
        if any(p.kind is inspect.Parameter.VAR_KEYWORD for p in params.values()):
            return kwargs
        return {k: v for k, v in kwargs.items() if k in params}

    def _get_categories(self, args: argparse.Namespace) -> list[str]:
        """Extrai lista de categorias de args.category."""
        cat = getattr(args, "category", None)
        return [cat] if cat and cat != "all" else []

    def _describe_plan(self, args: argparse.Namespace) -> int:
        """Descreve o plano de execucao quando --dry-run esta ativo.

        Sobrescrever em subclasses para gerar saida detalhada.
        Retorna 0 (sucesso) — nenhuma requisicao e enviada.
        """
        target = self._get_target(args) or "(nenhum alvo)"
        logger.warning("[DRY-RUN] %s — nenhuma requisicao executada", self.prog)
        logger.info("[DRY-RUN] Alvo: %s", target)
        return 0

    def _get_return_code(self, result: object) -> int:
        """Codigo de saida: 0 somente se o scan reportou 'secure'.

        Qualquer outro status (vuln, erro, unsigned, etc) retorna 1.
        Convencao do repo: modules retornam 1 quando ha falhas/vulns e
        0 quando tudo esta seguro. Sobrescrever se necessario.
        """
        status = getattr(result, "overall_status", "error")
        return 1 if status != "secure" else 0

    # ------------------------------------------------------------------
    # main()
    # ------------------------------------------------------------------

    def main(self) -> int:
        """Entry point — identico em todos os modulos."""
        return run_main_loop(
            parser=self.build_parser(),
            banner_fn=self._make_banner(),
            run_fn=self.run_once,
            has_target=lambda a: bool(self._get_target(a)),
            prompt=self.prompt,
            description=f"{self.description.strip()} interativo.",
            example=self._example(),
            contextual_help=self._help(),
        )

    def _make_banner(self) -> Callable[[], None]:
        """Cria callable do banner. Suporta banner_fn para modulos com banner pre-existente."""
        if self.banner_fn is not None:
            return self.banner_fn
        return create_banner(self.banner_text, self.description)

    @abstractmethod
    def _example(self) -> str:
        """Exemplo de uso para o shell interativo."""
        ...

    @abstractmethod
    def _help(self) -> str:
        """Help contextual para o shell interativo."""
        ...
