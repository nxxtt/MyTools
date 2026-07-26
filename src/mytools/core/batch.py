#!/usr/bin/env python3
"""Batch scanner — executa N modulos contra M alvos.

Le alvos de um arquivo e executa modulos MyTools selecionados contra cada um.
Soh orquestracao — nao contem logica de scanning.

Exemplos:
  mytools-batch targets.txt webrecon attackaudit
  mytools-batch targets.txt all --skip portscanner
  mytools-batch targets.txt webrecon -p 3 -o results/
  mytools-batch targets.txt webrecon --strict --fail-fast
  mytools-batch targets.txt webrecon --format json
"""
import argparse
import contextlib
import importlib
import io
import json
import logging
import re
import sys
import time
import types
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from mytools.core.utils import __version__, setup_logging

logger = logging.getLogger("mytools.batch")

# ---------------------------------------------------------------------------
# Module registry
# ---------------------------------------------------------------------------

_MODULE_REGISTRY: dict[str, str] | None = None


def _find_project_root() -> Path:
    """Sobe a arvore procurando pyproject.toml."""
    path = Path(__file__).resolve().parent
    for _ in range(6):
        if (path / "pyproject.toml").exists():
            return path
        path = path.parent
    raise FileNotFoundError("pyproject.toml não encontrado")


def _discover_modules() -> dict[str, str]:
    """Le pyproject.toml via root absoluto.

    Returns:
        {"webrecon": "mytools.web.webrecon", ...}
    """
    root = _find_project_root()
    text = (root / "pyproject.toml").read_text(encoding="utf-8")
    modules: dict[str, str] = {}
    in_scripts = False
    for line in text.splitlines():
        if line.strip() in ("[tool.poetry.scripts]", "[project.scripts]"):
            in_scripts = True
            continue
        if in_scripts:
            if line.startswith("["):
                break
            m = re.match(r'^([\w-]+)\s*=\s*"([^"]+)"', line.strip())
            if m:
                key, val = m.group(1), m.group(2)
                if (
                    key.startswith("mytools-")
                    and key
                    not in ("mytools", "mytools-cred", "mytools-reconall")
                ):
                    mod_name = key[len("mytools-"):]
                    modules[mod_name] = val.split(":")[0]
    return modules


def _get_registry() -> dict[str, str]:
    global _MODULE_REGISTRY
    if _MODULE_REGISTRY is None:
        _MODULE_REGISTRY = _discover_modules()
    return _MODULE_REGISTRY


def _get_all_module_names() -> list[str]:
    return sorted(_get_registry().keys())


def _resolve_module(name: str) -> types.ModuleType:
    registry = _get_registry()
    if name not in registry:
        available = ", ".join(sorted(registry.keys()))
        msg = f"modulo '{name}' nao encontrado. Disponiveis: {available}"
        raise ValueError(msg)
    return importlib.import_module(registry[name])


# ---------------------------------------------------------------------------
# Dataclass
# ---------------------------------------------------------------------------


@dataclass
class TargetResult:
    target: str
    sanitized: str
    success: int = 0
    vulns: int = 0
    errors: int = 0
    details: dict[str, int] = field(default_factory=dict)
    duration: float = 0.0


# ---------------------------------------------------------------------------
# Funcoes de suporte
# ---------------------------------------------------------------------------


def read_targets(path: str) -> list[str]:
    """Le arquivo de targets (1 por linha, ignora # e vazios)."""
    p = Path(path)
    if not p.exists():
        msg = f"arquivo nao encontrado: {path}"
        raise FileNotFoundError(msg)
    targets: list[str] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            targets.append(line)
    if not targets:
        msg = f"nenhum target valido em {path}"
        raise ValueError(msg)
    return targets


def _sanitize_target(target: str) -> str:
    """Sanitiza target para uso como nome de diretorio."""
    s = re.sub(r"[^\w.\-]", "_", target)
    return s[:100]


def _detect_target_type(target: str) -> str:
    if target.startswith(("http://", "https://")):
        return "url"
    return "domain"


def _is_compatible(target: str, parser: argparse.ArgumentParser) -> bool:
    """Verifica se o modulo aceita o tipo de target."""
    arg_names = {a.dest for a in parser._actions if hasattr(a, "dest")}
    target_type = _detect_target_type(target)
    if target_type == "url":
        return bool({"url", "target", "targets"} & arg_names)
    return bool({"domain", "target", "targets", "ips"} & arg_names)


def _make_args(
    extra: dict[str, object],
    base_ns: argparse.Namespace,
) -> argparse.Namespace:
    """Cria namespace combinando base_ns com extras do target."""
    ns = argparse.Namespace(**vars(base_ns))
    for k, v in extra.items():
        setattr(ns, k, v)
    return ns


# ---------------------------------------------------------------------------
# Base namespace — defaults dos modulos selecionados
# ---------------------------------------------------------------------------


def _get_parser_defaults(module_names: list[str]) -> dict[str, object]:
    """Le defaults so dos modulos selecionados via _actions.

    Extrai defaults direto de parser._actions em vez de parse_args([]),
    que falha em positionais obrigatórios.
    """
    defaults: dict[str, object] = {}
    registry = _get_registry()
    for name in module_names:
        if name in registry:
            try:
                mod = importlib.import_module(registry[name])
                for a in mod.build_parser()._actions:
                    if hasattr(a, "dest") and a.default is not argparse.SUPPRESS:
                        defaults[a.dest] = a.default
            except Exception:
                pass
    return defaults


def _build_base_ns(
    args: argparse.Namespace,
    module_names: list[str],
) -> argparse.Namespace:
    """Constroi namespace base com defaults dos modulos selecionados."""
    all_defaults = dict(_get_parser_defaults(module_names))

    all_defaults.update(
        {
            # Output
            "output": None,
            "output_dir": getattr(args, "output_dir", None),
            # Logging
            "quiet": True,
            "verbose": getattr(args, "verbose", False),
            "log_file": None,
            "color": None,
            # Rede
            "timeout": getattr(args, "timeout", 5.0),
            "user_agent": f"MyTools/{__version__}",
            "verify": False,
            "proxy": None,
            "threads": None,
            # Auth
            "auth": getattr(args, "auth", None),
            "bearer_token": getattr(args, "bearer_token", None),
            "cookie": getattr(args, "cookie", None),
            "header": getattr(args, "header", None),
            # Batch
            "dry_run": getattr(args, "dry_run", False),
        }
    )

    return argparse.Namespace(**all_defaults)


# ---------------------------------------------------------------------------
# Supressao de stdout
# ---------------------------------------------------------------------------


@contextlib.contextmanager
def _suppress_stdout() -> Iterator[None]:
    """Suprime stdout durante execucao paralela."""
    old = sys.stdout
    sys.stdout = io.StringIO()  # type: ignore[assignment]
    try:
        yield
    finally:
        sys.stdout = old  # type: ignore[assignment]


# ---------------------------------------------------------------------------
# process_target
# ---------------------------------------------------------------------------


def process_target(
    target: str,
    module_list: list[tuple[str, Callable[[argparse.Namespace], int], Callable[[], argparse.ArgumentParser]]],
    base_ns: argparse.Namespace,
    output_dir: str | None,
    timeout: float,
) -> TargetResult:
    """Executa todos os modulos contra um target."""
    sanitized = _sanitize_target(target)
    result = TargetResult(target=target, sanitized=sanitized)
    start = time.monotonic()

    target_dir = None
    if output_dir:
        target_dir = Path(output_dir) / sanitized
        target_dir.mkdir(parents=True, exist_ok=True)

    for mod_name, run_fn, build_parser_fn in module_list:
        parser = build_parser_fn()
        if not _is_compatible(target, parser):
            logger.info("  %s: incompatible with %s, skipping", mod_name, target)
            continue

        extra: dict[str, object] = {"timeout": timeout}
        extra["url"] = target
        extra["domain"] = target
        extra["target"] = target
        extra["targets"] = [target]
        extra["ips"] = [target]
        if target_dir:
            extra["output"] = str(target_dir / f"{mod_name}.json")

        args = _make_args(extra, base_ns)

        logger.info("  %s: running...", mod_name)
        try:
            code = run_fn(args)
            result.details[mod_name] = code
            if code == 0:
                result.success += 1
            else:
                result.vulns += 1
        except Exception as exc:
            logger.error("  %s: exception: %s", mod_name, exc)
            result.details[mod_name] = -1
            result.errors += 1

    result.duration = time.monotonic() - start
    return result


# ---------------------------------------------------------------------------
# run_batch
# ---------------------------------------------------------------------------


def run_batch(args: argparse.Namespace) -> int:
    """Executa batch: resolve modulos, carrega targets, processa."""
    targets = read_targets(args.targets)

    # Detectar all + outros args
    if "all" in args.modules and len(args.modules) > 1:
        logger.error("'all' nao pode ser combinado com outros modulos")
        return 1

    mod_names = (
        [n for n in _get_all_module_names() if n not in args.skip]
        if args.modules == ["all"]
        else [n for n in args.modules if n not in args.skip]
    )

    module_list: list[tuple[str, Callable[[argparse.Namespace], int], Callable[[], argparse.ArgumentParser]]] = []
    for name in mod_names:
        mod = _resolve_module(name)
        module_list.append((name, mod.run_once, mod.build_parser))

    base_ns = _build_base_ns(args, mod_names)
    parallel = getattr(args, "parallel", 1)

    ctx = _suppress_stdout() if parallel > 1 else contextlib.nullcontext()
    results: list[TargetResult] = []

    with ctx:
        if parallel <= 1:
            for target in targets:
                if args.fail_fast and results and any(r.errors > 0 for r in results):
                    break
                results.append(
                    process_target(
                        target, module_list, base_ns,
                        args.output_dir, args.timeout,
                    ),
                )
        else:
            with ThreadPoolExecutor(max_workers=parallel) as pool:
                futures = {
                    pool.submit(
                        process_target,
                        t,
                        module_list,
                        base_ns,
                        args.output_dir,
                        args.timeout,
                    ): t
                    for t in targets
                }
                for future in as_completed(futures):
                    target = futures[future]
                    try:
                        results.append(future.result())
                    except Exception as exc:
                        logger.error("Target %s failed: %s", target, exc)
                        results.append(
                            TargetResult(
                                target=target,
                                sanitized=_sanitize_target(target),
                                errors=1,
                                details={"__init__": -1},
                            ),
                        )

    return _print_report(
        results,
        strict=args.strict,
        fmt=getattr(args, "format", "text"),
    )


# ---------------------------------------------------------------------------
# _print_report
# ---------------------------------------------------------------------------


def _print_report(
    results: list[TargetResult],
    strict: bool,
    fmt: str = "text",
) -> int:
    """Imprime relatorio final e retorna exit code."""
    total_targets = len(results)
    total_success = sum(r.success for r in results)
    total_vulns = sum(r.vulns for r in results)
    total_errors = sum(r.errors for r in results)
    total_duration = sum(r.duration for r in results)

    if fmt == "json":
        report = {
            "summary": {
                "targets": total_targets,
                "success": total_success,
                "vulnerabilities": total_vulns,
                "errors": total_errors,
                "total_duration_s": round(total_duration, 1),
            },
            "results": [
                {
                    "target": r.target,
                    "sanitized": r.sanitized,
                    "success": r.success,
                    "vulns": r.vulns,
                    "errors": r.errors,
                    "duration_s": round(r.duration, 1),
                    "modules": {
                        mod: {
                            "exit_code": code,
                            "status": (
                                "ok"
                                if code == 0
                                else "vuln"
                                if code > 0
                                else "error"
                            ),
                        }
                        for mod, code in r.details.items()
                    },
                }
                for r in results
            ],
        }
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print()
        print("=" * 70)
        print("  BATCH RESULTS")
        print("=" * 70)
        for r in results:
            status = "OK" if r.errors == 0 else "ERROR"
            vuln_str = f" ({r.vulns} vulns)" if r.vulns else ""
            print(f"  [{status}] {r.target}{vuln_str} ({r.duration:.1f}s)")
            for mod, code in r.details.items():
                icon = "ok" if code == 0 else "!!" if code > 0 else "ERR"
                print(f"    {icon} {mod}")
        print("-" * 70)
        print(
            f"  Targets: {total_targets} | OK: {total_success} "
            f"| Vulns: {total_vulns} | Errors: {total_errors}",
        )
        print(f"  Tempo total: {total_duration:.1f}s")
        print("=" * 70)

    if total_errors > 0:
        return 1
    if strict and total_vulns > 0:
        return 2
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Monta parser CLI para mytools-batch."""
    parser = argparse.ArgumentParser(
        prog="mytools-batch",
        description="Executa modulos MyTools contra multiplos alvos.",
    )
    parser.add_argument("targets", help="Arquivo com alvos (1 por linha)")
    parser.add_argument("modules", nargs="+", help="Modulos (ou 'all')")
    parser.add_argument(
        "-p", "--parallel", type=int, default=1,
        help="Targets simultaneos",
    )
    parser.add_argument("-o", "--output-dir", help="Dir para JSONs")
    parser.add_argument(
        "--skip", action="append", default=[],
        help="Modulo para pular",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=5.0,
        help="Timeout (default: 5s)",
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Exit 2 se vulns",
    )
    parser.add_argument(
        "--fail-fast", action="store_true",
        help="Para no 1o erro (apenas --parallel 1)",
    )
    parser.add_argument(
        "--format", choices=["text", "json"], default="text",
        help="Formato do relatorio",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Mostra plano sem executar",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-q", "--quiet", action="store_true")
    parser.add_argument("--auth", help="Basic auth (user:pass)")
    parser.add_argument("--bearer-token", help="Bearer token")
    parser.add_argument("--cookie", help="Cookie header")
    parser.add_argument(
        "--header", action="append", default=[],
        help="Header customizado",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser


def main() -> int:
    """Entry point para mytools-batch."""
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(verbose=args.verbose)

    if args.dry_run:
        targets = read_targets(args.targets)
        mod_names = (
            _get_all_module_names()
            if args.modules == ["all"]
            else args.modules
        )
        mod_names = [n for n in mod_names if n not in args.skip]
        logger.info(
            "Dry-run: %d targets x %d modulos = %d execucoes",
            len(targets),
            len(mod_names),
            len(targets) * len(mod_names),
        )
        logger.info("Targets: %s", targets)
        logger.info("Modulos: %s", mod_names)
        if args.parallel > 1:
            logger.info("Paralelismo: %d", args.parallel)
        return 0

    return run_batch(args)
