"""Secret Scanning — deteccao de credenciais e chaves hardcoded em arquivos."""

from __future__ import annotations

import argparse
import fnmatch
import logging
import re
from pathlib import Path
from typing import Any

from anyio import Path as AsyncPath

from mytools.core.base import BaseScanner, ScanGroup
from mytools.core.utils import (
    Cyber,
    color,
    create_banner,
)
from mytools.secret._common import (
    PATTERN_CATEGORIES,
    SECRET_PATTERNS,
    SecretAttempt,
    SecretResult,
)

logger = logging.getLogger(__name__)

_BANNER_TEXT = (
    "  ____                          _                \n"
    " / ___|  __ _ _ __ ___   ___  __| | ___ _ __     \n"
    " \\___ \\ / _` | '_ ` _ \\ / _ \\/ _` |/ _ \\ '__|   \n"
    "  ___) | (_| | | | | | |  __/ (_| |  __/ |      \n"
    " |____/ \\__,_|_| |_| |_|\\___|\\__,_|\\___|_|      \n"
)

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _load_ignore_patterns() -> list[str]:
    return [
        "*.min.js",
        "*.min.css",
        "node_modules/**",
        ".git/**",
        "__pycache__/**",
        "*.pyc",
        "*.pyo",
        ".venv/**",
        "venv/**",
        "env/**",
        "*.lock",
        "package-lock.json",
        "yarn.lock",
        "*.svg",
        "*.png",
        "*.jpg",
        "*.jpeg",
        "*.gif",
        "*.ico",
        "*.woff",
        "*.woff2",
        "*.ttf",
        "*.eot",
    ]


def _load_scan_extensions() -> set[str]:
    return {
        ".py",
        ".js",
        ".ts",
        ".jsx",
        ".tsx",
        ".java",
        ".go",
        ".rb",
        ".php",
        ".rs",
        ".cs",
        ".c",
        ".cpp",
        ".h",
        ".yml",
        ".yaml",
        ".toml",
        ".ini",
        ".cfg",
        ".conf",
        ".env",
        ".properties",
        ".xml",
        ".json",
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".bat",
        ".cmd",
        ".sql",
        ".md",
        ".txt",
        ".tf",
        ".hcl",
        ".dockerfile",
    }


_IGNORE_PATTERNS = _load_ignore_patterns()
_SCAN_EXTENSIONS = _load_scan_extensions()

_ALWAYS_SCAN = {
    "Dockerfile",
    "docker-compose.yml",
    "Makefile",
    "Vagrantfile",
    ".env",
    ".env.local",
    ".env.production",
}


def _should_skip(path: Path, base_dir: Path) -> bool:
    try:
        rel = path.relative_to(base_dir)
    except ValueError:
        rel = path
    parts = rel.parts
    for part in parts:
        if any(fnmatch.fnmatch(part, pat.split("/")[0]) for pat in _IGNORE_PATTERNS):
            return True
    return any(fnmatch.fnmatch(str(rel), pat) for pat in _IGNORE_PATTERNS)


def _should_scan(path: Path) -> bool:
    if path.name in _ALWAYS_SCAN:
        return True
    return path.suffix.lower() in _SCAN_EXTENSIONS


def _preview_match(line: str, start: int, end: int, max_len: int = 60) -> str:
    excerpt = line[max(0, start - 10) : end + 10].strip()
    if len(excerpt) > max_len:
        excerpt = excerpt[:max_len] + "..."
    return excerpt


async def scan_file(
    file_path: Path,
    patterns: dict[str, re.Pattern[str]],
    base_dir: Path,
    min_severity: str = "low",
) -> list[SecretAttempt]:
    attempts: list[SecretAttempt] = []
    severity_order = _SEVERITY_ORDER

    try:
        text = await AsyncPath(file_path).read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError) as exc:
        logger.debug("Cannot read %s: %s", file_path, exc)
        return attempts

    min_sev = severity_order.get(min_severity, 3)

    for line_num, line in enumerate(text.splitlines(), start=1):
        for pat_name, pattern in patterns.items():
            m = pattern.search(line)
            if not m:
                continue
            sev = "medium"
            if "key" in pat_name or "token" in pat_name or "secret" in pat_name:
                sev = "high"
            if "private_key" in pat_name or "aws_" in pat_name:
                sev = "critical"
            if severity_order.get(sev, 3) > min_sev:
                continue
            preview = _preview_match(line, m.start(), m.end())
            attempts.append(
                SecretAttempt(
                    file_path=str(file_path.relative_to(base_dir)),
                    line_number=line_num,
                    pattern_name=pat_name,
                    secret_type=pat_name,
                    match_preview=preview,
                    severity=sev,
                )
            )
    return attempts


async def run_secret_scan(
    target: str,
    patterns: dict[str, re.Pattern[str]] | None = None,
    categories: list[str] | None = None,
    exclude_dirs: list[str] | None = None,
    min_severity: str = "low",
    max_file_size: int = 1_048_576,
) -> SecretResult:
    base_dir = await AsyncPath(target).resolve()
    if not await base_dir.exists():
        return SecretResult(
            target=target,
            total_files=0,
            scanned_files=0,
            skipped_files=0,
            issues=[f"Target not found: {target}"],
            overall_status="error",
        )

    effective_patterns = patterns or SECRET_PATTERNS
    if categories:
        allowed: set[str] = set()
        for cat in categories:
            allowed.update(PATTERN_CATEGORIES.get(cat, []))
        if allowed:
            effective_patterns = {
                k: v for k, v in effective_patterns.items() if k in allowed
            }

    all_attempts: list[SecretAttempt] = []
    total_files = 0
    scanned_files = 0
    skipped_files = 0
    exclude_set = set(exclude_dirs) if exclude_dirs else set()

    async for f in base_dir.rglob("*"):
        if not await f.is_file():
            continue
        total_files += 1
        pathlib_f = Path(str(f))
        rel = str(f.relative_to(base_dir))
        if _should_skip(pathlib_f, Path(str(base_dir))):
            skipped_files += 1
            continue
        skip_dir = False
        for ex in exclude_set:
            if rel.startswith(ex):
                skip_dir = True
                break
        if skip_dir:
            skipped_files += 1
            continue
        if not _should_scan(pathlib_f):
            skipped_files += 1
            continue
        try:
            stat_info = await f.stat()
            if stat_info.st_size > max_file_size:
                skipped_files += 1
                continue
        except OSError:
            skipped_files += 1
            continue
        pathlib_base = Path(str(base_dir))
        attempts = await scan_file(
            pathlib_f, effective_patterns, pathlib_base, min_severity
        )
        if attempts:
            scanned_files += 1
            all_attempts.extend(attempts)

    issues = []
    overall = "clean"
    if all_attempts:
        overall = "found"
        sev_counts: dict[str, int] = {}
        for a in all_attempts:
            sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
        issues.extend(
            f"{sev_counts[sev]} {sev} secret(s)"
            for sev in ("critical", "high", "medium", "low")
            if sev in sev_counts
        )

    return SecretResult(
        target=target,
        total_files=total_files,
        scanned_files=scanned_files,
        skipped_files=skipped_files,
        attempts=all_attempts,
        issues=issues,
        overall_status=overall,
    )


class SecretScanScanner(BaseScanner):
    prog = "mytools-secret"
    description = "Secret Scanning — deteccao de credenciais hardcoded em arquivos"
    prompt = "secret> "
    module_name = "mytools.secret"
    banner_text = _BANNER_TEXT
    group = ScanGroup.B

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "target",
            nargs="?",
            help="Diretorio ou arquivo para escanear",
        )
        parser.add_argument(
            "-c",
            "--categories",
            nargs="+",
            choices=["cloud", "saas", "generic", "crypto"],
            help="Categorias de padroes para escanear",
        )
        parser.add_argument(
            "--min-severity",
            choices=["critical", "high", "medium", "low"],
            default="low",
            help="Severidade minima para reportar",
        )
        parser.add_argument(
            "--exclude-dirs",
            nargs="*",
            default=[],
            help="Diretorios para excluir",
        )
        parser.add_argument(
            "--max-file-size",
            type=int,
            default=1_048_576,
            help="Tamanho maximo de arquivo em bytes (default: 1MB)",
        )

    @staticmethod
    def _get_target(args: argparse.Namespace) -> str | None:
        return getattr(args, "target", None)

    def _build_run_once_kwargs(self, args: argparse.Namespace) -> dict[str, Any]:
        return {
            "target": self._get_target(args) or ".",
            "categories": getattr(args, "categories", None),
            "exclude_dirs": getattr(args, "exclude_dirs", None),
            "min_severity": getattr(args, "min_severity", "low"),
            "max_file_size": getattr(args, "max_file_size", 1_048_576),
        }

    async def run_scan(
        self,
        target: str = ".",
        categories: list[str] | None = None,
        exclude_dirs: list[str] | None = None,
        min_severity: str = "low",
        max_file_size: int = 1_048_576,
        **_kwargs: Any,
    ) -> SecretResult:
        return await run_secret_scan(
            target=target,
            categories=categories,
            exclude_dirs=exclude_dirs,
            min_severity=min_severity,
            max_file_size=max_file_size,
        )

    def print_results(self, result: object) -> None:
        assert isinstance(result, SecretResult)

        status_color = Cyber.RED if result.overall_status == "found" else Cyber.GREEN
        status_text = "VULNERAVEL" if result.overall_status == "found" else "LIMPO"
        print(f"\n{color(status_color, status_text)}")
        print(
            f"  Arquivos: {result.scanned_files} escaneados, "
            f"{result.skipped_files} ignorados de {result.total_files} total"
        )

        if result.issues:
            print(f"\n  {color(Cyber.YELLOW, 'Resumo:')}")
            for issue in result.issues:
                print(f"    - {issue}")

        if result.attempts:
            print(f"\n  {color(Cyber.RED, 'Segredos encontrados:')}")
            for att in result.attempts:
                sev_color = {
                    "critical": Cyber.RED,
                    "high": Cyber.RED,
                    "medium": Cyber.YELLOW,
                    "low": Cyber.CYAN,
                }.get(att.severity, Cyber.WHITE)
                print(
                    f"    {color(sev_color, att.severity.upper()):>10} "
                    f" {att.file_path}:{att.line_number} "
                    f"[{att.pattern_name}]"
                )
                print(f"             {color(Cyber.GRAY, att.match_preview)}")

    def _example(self) -> str:
        return "scan ./src"

    def _help(self) -> str:
        return (
            "Secret Scanning — deteccao de credenciais hardcoded\n\n"
            "Escaneia arquivos de codigo-fonte em busca de chaves, tokens,\n"
            "senhas e outros segredos hardcodados.\n\n"
            "Padroes suportados:\n"
            "  cloud: AWS, GCP, Azure keys\n"
            "  saas: GitHub, Slack, Stripe, SendGrid tokens\n"
            "  generic: passwords, API keys, connection strings\n"
            "  crypto: private keys, JWT, bearer tokens\n"
        )


_scanner = SecretScanScanner()
main = _scanner.main
run_once = _scanner.run_once
banner_art = create_banner(_BANNER_TEXT, _scanner.description)
build_parser = _scanner.build_parser
