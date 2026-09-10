"""Binary Analysis — analise estatica de ELF, PE e Mach-O via lief."""

from __future__ import annotations

import argparse
import logging
import re
from pathlib import Path
from typing import Any

from anyio import Path as AsyncPath

from mytools.binary._common import (
    BINARY_SECRET_PATTERNS,
    BinaryAttempt,
    BinaryResult,
)
from mytools.core.base import BaseScanner, ScanGroup
from mytools.core.utils import Cyber, color, create_banner

logger = logging.getLogger(__name__)

_BANNER_TEXT = (
    "  ____                           _               \n"
    " | __ )  _ __ _____  ___   _ ___| |__   ___ _ __ \n"
    " |  _ \\ | '__/ _ \\ \\/ / | | / __| '_ \\ / _ \\ '__|\n"
    " | |_) || | | (_) >  <| |_| \\__ \\ | | |  __/ |   \n"
    " |____/ |_|  \\___/_/\\_\\\\__,_|___/_| |_|\\___|_|   \n"
)


def _detect_binary_type(file_path: Path) -> str:
    try:
        data = file_path.read_bytes()[:16]
    except OSError, PermissionError:
        return "unknown"
    if data[:4] == b"\x7fELF":
        return "elf"
    if data[:2] == b"MZ" or data[:4] == b"PE\x00\x00":
        return "pe"
    if data[:4] in (
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
    ):
        return "macho"
    if data[:4] in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        return "macho_fat"
    return "unknown"


def _check_lief_security(binary: Any, file_path: Path) -> list[BinaryAttempt]:
    attempts: list[BinaryAttempt] = []
    rel = str(file_path)

    binary_type = type(binary).__name__

    if hasattr(binary, "has_section"):
        if not binary.has_section(".note.GNU-stack") and not binary.has_section(
            ".note.gnu.property"
        ):
            has_nx = False
            if hasattr(binary, "segments"):
                for seg in binary.segments:
                    if hasattr(seg, "flags") and seg.flags & 1:  # PF_X
                        has_nx = True
            if not has_nx:
                attempts.append(
                    BinaryAttempt(
                        file_path=rel,
                        check_name="no_nx",
                        binary_type=binary_type,
                        vulnerable=True,
                        severity="high",
                        description="Binario sem NX (non-executable stack)",
                    )
                )

        if hasattr(binary, "segments"):
            has_pie = False
            for seg in binary.segments:
                if hasattr(seg, "type") and seg.type == 3:  # PT_DYNAMIC
                    has_pie = True
            if not has_pie and not getattr(binary, "has_nx", False):
                pass

    if hasattr(binary, "exported_functions"):
        suspicious = []
        for func in binary.exported_functions:
            name = str(func.name) if hasattr(func, "name") else str(func)
            suspicious_names = {
                "system",
                "popen",
                "exec",
                "execve",
                "execl",
                "strcpy",
                "strcat",
                "sprintf",
                "gets",
            }
            base = name.split("@")[0].split("$")[0].lstrip("_")
            if base.lower() in suspicious_names:
                suspicious.append(name)
        if suspicious:
            attempts.append(
                BinaryAttempt(
                    file_path=rel,
                    check_name="suspicious_exports",
                    binary_type=binary_type,
                    vulnerable=True,
                    severity="medium",
                    description=f"Exports suspeitas: {', '.join(suspicious[:5])}",
                    details=f"Total: {len(suspicious)}",
                )
            )

    if hasattr(binary, "imports"):
        dangerous_imports = []
        for imp in binary.imports:
            name = imp.name if hasattr(imp, "name") else str(imp)
            dangerous_names = {
                "system",
                "popen",
                "exec",
                "execve",
                "execl",
                "strcpy",
                "strcat",
                "sprintf",
                "gets",
                "LoadLibrary",
                "GetProcAddress",
            }
            if name in dangerous_names:
                dangerous_imports.append(name)
        if dangerous_imports:
            attempts.append(
                BinaryAttempt(
                    file_path=rel,
                    check_name="dangerous_imports",
                    binary_type=binary_type,
                    vulnerable=True,
                    severity="medium",
                    description=f"Imports perigosos: {', '.join(dangerous_imports[:5])}",
                    details=f"Total: {len(dangerous_imports)}",
                )
            )

    if hasattr(binary, "sections"):
        large_sections = []
        for sec in binary.sections:
            if hasattr(sec, "size") and sec.size > 10_000_000:
                name = sec.name if hasattr(sec, "name") else "unknown"
                large_sections.append(f"{name}({sec.size // 1_000_000}MB)")
        if large_sections:
            attempts.append(
                BinaryAttempt(
                    file_path=rel,
                    check_name="large_sections",
                    binary_type=binary_type,
                    vulnerable=False,
                    severity="low",
                    description=f"Secoes grandes: {', '.join(large_sections)}",
                )
            )

    return attempts


def _check_secrets(
    file_path: Path,
    patterns: dict[str, re.Pattern[bytes]] | None = None,
) -> list[BinaryAttempt]:
    attempts: list[BinaryAttempt] = []
    effective = patterns or BINARY_SECRET_PATTERNS

    try:
        raw = file_path.read_bytes()
        data = raw.replace(b"\x00", b" ")
    except OSError, PermissionError:
        return attempts

    for pat_name, pattern in effective.items():
        match = pattern.search(data)
        if match:
            preview = match.group(0)[:60] if match.group(0) else ""
            sev = "high"
            if "private_key" in pat_name or "aws_" in pat_name:
                sev = "critical"
            attempts.append(
                BinaryAttempt(
                    file_path=str(file_path),
                    check_name=f"secret_{pat_name}",
                    binary_type="binary",
                    vulnerable=True,
                    severity=sev,
                    description=f"Segredo detectado: {pat_name}",
                    details=preview.decode("utf-8", errors="replace")
                    if isinstance(preview, bytes)
                    else preview,
                )
            )
    return attempts


async def run_binary_scan(
    target: str,
    checks: list[str] | None = None,
) -> BinaryResult:
    file_path = await AsyncPath(target).resolve()
    if not await file_path.exists():
        return BinaryResult(
            target=target,
            file_size=0,
            binary_type="unknown",
            issues=[f"Target not found: {target}"],
            overall_status="error",
        )

    if not await file_path.is_file():
        return BinaryResult(
            target=target,
            file_size=0,
            binary_type="unknown",
            issues=["Target is not a file"],
            overall_status="error",
        )

    stat_info = await file_path.stat()
    file_size = stat_info.st_size
    pathlib_file = Path(str(file_path))
    binary_type = _detect_binary_type(pathlib_file)

    effective_checks = set(checks) if checks is not None else {"security", "secrets"}

    all_attempts: list[BinaryAttempt] = []

    if binary_type != "unknown" and "security" in effective_checks:
        try:
            import lief

            binary = lief.parse(str(file_path))
            if binary is not None:
                all_attempts.extend(_check_lief_security(binary, pathlib_file))
        except Exception as exc:
            logger.debug("lief parse failed for %s: %s", file_path, exc)

    if "secrets" in effective_checks:
        all_attempts.extend(_check_secrets(pathlib_file))

    issues: list[str] = []
    overall = "clean"
    if all_attempts:
        overall = "found"
        sev_counts: dict[str, int] = {}
        for a in all_attempts:
            sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
        issues.extend(
            f"{sev_counts[s]} {s} issue(s)"
            for s in ("critical", "high", "medium", "low")
            if s in sev_counts
        )

    return BinaryResult(
        target=target,
        file_size=file_size,
        binary_type=binary_type,
        attempts=all_attempts,
        issues=issues,
        overall_status=overall,
    )


class BinaryScanScanner(BaseScanner):
    prog = "mytools-binary"
    description = "Binary Analysis — analise estatica de ELF, PE e Mach-O"
    prompt = "binary> "
    module_name = "mytools.binary"
    banner_text = _BANNER_TEXT
    group = ScanGroup.B

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "target",
            nargs="?",
            help="Arquivo binario para analisar",
        )
        parser.add_argument(
            "-c",
            "--checks",
            nargs="+",
            choices=["security", "secrets", "all"],
            default=["security", "secrets"],
            help="Tipos de check para executar",
        )

    @staticmethod
    def _get_target(args: argparse.Namespace) -> str | None:
        return getattr(args, "target", None)

    def _build_run_once_kwargs(self, args: argparse.Namespace) -> dict[str, Any]:
        checks = getattr(args, "checks", ["security", "secrets"])
        if checks and "all" in checks:
            checks = ["security", "secrets"]
        return {
            "target": self._get_target(args) or ".",
            "checks": checks,
        }

    async def run_scan(
        self,
        target: str = ".",
        checks: list[str] | None = None,
        **_kwargs: Any,
    ) -> BinaryResult:
        return await run_binary_scan(target=target, checks=checks)

    def print_results(self, result: object) -> None:
        assert isinstance(result, BinaryResult)

        status_color = Cyber.RED if result.overall_status == "found" else Cyber.GREEN
        status_text = "VULNERAVEL" if result.overall_status == "found" else "LIMPO"
        print(f"\n{color(status_color, status_text)}")
        print(
            f"  Tipo: {result.binary_type.upper()} | "
            f"Tamanho: {result.file_size:,} bytes"
        )

        if result.issues:
            print(f"\n  {color(Cyber.YELLOW, 'Resumo:')}")
            for issue in result.issues:
                print(f"    - {issue}")

        if result.attempts:
            print(f"\n  {color(Cyber.RED, 'Problemas encontrados:')}")
            for att in result.attempts:
                sev_color = {
                    "critical": Cyber.RED,
                    "high": Cyber.RED,
                    "medium": Cyber.YELLOW,
                    "low": Cyber.CYAN,
                }.get(att.severity, Cyber.WHITE)
                print(
                    f"    {color(sev_color, att.severity.upper()):>10} "
                    f" [{att.check_name}] {att.description}"
                )
                if att.details:
                    print(f"             {color(Cyber.GRAY, att.details)}")

    def _example(self) -> str:
        return "scan /usr/bin/ls"

    def _help(self) -> str:
        return (
            "Binary Analysis — analise estatica de binarios\n\n"
            "Analisa arquivos ELF, PE e Mach-O em busca de:\n"
            "  security: protecoes (NX, PIE), imports/exports perigosos\n"
            "  secrets: chaves, senhas e credenciais hardcoded\n\n"
            "Formatos suportados:\n"
            "  ELF: executaveis Linux/BSD\n"
            "  PE: executaveis Windows (.exe, .dll)\n"
            "  Mach-O: executaveis macOS\n"
        )


_scanner = BinaryScanScanner()
main = _scanner.main
run_once = _scanner.run_once
banner_art = create_banner(_BANNER_TEXT, _scanner.description)
build_parser = _scanner.build_parser
