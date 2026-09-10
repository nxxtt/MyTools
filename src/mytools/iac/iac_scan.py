"""IaC Static Scan — analise estatica de Terraform, Kubernetes, Dockerfile e CloudFormation."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any

from anyio import Path as AsyncPath

from mytools.core.base import BaseScanner, ScanGroup
from mytools.core.utils import Cyber, color, create_banner
from mytools.iac._common import IacAttempt, IacResult

logger = logging.getLogger(__name__)

_BANNER_TEXT = (
    "  _____ ___     _______         __\n"
    " |_   _/ _ \\   / ____(_)___  __/ /__\n"
    "   | || | | | / /   / / __ \\/ / / _ \\\n"
    "   | || |_| |/ /___/ / / / / / /  __/\n"
    "   |_| \\___/ \\____/_/_/ /_/_/\\__/\\___/\n"
)

_IAC_EXTENSIONS = {".tf", ".hcl", ".yaml", ".yml", ".json", ".dockerfile"}
_IAC_FILENAMES = {
    "Dockerfile",
    "docker-compose.yml",
    "docker-compose.yaml",
    "helmfile.yaml",
    "Chart.yaml",
    "values.yaml",
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _classify_file(path: Path) -> str | None:
    name = path.name.lower()
    if name.endswith(".tf") or name.endswith(".hcl"):
        return "terraform"
    if name == "dockerfile" or name.endswith(".dockerfile"):
        return "dockerfile"
    if name.endswith((".yaml", ".yml", ".json")):
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError, PermissionError:
            return None
        if "AWSTemplateFormatVersion" in text or "AWS::CloudFormation" in text:
            return "cloudformation"
        if any(
            kw in text
            for kw in (
                "apiVersion:",
                "kind:",
                "metadata:",
                "spec:",
                "containers:",
                '"apiVersion"',
                '"kind"',
                '"metadata"',
            )
        ):
            return "kubernetes"
        return None
    return None


async def run_iac_scan(
    target: str = ".",
    categories: list[str] | None = None,
    min_severity: str = "low",
    exclude_dirs: list[str] | None = None,
) -> IacResult:
    base_dir = await AsyncPath(target).resolve()
    if not await base_dir.exists():
        return IacResult(
            target=target,
            total_files=0,
            scanned_files=0,
            skipped_files=0,
            issues=[f"Target not found: {target}"],
            overall_status="error",
        )

    exclude_set = set(exclude_dirs) if exclude_dirs else set()
    min_sev = _SEVERITY_ORDER.get(min_severity, 3)

    all_attempts: list[IacAttempt] = []
    total_files = 0
    scanned_files = 0
    skipped_files = 0

    from mytools.iac.cloudformation_scan import scan_cloudformation_file
    from mytools.iac.dockerfile_scan import scan_dockerfile
    from mytools.iac.kubernetes_scan import scan_kubernetes_file
    from mytools.iac.terraform_scan import scan_terraform_file

    scanners = {
        "terraform": scan_terraform_file,
        "kubernetes": scan_kubernetes_file,
        "dockerfile": scan_dockerfile,
        "cloudformation": scan_cloudformation_file,
    }

    allowed_types: set[str] | None = None
    if categories:
        allowed_types = set()
        cat_map = {
            "terraform": "terraform",
            "tf": "terraform",
            "kubernetes": "kubernetes",
            "k8s": "kubernetes",
            "dockerfile": "dockerfile",
            "docker": "dockerfile",
            "cloudformation": "cloudformation",
            "cfn": "cloudformation",
        }
        for cat in categories:
            resolved = cat_map.get(cat.lower(), cat.lower())
            allowed_types.add(resolved)

    async for f in base_dir.rglob("*"):
        if not await f.is_file():
            continue
        total_files += 1

        rel = str(f.relative_to(base_dir))
        skip_dir = False
        for ex in exclude_set:
            if rel.startswith(ex):
                skip_dir = True
                break
        if skip_dir:
            skipped_files += 1
            continue

        pathlib_f = Path(str(f))
        file_type = _classify_file(pathlib_f)
        if file_type is None:
            skipped_files += 1
            continue

        if allowed_types and file_type not in allowed_types:
            skipped_files += 1
            continue

        scanner_fn = scanners.get(file_type)
        if scanner_fn is None:
            skipped_files += 1
            continue

        pathlib_base = Path(str(base_dir))
        attempts = scanner_fn(pathlib_f, pathlib_base)
        all_attempts.extend(
            att for att in attempts if _SEVERITY_ORDER.get(att.severity, 3) <= min_sev
        )

        if attempts:
            scanned_files += 1

    issues: list[str] = []
    overall = "clean"
    if all_attempts:
        overall = "found"
        sev_counts: dict[str, int] = {}
        type_counts: dict[str, int] = {}
        for a in all_attempts:
            sev_counts[a.severity] = sev_counts.get(a.severity, 0) + 1
            type_counts[a.file_type] = type_counts.get(a.file_type, 0) + 1
        issues.extend(
            f"{sev_counts[sev]} {sev} issue(s)"
            for sev in ("critical", "high", "medium", "low")
            if sev in sev_counts
        )
        issues.extend(
            f"{count} issue(s) in {ftype}"
            for ftype, count in sorted(type_counts.items())
        )

    return IacResult(
        target=target,
        total_files=total_files,
        scanned_files=scanned_files,
        skipped_files=skipped_files,
        attempts=all_attempts,
        issues=issues,
        overall_status=overall,
    )


class IacScanScanner(BaseScanner):
    prog = "mytools-iac"
    description = "IaC Static Scan — Terraform, Kubernetes, Dockerfile, CloudFormation"
    prompt = "iac> "
    module_name = "mytools.iac"
    banner_text = _BANNER_TEXT
    group = ScanGroup.B

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "target",
            nargs="?",
            help="Diretorio para escanear (default: diretorio atual)",
        )
        parser.add_argument(
            "-c",
            "--categories",
            nargs="+",
            choices=[
                "terraform",
                "tf",
                "kubernetes",
                "k8s",
                "dockerfile",
                "docker",
                "cloudformation",
                "cfn",
            ],
            help="Tipos de IaC para escanear",
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

    @staticmethod
    def _get_target(args: argparse.Namespace) -> str | None:
        return getattr(args, "target", None)

    def _build_run_once_kwargs(self, args: argparse.Namespace) -> dict[str, Any]:
        return {
            "target": self._get_target(args) or ".",
            "categories": getattr(args, "categories", None),
            "min_severity": getattr(args, "min_severity", "low"),
            "exclude_dirs": getattr(args, "exclude_dirs", None),
        }

    async def run_scan(
        self,
        target: str = ".",
        categories: list[str] | None = None,
        min_severity: str = "low",
        exclude_dirs: list[str] | None = None,
        **_kwargs: Any,
    ) -> IacResult:
        return await run_iac_scan(
            target=target,
            categories=categories,
            min_severity=min_severity,
            exclude_dirs=exclude_dirs,
        )

    def print_results(self, result: object) -> None:
        assert isinstance(result, IacResult)

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
                    f" [{att.file_type}] {att.file_path}:{att.line_number} "
                    f"({att.check_name})"
                )
                print(f"             {color(Cyber.GRAY, att.description)}")
                if att.details:
                    print(f"             {color(Cyber.GRAY, att.details)}")

    def _example(self) -> str:
        return "scan ./infra"

    def _help(self) -> str:
        return (
            "IaC Static Scan — analise estatica de infraestrutura\n\n"
            "Escaneia arquivos Terraform, Kubernetes, Dockerfile e\n"
            "CloudFormation em busca de configuracoes inseguras.\n\n"
            "Tipos suportados:\n"
            "  terraform: .tf/.hcl (regex-based)\n"
            "  kubernetes: manifests YAML (.yaml/.yml)\n"
            "  dockerfile: Dockerfile best practices\n"
            "  cloudformation: templates AWS CFN\n\n"
            "Severidade:\n"
            "  critical: expoe dados/infraestrutura publicamente\n"
            "  high: configuracao com risco significativo\n"
            "  medium: best practice nao seguida\n"
            "  low: melhoria sugerida\n"
        )


_scanner = IacScanScanner()
main = _scanner.main
run_once = _scanner.run_once
banner_art = create_banner(_BANNER_TEXT, _scanner.description)
build_parser = _scanner.build_parser
