"""Scanner para arquivos Terraform (.tf, .hcl) via regex."""

from __future__ import annotations

import re
from pathlib import Path

from mytools.iac._common import TERRAFORM_RULES, IacAttempt

__all__ = ["scan_terraform_file"]


def scan_terraform_file(
    file_path: Path,
    base_dir: Path,
    rules: dict[str, dict[str, object]] | None = None,
) -> list[IacAttempt]:
    effective_rules = rules or TERRAFORM_RULES
    attempts: list[IacAttempt] = []

    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError, PermissionError:
        return attempts

    for rule_name, rule_def in effective_rules.items():
        pat = rule_def["pattern"]
        assert isinstance(pat, re.Pattern)
        for line_num, line in enumerate(text.splitlines(), start=1):
            if pat.search(line):
                attempts.append(
                    IacAttempt(
                        file_path=str(file_path.relative_to(base_dir)),
                        line_number=line_num,
                        check_name=rule_name,
                        file_type="terraform",
                        vulnerable=True,
                        severity=str(rule_def.get("severity", "medium")),
                        description=str(rule_def.get("description", "")),
                        details=line.strip()[:120],
                    )
                )
    return attempts
