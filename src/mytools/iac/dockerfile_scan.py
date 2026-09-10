"""Scanner para Dockerfiles via regex."""

from __future__ import annotations

import re
from pathlib import Path

from mytools.iac._common import DOCKERFILE_RULES, IacAttempt

__all__ = ["scan_dockerfile"]


def scan_dockerfile(
    file_path: Path,
    base_dir: Path,
    rules: dict[str, dict[str, object]] | None = None,
) -> list[IacAttempt]:
    effective_rules = rules or DOCKERFILE_RULES
    attempts: list[IacAttempt] = []

    try:
        text = file_path.read_text(encoding="utf-8", errors="ignore")
    except OSError, PermissionError:
        return attempts

    for rule_name, rule_def in effective_rules.items():
        pat = rule_def["pattern"]
        negate = rule_def.get("negate", False)
        assert isinstance(pat, re.Pattern)

        if negate:
            if not pat.search(text):
                attempts.append(
                    IacAttempt(
                        file_path=str(file_path.relative_to(base_dir)),
                        line_number=0,
                        check_name=rule_name,
                        file_type="dockerfile",
                        vulnerable=True,
                        severity=str(rule_def.get("severity", "medium")),
                        description=str(rule_def.get("description", "")),
                        details="Padrao nao encontrado no arquivo",
                    )
                )
        else:
            for line_num, line in enumerate(text.splitlines(), start=1):
                if pat.search(line):
                    attempts.append(
                        IacAttempt(
                            file_path=str(file_path.relative_to(base_dir)),
                            line_number=line_num,
                            check_name=rule_name,
                            file_type="dockerfile",
                            vulnerable=True,
                            severity=str(rule_def.get("severity", "medium")),
                            description=str(rule_def.get("description", "")),
                            details=line.strip()[:120],
                        )
                    )
    return attempts
