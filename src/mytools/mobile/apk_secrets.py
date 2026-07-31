"""Hardcoded secrets detection in APK DEX bytecode."""

from __future__ import annotations

import logging
from typing import Any

from mytools.mobile._common import MOBILE_SECRET_PATTERNS

__all__ = ["detect_secrets"]

logger = logging.getLogger("mytools.mobile.apk_secrets")

_SECRET_PATTERNS = MOBILE_SECRET_PATTERNS


def detect_secrets(file_path: str) -> dict[str, Any]:
    """Detecta secrets hardcoded em um APK.

    Returns:
        Dict com keys: findings (lista de dicts com pattern, value, context),
        total_secrets, unique_patterns.
    """
    try:
        import zipfile

        findings: list[dict[str, str]] = []
        seen_values: set[str] = set()

        with zipfile.ZipFile(file_path, "r") as apk:
            dex_files = [n for n in apk.namelist() if n.endswith(".dex")]

            for dex_name in dex_files:
                try:
                    data = apk.read(dex_name)
                except Exception:
                    continue

                for pattern_name, pattern in _SECRET_PATTERNS.items():
                    for match in pattern.finditer(data):
                        value = match.group().decode("utf-8", errors="replace")[:100]
                        # Deduplicate by value
                        if value in seen_values:
                            continue
                        seen_values.add(value)
                        findings.append(
                            {
                                "pattern": pattern_name,
                                "value": value,
                                "source": dex_name,
                            }
                        )

        # Sort by pattern name
        findings.sort(key=lambda x: x["pattern"])

        return {
            "findings": findings,
            "total_secrets": len(findings),
            "unique_patterns": len({f["pattern"] for f in findings}),
        }

    except Exception as e:
        logger.error("Failed to detect secrets in %s: %s", file_path, e)
        return {"error": str(e)[:200], "findings": [], "total_secrets": 0}
