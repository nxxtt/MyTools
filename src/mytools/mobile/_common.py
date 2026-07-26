"""Tipos compartilhados para Mobile API Testing."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class MobileAttempt:
    """Tentativa individual de check mobile."""

    technique: str
    platform: str  # "android" | "ios" | "oauth2"
    check: str  # "apk_metadata" | "apk_pinning" | ...
    file_path: str
    vulnerable: bool
    findings: list[str] = field(default_factory=list)
    details: str = ""
    error: str = ""


@dataclass(frozen=True, slots=True)
class MobileResult:
    """Resultado consolidado do scan mobile."""

    target: str
    platform: str
    file_size: int
    attempts: list[MobileAttempt] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    overall_status: str = "secure"
