"""Tipos e padroes compartilhados para Binary Analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "BINARY_SECRET_PATTERNS",
    "BinaryAttempt",
    "BinaryResult",
]

BINARY_SECRET_PATTERNS: dict[str, re.Pattern[bytes]] = {
    "hardcoded_password": re.compile(
        rb"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^\s'\"]{8,})['\"]"
    ),
    "api_key": re.compile(
        rb"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]([^\s'\"]{8,})['\"]"
    ),
    "private_key_block": re.compile(rb"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "aws_key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(rb"ghp_[0-9a-zA-Z]{36}"),
    "connection_string": re.compile(
        rb"(?:mysql|postgres|mongodb|redis)://[^\s\"'<>]{10,}"
    ),
    "url_with_creds": re.compile(rb"https?://[^:]+:[^@]+@[a-zA-Z0-9]"),
}


@dataclass(frozen=True, slots=True)
class BinaryAttempt:
    """Tentativa individual de analise binaria."""

    file_path: str
    check_name: str
    binary_type: str
    vulnerable: bool
    severity: str = "medium"
    description: str = ""
    details: str = ""


@dataclass(frozen=True, slots=True)
class BinaryResult:
    """Resultado consolidado da analise binaria."""

    target: str
    file_size: int
    binary_type: str
    attempts: list[BinaryAttempt] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    overall_status: str = "clean"
