"""Tipos e padroes compartilhados para PCAP Analysis."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "PCAP_SECRET_PATTERNS",
    "PcapAttempt",
    "PcapResult",
]

PCAP_SECRET_PATTERNS: dict[str, re.Pattern[bytes]] = {
    "basic_auth": re.compile(
        rb"(?i)Authorization:\s*Basic\s+([A-Za-z0-9+/]{12,}={0,2})"
    ),
    "bearer_token": re.compile(
        rb"(?i)Authorization:\s*Bearer\s+[A-Za-z0-9\-._~+/]{20,}=*"
    ),
    "password_in_form": re.compile(rb"(?i)(?:password|passwd|pwd)\s*[=:]\s*[^\s&]+"),
    "aws_key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "github_token": re.compile(rb"ghp_[0-9a-zA-Z]{36}"),
    "private_key": re.compile(rb"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "connection_string": re.compile(
        rb"(?:mysql|postgres|mongodb|redis)://[^\s\"'<>]{10,}"
    ),
    "api_key_header": re.compile(rb"(?i)(?:x-api-key|api-key|apikey)\s*[:=]\s*[^\s&]+"),
    "cookie_session": re.compile(
        rb"(?i)(?:session|sid|token)\s*=\s*[A-Za-z0-9\-._]{16,}"
    ),
}


@dataclass(frozen=True, slots=True)
class PcapAttempt:
    """Tentativa individual de analise PCAP."""

    check_name: str
    vulnerable: bool
    severity: str = "medium"
    description: str = ""
    details: str = ""


@dataclass(frozen=True, slots=True)
class PcapResult:
    """Resultado consolidado da analise PCAP."""

    target: str
    file_size: int
    total_packets: int
    protocols: list[str] = field(default_factory=list)
    attempts: list[PcapAttempt] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    overall_status: str = "clean"
