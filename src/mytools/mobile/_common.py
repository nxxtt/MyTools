"""Tipos e padroes compartilhados para Mobile API Testing."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = ["MOBILE_SECRET_PATTERNS", "MobileAttempt", "MobileResult"]

# Canonical secret patterns (shared between apk_secrets and ipa_secrets).
# Bytes patterns for binary/DEX/Mach-O matching.
MOBILE_SECRET_PATTERNS: dict[str, re.Pattern[bytes]] = {
    "Google API Key": re.compile(rb"AIza[0-9A-Za-z\-_]{35}"),
    "Firebase URL": re.compile(rb"https://[a-z0-9\-]+\.firebaseio\.com"),
    "Firebase Key": re.compile(rb"AAAA[A-Za-z0-9\-_]{7}:[A-Za-z0-9\-_]{140}"),
    "AWS Access Key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key": re.compile(
        rb"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"
    ),
    "GitHub Token": re.compile(rb"ghp_[0-9a-zA-Z]{36}"),
    "GitHub OAuth": re.compile(rb"gho_[0-9a-zA-Z]{36}"),
    "Slack Token": re.compile(rb"xox[bporas]-[0-9]{10,}-[0-9a-z\-]+"),
    "Slack Webhook": re.compile(
        rb"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"
    ),
    "Private Key Block": re.compile(rb"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "JWT Token": re.compile(rb"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"),
    "OAuth Token": re.compile(rb"ya29\.[0-9A-Za-z_-]+"),
    "Bearer Token": re.compile(rb"(?i)\bbearer\s+[a-zA-Z0-9\-._~+/]{20,}=*"),
    "Basic Auth": re.compile(
        rb"(?i)\bbasic\s+(?=[A-Za-z0-9+/]*[0-9+/=])([A-Za-z0-9+/]{12,}={0,2})"
    ),
    "Heroku API Key": re.compile(
        rb"(?i)heroku.*api[_-]?key\s*[=:]\s*['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"
    ),
    "Twilio Account SID": re.compile(rb"AC[a-f0-9]{32}"),
    "SendGrid API Key": re.compile(rb"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
    "Stripe Secret Key": re.compile(rb"sk_live_[0-9a-zA-Z]{24,}"),
    "Stripe Publishable Key": re.compile(rb"pk_live_[0-9a-zA-Z]{24,}"),
    "PayPal Braintree": re.compile(
        rb"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"
    ),
    "Twilio SID": re.compile(rb"SK[0-9a-fA-F]{32}"),
    "Alphanumeric Secret": re.compile(
        rb"(?i)(?:secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)"
        rb"\s*[=:]\s*['\"]([A-Za-z0-9\-._]{20,})['\"]"
    ),
    "Hardcoded Password": re.compile(
        rb"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]"
    ),
    "Hardcoded URL with creds": re.compile(rb"(?i)https?://[^:]+:[^@]+@[a-zA-Z0-9]"),
    "Base64 Encoded Secret": re.compile(
        rb"(?i)(?:secret|key|token|password)\s*[=:]\s*['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]"
    ),
}


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
