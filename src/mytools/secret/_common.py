"""Tipos e padroes compartilhados para Secret Scanning."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "SECRET_PATTERNS",
    "SecretAttempt",
    "SecretResult",
]

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "aws_access_key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key": re.compile(
        r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*"
        r"['\"]?([A-Za-z0-9/+=]{40})['\"]?"
    ),
    "github_token": re.compile(r"ghp_[0-9a-zA-Z]{36}"),
    "github_oauth": re.compile(r"gho_[0-9a-zA-Z]{36}"),
    "github_app_token": re.compile(r"(?:ghu|ghs)_[0-9a-zA-Z]{36}"),
    "gitlab_token": re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
    "slack_token": re.compile(r"xox[bporas]-[0-9]{10,}-[0-9a-z\-]+"),
    "slack_webhook": re.compile(
        r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"
    ),
    "stripe_key": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"),
    "stripe_publishable": re.compile(r"pk_live_[0-9a-zA-Z]{24,}"),
    "heroku_api_key": re.compile(
        r"(?:heroku.*api[_-]?key|HEROKU_API_KEY)\s*[=:]\s*"
        r"['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})['\"]?"
    ),
    "twilio_sid": re.compile(r"AC[a-f0-9]{32}"),
    "twilio_api_key": re.compile(r"SK[0-9a-fA-F]{32}"),
    "sendgrid_key": re.compile(r"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
    "private_key_block": re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"),
    "google_oauth": re.compile(r"ya29\.[0-9A-Za-z_-]+"),
    "google_api_key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "firebase_key": re.compile(r"AAAA[A-Za-z0-9\-_]{7}:[A-Za-z0-9\-_]{140}"),
    "heroku_oauth": re.compile(
        r"(?:heroku.*oauth|HEROKU_OAUTH)\s*[=:]\s*['\"]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\"]?"
    ),
    "password_assign": re.compile(
        r"(?i)(?:password|passwd|pwd|PASSWD|PASSWORD)\s*[:=]\s*"
        r"['\"]?([^\s'\"<>]{8,})['\"]?"
    ),
    "api_key_assign": re.compile(
        r"(?i)(?:api[_-]?key|apikey|API_KEY|APIKEY)\s*[:=]\s*"
        r"['\"]?([^\s'\"<>]{8,})['\"]?"
    ),
    "secret_assign": re.compile(
        r"(?i)(?:secret|secret[_-]?key|SECRET_KEY)\s*[:=]\s*"
        r"['\"]?([^\s'\"<>]{8,})['\"]?"
    ),
    "token_assign": re.compile(
        r"(?i)(?:auth[_-]?token|access[_-]?token|AUTH_TOKEN|ACCESS_TOKEN)\s*[:=]\s*"
        r"['\"]?([^\s'\"<>]{8,})['\"]?"
    ),
    "connection_string": re.compile(
        r"(?:mysql|postgres|mongodb|redis|amqp)://[^\s\"'<>]{10,}"
    ),
    "base64_secret": re.compile(
        r"(?i)(?:secret|key|token|password)\s*[:=]\s*"
        r"['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]"
    ),
    "hardcoded_url_creds": re.compile(r"https?://[^:]+:[^@]+@[a-zA-Z0-9]"),
    "npm_token": re.compile(r"npm_[A-Za-z0-9]{36}"),
    "pypi_token": re.compile(r"pypi-[A-Za-z0-9\-_]{50,}"),
    "openai_key": re.compile(r"sk-[A-Za-z0-9]{48}"),
    "anthropic_key": re.compile(r"sk-ant-[A-Za-z0-9\-_]{40,}"),
    "huggingface_token": re.compile(r"hf_[A-Za-z0-9]{34,}"),
    "confluent_key": re.compile(r"api_key\s*[:=]\s*['\"]?([a-z0-9]{16})['\"]?"),
    "datadog_key": re.compile(
        r"(?:dd_api_key|DD_API_KEY)\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?"
    ),
    "sentry_dsn": re.compile(
        r"https://[a-f0-9]{32}@[a-z0-9\-]+\.ingest\.sentry\.io/[0-9]+"
    ),
    "bearer_token": re.compile(r"(?i)\bbearer\s+[a-zA-Z0-9\-._~+/]{20,}=*"),
    "basic_auth": re.compile(
        r"(?i)\bbasic\s+(?=[A-Za-z0-9+/]*[0-9+/=])([A-Za-z0-9+/]{12,}={0,2})"
    ),
    "npmrc_token": re.compile(r"//registry\.npmjs\.org/:_authToken\s*=\s*([^\s]+)"),
    "netrc_password": re.compile(r"password\s+([^\s]+)"),
}


@dataclass(frozen=True, slots=True)
class SecretAttempt:
    """Tentativa individual de deteccao de segredo."""

    file_path: str
    line_number: int
    pattern_name: str
    secret_type: str
    match_preview: str
    severity: str = "high"
    details: str = ""


@dataclass(frozen=True, slots=True)
class SecretResult:
    """Resultado consolidado do scan de segredos."""

    target: str
    total_files: int
    scanned_files: int
    skipped_files: int
    attempts: list[SecretAttempt] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    overall_status: str = "clean"


PATTERN_CATEGORIES: dict[str, list[str]] = {
    "cloud": [
        "aws_access_key",
        "aws_secret_key",
        "google_api_key",
        "firebase_key",
        "heroku_api_key",
        "heroku_oauth",
    ],
    "saas": [
        "github_token",
        "github_oauth",
        "github_app_token",
        "gitlab_token",
        "slack_token",
        "slack_webhook",
        "stripe_key",
        "stripe_publishable",
        "sendgrid_key",
        "openai_key",
        "anthropic_key",
        "huggingface_token",
        "npm_token",
        "pypi_token",
        "confluent_key",
        "datadog_key",
        "sentry_dsn",
    ],
    "generic": [
        "password_assign",
        "api_key_assign",
        "secret_assign",
        "token_assign",
        "connection_string",
        "base64_secret",
        "hardcoded_url_creds",
        "netrc_password",
        "npmrc_token",
    ],
    "crypto": [
        "private_key_block",
        "jwt_token",
        "google_oauth",
        "bearer_token",
        "basic_auth",
    ],
}
