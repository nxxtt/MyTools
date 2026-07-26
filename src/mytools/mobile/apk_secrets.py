"""Hardcoded secrets detection in APK DEX bytecode."""

from __future__ import annotations

import logging
import re
from typing import Any

logger = logging.getLogger("mytools.mobile.apk_secrets")

# Secret patterns: name → regex (compiled as bytes for matching against DEX binary data)
_SECRET_PATTERNS: dict[str, re.Pattern[bytes]] = {
    "Google API Key": re.compile(rb"AIza[0-9A-Za-z\-_]{35}"),
    "Firebase URL": re.compile(rb"https://[a-z0-9\-]+\.firebaseio\.com"),
    "Firebase Key": re.compile(rb"AAAA[A-Za-z0-9\-_]{7}:[A-Za-z0-9\-_]{140}"),
    "AWS Access Key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key": re.compile(rb"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"),
    "GitHub Token": re.compile(rb"ghp_[0-9a-zA-Z]{36}"),
    "GitHub OAuth": re.compile(rb"gho_[0-9a-zA-Z]{36}"),
    "Slack Token": re.compile(rb"xox[bporas]-[0-9]{10,}-[0-9a-z\-]+"),
    "Slack Webhook": re.compile(rb"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+"),
    "Private Key Block": re.compile(rb"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "JWT Token": re.compile(rb"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"),
    "OAuth Token": re.compile(rb"ya29\.[0-9A-Za-z_-]+"),
    "Bearer Token": re.compile(rb"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*"),
    "Basic Auth": re.compile(rb"(?i)basic\s+[A-Za-z0-9+/]+=*"),
    "Heroku API Key": re.compile(rb"(?i)heroku.*api[_-]?key\s*[=:]\s*['\"]?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})"),
    "Twilio Account SID": re.compile(rb"AC[a-f0-9]{32}"),
    "SendGrid API Key": re.compile(rb"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
    "Stripe Secret Key": re.compile(rb"sk_live_[0-9a-zA-Z]{24,}"),
    "Stripe Publishable Key": re.compile(rb"pk_live_[0-9a-zA-Z]{24,}"),
    "PayPal Braintree": re.compile(rb"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"),
    "Twilio SID": re.compile(rb"SK[0-9a-fA-F]{32}"),
    "Alphanumeric Secret": re.compile(rb"(?i)(?:secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[=:]\s*['\"]([A-Za-z0-9\-._]{20,})['\"]"),
    "Hardcoded Password": re.compile(rb"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]"),
    "Hardcoded URL with creds": re.compile(rb"(?i)https?://[^:]+:[^@]+@[a-zA-Z0-9]"),
    "Base64 Encoded Secret": re.compile(rb"(?i)(?:secret|key|token|password)\s*[=:]\s*['\"]([A-Za-z0-9+/]{40,}={0,2})['\"]"),
}


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
