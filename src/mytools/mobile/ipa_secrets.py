"""Secrets detection in IPA Mach-O strings and Info.plist."""

from __future__ import annotations

import logging
import plistlib
import re
import zipfile
from typing import Any

logger = logging.getLogger("mytools.mobile.ipa_secrets")

# Same secret patterns as apk_secrets.py (bytes patterns for binary matching)
_SECRET_PATTERNS: dict[str, re.Pattern[bytes]] = {
    "Google API Key": re.compile(rb"AIza[0-9A-Za-z\-_]{35}"),
    "Firebase URL": re.compile(rb"https://[a-z0-9\-]+\.firebaseio\.com"),
    "AWS Access Key": re.compile(rb"AKIA[0-9A-Z]{16}"),
    "GitHub Token": re.compile(rb"ghp_[0-9a-zA-Z]{36}"),
    "Slack Token": re.compile(rb"xox[bporas]-[0-9]{10,}-[0-9a-z\-]+"),
    "Private Key Block": re.compile(rb"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    "JWT Token": re.compile(rb"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"),
    "Stripe Secret Key": re.compile(rb"sk_live_[0-9a-zA-Z]{24,}"),
    "SendGrid API Key": re.compile(rb"SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}"),
    "Twilio Account SID": re.compile(rb"AC[a-f0-9]{32}"),
    "Hardcoded Password": re.compile(
        rb"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]"
    ),
    "Alphanumeric Secret": re.compile(
        rb"(?i)(?:secret|api[_-]?key|apikey|access[_-]?token|auth[_-]?token|client[_-]?secret)"
        rb"\s*[=:]\s*['\"]([A-Za-z0-9\-._]{20,})['\"]"
    ),
    "Bearer Token": re.compile(rb"(?i)bearer\s+[a-zA-Z0-9\-._~+/]+=*"),
    "Basic Auth": re.compile(rb"(?i)basic\s+[A-Za-z0-9+/]+=*"),
    "Hardcoded URL with creds": re.compile(rb"(?i)https?://[^:]+:[^@]+@[a-zA-Z0-9]"),
}


def _check_plist_values(
    obj: object,
    source: str,
    findings: list[dict[str, str]],
    seen: set[str],
) -> None:
    """Recursively check plist string values for secrets."""
    if isinstance(obj, str):
        for pattern_name, pattern in _SECRET_PATTERNS.items():
            for match in pattern.finditer(obj.encode("utf-8", errors="replace")):
                value = match.group().decode("utf-8", errors="replace")[:100]
                if value not in seen:
                    seen.add(value)
                    findings.append(
                        {
                            "pattern": pattern_name,
                            "value": value,
                            "source": source,
                        }
                    )
    elif isinstance(obj, dict):
        for v in obj.values():
            _check_plist_values(v, source, findings, seen)
    elif isinstance(obj, list):
        for item in obj:
            _check_plist_values(item, source, findings, seen)


def detect_ipa_secrets(file_path: str) -> dict[str, Any]:
    """Detecta secrets em um IPA (Info.plist + Mach-O strings).

    Returns:
        Dict com keys: findings, total_secrets, unique_patterns.
    """
    findings: list[dict[str, str]] = []
    seen_values: set[str] = set()

    try:
        with zipfile.ZipFile(file_path, "r") as ipa:
            # Scan Info.plist
            for name in ipa.namelist():
                if name.endswith("Info.plist"):
                    try:
                        plist_data = ipa.read(name)
                        # Try parsing as plist to check string values
                        try:
                            plist_dict = plistlib.loads(plist_data)
                            _check_plist_values(plist_dict, name, findings, seen_values)
                        except Exception:
                            pass
                        # Also scan raw bytes for patterns
                        for pattern_name, pattern in _SECRET_PATTERNS.items():
                            for match in pattern.finditer(plist_data):
                                value = match.group().decode("utf-8", errors="replace")[
                                    :100
                                ]
                                if value not in seen_values:
                                    seen_values.add(value)
                                    findings.append(
                                        {
                                            "pattern": pattern_name,
                                            "value": value,
                                            "source": name,
                                        }
                                    )
                    except Exception:
                        pass

            # Scan Mach-O binaries
            for name in ipa.namelist():
                if name.endswith(
                    (".plist", ".nib", ".storyboardc", ".strings", ".lproj", ".bundle")
                ):
                    continue
                if ".app/" in name and "." not in name.split("/")[-1]:
                    try:
                        binary_data = ipa.read(name)
                        for pattern_name, pattern in _SECRET_PATTERNS.items():
                            for match in pattern.finditer(binary_data):
                                value = match.group().decode("utf-8", errors="replace")[
                                    :100
                                ]
                                if value not in seen_values:
                                    seen_values.add(value)
                                    findings.append(
                                        {
                                            "pattern": pattern_name,
                                            "value": value,
                                            "source": name,
                                        }
                                    )
                    except Exception:
                        continue

    except Exception as e:
        logger.error("Failed to detect secrets in %s: %s", file_path, e)
        return {"error": str(e)[:200], "findings": [], "total_secrets": 0}

    findings.sort(key=lambda x: x["pattern"])
    return {
        "findings": findings,
        "total_secrets": len(findings),
        "unique_patterns": len({f["pattern"] for f in findings}),
    }
