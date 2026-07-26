"""Network Security Config analysis for APK."""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("mytools.mobile.apk_nsc")

# NSC XML indicators (binary XML patterns)
_NSC_BINARY_PATTERNS: dict[str, bytes] = {
    "cleartext_permitted": b"cleartextTrafficPermitted",
    "pin_set": b"pin-set",
    "pin_element": b"<pin",
    "trust_anchors": b"trust-anchors",
    "certificates": b"certificates",
    "domain_config": b"domain-config",
    "base_config": b"base-config",
    "debug_overrides": b"debug-overrides",
    "certificates_user": b"user",
    "certificates_system": b"system",
    "include_subdomains": b"includeSubdomains",
}

# Manifest indicators for NSC reference
_MANIFEST_PATTERNS = {
    "network_security_config_ref": b"networkSecurityConfig",
    "uses_cleartext_traffic": b"usesCleartextTraffic",
    "debuggable": b"android:debuggable",
}


def analyze_nsc(file_path: str) -> dict[str, Any]:
    """Analisa Network Security Config de um APK.

    Returns:
        Dict com keys: has_nsc, has_pins, has_cleartext, debug_overrides,
        trust_user_ca, trust_system_ca, findings.
    """
    try:
        import zipfile

        findings: list[str] = []
        nsc_content = b""
        has_nsc = False

        with zipfile.ZipFile(file_path, "r") as apk:
            # Find NSC XML file
            for name in apk.namelist():
                if "network_security_config" in name.lower():
                    has_nsc = True
                    try:
                        nsc_content = apk.read(name)
                        findings.append(f"NSC file found: {name}")
                    except Exception:
                        pass
                    break

            # Check manifest for NSC reference
            manifest_name = "AndroidManifest.xml"
            if manifest_name in apk.namelist():
                try:
                    manifest_data = apk.read(manifest_name)
                    for key, pattern in _MANIFEST_PATTERNS.items():
                        if pattern in manifest_data:
                            findings.append(f"Manifest: {key}")
                except Exception:
                    pass

        # Analyze NSC content (binary XML)
        has_pins = False
        has_cleartext = False
        debug_overrides = False
        trust_user_ca = False
        trust_system_ca = False

        if nsc_content:
            for indicator, pattern in _NSC_BINARY_PATTERNS.items():
                if pattern in nsc_content:
                    if indicator == "pin_set" or indicator == "pin_element":
                        has_pins = True
                        findings.append("NSC: pin-set detected")
                    elif indicator == "cleartext_permitted":
                        has_cleartext = True
                        findings.append("NSC: cleartext traffic permitted")
                    elif indicator == "debug_overrides":
                        debug_overrides = True
                        findings.append("NSC: debug-overrides present")
                    elif indicator == "certificates_user":
                        trust_user_ca = True
                        findings.append("NSC: trusts user CA certificates")
                    elif indicator == "certificates_system":
                        trust_system_ca = True
                        findings.append("NSC: trusts system CA certificates")

        return {
            "has_nsc": has_nsc,
            "has_pins": has_pins,
            "has_cleartext": has_cleartext,
            "debug_overrides": debug_overrides,
            "trust_user_ca": trust_user_ca,
            "trust_system_ca": trust_system_ca,
            "findings": findings,
            "risk_score": sum([
                2 if has_cleartext else 0,
                2 if debug_overrides else 0,
                3 if trust_user_ca else 0,
                1 if has_pins else 0,
            ]),
        }

    except Exception as e:
        logger.error("Failed to analyze NSC in %s: %s", file_path, e)
        return {"error": str(e)[:200], "has_nsc": False, "findings": []}
