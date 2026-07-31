"""SSL/TLS certificate pinning detection in APK bytecode."""

from __future__ import annotations

import logging
import re
from typing import Any

__all__ = ["detect_pinning"]

logger = logging.getLogger("mytools.mobile.apk_pinning")

# Patterns that indicate certificate pinning implementations
_PINNING_PATTERNS: dict[str, str] = {
    "OkHttp CertificatePinner": r"CertificatePinner",
    "OkHttp certificate_pinner": r"certificate_pinner",
    "TrustManager (custom)": r"checkServerTrusted",
    "TrustManager (checkClientTrusted)": r"checkClientTrusted",
    "HostnameVerifier (custom)": r"verify.*hostname",
    "SSLContext init": r"SSLContext\.getInstance",
    "NetworkSecurityConfig": r"network_security_config",
    "TrustKit": r"TrustKit",
    "PinningTrustManager": r"PinningTrustManager",
    "CertificateValidation": r"CertificateValidat",
    "SSL Pinning": r"ssl.*pin",
    "PublicKey Pinning": r"public.*key.*pin",
    "X509TrustManager": r"X509TrustManager",
    "PKIXParameters": r"PKIXParameters",
    "NetworkSecurityConfigBuilder": r"NetworkSecurityConfigBuilder",
    "WebViewClient onReceivedSslError": r"onReceivedSslError",
    "OkHttp Builder sslSocketFactory": r"sslSocketFactory",
    "Conscrypt": r"Conscrypt",
    "Cronet": r"CronetEngine",
    "gRPC SslContext": r"GrpcSslContext",
    "CertificateFactory": r"CertificateFactory.*generate",
}

# Network Security Config XML indicators
_NSC_PINNING_PATTERNS = [
    "pin-set",
    "pin",
    "expiration",
    "trust-anchors",
    "certificates",
    "cleartextTrafficPermitted",
    "domain-config",
]


def detect_pinning(file_path: str) -> dict[str, Any]:
    """Detecta certificate pinning em um APK.

    Returns:
        Dict com keys: techniques (lista de strings encontradas),
        nsc_config (indicadores de NSC XML), total_indicators.
    """
    try:
        import zipfile

        techniques: list[str] = []
        nsc_indicators: list[str] = []

        with zipfile.ZipFile(file_path, "r") as apk:
            dex_files = [n for n in apk.namelist() if n.endswith(".dex")]
            xml_files = [
                n
                for n in apk.namelist()
                if "network_security_config" in n.lower()
                or n.endswith("network_security_config.xml")
            ]

            # Scan DEX files for pinning patterns
            for dex_name in dex_files:
                try:
                    data = apk.read(dex_name)
                    for technique_name, pattern in _PINNING_PATTERNS.items():
                        if (
                            re.search(pattern.encode(), data, re.IGNORECASE)
                            and technique_name not in techniques
                        ):
                            techniques.append(technique_name)
                except Exception:
                    continue

            # Check for Network Security Config XML
            for xml_name in xml_files:
                try:
                    nsc_data = apk.read(xml_name)
                    nsc_indicators.extend(
                        indicator
                        for indicator in _NSC_PINNING_PATTERNS
                        if indicator.encode() in nsc_data
                    )
                except Exception:
                    continue

            # Also check AndroidManifest.xml for android:networkSecurityConfig ref
            manifest_name = "AndroidManifest.xml"
            if manifest_name in apk.namelist():
                try:
                    manifest_data = apk.read(manifest_name)
                    if b"networkSecurityConfig" in manifest_data:
                        nsc_indicators.append("manifest_networkSecurityConfig_ref")
                except Exception:
                    pass

        return {
            "techniques": techniques,
            "nsc_indicators": nsc_indicators,
            "total_indicators": len(techniques) + len(nsc_indicators),
            "vulnerable": len(techniques) > 0 or len(nsc_indicators) > 0,
        }

    except Exception as e:
        logger.error("Failed to detect pinning in %s: %s", file_path, e)
        return {"error": str(e)[:200], "techniques": [], "vulnerable": False}
