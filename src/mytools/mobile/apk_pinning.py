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

# Técnicas que indicam validação customizada/possivelmente insegura da cadeia
# de confiança (TrustManager/verifier/socket customizados podem aceitar
# qualquer certificado). Demais técnicas são controles informativos.
_RISKY_TECHNIQUES = {
    "TrustManager (custom)",
    "TrustManager (checkClientTrusted)",
    "HostnameVerifier (custom)",
    "WebViewClient onReceivedSslError",
    "OkHttp Builder sslSocketFactory",
    "CertificateFactory",
}

# Network Security Config XML indicators (controles, nunca vulnerabilizam)
_NSC_PINNING_PATTERNS = [
    "pin-set",
    "trust-anchors",
    "domain-config",
]


def detect_pinning(file_path: str) -> dict[str, Any]:
    """Detecta certificate pinning em um APK.

    Returns:
        Dict com keys: techniques (lista de strings encontradas),
        nsc_indicators (indicadores de NSC XML), total_indicators,
        vulnerable (True apenas se uma tecnica arriscada foi encontrada).
    """
    try:
        import zipfile

        techniques: list[str] = []
        nsc_indicators: set[str] = set()

        with zipfile.ZipFile(file_path, "r") as apk:
            dex_files = [n for n in apk.namelist() if n.endswith(".dex")]
            xml_files = [
                n for n in apk.namelist() if "network_security_config" in n.lower()
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
                    nsc_indicators.update(
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
                        nsc_indicators.add("manifest_networkSecurityConfig_ref")
                except Exception:
                    pass

        return {
            "techniques": techniques,
            "nsc_indicators": sorted(nsc_indicators),
            "total_indicators": len(techniques) + len(nsc_indicators),
            "vulnerable": any(t in _RISKY_TECHNIQUES for t in techniques),
        }

    except Exception as e:
        logger.error("Failed to detect pinning in %s: %s", file_path, e)
        return {"error": str(e)[:200], "techniques": [], "vulnerable": False}
