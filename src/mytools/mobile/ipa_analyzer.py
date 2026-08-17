"""IPA metadata and Mach-O analysis via plistlib + lief."""

from __future__ import annotations

import logging
import plistlib
import re
import zipfile
from typing import Any

logger = logging.getLogger("mytools.mobile.ipa_analyzer")

__all__ = ["analyze_ipa"]

# Binário principal: exatamente Payload/<app>.app/<bin> (2 segmentos),
# evita PlugIns/*.appex/* e Watch/*.app/*.
_MAIN_BINARY_RE = re.compile(r"Payload/[^/]+\.app/[^/]+")


def _macho_info(macho: Any) -> dict[str, Any]:
    """Extrai info de um Mach-O thin ou universal (FatBinary).

    Um FatBinary (binário universal) expõe `.at(i)`/`.size`; cada slice é
    um Mach-O thin. Faltas em um slice são ignoradas.
    """
    is_fat = hasattr(macho, "at") and hasattr(macho, "size")
    binaries = [macho.at(i) for i in range(macho.size)] if is_fat else [macho]
    binaries = [b for b in binaries if b is not None]

    info: dict[str, Any] = {
        "name": getattr(macho, "name", None) or "",
        "type": "fat_binary"
        if is_fat
        else str(getattr(getattr(macho, "header", None), "file_type", "") or ""),
        "libraries": [],
        "rpaths": [],
    }
    exports = 0
    symbols = 0
    for b in binaries:
        libs = getattr(b, "libraries", None)
        if libs:
            info["libraries"].extend(lib.name for lib in libs if lib.name)
        exports += len(getattr(b, "exported_functions", []) or [])
        symbols += len(list(getattr(b, "symbols", []) or []))
        rpaths = getattr(b, "rpaths", None)
        if rpaths and not info["rpaths"]:
            info["rpaths"] = [r.path for r in rpaths if r.path]
    info["exported_count"] = exports
    info["symbol_count"] = symbols
    return info


def analyze_ipa(file_path: str) -> dict[str, Any]:
    """Extrai metadata completa de um IPA.

    Returns:
        Dict com keys: bundle_id, display_name, version, build,
        min_os_version, bundle_short_version, entitlements,
        provisioning, macho, url_schemes, ats_settings, file_size.
        Em falha, dict com a key ``error``.
    """
    result: dict[str, Any] = {
        "bundle_id": "",
        "display_name": "",
        "version": "",
        "build": "",
        "min_os_version": "",
        "bundle_short_version": "",
        "entitlements": {},
        "provisioning": {},
        "macho": {},
        "url_schemes": [],
        "ats_settings": {},
        "file_size": 0,
    }

    try:
        from pathlib import Path

        result["file_size"] = Path(file_path).stat().st_size

        with zipfile.ZipFile(file_path, "r") as ipa:
            # Find Info.plist
            info_plist_path = None
            for name in ipa.namelist():
                if name.endswith("Info.plist"):
                    info_plist_path = name
                    break

            if info_plist_path:
                try:
                    plist_data = ipa.read(info_plist_path)
                    plist = plistlib.loads(plist_data)
                    result["bundle_id"] = plist.get("CFBundleIdentifier", "")
                    result["display_name"] = plist.get("CFBundleDisplayName", "")
                    result["version"] = plist.get("CFBundleShortVersionString", "")
                    result["build"] = plist.get("CFBundleVersion", "")
                    result["min_os_version"] = plist.get("MinimumOSVersion", "")
                    result["bundle_short_version"] = plist.get(
                        "CFBundleShortVersionString", ""
                    )

                    # URL schemes
                    url_types = plist.get("CFBundleURLTypes", []) or []
                    for url_type in url_types:
                        if not isinstance(url_type, dict):
                            continue
                        schemes = url_type.get("CFBundleURLSchemes", []) or []
                        if isinstance(schemes, list):
                            result["url_schemes"].extend(schemes)

                    # ATS settings
                    ats = plist.get("NSAppTransportSecurity", {})
                    if isinstance(ats, dict) and ats:
                        exception_domains = ats.get("NSExceptionDomains", {})
                        result["ats_settings"] = {
                            "allows_insecure_http": ats.get(
                                "NSAllowsArbitraryLoads", False
                            ),
                            "exception_domains": list(exception_domains.keys())
                            if isinstance(exception_domains, dict)
                            else [],
                        }
                except Exception as e:
                    logger.warning("Failed to parse Info.plist: %s", e)

            # Find embedded.mobileprovision
            for name in ipa.namelist():
                if name.endswith("embedded.mobileprovision"):
                    try:
                        prov_data = ipa.read(name)
                        # mobileprovision is XML plist (not binary usually)
                        try:
                            prov_plist = plistlib.loads(prov_data)
                        except Exception:
                            # Try extracting XML from CMS signed data
                            xml_match = re.search(
                                rb"(<\?xml.*</plist>)", prov_data, re.DOTALL
                            )
                            if xml_match:
                                prov_plist = plistlib.loads(xml_match.group(1))
                            else:
                                continue

                        result["provisioning"] = {
                            "name": prov_plist.get("Name", ""),
                            "team_name": prov_plist.get("TeamName", ""),
                            "team_id": prov_plist.get("TeamIdentifier", ""),
                            "created": str(prov_plist.get("CreationDate", "")),
                            "expires": str(prov_plist.get("ExpirationDate", "")),
                            "app_id": prov_plist.get("Entitlements", {}).get(
                                "application-identifier", ""
                            ),
                            "devices": len(
                                prov_plist.get("ProvisionedDevices", []) or []
                            ),
                            "push": bool(
                                prov_plist.get("Entitlements", {}).get(
                                    "aps-environment", ""
                                )
                            ),
                        }

                        # Extract entitlements
                        ent = prov_plist.get("Entitlements", {})
                        if ent:
                            result["entitlements"] = {
                                k: v
                                for k, v in ent.items()
                                if not k.startswith("com.apple")
                            }
                    except Exception as e:
                        logger.warning("Failed to parse provisioning: %s", e)
                    break

            # Mach-O analysis via lief
            try:
                import lief

                for name in ipa.namelist():
                    if name.endswith((".arm64", ".arm64e")) or (
                        "Frameworks/" in name
                        and not name.endswith((".plist", ".bundle", ".nib"))
                    ):
                        continue
                    # Main binary: typically in Payload/*.app/*
                    if (
                        _MAIN_BINARY_RE.fullmatch(name)
                        and not name.endswith(
                            (".plist", ".nib", ".storyboardc", ".strings", ".lproj")
                        )
                        and "." not in name.split("/")[-1]
                    ):
                        try:
                            binary_data = ipa.read(name)
                            binary = lief.parse(bytes(binary_data))
                            if binary is not None:
                                result["macho"] = _macho_info(binary)
                                break
                        except Exception:
                            continue
            except Exception:
                pass

    except Exception as e:
        logger.error("Failed to analyze IPA %s: %s", file_path, e)
        result["error"] = str(e)[:200]

    return result
