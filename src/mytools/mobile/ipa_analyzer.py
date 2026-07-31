"""IPA metadata and Mach-O analysis via plistlib + lief."""

from __future__ import annotations

import logging
import plistlib
import zipfile
from typing import Any

logger = logging.getLogger("mytools.mobile.ipa_analyzer")


def analyze_ipa(file_path: str) -> dict[str, Any]:
    """Extrai metadata completa de um IPA.

    Returns:
        Dict com keys: bundle_id, display_name, version, build,
        min_os_version, bundle_short_version, entitlements,
        provisioning, macho, url_schemes, file_size.
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
                    url_types = plist.get("CFBundleURLTypes", [])
                    for url_type in url_types:
                        schemes = url_type.get("CFBundleURLSchemes", [])
                        result["url_schemes"].extend(schemes)

                    # ATS settings
                    ats = plist.get("NSAppTransportSecurity", {})
                    if ats:
                        result["ats_settings"] = {
                            "allows_insecure_http": ats.get(
                                "NSAllowsArbitraryLoads", False
                            ),
                            "exception_domains": list(
                                ats.get("NSExceptionDomains", {}).keys()
                            ),
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
                            import re

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
                        ".app/" in name
                        and not name.endswith(
                            (".plist", ".nib", ".storyboardc", ".strings", ".lproj")
                        )
                        and "/" in name
                        and "." not in name.split("/")[-1]
                    ):
                        try:
                            binary_data = ipa.read(name)
                            # lief.parse from binary data
                            binary = lief.parse(list(binary_data))
                            if binary is not None and hasattr(binary, "name"):
                                macho_info: dict[str, Any] = {
                                    "name": binary.name or name,  # type: ignore[union-attr]
                                    "type": str(binary.header.file_type)  # type: ignore[union-attr]
                                    if hasattr(binary, "header")
                                    else "",
                                }

                                # Imports
                                if hasattr(binary, "libraries"):
                                    macho_info["libraries"] = [
                                        lib.name  # type: ignore[union-attr]
                                        for lib in binary.libraries  # type: ignore[union-attr]
                                        if lib.name  # type: ignore[union-attr]
                                    ]

                                # Exports
                                if hasattr(binary, "exported_functions"):
                                    macho_info["exported_count"] = len(
                                        binary.exported_functions  # type: ignore[union-attr]
                                    )  # type: ignore[arg-type]

                                # Symbols
                                if hasattr(binary, "symbols"):
                                    macho_info["symbol_count"] = len(
                                        list(binary.symbols)
                                    )  # type: ignore[arg-type]

                                # Rpaths
                                if hasattr(binary, "rpaths"):
                                    macho_info["rpaths"] = [
                                        r.path
                                        for r in binary.rpaths
                                        if r.path  # type: ignore[union-attr]
                                    ]

                                result["macho"] = macho_info
                                break
                        except Exception:
                            continue
            except Exception:
                pass

    except Exception as e:
        logger.error("Failed to analyze IPA %s: %s", file_path, e)
        result["error"] = str(e)[:200]

    return result
