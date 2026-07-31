"""DEX Layer analysis, Dalvik disassembly, and Java decompilation via androguard."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger("mytools.mobile.apk_dex")

__all__ = ["analyze_dex_layer", "decompile_java", "disassemble_dalvik"]


def _load_apk(file_path: str) -> tuple[Any, list[Any], Any]:
    """Parse APK once. Returns (apk_obj, dex_list, analysis).

    Raises:
        FileNotFoundError: If file does not exist.
        ImportError: If androguard is not installed.
        Exception: If APK parsing fails.
    """
    if not Path(file_path).is_file():
        raise FileNotFoundError(f"File not found: {file_path}")

    try:
        from androguard.misc import AnalyzeAPK
    except ImportError as exc:
        raise ImportError(
            "androguard not installed: pip install androguard[full]"
        ) from exc

    a, d_list, dx = AnalyzeAPK(file_path)
    if not d_list:
        raise ValueError("No DEX files found in APK")
    return a, d_list, dx


def analyze_dex_layer(file_path: str) -> dict[str, Any]:
    """Extract DEX structure: header, classes, methods, strings.

    Returns:
        Dict with keys: dex_count, package, dex_files (list of dicts),
        total_classes, total_methods, total_strings.
    """
    a, d_list, _dx = _load_apk(file_path)

    dex_files: list[dict[str, Any]] = []
    total_classes = 0
    total_methods = 0
    total_strings = 0

    for i, df in enumerate(d_list):
        classes = list(df.get_classes_names())
        methods = list(df.get_encoded_methods())
        strings = [str(s) for s in df.get_strings()]

        header = df.get_header_item()
        header_info = {
            "magic": str(getattr(header, "magic", "")),
            "file_size": int(getattr(header, "file_size", 0)),
            "dex_version": int(getattr(header, "dex_version", 0)),
            "endian_tag": int(getattr(header, "endian_tag", 0)),
            "checksum": str(getattr(header, "checksum", "")),
        }

        dex_files.append(
            {
                "index": i,
                "class_count": len(classes),
                "method_count": len(methods),
                "string_count": len(strings),
                "header": header_info,
                "classes": classes[:50],
                "methods": [
                    f"{m.get_class_name()}->{m.get_name()}" for m in methods[:50]
                ],
                "strings": strings[:100],
            }
        )

        total_classes += len(classes)
        total_methods += len(methods)
        total_strings += len(strings)

    return {
        "dex_count": len(d_list),
        "package": a.get_package() or "",
        "dex_files": dex_files,
        "total_classes": total_classes,
        "total_methods": total_methods,
        "total_strings": total_strings,
    }


def disassemble_dalvik(
    file_path: str,
    class_filter: str | None = None,
    max_methods: int = 20,
) -> dict[str, Any]:
    """Disassemble Dalvik bytecode per method.

    Args:
        file_path: Path to APK file.
        class_filter: Optional substring to filter classes (e.g. "com.example").
        max_methods: Maximum number of methods to disassemble.

    Returns:
        Dict with keys: class_filter, methods (list), total_methods,
        total_instructions, truncated.
    """
    _a, d_list, _dx = _load_apk(file_path)

    result_methods: list[dict[str, Any]] = []
    total_methods = 0
    total_instructions = 0
    truncated = False

    for df in d_list:
        for method in df.get_encoded_methods():
            if class_filter and class_filter not in method.get_class_name():
                continue

            if method.get_code() is None:
                continue

            total_methods += 1

            if len(result_methods) >= max_methods:
                truncated = True
                continue

            try:
                insns = list(method.get_instructions())
            except Exception as e:
                logger.debug("Failed to disassemble %s: %s", method.get_name(), e)
                continue

            total_instructions += len(insns)

            result_methods.append(
                {
                    "class_name": method.get_class_name(),
                    "method_name": method.get_name(),
                    "descriptor": method.get_descriptor(),
                    "access_flags": str(method.get_access_flags()),
                    "instruction_count": len(insns),
                    "instructions": [
                        {
                            "hex": insn.get_hex(),
                            "mnemonic": insn.get_name(),
                            "output": insn.get_output(),
                        }
                        for insn in insns
                    ],
                }
            )

    return {
        "class_filter": class_filter,
        "methods": result_methods,
        "total_methods": total_methods,
        "total_instructions": total_instructions,
        "truncated": truncated,
    }


def decompile_java(
    file_path: str,
    class_filter: str | None = None,
    max_classes: int = 10,
) -> dict[str, Any]:
    """Decompile Dalvik bytecode to Java source via DAD decompiler.

    Args:
        file_path: Path to APK file.
        class_filter: Optional substring to filter classes.
        max_classes: Maximum number of classes to decompile.

    Returns:
        Dict with keys: class_filter, classes (list), total_classes,
        total_decompiled, total_empty, truncated.
    """
    _a, d_list, _dx = _load_apk(file_path)

    result_classes: list[dict[str, Any]] = []
    total_classes = 0
    total_decompiled = 0
    total_empty = 0
    truncated = False

    for df in d_list:
        for class_def in df.get_classes():
            name = class_def.get_name()

            # Skip framework classes
            if name.startswith("Landroid/") or name.startswith("Ljava/"):
                continue

            if class_filter and class_filter not in name:
                continue

            total_classes += 1

            if total_decompiled >= max_classes:
                truncated = True
                continue

            try:
                source = class_def.get_source()
            except Exception as e:
                logger.debug("Failed to decompile %s: %s", name, e)
                total_empty += 1
                continue

            if source and len(source.strip()) > 10:
                lines = source.split("\n")
                # Count methods (lines with 'public', 'private', 'protected', 'static')
                method_count = sum(
                    1
                    for line in lines
                    if any(
                        line.strip().startswith(kw)
                        for kw in ("public ", "private ", "protected ", "static ")
                    )
                )
                result_classes.append(
                    {
                        "class_name": name,
                        "source": source,
                        "method_count": method_count,
                        "line_count": len(lines),
                    }
                )
                total_decompiled += 1
            else:
                total_empty += 1

    return {
        "class_filter": class_filter,
        "classes": result_classes,
        "total_classes": total_classes,
        "total_decompiled": total_decompiled,
        "total_empty": total_empty,
        "truncated": truncated,
    }
