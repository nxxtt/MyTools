"""Tests para Binary Analysis module."""

from __future__ import annotations

from pathlib import Path

import pytest

from mytools.binary._common import (
    BINARY_SECRET_PATTERNS,
    BinaryAttempt,
    BinaryResult,
)
from mytools.binary.binary_scan import (
    BinaryScanScanner,
    _check_secrets,
    _detect_binary_type,
    run_binary_scan,
)


class TestBinaryAttempt:
    def test_frozen(self) -> None:
        att = BinaryAttempt(
            file_path="test",
            check_name="x",
            binary_type="elf",
            vulnerable=True,
        )
        with pytest.raises(AttributeError):
            att.file_path = "other"  # type: ignore[misc]

    def test_defaults(self) -> None:
        att = BinaryAttempt(
            file_path="test",
            check_name="x",
            binary_type="elf",
            vulnerable=True,
        )
        assert att.severity == "medium"
        assert att.description == ""
        assert att.details == ""


class TestBinaryResult:
    def test_frozen(self) -> None:
        r = BinaryResult(target=".", file_size=0, binary_type="unknown")
        with pytest.raises(AttributeError):
            r.target = "other"  # type: ignore[misc]

    def test_defaults(self) -> None:
        r = BinaryResult(target=".", file_size=0, binary_type="unknown")
        assert r.overall_status == "clean"
        assert r.attempts == []
        assert r.issues == []


class TestSecretPatterns:
    def test_all_patterns_compiled(self) -> None:
        for name, pat in BINARY_SECRET_PATTERNS.items():
            assert hasattr(pat, "search"), f"{name} not compiled"

    def test_private_key_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "key.bin"
        f.write_bytes(b"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...")
        attempts = _check_secrets(f)
        assert any("private_key" in a.check_name for a in attempts)

    def test_aws_key_detected(self, tmp_path: Path) -> None:
        f = tmp_path / "data.bin"
        f.write_bytes(b"key=AKIAIOSFODNN7EXAMPLE")
        attempts = _check_secrets(f)
        assert any("aws_key" in a.check_name for a in attempts)

    def test_no_secrets(self, tmp_path: Path) -> None:
        f = tmp_path / "clean.bin"
        f.write_bytes(b"hello world no secrets here")
        attempts = _check_secrets(f)
        assert len(attempts) == 0

    def test_file_not_readable(self, tmp_path: Path) -> None:
        f = tmp_path / "gone.bin"
        attempts = _check_secrets(f)
        assert len(attempts) == 0


class TestDetectBinaryType:
    def test_elf(self, tmp_path: Path) -> None:
        f = tmp_path / "prog"
        f.write_bytes(b"\x7fELF" + b"\x00" * 12)
        assert _detect_binary_type(f) == "elf"

    def test_pe(self, tmp_path: Path) -> None:
        f = tmp_path / "app.exe"
        f.write_bytes(b"MZ" + b"\x00" * 14)
        assert _detect_binary_type(f) == "pe"

    def test_macho(self, tmp_path: Path) -> None:
        f = tmp_path / "app"
        f.write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 12)
        assert _detect_binary_type(f) == "macho"

    def test_macho_fat(self, tmp_path: Path) -> None:
        f = tmp_path / "app.fat"
        f.write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 12)
        assert _detect_binary_type(f) == "macho_fat"

    def test_unknown(self, tmp_path: Path) -> None:
        f = tmp_path / "script.py"
        f.write_bytes(b"#!/usr/bin/env python3\nprint('hello')")
        assert _detect_binary_type(f) == "unknown"

    def test_nonexistent(self, tmp_path: Path) -> None:
        f = tmp_path / "nope.bin"
        assert _detect_binary_type(f) == "unknown"


class TestRunBinaryScan:
    def test_nonexistent(self, tmp_path: Path) -> None:
        import asyncio

        result = asyncio.run(run_binary_scan(str(tmp_path / "nope")))
        assert result.overall_status == "error"

    def test_directory_not_file(self, tmp_path: Path) -> None:
        import asyncio

        result = asyncio.run(run_binary_scan(str(tmp_path)))
        assert result.overall_status == "error"

    def test_unknown_binary(self, tmp_path: Path) -> None:
        import asyncio

        f = tmp_path / "script.py"
        f.write_bytes(b"#!/usr/bin/env python3\nprint('hello')")
        result = asyncio.run(run_binary_scan(str(f)))
        assert result.binary_type == "unknown"

    def test_elf_with_secrets(self, tmp_path: Path) -> None:
        import asyncio

        f = tmp_path / "prog"
        f.write_bytes(b"\x7fELF" + b"\x00" * 12 + b"\npassword='hunter222'\n")
        result = asyncio.run(run_binary_scan(str(f)))
        assert result.binary_type == "elf"
        assert result.overall_status == "found"

    def test_checks_filter(self, tmp_path: Path) -> None:
        import asyncio

        f = tmp_path / "prog"
        f.write_bytes(b"\x7fELF" + b"\x00" * 12 + b"\npassword='hunter222'\n")
        result = asyncio.run(run_binary_scan(str(f), checks=["secrets"]))
        assert any("secret" in a.check_name for a in result.attempts)

    def test_no_checks(self, tmp_path: Path) -> None:
        import asyncio

        f = tmp_path / "prog"
        f.write_bytes(b"\x7fELF" + b"\x00" * 12)
        result = asyncio.run(run_binary_scan(str(f), checks=[]))
        assert len(result.attempts) == 0


class TestBinaryScanScanner:
    def test_build_parser(self) -> None:
        scanner = BinaryScanScanner()
        parser = scanner.build_parser()
        args = parser.parse_args([])
        assert args.target is None

    def test_build_parser_with_target(self) -> None:
        scanner = BinaryScanScanner()
        parser = scanner.build_parser()
        args = parser.parse_args(["/usr/bin/ls"])
        assert args.target == "/usr/bin/ls"

    def test_get_target(self) -> None:
        import argparse

        ns = argparse.Namespace(target="/usr/bin/ls")
        assert BinaryScanScanner._get_target(ns) == "/usr/bin/ls"

    def test_get_target_none(self) -> None:
        import argparse

        ns = argparse.Namespace()
        assert BinaryScanScanner._get_target(ns) is None

    def test_module_level_exports(self) -> None:
        from mytools.binary.binary_scan import build_parser, main, run_once

        assert callable(build_parser)
        assert callable(main)
        assert callable(run_once)
