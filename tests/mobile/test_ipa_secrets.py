"""Testes do módulo ipa_secrets.py."""

from __future__ import annotations

import plistlib
import zipfile
from unittest.mock import patch

from mytools.mobile.ipa_secrets import detect_ipa_secrets


class TestDetectIpaSecrets:
    def test_nonexistent_file(self) -> None:
        result = detect_ipa_secrets("nonexistent.ipa")
        assert "error" in result
        assert result["total_secrets"] == 0

    def test_empty_ipa(self, tmp_path) -> None:
        ipa_path = tmp_path / "clean.ipa"
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr(
                "Payload/Test.app/Info.plist",
                plistlib.dumps({"CFBundleIdentifier": "com.test"}),
            )
        result = detect_ipa_secrets(str(ipa_path))
        assert result["total_secrets"] == 0

    def test_secret_in_plist(self, tmp_path) -> None:
        ipa_path = tmp_path / "secrets.ipa"
        # AIza + 35 chars = valid Google API key pattern
        plist_dict = {
            "CFBundleIdentifier": "com.test",
            "API_KEY": "AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1",
        }
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps(plist_dict))
        result = detect_ipa_secrets(str(ipa_path))
        assert result["total_secrets"] > 0
        assert any("Google" in f["pattern"] for f in result["findings"])

    def test_secret_in_plist_list(self, tmp_path) -> None:
        ipa_path = tmp_path / "list.ipa"
        plist_dict = {
            "CFBundleIdentifier": "com.test",
            "Urls": ["https://example.com", "https://hook.example.com"],
            "Keys": ["AIzaSyBxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx1", "plain"],
        }
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps(plist_dict))
        result = detect_ipa_secrets(str(ipa_path))
        assert any("Google" in f["pattern"] for f in result["findings"])

    def test_aws_key_in_binary(self, tmp_path) -> None:
        ipa_path = tmp_path / "aws.ipa"
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr(
                "Payload/Test.app/Info.plist",
                plistlib.dumps({"CFBundleIdentifier": "com.test"}),
            )
            zf.writestr("Payload/Test.app/binary", b"AKIAIOSFODNN7EXAMPLE")
        result = detect_ipa_secrets(str(ipa_path))
        assert result["total_secrets"] > 0

    def test_deduplication(self, tmp_path) -> None:
        ipa_path = tmp_path / "dedup.ipa"
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr(
                "Payload/Test.app/Info.plist",
                plistlib.dumps({"CFBundleIdentifier": "com.test"}),
            )
            zf.writestr(
                "Payload/Test.app/binary",
                b"AKIAIOSFODNN7EXAMPLE here and AKIAIOSFODNN7EXAMPLE there",
            )
        result = detect_ipa_secrets(str(ipa_path))
        aws_count = sum(1 for f in result["findings"] if "AWS" in f["pattern"])
        assert aws_count == 1

    def test_invalid_plist_raw_scan(self, tmp_path) -> None:
        ipa_path = tmp_path / "raw.ipa"
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr(
                "Payload/Test.app/Info.plist",
                b"API_KEY = 'AKIAIOSFODNN7EXAMPLE'",
            )
        result = detect_ipa_secrets(str(ipa_path))
        assert result["total_secrets"] > 0
        assert any("AWS" in f["pattern"] for f in result["findings"])

    def test_binary_read_error_skipped(self, tmp_path) -> None:
        ipa_path = tmp_path / "badread.ipa"
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr(
                "Payload/Test.app/Info.plist",
                plistlib.dumps({"CFBundleIdentifier": "com.test"}),
            )
            zf.writestr("Payload/Test.app/binary", b"AKIAIOSFODNN7EXAMPLE")

        def _boom(name: str) -> bytes:
            if ".app/" in name and name != "Payload/Test.app/Info.plist":
                raise RuntimeError("corrupt")
            return plistlib.dumps({"CFBundleIdentifier": "com.test"})

        with patch.object(zipfile.ZipFile, "read", side_effect=_boom):
            result = detect_ipa_secrets(str(ipa_path))
        assert result["total_secrets"] == 0

    def test_plist_read_error_skipped(self, tmp_path) -> None:
        ipa_path = tmp_path / "badplistread.ipa"
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", b"data")
            zf.writestr("Payload/Test.app/binary", b"AKIAIOSFODNN7EXAMPLE")

        def _boom(name: str) -> bytes:
            if name.endswith("Info.plist"):
                raise RuntimeError("corrupt")
            return b"AKIAIOSFODNN7EXAMPLE"

        with patch.object(zipfile.ZipFile, "read", side_effect=_boom):
            result = detect_ipa_secrets(str(ipa_path))
        assert result["total_secrets"] > 0

    def test_secret_dedup_within_plist_value(self, tmp_path) -> None:
        ipa_path = tmp_path / "dedupplist.ipa"
        plist_dict = {
            "CFBundleIdentifier": "com.test",
            "Keys": "AKIAIOSFODNN7EXAMPLE and AKIAIOSFODNN7EXAMPLE",
        }
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps(plist_dict))
        result = detect_ipa_secrets(str(ipa_path))
        aws_count = sum(1 for f in result["findings"] if "AWS" in f["pattern"])
        assert aws_count == 1

    def test_plist_scalar_types_skipped(self, tmp_path) -> None:
        ipa_path = tmp_path / "scalars.ipa"
        plist_dict = {
            "CFBundleIdentifier": "com.test",
            "Build": 42,
            "Flag": True,
        }
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps(plist_dict))
        result = detect_ipa_secrets(str(ipa_path))
        assert result["total_secrets"] == 0

    def test_non_binary_app_files_skipped(self, tmp_path) -> None:
        ipa_path = tmp_path / "nonbin.ipa"
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps({}))
            zf.writestr("Payload/Test.app/Assets.car", b"AKIAIOSFODNN7EXAMPLE")
        result = detect_ipa_secrets(str(ipa_path))
        assert result["total_secrets"] == 0
