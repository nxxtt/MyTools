"""Testes do módulo ipa_secrets.py."""

from __future__ import annotations

import plistlib
import zipfile

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
