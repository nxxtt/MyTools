"""Testes do módulo apk_secrets.py."""

from __future__ import annotations

import zipfile
from unittest.mock import patch

from mytools.mobile.apk_secrets import _SECRET_PATTERNS, detect_secrets


class TestSecretPatterns:
    def test_has_patterns(self) -> None:
        assert len(_SECRET_PATTERNS) > 10

    def test_known_patterns(self) -> None:
        assert "Google API Key" in _SECRET_PATTERNS
        assert "AWS Access Key" in _SECRET_PATTERNS
        assert "GitHub Token" in _SECRET_PATTERNS
        assert "Private Key Block" in _SECRET_PATTERNS
        assert "JWT Token" in _SECRET_PATTERNS


class TestDetectSecrets:
    def test_nonexistent_file(self) -> None:
        result = detect_secrets("nonexistent.apk")
        assert "error" in result
        assert result["total_secrets"] == 0

    def test_empty_apk(self, tmp_path) -> None:
        apk_path = tmp_path / "clean.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"no secrets here")
        result = detect_secrets(str(apk_path))
        assert result["total_secrets"] == 0

    def test_aws_key_detected(self, tmp_path) -> None:
        apk_path = tmp_path / "secrets.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"AKIAIOSFODNN7EXAMPLE")
        result = detect_secrets(str(apk_path))
        assert result["total_secrets"] > 0
        assert any("AWS" in f["pattern"] for f in result["findings"])

    def test_jwt_detected(self, tmp_path) -> None:
        apk_path = tmp_path / "jwt.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr(
                "classes.dex",
                b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
            )
        result = detect_secrets(str(apk_path))
        assert result["total_secrets"] > 0

    def test_private_key_detected(self, tmp_path) -> None:
        apk_path = tmp_path / "key.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"-----BEGIN RSA PRIVATE KEY-----")
        result = detect_secrets(str(apk_path))
        assert result["total_secrets"] > 0

    def test_hardcoded_password(self, tmp_path) -> None:
        apk_path = tmp_path / "pwd.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b'password = "SuperSecret123"')
        result = detect_secrets(str(apk_path))
        assert result["total_secrets"] > 0

    def test_deduplication_by_value(self, tmp_path) -> None:
        apk_path = tmp_path / "dedup.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr(
                "classes.dex",
                b"AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE AKIAIOSFODNN7EXAMPLE",
            )
        result = detect_secrets(str(apk_path))
        aws_count = sum(1 for f in result["findings"] if "AWS" in f["pattern"])
        assert aws_count == 1
        assert result["unique_patterns"] == 1

    def test_dex_read_error_skipped(self, tmp_path) -> None:
        apk_path = tmp_path / "bad.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"AKIAIOSFODNN7EXAMPLE")
            zf.writestr("classes2.dex", b"ok")

        def _boom(name: str) -> bytes:
            if name == "classes.dex":
                raise RuntimeError("corrupt")
            return b""

        with patch.object(zipfile.ZipFile, "read", side_effect=_boom):
            result = detect_secrets(str(apk_path))
        assert result["total_secrets"] == 0
