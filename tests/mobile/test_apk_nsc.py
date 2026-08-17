"""Testes do módulo apk_nsc.py."""

from __future__ import annotations

import zipfile
from unittest.mock import patch

from mytools.mobile.apk_nsc import _NSC_BINARY_PATTERNS, analyze_nsc


class TestAnalyzeNsc:
    def test_nonexistent_file(self) -> None:
        result = analyze_nsc("nonexistent.apk")
        assert "error" in result
        assert result["has_nsc"] is False

    def test_empty_apk(self, tmp_path) -> None:
        apk_path = tmp_path / "empty.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("AndroidManifest.xml", b"no nsc")
        result = analyze_nsc(str(apk_path))
        assert result["has_nsc"] is False

    def test_nsc_found(self, tmp_path) -> None:
        apk_path = tmp_path / "nsc.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr(
                "res/xml/network_security_config.xml",
                b"cleartextTrafficPermitted pin-set",
            )
        result = analyze_nsc(str(apk_path))
        assert result["has_nsc"] is True
        assert result["has_cleartext"] is True
        assert result["has_pins"] is True

    def test_nsc_pattern_elif_false(self, tmp_path) -> None:
        apk_path = tmp_path / "elif.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr(
                "res/xml/network_security_config.xml",
                b"custom-pattern",
            )
        patterns = dict(_NSC_BINARY_PATTERNS)
        patterns["custom"] = b"custom-pattern"
        with patch("mytools.mobile.apk_nsc._NSC_BINARY_PATTERNS", patterns):
            result = analyze_nsc(str(apk_path))
        assert result["debug_overrides"] is False
        assert all("pin-set" not in f for f in result["findings"])

    def test_debug_overrides(self, tmp_path) -> None:
        apk_path = tmp_path / "debug.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr(
                "res/xml/network_security_config.xml",
                b'debug-overrides trust-anchors <certificates src="user"/>',
            )
        result = analyze_nsc(str(apk_path))
        assert result["debug_overrides"] is True
        assert result["trust_user_ca"] is True
        assert result["risk_score"] > 0

    def test_manifest_ref(self, tmp_path) -> None:
        apk_path = tmp_path / "manifest.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("AndroidManifest.xml", b"networkSecurityConfig")
        result = analyze_nsc(str(apk_path))
        assert any("manifest" in f.lower() for f in result["findings"])

    def test_system_ca(self, tmp_path) -> None:
        apk_path = tmp_path / "system.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr(
                "res/xml/network_security_config.xml",
                b'<certificates src="system"/>',
            )
        result = analyze_nsc(str(apk_path))
        assert result["trust_system_ca"] is True
        assert any("system CA" in f for f in result["findings"])

    def test_bare_user_token_not_trusted(self, tmp_path) -> None:
        apk_path = tmp_path / "fp.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr(
                "res/xml/network_security_config.xml",
                b"debug-overrides userAgent systemService",
            )
        result = analyze_nsc(str(apk_path))
        assert result["trust_user_ca"] is False
        assert result["trust_system_ca"] is False
        assert result["has_cleartext"] is False

    def test_nsc_read_error_ignored(self, tmp_path) -> None:
        apk_path = tmp_path / "badread.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("res/xml/network_security_config.xml", b"pin-set")

        def _boom(name: str) -> bytes:
            if "network_security_config" in name:
                raise RuntimeError("corrupt")
            return b""

        with patch.object(zipfile.ZipFile, "read", side_effect=_boom):
            result = analyze_nsc(str(apk_path))
        assert result["has_nsc"] is True
        assert result["has_pins"] is False

    def test_manifest_read_error_ignored(self, tmp_path) -> None:
        apk_path = tmp_path / "badmanifest.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("AndroidManifest.xml", b"networkSecurityConfig")

        def _boom(name: str) -> bytes:
            if name == "AndroidManifest.xml":
                raise RuntimeError("corrupt")
            return b""

        with patch.object(zipfile.ZipFile, "read", side_effect=_boom):
            result = analyze_nsc(str(apk_path))
        assert result["has_nsc"] is False
        assert all("Manifest" not in f for f in result["findings"])
