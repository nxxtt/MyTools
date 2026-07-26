"""Testes do módulo apk_nsc.py."""

from __future__ import annotations

import zipfile

from mytools.mobile.apk_nsc import analyze_nsc


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

    def test_debug_overrides(self, tmp_path) -> None:
        apk_path = tmp_path / "debug.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr(
                "res/xml/network_security_config.xml",
                b"debug-overrides trust-anchors certificates user",
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
