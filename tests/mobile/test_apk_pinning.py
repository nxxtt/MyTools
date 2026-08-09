"""Testes do módulo apk_pinning.py."""

from __future__ import annotations

import zipfile
from unittest.mock import patch

from mytools.mobile.apk_pinning import _PINNING_PATTERNS, detect_pinning


class TestPinningPatterns:
    def test_has_patterns(self) -> None:
        assert len(_PINNING_PATTERNS) > 15

    def test_known_patterns(self) -> None:
        assert "OkHttp CertificatePinner" in _PINNING_PATTERNS
        assert "TrustManager (custom)" in _PINNING_PATTERNS
        assert "NetworkSecurityConfig" in _PINNING_PATTERNS


class TestDetectPinning:
    def test_nonexistent_file(self) -> None:
        result = detect_pinning("nonexistent.apk")
        assert "error" in result
        assert result["vulnerable"] is False

    def test_empty_apk(self, tmp_path) -> None:
        apk_path = tmp_path / "empty.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"no pinning here")
        result = detect_pinning(str(apk_path))
        assert result["vulnerable"] is False
        assert isinstance(result["techniques"], list)

    def test_pinning_detected(self, tmp_path) -> None:
        apk_path = tmp_path / "pinned.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"CertificatePinner checkServerTrusted")
        result = detect_pinning(str(apk_path))
        assert result["vulnerable"] is True
        assert len(result["techniques"]) >= 2

    def test_nsc_detected(self, tmp_path) -> None:
        apk_path = tmp_path / "nsc.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"network_security_config")
            zf.writestr("res/xml/network_security_config.xml", b"pin-set")
        result = detect_pinning(str(apk_path))
        assert result["nsc_indicators"] or result["techniques"]

    def test_manifest_nsc_ref(self, tmp_path) -> None:
        apk_path = tmp_path / "manifest.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"")
            zf.writestr(
                "AndroidManifest.xml", b'android:networkSecurityConfig="@xml/nsc"'
            )
        result = detect_pinning(str(apk_path))
        assert "manifest_networkSecurityConfig_ref" in result["nsc_indicators"]
        assert result["vulnerable"] is True

    def test_dex_read_error_skipped(self, tmp_path) -> None:
        apk_path = tmp_path / "baddex.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"CertificatePinner")
            zf.writestr("classes2.dex", b"ok")

        def _boom(name: str) -> bytes:
            if name == "classes.dex":
                raise RuntimeError("corrupt")
            return b""

        with patch.object(zipfile.ZipFile, "read", side_effect=_boom):
            result = detect_pinning(str(apk_path))
        assert result["techniques"] == []

    def test_nsc_read_error_skipped(self, tmp_path) -> None:
        apk_path = tmp_path / "badnsc.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"")
            zf.writestr("res/xml/network_security_config.xml", b"pin-set")

        def _boom(name: str) -> bytes:
            if "network_security_config" in name:
                raise RuntimeError("corrupt")
            return b""

        with patch.object(zipfile.ZipFile, "read", side_effect=_boom):
            result = detect_pinning(str(apk_path))
        assert result["nsc_indicators"] == []

    def test_manifest_read_error_skipped(self, tmp_path) -> None:
        apk_path = tmp_path / "badmanifest.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"")
            zf.writestr("AndroidManifest.xml", b"networkSecurityConfig")

        def _boom(name: str) -> bytes:
            if name == "AndroidManifest.xml":
                raise RuntimeError("corrupt")
            return b""

        with patch.object(zipfile.ZipFile, "read", side_effect=_boom):
            result = detect_pinning(str(apk_path))
        assert "manifest_networkSecurityConfig_ref" not in result["nsc_indicators"]

    def test_manifest_without_nsc_ref(self, tmp_path) -> None:
        apk_path = tmp_path / "plainmanifest.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"")
            zf.writestr(
                "AndroidManifest.xml", b"<manifest package='com.example.test'/>"
            )
        result = detect_pinning(str(apk_path))
        assert "manifest_networkSecurityConfig_ref" not in result["nsc_indicators"]
        assert result["vulnerable"] is False
