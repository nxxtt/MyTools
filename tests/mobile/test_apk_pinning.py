"""Testes do módulo apk_pinning.py."""

from __future__ import annotations

import zipfile

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
