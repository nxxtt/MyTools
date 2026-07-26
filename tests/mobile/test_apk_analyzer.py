"""Testes do módulo apk_analyzer.py."""

from __future__ import annotations

from unittest.mock import patch

from mytools.mobile.apk_analyzer import _SDK_FINGERPRINTS, analyze_apk


class TestSDKFingerprints:
    def test_has_fingerprints(self) -> None:
        assert len(_SDK_FINGERPRINTS) > 20

    def test_known_sdks(self) -> None:
        assert "Firebase" in _SDK_FINGERPRINTS.values()
        assert "OkHttp" in _SDK_FINGERPRINTS.values()
        assert "React Native" in _SDK_FINGERPRINTS.values()


class TestAnalyzeApk:
    def test_import_error(self) -> None:
        with patch.dict("sys.modules", {"androguard": None}):
            result = analyze_apk("nonexistent.apk")
            assert "error" in result

    def test_nonexistent_file(self) -> None:
        result = analyze_apk("nonexistent.apk")
        # Should handle gracefully (either error or exception)
        assert isinstance(result, dict)
