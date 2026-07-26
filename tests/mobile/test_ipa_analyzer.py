"""Testes do módulo ipa_analyzer.py."""

from __future__ import annotations

import plistlib
import zipfile

from mytools.mobile.ipa_analyzer import analyze_ipa


class TestAnalyzeIpa:
    def test_nonexistent_file(self) -> None:
        result = analyze_ipa("nonexistent.ipa")
        assert result["bundle_id"] == ""
        assert "error" in result

    def test_empty_ipa(self, tmp_path) -> None:
        ipa_path = tmp_path / "empty.ipa"
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", b"not plist")
        result = analyze_ipa(str(ipa_path))
        assert isinstance(result, dict)

    def test_info_plist_parsed(self, tmp_path) -> None:
        ipa_path = tmp_path / "info.ipa"
        plist_dict = {
            "CFBundleIdentifier": "com.example.app",
            "CFBundleDisplayName": "TestApp",
            "CFBundleShortVersionString": "1.0.0",
            "CFBundleVersion": "42",
            "MinimumOSVersion": "14.0",
        }
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps(plist_dict))
        result = analyze_ipa(str(ipa_path))
        assert result["bundle_id"] == "com.example.app"
        assert result["display_name"] == "TestApp"
        assert result["version"] == "1.0.0"
        assert result["build"] == "42"
        assert result["min_os_version"] == "14.0"

    def test_url_schemes(self, tmp_path) -> None:
        ipa_path = tmp_path / "schemes.ipa"
        plist_dict = {
            "CFBundleIdentifier": "com.test",
            "CFBundleURLTypes": [
                {"CFBundleURLSchemes": ["myapp", "myapp-beta"]},
            ],
        }
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps(plist_dict))
        result = analyze_ipa(str(ipa_path))
        assert "myapp" in result["url_schemes"]
        assert "myapp-beta" in result["url_schemes"]

    def test_ats_settings(self, tmp_path) -> None:
        ipa_path = tmp_path / "ats.ipa"
        plist_dict = {
            "CFBundleIdentifier": "com.test",
            "NSAppTransportSecurity": {
                "NSAllowsArbitraryLoads": True,
                "NSExceptionDomains": {"example.com": {}},
            },
        }
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps(plist_dict))
        result = analyze_ipa(str(ipa_path))
        assert result["ats_settings"]["allows_insecure_http"] is True
        assert "example.com" in result["ats_settings"]["exception_domains"]
