"""Testes do módulo ipa_analyzer.py."""

from __future__ import annotations

import plistlib
import zipfile
from datetime import datetime
from types import SimpleNamespace
from typing import ClassVar
from unittest.mock import patch

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

    def test_url_schemes_non_dict_entry(self, tmp_path) -> None:
        ipa_path = tmp_path / "nondict.ipa"
        plist_dict = {
            "CFBundleIdentifier": "com.test",
            "CFBundleURLTypes": ["not-a-dict", {"CFBundleURLSchemes": ["kept"]}],
        }
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps(plist_dict))
        result = analyze_ipa(str(ipa_path))
        assert result["url_schemes"] == ["kept"]

    def test_url_schemes_schemes_not_list(self, tmp_path) -> None:
        ipa_path = tmp_path / "notlist.ipa"
        plist_dict = {
            "CFBundleIdentifier": "com.test",
            "CFBundleURLTypes": [{"CFBundleURLSchemes": "myapp"}],
        }
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps(plist_dict))
        result = analyze_ipa(str(ipa_path))
        assert result["url_schemes"] == []

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

    def test_no_info_plist(self, tmp_path) -> None:
        ipa_path = tmp_path / "noplist.ipa"
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Other", b"data")
        result = analyze_ipa(str(ipa_path))
        assert result["bundle_id"] == ""

    def test_provisioning_parsed(self, tmp_path) -> None:
        ipa_path = tmp_path / "prov.ipa"
        prov = {
            "Name": "iOS Team Provisioning Profile: com.test",
            "TeamName": "Acme Inc",
            "TeamIdentifier": "ABCDEFGH12",
            "CreationDate": datetime(2025, 1, 1),
            "ExpirationDate": datetime(2026, 1, 1),
            "Entitlements": {
                "application-identifier": "ABCDEFGH12.com.test",
                "aps-environment": "production",
                "com.apple.security.foo": "bar",
            },
            "ProvisionedDevices": ["d1", "d2", "d3"],
        }
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr(
                "Payload/Test.app/Info.plist",
                plistlib.dumps({"CFBundleIdentifier": "com.test"}),
            )
            zf.writestr(
                "Payload/Test.app/embedded.mobileprovision",
                plistlib.dumps(prov, fmt=plistlib.FMT_XML),
            )
        result = analyze_ipa(str(ipa_path))
        assert result["provisioning"]["name"] == prov["Name"]
        assert result["provisioning"]["team_name"] == "Acme Inc"
        assert result["provisioning"]["team_id"] == "ABCDEFGH12"
        assert "2025" in result["provisioning"]["created"]
        assert "2026" in result["provisioning"]["expires"]
        assert result["provisioning"]["app_id"] == "ABCDEFGH12.com.test"
        assert result["provisioning"]["devices"] == 3
        assert result["provisioning"]["push"] is True
        assert result["entitlements"] == {
            "application-identifier": "ABCDEFGH12.com.test",
            "aps-environment": "production",
        }

    def test_provisioning_cms_extraction(self, tmp_path) -> None:
        ipa_path = tmp_path / "cms.ipa"
        prov = {
            "Name": "CMS Profile",
            "TeamName": "Acme",
            "TeamIdentifier": "TEAMID01",
            "Entitlements": {},
            "ProvisionedDevices": [],
        }
        xml = plistlib.dumps(prov, fmt=plistlib.FMT_XML)
        cms_data = b"\x30\x82\x03\x04-signed-blob-" + xml + b"-trailing"
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps({}))
            zf.writestr("Payload/Test.app/embedded.mobileprovision", cms_data)
        result = analyze_ipa(str(ipa_path))
        assert result["provisioning"]["name"] == "CMS Profile"

    def test_provisioning_no_xml(self, tmp_path) -> None:
        ipa_path = tmp_path / "noxml.ipa"
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps({}))
            zf.writestr(
                "Payload/Test.app/embedded.mobileprovision", b"\x30\x82 binary only"
            )
        result = analyze_ipa(str(ipa_path))
        assert result["provisioning"] == {}

    def test_provisioning_parse_error(self, tmp_path) -> None:
        ipa_path = tmp_path / "badprov.ipa"
        with zipfile.ZipFile(str(ipa_path), "w") as zf:
            zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps({}))
            zf.writestr(
                "Payload/Test.app/embedded.mobileprovision",
                plistlib.dumps("just a string", fmt=plistlib.FMT_XML),
            )
        result = analyze_ipa(str(ipa_path))
        assert result["provisioning"] == {}


class _FakeLib:
    name = "libSystem.dylib"


class _FakeRpath:
    path = "@executable_path/Frameworks"


class _FakeMacho:
    name = "Test"
    header = SimpleNamespace(file_type="Mach-O 64-bit")
    libraries: ClassVar[list[_FakeLib]] = [_FakeLib()]
    exported_functions: ClassVar[list[int]] = [1, 2, 3]
    symbols: ClassVar[list[str]] = ["_main", "_foo"]
    rpaths: ClassVar[list[_FakeRpath]] = [_FakeRpath()]


class _FakeMachoMinimal:
    name = "Test"
    header = SimpleNamespace(file_type="Mach-O 64-bit")


def _write_macho_ipa(ipa_path, files: list[tuple[str, bytes]]) -> None:
    with zipfile.ZipFile(str(ipa_path), "w") as zf:
        zf.writestr("Payload/Test.app/Info.plist", plistlib.dumps({}))
        for name, data in files:
            zf.writestr(name, data)


class TestMachoAnalysis:
    def test_macho_parsed(self, tmp_path) -> None:
        ipa_path = tmp_path / "macho.ipa"
        _write_macho_ipa(ipa_path, [("Payload/Test.app/Test", b"\x7fELF-fake")])
        with patch("lief.parse", return_value=_FakeMacho()):
            result = analyze_ipa(str(ipa_path))
        assert result["macho"]["name"] == "Test"
        assert "Mach-O" in result["macho"]["type"]
        assert result["macho"]["libraries"] == ["libSystem.dylib"]
        assert result["macho"]["exported_count"] == 3
        assert result["macho"]["symbol_count"] == 2
        assert result["macho"]["rpaths"] == ["@executable_path/Frameworks"]

    def test_macho_none(self, tmp_path) -> None:
        ipa_path = tmp_path / "machonone.ipa"
        _write_macho_ipa(ipa_path, [("Payload/Test.app/Test", b"\x7fELF-fake")])
        with patch("lief.parse", return_value=None):
            result = analyze_ipa(str(ipa_path))
        assert result["macho"] == {}

    def test_macho_minimal_attributes(self, tmp_path) -> None:
        ipa_path = tmp_path / "machomin.ipa"
        _write_macho_ipa(ipa_path, [("Payload/Test.app/Test", b"\x7fELF-fake")])
        with patch("lief.parse", return_value=_FakeMachoMinimal()):
            result = analyze_ipa(str(ipa_path))
        assert result["macho"]["name"] == "Test"
        assert "Mach-O" in result["macho"]["type"]
        assert result["macho"]["libraries"] == []
        assert result["macho"]["exported_count"] == 0
        assert result["macho"]["symbol_count"] == 0
        assert result["macho"]["rpaths"] == []

    def test_macho_parse_error(self, tmp_path) -> None:
        ipa_path = tmp_path / "machoerr.ipa"
        _write_macho_ipa(ipa_path, [("Payload/Test.app/Test", b"junk")])
        with patch("lief.parse", side_effect=RuntimeError("bad binary")):
            result = analyze_ipa(str(ipa_path))
        assert result["macho"] == {}

    def test_skips_arm64_and_frameworks(self, tmp_path) -> None:
        ipa_path = tmp_path / "skip.ipa"
        _write_macho_ipa(
            ipa_path,
            [
                ("Payload/Test.app/slice.arm64", b"arm"),
                ("Payload/Test.app/Frameworks/Test.dylib", b"dylib"),
                ("Payload/Test.app/Test", b"main"),
            ],
        )
        with patch("lief.parse", return_value=_FakeMacho()) as mock_parse:
            result = analyze_ipa(str(ipa_path))
        assert mock_parse.call_count == 1
        assert result["macho"]["name"] == "Test"

    def test_lief_import_error(self, tmp_path) -> None:
        ipa_path = tmp_path / "nolief.ipa"
        _write_macho_ipa(ipa_path, [("Payload/Test.app/Test", b"main")])
        with patch.dict("sys.modules", {"lief": None}):
            result = analyze_ipa(str(ipa_path))
        assert result["macho"] == {}
