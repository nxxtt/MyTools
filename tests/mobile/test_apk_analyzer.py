"""Testes do módulo apk_analyzer.py."""

from __future__ import annotations

from unittest.mock import patch

from mytools.mobile.apk_analyzer import (
    _SDK_FINGERPRINTS,
    _extract_exported,
    _is_exported,
    analyze_apk,
)

_NS = "{http://schemas.android.com/apk/res/android}"


class TestSDKFingerprints:
    def test_has_fingerprints(self) -> None:
        assert len(_SDK_FINGERPRINTS) > 20

    def test_known_sdks(self) -> None:
        assert "Firebase" in _SDK_FINGERPRINTS.values()
        assert "OkHttp" in _SDK_FINGERPRINTS.values()
        assert "React Native" in _SDK_FINGERPRINTS.values()


class _FakeElem:
    def __init__(
        self, name: str, exported: str | None = None, intent_filter: bool = False
    ) -> None:
        self._name = name
        self._exported = exported
        self._intent_filter = intent_filter

    def get(self, key: str, default: str | None = None) -> str | None:
        if key == f"{_NS}name":
            return self._name
        if key == f"{_NS}exported":
            return self._exported if self._exported is not None else default
        return default

    def findall(self, tag: str) -> list[int]:
        return [1] if tag == "intent-filter" and self._intent_filter else []


class _FakeManifest:
    def __init__(self, mapping: dict[str, list[_FakeElem]]) -> None:
        self._mapping = mapping

    def iter(self, tag: str) -> list[_FakeElem]:
        return self._mapping.get(tag, [])


class _FakeApk:
    def __init__(self, manifest: _FakeManifest | None = None) -> None:
        self._manifest = manifest

    def get_package(self) -> str:
        return "com.example.app"

    def get_androidversion_name(self) -> str:
        return "1.0"

    def get_androidversion_code(self) -> str:
        return "10"

    def get_min_sdk_version(self) -> str:
        return "21"

    def get_target_sdk_version(self) -> str:
        return "33"

    def get_permissions(self) -> list[str]:
        return ["android.permission.INTERNET", "android.permission.CAMERA"]

    def get_activities(self) -> list[str]:
        return ["com.example.MainActivity", "com.example.ExportedActivity"]

    def get_services(self) -> list[str]:
        return ["com.example.SyncService"]

    def get_receivers(self) -> list[str]:
        return ["com.example.BootReceiver"]

    def get_providers(self) -> list[str]:
        return ["com.example.FileProvider"]

    def get_android_manifest_xml(self) -> _FakeManifest | None:
        return self._manifest


class _FakeStr:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_value(self) -> str:
        return self._value


class _FakeDx:
    def __init__(self, strings: list[str], raise_on_strings: bool = False) -> None:
        self._strings = strings
        self._raise = raise_on_strings

    def get_strings(self) -> list[_FakeStr]:
        if self._raise:
            raise RuntimeError("boom")
        return [_FakeStr(s) for s in self._strings]


class TestAnalyzeApk:
    def test_import_error(self) -> None:
        with patch.dict("sys.modules", {"androguard": None}):
            result = analyze_apk("nonexistent.apk")
            assert "error" in result

    def test_nonexistent_file(self) -> None:
        result = analyze_apk("nonexistent.apk")
        assert isinstance(result, dict)

    @patch("androguard.misc.AnalyzeAPK", side_effect=RuntimeError("parse failed"))
    def test_parse_error_returns_error(self, _mock) -> None:
        result = analyze_apk("any.apk")
        assert result == {"error": "parse failed"}

    def test_full_analysis(self, tmp_path) -> None:
        p = tmp_path / "real.apk"
        p.write_bytes(b"MZfake")
        manifest = _FakeManifest(
            {
                "activity": [
                    _FakeElem("com.example.ExportedActivity", exported="true"),
                    _FakeElem("com.example.Hidden", exported="false"),
                    _FakeElem("com.example.IntentExported", intent_filter=True),
                ],
                "service": [_FakeElem("com.example.SyncService", exported="true")],
                "receiver": [_FakeElem("com.example.BootReceiver", exported="false")],
                "provider": [],
            }
        )
        apk = _FakeApk(manifest)
        dx = _FakeDx(
            ["com.google.firebase.analytics", "com.squareup.okhttp.OkHttpClient"]
        )

        def fake_analyze(path):
            return apk, [], dx

        with patch("androguard.misc.AnalyzeAPK", side_effect=fake_analyze):
            result = analyze_apk(str(p))

        assert result["package"] == "com.example.app"
        assert result["version_name"] == "1.0"
        assert result["version_code"] == "10"
        assert result["min_sdk"] == "21"
        assert result["target_sdk"] == "33"
        assert result["permissions_count"] == 2
        assert "Firebase" in result["sdk_fingerprints"]
        assert "OkHttp" in result["sdk_fingerprints"]
        assert result["exported_activities"] == [
            "com.example.ExportedActivity",
            "com.example.IntentExported",
        ]
        assert result["exported_services"] == ["com.example.SyncService"]
        assert result["exported_receivers"] == []
        assert result["exported_providers"] == []
        assert result["file_size"] == p.stat().st_size

    def test_manifest_none_falls_back_to_lists(self, tmp_path) -> None:
        p = tmp_path / "real.apk"
        p.write_bytes(b"MZfake")
        apk = _FakeApk(manifest=None)
        dx = _FakeDx([])

        with patch("androguard.misc.AnalyzeAPK", return_value=(apk, [], dx)):
            result = analyze_apk(str(p))

        assert result["exported_activities"] == sorted(
            ["com.example.MainActivity", "com.example.ExportedActivity"]
        )
        assert result["exported_services"] == ["com.example.SyncService"]
        assert result["exported_receivers"] == ["com.example.BootReceiver"]
        assert result["exported_providers"] == ["com.example.FileProvider"]

    def test_strings_exception_ignored(self, tmp_path) -> None:
        p = tmp_path / "real.apk"
        p.write_bytes(b"MZfake")
        apk = _FakeApk(_FakeManifest({}))
        dx = _FakeDx([], raise_on_strings=True)

        with patch("androguard.misc.AnalyzeAPK", return_value=(apk, [], dx)):
            result = analyze_apk(str(p))

        assert result["sdk_fingerprints"] == []


class TestIsExported:
    def test_exported_true(self) -> None:
        assert _is_exported(_FakeElem("X", exported="true")) is True

    def test_exported_false(self) -> None:
        assert _is_exported(_FakeElem("X", exported="false")) is False

    def test_missing_attr_with_intent_filter(self) -> None:
        assert _is_exported(_FakeElem("X", intent_filter=True)) is True

    def test_missing_attr_without_intent_filter(self) -> None:
        assert _is_exported(_FakeElem("X", intent_filter=False)) is False


class TestExtractExported:
    def test_extracts_and_sorts(self) -> None:
        manifest = _FakeManifest(
            {
                "activity": [
                    _FakeElem("com.example.B", exported="true"),
                    _FakeElem("com.example.A", exported="true"),
                    _FakeElem("com.example.C", exported="false"),
                ]
            }
        )
        assert _extract_exported(manifest, "activity") == [
            "com.example.A",
            "com.example.B",
        ]

    def test_empty(self) -> None:
        assert _extract_exported(_FakeManifest({}), "provider") == []
