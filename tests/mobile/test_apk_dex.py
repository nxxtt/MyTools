"""Testes do modulo apk_dex.py — DEX Layer, Dalvik Disassembly, Java Decompilation."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from mytools.mobile.apk_dex import analyze_dex_layer, decompile_java, disassemble_dalvik

APK_FIXTURE = Path(__file__).parent.parent / "fixtures" / "SportzX_3.0v.apk"


# ---------------------------------------------------------------------------
# _load_apk helper
# ---------------------------------------------------------------------------


class TestLoadApk:
    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError, match="File not found"):
            from mytools.mobile.apk_dex import _load_apk

            _load_apk("nonexistent.apk")

    def test_invalid_file(self, tmp_path: Path) -> None:
        p = tmp_path / "fake.apk"
        p.write_bytes(b"not an apk")
        from mytools.mobile.apk_dex import _load_apk

        with pytest.raises((ValueError, Exception, OSError)):
            _load_apk(str(p))

    def test_import_error(self) -> None:
        from mytools.mobile.apk_dex import _load_apk

        with (
            patch("mytools.mobile.apk_dex.Path.is_file", return_value=True),
            patch.dict("sys.modules", {"androguard": None, "androguard.misc": None}),
            pytest.raises(ImportError, match="androguard not installed"),
        ):
            _load_apk("test.apk")

    def test_success_returns_triple(self) -> None:
        from mytools.mobile.apk_dex import _load_apk

        mock_a = MagicMock()
        mock_dex = MagicMock()
        mock_dx = MagicMock()
        with (
            patch("mytools.mobile.apk_dex.Path.is_file", return_value=True),
            patch(
                "androguard.misc.AnalyzeAPK",
                return_value=(mock_a, [mock_dex], mock_dx),
            ),
        ):
            result = _load_apk("test.apk")
        assert result == (mock_a, [mock_dex], mock_dx)


# ---------------------------------------------------------------------------
# analyze_dex_layer
# ---------------------------------------------------------------------------


class TestAnalyzeDexLayer:
    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            analyze_dex_layer("nonexistent.apk")

    def test_invalid_file(self, tmp_path: Path) -> None:
        p = tmp_path / "fake.apk"
        p.write_bytes(b"not an apk")
        with pytest.raises((ValueError, Exception, OSError)):
            analyze_dex_layer(str(p))


# ---------------------------------------------------------------------------
# disassemble_dalvik
# ---------------------------------------------------------------------------


class TestDisassembleDalvik:
    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            disassemble_dalvik("nonexistent.apk")

    def test_invalid_file(self, tmp_path: Path) -> None:
        p = tmp_path / "fake.apk"
        p.write_bytes(b"not an apk")
        with pytest.raises((ValueError, Exception, OSError)):
            disassemble_dalvik(str(p))


# ---------------------------------------------------------------------------
# decompile_java
# ---------------------------------------------------------------------------


class TestDecompileJava:
    def test_file_not_found(self) -> None:
        with pytest.raises(FileNotFoundError):
            decompile_java("nonexistent.apk")

    def test_invalid_file(self, tmp_path: Path) -> None:
        p = tmp_path / "fake.apk"
        p.write_bytes(b"not an apk")
        with pytest.raises((ValueError, Exception, OSError)):
            decompile_java(str(p))


# ---------------------------------------------------------------------------
# Mock-based unit tests
# ---------------------------------------------------------------------------


def _mock_dex_class(
    name: str = "Lcom/test/Foo;", source: str = "package com.test;\npublic class Foo {}"
) -> MagicMock:
    mock = MagicMock()
    mock.get_name.return_value = name
    mock.get_source.return_value = source
    return mock


def _mock_dex(
    classes: list[str] | None = None, methods: list[str] | None = None
) -> MagicMock:
    mock = MagicMock()
    mock.get_classes_names.return_value = classes or ["Lcom/test/Foo;"]
    mock.get_classes.return_value = [
        _mock_dex_class(n) for n in (classes or ["Lcom/test/Foo;"])
    ]

    encoded_methods = []
    for m_name in methods or ["<init>"]:
        m = MagicMock()
        m.get_class_name.return_value = "Lcom/test/Foo;"
        m.get_name.return_value = m_name
        m.get_descriptor.return_value = "()V"
        m.get_access_flags.return_value = 1
        m.get_code.return_value = MagicMock()
        encoded_methods.append(m)
    mock.get_encoded_methods.return_value = encoded_methods

    header = MagicMock()
    header.magic = b"dex\n035\0"
    header.file_size = 1024
    header.dex_version = 35
    header.endian_tag = 12345
    header.checksum = "abc123"
    mock.get_header_item.return_value = header

    string_mock = MagicMock()
    string_mock.get_value.return_value = "test_string"
    mock.get_strings.return_value = [string_mock]

    return mock


class TestAnalyzeDexLayerMock:
    @patch("mytools.mobile.apk_dex._load_apk")
    def test_returns_correct_structure(self, mock_load: MagicMock) -> None:
        mock_dex = _mock_dex()
        mock_a = MagicMock()
        mock_a.get_package.return_value = "com.test"
        mock_load.return_value = (mock_a, [mock_dex], MagicMock())

        result = analyze_dex_layer("test.apk")
        assert result["dex_count"] == 1
        assert result["package"] == "com.test"
        assert result["total_classes"] == 1
        assert result["total_methods"] == 1
        assert result["total_strings"] == 1
        assert len(result["dex_files"]) == 1
        assert result["dex_files"][0]["header"]["magic"] == "b'dex\\n035\\x00'"

    @patch("mytools.mobile.apk_dex._load_apk")
    def test_multidex(self, mock_load: MagicMock) -> None:
        mock_dex1 = _mock_dex(classes=["Lcom/a/Foo;"])
        mock_dex2 = _mock_dex(classes=["Lcom/b/Bar;"])
        mock_a = MagicMock()
        mock_a.get_package.return_value = "com.multi"
        mock_load.return_value = (mock_a, [mock_dex1, mock_dex2], MagicMock())

        result = analyze_dex_layer("test.apk")
        assert result["dex_count"] == 2
        assert result["total_classes"] == 2

    @patch("androguard.misc.AnalyzeAPK", return_value=(MagicMock(), [], MagicMock()))
    @patch("mytools.mobile.apk_dex.Path.is_file", return_value=True)
    def test_empty_dex_raises(
        self, mock_isfile: MagicMock, mock_analyze: MagicMock
    ) -> None:
        from mytools.mobile.apk_dex import _load_apk

        with pytest.raises(ValueError, match="No DEX files"):
            _load_apk("test.apk")


class TestDisassembleDalvikMock:
    @patch("mytools.mobile.apk_dex._load_apk")
    def test_returns_correct_structure(self, mock_load: MagicMock) -> None:
        mock_dex = _mock_dex()
        mock_a = MagicMock()
        mock_load.return_value = (mock_a, [mock_dex], MagicMock())

        result = disassemble_dalvik("test.apk")
        assert "methods" in result
        assert "total_methods" in result
        assert "total_instructions" in result
        assert "truncated" in result

    @patch("mytools.mobile.apk_dex._load_apk")
    def test_max_methods_truncates(self, mock_load: MagicMock) -> None:
        methods = [f"method_{i}" for i in range(30)]
        mock_dex = _mock_dex(methods=methods)
        mock_a = MagicMock()
        mock_load.return_value = (mock_a, [mock_dex], MagicMock())

        result = disassemble_dalvik("test.apk", max_methods=5)
        assert result["truncated"] is True
        assert len(result["methods"]) == 5

    @patch("mytools.mobile.apk_dex._load_apk")
    def test_class_filter(self, mock_load: MagicMock) -> None:
        mock_dex = _mock_dex()
        mock_a = MagicMock()
        mock_load.return_value = (mock_a, [mock_dex], MagicMock())

        result = disassemble_dalvik("test.apk", class_filter="nonexistent")
        assert result["total_methods"] == 0

    @patch("mytools.mobile.apk_dex._load_apk")
    def test_no_code_methods_skipped(self, mock_load: MagicMock) -> None:
        mock_dex = _mock_dex()
        # Set code to None for all methods (abstract/native)
        for m in mock_dex.get_encoded_methods():
            m.get_code.return_value = None
        mock_a = MagicMock()
        mock_load.return_value = (mock_a, [mock_dex], MagicMock())

        result = disassemble_dalvik("test.apk")
        assert result["total_methods"] == 0

    @patch("mytools.mobile.apk_dex._load_apk")
    def test_instruction_error_skipped(self, mock_load: MagicMock) -> None:
        mock_dex = _mock_dex()
        for m in mock_dex.get_encoded_methods():
            m.get_instructions.side_effect = RuntimeError("disasm failed")
        mock_a = MagicMock()
        mock_load.return_value = (mock_a, [mock_dex], MagicMock())

        result = disassemble_dalvik("test.apk")
        assert result["total_methods"] == 1
        assert result["methods"] == []


class TestDecompileJavaMock:
    @patch("mytools.mobile.apk_dex._load_apk")
    def test_returns_correct_structure(self, mock_load: MagicMock) -> None:
        mock_dex = _mock_dex()
        mock_a = MagicMock()
        mock_load.return_value = (mock_a, [mock_dex], MagicMock())

        result = decompile_java("test.apk")
        assert "classes" in result
        assert "total_decompiled" in result
        assert "total_empty" in result
        assert "truncated" in result

    @patch("mytools.mobile.apk_dex._load_apk")
    def test_max_classes_truncates(self, mock_load: MagicMock) -> None:
        classes = [f"Lcom/test/Class{i};" for i in range(20)]
        mock_dex = _mock_dex(classes=classes)
        mock_a = MagicMock()
        mock_load.return_value = (mock_a, [mock_dex], MagicMock())

        result = decompile_java("test.apk", max_classes=3)
        assert result["truncated"] is True
        assert result["total_decompiled"] == 3

    @patch("mytools.mobile.apk_dex._load_apk")
    def test_class_filter(self, mock_load: MagicMock) -> None:
        mock_dex = _mock_dex()
        mock_a = MagicMock()
        mock_load.return_value = (mock_a, [mock_dex], MagicMock())

        result = decompile_java("test.apk", class_filter="nonexistent")
        assert result["total_decompiled"] == 0

    @patch("mytools.mobile.apk_dex._load_apk")
    def test_framework_classes_skipped(self, mock_load: MagicMock) -> None:
        mock_dex = _mock_dex(classes=["Landroid/app/Activity;", "Ljava/lang/String;"])
        mock_a = MagicMock()
        mock_load.return_value = (mock_a, [mock_dex], MagicMock())

        result = decompile_java("test.apk")
        assert result["total_classes"] == 0

    @patch("mytools.mobile.apk_dex._load_apk")
    def test_empty_source_counted(self, mock_load: MagicMock) -> None:
        mock_class = _mock_dex_class(source="")
        mock_dex = MagicMock()
        mock_dex.get_classes.return_value = [mock_class]
        mock_a = MagicMock()
        mock_load.return_value = (mock_a, [mock_dex], MagicMock())

        result = decompile_java("test.apk")
        assert result["total_empty"] == 1
        assert result["total_decompiled"] == 0

    @patch("mytools.mobile.apk_dex._load_apk")
    def test_get_source_error_skipped(self, mock_load: MagicMock) -> None:
        mock_class = _mock_dex_class()
        mock_class.get_source.side_effect = RuntimeError("decompile failed")
        mock_dex = MagicMock()
        mock_dex.get_classes.return_value = [mock_class]
        mock_a = MagicMock()
        mock_load.return_value = (mock_a, [mock_dex], MagicMock())

        result = decompile_java("test.apk")
        assert result["total_empty"] == 1
        assert result["total_decompiled"] == 0

    @patch("mytools.mobile.apk_dex._load_apk")
    def test_method_count_from_source(self, mock_load: MagicMock) -> None:
        source = (
            "package com.test;\n"
            "public class Foo {\n"
            "    public void run() {}\n"
            "    private int count() { return 1; }\n"
            "    static void util() {}\n"
            "    void plain() {}\n"
            "}\n"
        )
        mock_class = _mock_dex_class(source=source)
        mock_dex = MagicMock()
        mock_dex.get_classes.return_value = [mock_class]
        mock_a = MagicMock()
        mock_load.return_value = (mock_a, [mock_dex], MagicMock())

        result = decompile_java("test.apk")
        assert result["total_decompiled"] == 1
        assert result["classes"][0]["method_count"] == 4
        assert result["classes"][0]["line_count"] == 8


# ---------------------------------------------------------------------------
# Integration tests with real APK fixture
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not APK_FIXTURE.exists(), reason="APK fixture not found")
class TestWithFixture:
    def test_dex_layer_real(self) -> None:
        result = analyze_dex_layer(str(APK_FIXTURE))
        assert result["package"] == "com.sportzx.live"
        assert result["dex_count"] >= 1
        assert result["total_classes"] > 0
        assert result["total_methods"] > 0

    def test_disasm_real(self) -> None:
        result = disassemble_dalvik(str(APK_FIXTURE))
        assert result["total_methods"] > 0
        assert result["total_instructions"] > 0
        assert len(result["methods"]) > 0
        assert result["methods"][0]["instruction_count"] > 0

    def test_decompile_real(self) -> None:
        result = decompile_java(str(APK_FIXTURE))
        assert result["total_decompiled"] > 0
        assert len(result["classes"]) > 0
        assert result["classes"][0]["line_count"] > 0


# ---------------------------------------------------------------------------
# Mobile audit dispatch tests
# ---------------------------------------------------------------------------


class TestMobileAuditDispatch:
    def test_dex_check_choice_exists(self) -> None:
        from mytools.mobile.mobile_audit import MobileAuditScanner

        s = MobileAuditScanner()
        parser = s.build_parser()
        args = parser.parse_args(["app.apk", "-c", "apk_dex"])
        assert "apk_dex" in args.checks

    def test_disasm_check_choice_exists(self) -> None:
        from mytools.mobile.mobile_audit import MobileAuditScanner

        s = MobileAuditScanner()
        parser = s.build_parser()
        args = parser.parse_args(["app.apk", "-c", "apk_disasm"])
        assert "apk_disasm" in args.checks

    def test_decompile_check_choice_exists(self) -> None:
        from mytools.mobile.mobile_audit import MobileAuditScanner

        s = MobileAuditScanner()
        parser = s.build_parser()
        args = parser.parse_args(["app.apk", "-c", "apk_decompile"])
        assert "apk_decompile" in args.checks

    def test_help_includes_new_checks(self) -> None:
        from mytools.mobile.mobile_audit import MobileAuditScanner

        s = MobileAuditScanner()
        help_text = s._help()
        assert "apk_dex" in help_text
        assert "apk_disasm" in help_text
        assert "apk_decompile" in help_text
