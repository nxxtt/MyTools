"""Testes do módulo mobile_audit.py — BaseScanner CLI."""

from __future__ import annotations

import argparse
import runpy
from typing import ClassVar
from unittest.mock import patch

import pytest

from mytools.mobile._common import MobileAttempt, MobileResult
from mytools.mobile.mobile_audit import MobileAuditScanner, _is_apk, _is_ipa, _run_check


class TestFileType:
    def test_is_apk(self) -> None:
        assert _is_apk("app.apk") is True
        assert _is_apk("APP.APK") is True
        assert _is_apk("app.ipa") is False
        assert _is_apk("app.txt") is False

    def test_is_ipa(self) -> None:
        assert _is_ipa("app.ipa") is True
        assert _is_ipa("APP.IPA") is True
        assert _is_ipa("app.apk") is False


class TestMobileAuditScanner:
    def test_has_attributes(self) -> None:
        s = MobileAuditScanner()
        assert s.prog == "mytools-mobile"
        assert s.group.value == 2  # ScanGroup.B

    def test_build_parser(self) -> None:
        s = MobileAuditScanner()
        parser = s.build_parser()
        args = parser.parse_args(["app.apk"])
        assert args.file_path == "app.apk"

    def test_build_parser_with_checks(self) -> None:
        s = MobileAuditScanner()
        parser = s.build_parser()
        args = parser.parse_args(["app.apk", "-c", "apk_pinning", "apk_secrets"])
        assert args.checks == ["apk_pinning", "apk_secrets"]

    def test_get_target(self) -> None:
        args = argparse.Namespace(file_path="test.apk")
        assert MobileAuditScanner._get_target(args) == "test.apk"

    def test_get_target_none(self) -> None:
        args = argparse.Namespace(file_path=None)
        assert MobileAuditScanner._get_target(args) is None

    def test_build_run_once_kwargs(self) -> None:
        s = MobileAuditScanner()
        args = argparse.Namespace(
            file_path="test.apk",
            checks=["apk_pinning"],
            idp=None,
            client_id=None,
            client_secret="",
            jwt=None,
        )
        kwargs = s._build_run_once_kwargs(args)
        assert kwargs["file_path"] == "test.apk"
        assert kwargs["checks"] == ["apk_pinning"]

    @pytest.mark.asyncio
    async def test_run_scan_no_file(self) -> None:
        s = MobileAuditScanner()
        result = await s.run_scan(file_path=None)
        assert result.overall_status == "error"

    @pytest.mark.asyncio
    async def test_run_scan_nonexistent(self) -> None:
        s = MobileAuditScanner()
        result = await s.run_scan(file_path="nonexistent.apk")
        assert result.overall_status == "error"

    @pytest.mark.asyncio
    async def test_run_scan_unsupported(self, tmp_path) -> None:
        p = tmp_path / "test.txt"
        p.write_text("not a mobile file")
        s = MobileAuditScanner()
        result = await s.run_scan(file_path=str(p))
        assert result.overall_status == "error"

    def test_example(self) -> None:
        s = MobileAuditScanner()
        assert "scan" in s._example()

    def test_help(self) -> None:
        s = MobileAuditScanner()
        assert "APK" in s._help()
        assert "IPA" in s._help()


class TestRunScanChecks:
    APK_DATA: ClassVar[dict[str, object]] = {
        "package": "com.test",
        "version_name": "1.0",
        "version_code": "1",
        "target_sdk": "33",
        "min_sdk": "21",
        "permissions_count": 3,
        "activities": ["com.test.Main"],
        "services": ["com.test.Svc"],
        "sdk_fingerprints": ["Firebase"],
    }
    DEX_DATA: ClassVar[dict[str, object]] = {
        "dex_count": 1,
        "package": "com.test",
        "total_classes": 2,
        "total_methods": 3,
        "total_strings": 4,
        "dex_files": [{"index": 0, "class_count": 2, "method_count": 3}],
    }
    DISASM_DATA: ClassVar[dict[str, object]] = {
        "total_methods": 3,
        "total_instructions": 10,
        "truncated": True,
        "methods": [
            {"class_name": "Lcom/test;", "method_name": "m", "instruction_count": 2}
        ],
    }
    PINNING_DATA: ClassVar[dict[str, object]] = {
        "techniques": ["OkHttp CertificatePinner"],
        "nsc_indicators": ["pin-set"],
        "vulnerable": True,
    }
    ENDPOINTS_DATA: ClassVar[dict[str, object]] = {
        "urls": ["https://api.example.com/x"],
        "api_paths": ["/api/v1"],
        "firebase_urls": ["https://x.firebaseio.com"],
        "schemes": ["myapp://"],
        "total_endpoints": 3,
    }
    SECRETS_DATA: ClassVar[dict[str, object]] = {
        "findings": [{"pattern": "AWS", "value": "AKIAIOSFODNN7EXAMPLE"}],
        "total_secrets": 1,
    }
    NSC_DATA: ClassVar[dict[str, object]] = {
        "findings": ["NSC: pin-set detected"],
        "risk_score": 2,
    }

    @pytest.mark.asyncio
    async def test_run_scan_apk_all_checks(self, tmp_path) -> None:
        p = tmp_path / "app.apk"
        p.write_bytes(b"fake apk")
        s = MobileAuditScanner()
        with (
            patch(
                "mytools.mobile.apk_analyzer.analyze_apk",
                return_value=self.APK_DATA,
            ),
            patch(
                "mytools.mobile.apk_pinning.detect_pinning",
                return_value=self.PINNING_DATA,
            ),
            patch(
                "mytools.mobile.apk_endpoints.extract_endpoints",
                return_value=self.ENDPOINTS_DATA,
            ),
            patch(
                "mytools.mobile.apk_secrets.detect_secrets",
                return_value=self.SECRETS_DATA,
            ),
            patch("mytools.mobile.apk_nsc.analyze_nsc", return_value=self.NSC_DATA),
            patch(
                "mytools.mobile.apk_dex.analyze_dex_layer",
                return_value=self.DEX_DATA,
            ),
            patch(
                "mytools.mobile.apk_dex.disassemble_dalvik",
                return_value=self.DISASM_DATA,
            ),
        ):
            result = await s.run_scan(file_path=str(p))
        assert result.platform == "android"
        assert result.file_size == p.stat().st_size
        assert len(result.attempts) == 8
        assert result.overall_status == "vulnerable"

    @pytest.mark.asyncio
    async def test_run_scan_ipa_all_checks(self, tmp_path) -> None:
        p = tmp_path / "app.ipa"
        p.write_bytes(b"fake ipa")
        s = MobileAuditScanner()
        ipa_data = {
            "bundle_id": "com.test",
            "display_name": "Test",
            "version": "1.0",
            "build": "42",
            "min_os_version": "14",
            "url_schemes": ["myapp"],
            "ats_settings": {"allows_insecure_http": True},
            "provisioning": {
                "name": "Profile",
                "team_name": "Team",
                "expires": "2026-01-01",
                "devices": 2,
            },
            "entitlements": {"app-id": "x"},
            "macho": {
                "name": "Test",
                "libraries": ["libA"],
                "rpaths": ["@rpath"],
                "exported_count": 1,
                "symbol_count": 2,
            },
        }
        with (
            patch("mytools.mobile.ipa_analyzer.analyze_ipa", return_value=ipa_data),
            patch(
                "mytools.mobile.ipa_secrets.detect_ipa_secrets",
                return_value={"findings": [], "total_secrets": 0},
            ),
        ):
            result = await s.run_scan(file_path=str(p))
        assert result.platform == "ios"
        assert len(result.attempts) == 4
        assert result.overall_status == "vulnerable"

    @pytest.mark.asyncio
    async def test_run_scan_custom_checks_plus_oauth2(self, tmp_path) -> None:
        p = tmp_path / "app.apk"
        p.write_bytes(b"fake apk")
        s = MobileAuditScanner()
        with (
            patch(
                "mytools.mobile.apk_pinning.detect_pinning",
                return_value={
                    "techniques": [],
                    "nsc_indicators": [],
                    "vulnerable": False,
                },
            ),
            patch(
                "mytools.mobile.apk_secrets.detect_secrets",
                return_value={"findings": [], "total_secrets": 0},
            ),
            patch(
                "mytools.mobile.oauth2_flows.generate_pkce_flow",
                return_value={
                    "flow": "authorization_code_pkce",
                    "auth_url": "https://idp/authorize?...",
                    "code_verifier": "v",
                    "code_challenge": "c",
                    "state": "s",
                    "instructions": "x",
                },
            ),
            patch(
                "mytools.mobile.oauth2_flows.validate_jwt",
                return_value={
                    "warnings": ["INFO: Symmetric algorithm HS256"],
                    "header": {"alg": "HS256"},
                    "is_expired": True,
                },
            ),
        ):
            result = await s.run_scan(
                file_path=str(p),
                checks=["apk_pinning", "apk_secrets", "oauth2_test", "jwt_validate"],
                idp="https://idp",
                client_id="cid",
                jwt_token="token",
            )
        assert len(result.attempts) == 4
        assert result.overall_status == "vulnerable"

    @pytest.mark.asyncio
    async def test_run_scan_check_exception(self, tmp_path) -> None:
        p = tmp_path / "app.apk"
        p.write_bytes(b"fake apk")
        s = MobileAuditScanner()
        with patch(
            "mytools.mobile.apk_analyzer.analyze_apk",
            side_effect=RuntimeError("boom"),
        ):
            result = await s.run_scan(file_path=str(p), checks=["apk_metadata"])
        assert result.attempts == []
        assert any("boom" in issue for issue in result.issues)
        assert result.overall_status == "error"

    @pytest.mark.asyncio
    async def test_run_scan_attempt_error_collected(self, tmp_path) -> None:
        p = tmp_path / "app.apk"
        p.write_bytes(b"fake apk")
        s = MobileAuditScanner()
        result = await s.run_scan(
            file_path=str(p), checks=["oauth2_test"], idp=None, client_id=None
        )
        assert len(result.attempts) == 1
        assert any("Requires" in issue for issue in result.issues)
        assert result.overall_status == "error"


class TestPrintResults:
    def test_print_results_vulnerable(self, capsys) -> None:
        result = MobileResult(
            target="app.apk",
            platform="android",
            file_size=100,
            issues=["apk_metadata: parse failed"],
            attempts=[
                MobileAttempt(
                    technique="pinning",
                    platform="android",
                    check="apk_pinning",
                    file_path="app.apk",
                    vulnerable=True,
                    findings=["OkHttp CertificatePinner"],
                ),
                MobileAttempt(
                    technique="secrets",
                    platform="android",
                    check="apk_secrets",
                    file_path="app.apk",
                    vulnerable=False,
                    findings=["AWS: AKIAIOSFODNN7EXAMPLE"],
                ),
                MobileAttempt(
                    technique="metadata",
                    platform="android",
                    check="apk_metadata",
                    file_path="app.apk",
                    vulnerable=False,
                ),
            ],
            overall_status="vulnerable",
        )
        s = MobileAuditScanner()
        s.print_results(result)
        out = capsys.readouterr().out
        assert "VULNERABLE" in out
        assert "Issues:" in out
        assert "parse failed" in out
        assert "finding(s)" in out
        assert "secure" in out

    def test_print_results_secure(self, capsys) -> None:
        result = MobileResult(
            target="app.ipa",
            platform="ios",
            file_size=10,
            attempts=[],
            issues=[],
            overall_status="secure",
        )
        s = MobileAuditScanner()
        s.print_results(result)
        assert "SECURE" in capsys.readouterr().out


class TestRunCheck:
    def test_unknown_check(self, tmp_path) -> None:
        p = tmp_path / "test.apk"
        p.write_bytes(b"fake")
        attempt = _run_check("unknown_check", str(p), "android", None, None, "", None)
        assert "Unknown check" in attempt.error

    def test_oauth2_missing_params(self, tmp_path) -> None:
        p = tmp_path / "test.apk"
        p.write_bytes(b"fake")
        attempt = _run_check("oauth2_test", str(p), "android", None, None, "", None)
        assert "Requires" in attempt.error

    def test_jwt_missing_token(self, tmp_path) -> None:
        p = tmp_path / "test.apk"
        p.write_bytes(b"fake")
        attempt = _run_check("jwt_validate", str(p), "android", None, None, "", None)
        assert "Requires" in attempt.error

    def test_apk_metadata_error(self, tmp_path) -> None:
        p = tmp_path / "test.apk"
        p.write_bytes(b"fake")
        with patch(
            "mytools.mobile.apk_analyzer.analyze_apk",
            return_value={"error": "parse failed"},
        ):
            attempt = _run_check(
                "apk_metadata", str(p), "android", None, None, "", None
            )
        assert "parse failed" in attempt.error
        assert attempt.vulnerable is False

    def test_apk_metadata_no_sdks(self, tmp_path) -> None:
        p = tmp_path / "test.apk"
        p.write_bytes(b"fake")
        data = {
            "package": "com.test",
            "version_name": "",
            "version_code": "",
            "target_sdk": "",
            "min_sdk": "",
            "permissions_count": 0,
            "activities": [],
            "services": [],
            "sdk_fingerprints": [],
        }
        with patch("mytools.mobile.apk_analyzer.analyze_apk", return_value=data):
            attempt = _run_check(
                "apk_metadata", str(p), "android", None, None, "", None
            )
        assert any(f.startswith("Package:") for f in attempt.findings)
        assert not any(f.startswith("SDKs:") for f in attempt.findings)

    def test_apk_secrets_long_value(self, tmp_path) -> None:
        p = tmp_path / "test.apk"
        p.write_bytes(b"fake")
        long_secret = "AKIA" + "x" * 45
        with patch(
            "mytools.mobile.apk_secrets.detect_secrets",
            return_value={
                "findings": [{"pattern": "AWS", "value": long_secret}],
                "total_secrets": 1,
            },
        ):
            attempt = _run_check("apk_secrets", str(p), "android", None, None, "", None)
        assert attempt.vulnerable is True
        assert any("..." in f for f in attempt.findings)

    def test_apk_decompile(self, tmp_path) -> None:
        p = tmp_path / "test.apk"
        p.write_bytes(b"fake")
        data = {
            "total_decompiled": 1,
            "total_empty": 2,
            "truncated": True,
            "classes": [
                {"class_name": "Lcom/test;", "line_count": 10, "method_count": 2}
            ],
        }
        with patch("mytools.mobile.apk_dex.decompile_java", return_value=data):
            attempt = _run_check(
                "apk_decompile", str(p), "android", None, None, "", None
            )
        assert attempt.check == "apk_decompile"
        assert "decompiled" in attempt.details

    def test_apk_disasm_not_truncated(self, tmp_path) -> None:
        p = tmp_path / "test.apk"
        p.write_bytes(b"fake")
        data = {
            "total_methods": 1,
            "total_instructions": 2,
            "truncated": False,
            "methods": [
                {"class_name": "Lcom/test;", "method_name": "m", "instruction_count": 2}
            ],
        }
        with patch("mytools.mobile.apk_dex.disassemble_dalvik", return_value=data):
            attempt = _run_check("apk_disasm", str(p), "android", None, None, "", None)
        assert attempt.check == "apk_disasm"
        assert not any("truncated" in f for f in attempt.findings)

    def test_apk_decompile_not_truncated(self, tmp_path) -> None:
        p = tmp_path / "test.apk"
        p.write_bytes(b"fake")
        data = {
            "total_decompiled": 0,
            "total_empty": 0,
            "truncated": False,
            "classes": [],
        }
        with patch("mytools.mobile.apk_dex.decompile_java", return_value=data):
            attempt = _run_check(
                "apk_decompile", str(p), "android", None, None, "", None
            )
        assert attempt.check == "apk_decompile"
        assert not any("truncated" in f for f in attempt.findings)

    def test_ipa_metadata_minimal(self, tmp_path) -> None:
        p = tmp_path / "test.ipa"
        p.write_bytes(b"fake")
        data = {
            "bundle_id": "",
            "display_name": "",
            "version": "",
            "build": "",
            "min_os_version": "",
            "url_schemes": [],
            "ats_settings": {"allows_insecure_http": False},
        }
        with patch("mytools.mobile.ipa_analyzer.analyze_ipa", return_value=data):
            attempt = _run_check("ipa_metadata", str(p), "ios", None, None, "", None)
        assert attempt.findings == []
        assert attempt.vulnerable is False

    def test_ipa_provisioning_empty(self, tmp_path) -> None:
        p = tmp_path / "test.ipa"
        p.write_bytes(b"fake")
        data = {"provisioning": {}, "entitlements": {}}
        with patch("mytools.mobile.ipa_analyzer.analyze_ipa", return_value=data):
            attempt = _run_check(
                "ipa_provisioning", str(p), "ios", None, None, "", None
            )
        assert attempt.findings == []

    def test_ipa_macho_empty(self, tmp_path) -> None:
        p = tmp_path / "test.ipa"
        p.write_bytes(b"fake")
        data = {"macho": {}}
        with patch("mytools.mobile.ipa_analyzer.analyze_ipa", return_value=data):
            attempt = _run_check("ipa_macho", str(p), "ios", None, None, "", None)
        assert any("Exported: 0" in f for f in attempt.findings)
        assert any("Symbols: 0" in f for f in attempt.findings)

    def test_ipa_secrets_long_value(self, tmp_path) -> None:
        p = tmp_path / "test.ipa"
        p.write_bytes(b"fake")
        long_secret = "AIzaSy" + "y" * 45
        with patch(
            "mytools.mobile.ipa_secrets.detect_ipa_secrets",
            return_value={
                "findings": [{"pattern": "Google API Key", "value": long_secret}],
                "total_secrets": 1,
            },
        ):
            attempt = _run_check("ipa_secrets", str(p), "ios", None, None, "", None)
        assert attempt.vulnerable is True

    def test_jwt_validate_error(self, tmp_path) -> None:
        p = tmp_path / "test.apk"
        p.write_bytes(b"fake")
        with patch(
            "mytools.mobile.oauth2_flows.validate_jwt",
            return_value={"error": "invalid token"},
        ):
            attempt = _run_check(
                "jwt_validate", str(p), "oauth2", None, None, "", "token"
            )
        assert "invalid token" in attempt.error


class TestRunCheckErrorBranches:
    """Cobre os ramos `if \"error\" in data` de cada handler do _run_check."""

    @staticmethod
    def _path(tmp_path, name: str, data: bytes = b"fake") -> str:
        p = tmp_path / name
        p.write_bytes(data)
        return str(p)

    def test_apk_pinning_error(self, tmp_path) -> None:
        path = self._path(tmp_path, "app.apk")
        with patch(
            "mytools.mobile.apk_pinning.detect_pinning", return_value={"error": "boom"}
        ):
            attempt = _run_check("apk_pinning", path, "android", None, None, "", None)
        assert attempt.error == "boom"
        assert attempt.vulnerable is False

    def test_apk_endpoints_error(self, tmp_path) -> None:
        path = self._path(tmp_path, "app.apk")
        with patch(
            "mytools.mobile.apk_endpoints.extract_endpoints",
            return_value={"error": "boom"},
        ):
            attempt = _run_check("apk_endpoints", path, "android", None, None, "", None)
        assert attempt.error == "boom"
        assert attempt.vulnerable is False

    def test_apk_secrets_error(self, tmp_path) -> None:
        path = self._path(tmp_path, "app.apk")
        with patch(
            "mytools.mobile.apk_secrets.detect_secrets", return_value={"error": "boom"}
        ):
            attempt = _run_check("apk_secrets", path, "android", None, None, "", None)
        assert attempt.error == "boom"
        assert attempt.vulnerable is False

    def test_apk_nsc_error(self, tmp_path) -> None:
        path = self._path(tmp_path, "app.apk")
        with patch(
            "mytools.mobile.apk_nsc.analyze_nsc", return_value={"error": "boom"}
        ):
            attempt = _run_check("apk_nsc", path, "android", None, None, "", None)
        assert attempt.error == "boom"
        assert attempt.vulnerable is False

    def test_apk_sdk_error(self, tmp_path) -> None:
        path = self._path(tmp_path, "app.apk")
        with patch(
            "mytools.mobile.apk_analyzer.analyze_apk", return_value={"error": "boom"}
        ):
            attempt = _run_check("apk_sdk", path, "android", None, None, "", None)
        assert attempt.error == "boom"
        assert attempt.vulnerable is False

    def test_ipa_metadata_error(self, tmp_path) -> None:
        path = self._path(tmp_path, "app.ipa")
        with patch(
            "mytools.mobile.ipa_analyzer.analyze_ipa", return_value={"error": "boom"}
        ):
            attempt = _run_check("ipa_metadata", path, "ios", None, None, "", None)
        assert attempt.error == "boom"
        assert attempt.vulnerable is False

    def test_ipa_provisioning_error(self, tmp_path) -> None:
        path = self._path(tmp_path, "app.ipa")
        with patch(
            "mytools.mobile.ipa_analyzer.analyze_ipa", return_value={"error": "boom"}
        ):
            attempt = _run_check("ipa_provisioning", path, "ios", None, None, "", None)
        assert attempt.error == "boom"
        assert attempt.vulnerable is False

    def test_ipa_macho_error(self, tmp_path) -> None:
        path = self._path(tmp_path, "app.ipa")
        with patch(
            "mytools.mobile.ipa_analyzer.analyze_ipa", return_value={"error": "boom"}
        ):
            attempt = _run_check("ipa_macho", path, "ios", None, None, "", None)
        assert attempt.error == "boom"
        assert attempt.vulnerable is False

    def test_ipa_secrets_error(self, tmp_path) -> None:
        path = self._path(tmp_path, "app.ipa")
        with patch(
            "mytools.mobile.ipa_secrets.detect_ipa_secrets",
            return_value={"error": "boom"},
        ):
            attempt = _run_check("ipa_secrets", path, "ios", None, None, "", None)
        assert attempt.error == "boom"
        assert attempt.vulnerable is False


class TestRunScanCacheAndSecure:
    APK_DATA: ClassVar[dict[str, object]] = {
        "package": "com.test",
        "version_name": "1.0",
        "version_code": "1",
        "target_sdk": "33",
        "min_sdk": "21",
        "permissions_count": 3,
        "activities": [],
        "services": [],
        "sdk_fingerprints": [],
    }

    @pytest.mark.asyncio
    async def test_run_scan_secure_overall(self, tmp_path) -> None:
        p = tmp_path / "app.apk"
        p.write_bytes(b"fake apk")
        s = MobileAuditScanner()
        with patch(
            "mytools.mobile.apk_analyzer.analyze_apk", return_value=self.APK_DATA
        ):
            result = await s.run_scan(file_path=str(p), checks=["apk_metadata"])
        assert result.overall_status == "secure"
        assert result.attempts[0].vulnerable is False

    @pytest.mark.asyncio
    async def test_run_scan_apk_shared_cache_reuse(self, tmp_path) -> None:
        p = tmp_path / "app.apk"
        p.write_bytes(b"fake apk")
        s = MobileAuditScanner()
        with patch(
            "mytools.mobile.apk_analyzer.analyze_apk", return_value=self.APK_DATA
        ) as mock_apk:
            result = await s.run_scan(
                file_path=str(p), checks=["apk_sdk", "apk_metadata", "apk_sdk"]
            )
        assert len(result.attempts) == 3
        assert mock_apk.call_count == 1
        assert result.overall_status == "secure"

    @pytest.mark.asyncio
    async def test_run_scan_ipa_shared_cache_reuse(self, tmp_path) -> None:
        p = tmp_path / "app.ipa"
        p.write_bytes(b"fake ipa")
        s = MobileAuditScanner()
        ipa_data = {
            "bundle_id": "com.test",
            "display_name": "Test",
            "version": "1.0",
            "build": "42",
            "min_os_version": "14",
            "url_schemes": [],
            "ats_settings": {"allows_insecure_http": False},
            "provisioning": {},
            "entitlements": {},
            "macho": {
                "name": "",
                "libraries": [],
                "rpaths": [],
                "exported_count": 0,
                "symbol_count": 0,
            },
        }
        with patch(
            "mytools.mobile.ipa_analyzer.analyze_ipa", return_value=ipa_data
        ) as mock_ipa:
            result = await s.run_scan(
                file_path=str(p),
                checks=["ipa_macho", "ipa_metadata", "ipa_provisioning"],
            )
        assert len(result.attempts) == 3
        assert mock_ipa.call_count == 1
        assert result.overall_status == "secure"


class TestMainGuard:
    def test_main_guard(self) -> None:
        with (
            patch("mytools.core.base.run_main_loop", side_effect=SystemExit(0)),
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.mobile.mobile_audit", run_name="__main__")
        assert exc_info.value.code == 0
