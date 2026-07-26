"""Testes do módulo mobile_audit.py — BaseScanner CLI."""

from __future__ import annotations

import argparse

import pytest

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
