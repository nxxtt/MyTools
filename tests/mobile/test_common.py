"""Testes do módulo _common.py — dataclasses mobile."""

from __future__ import annotations

import pytest

from mytools.mobile._common import MobileAttempt, MobileResult


class TestMobileAttempt:
    def test_creation(self) -> None:
        a = MobileAttempt(
            technique="pinning",
            platform="android",
            check="apk_pinning",
            file_path="app.apk",
            vulnerable=False,
        )
        assert a.technique == "pinning"
        assert a.platform == "android"
        assert a.vulnerable is False

    def test_frozen(self) -> None:
        a = MobileAttempt(
            technique="t", platform="p", check="c", file_path="f",
            vulnerable=False,
        )
        with pytest.raises(AttributeError):
            a.technique = "changed"  # type: ignore[misc]

    def test_with_findings(self) -> None:
        a = MobileAttempt(
            technique="secrets", platform="android", check="apk_secrets",
            file_path="app.apk", vulnerable=True,
            findings=["AWS Key: AKIA...", "JWT: eyJ..."],
            details="2 secrets found",
        )
        assert len(a.findings) == 2
        assert a.vulnerable is True


class TestMobileResult:
    def test_creation(self) -> None:
        r = MobileResult(
            target="app.apk",
            platform="android",
            file_size=1024,
        )
        assert r.target == "app.apk"
        assert r.platform == "android"
        assert r.overall_status == "secure"

    def test_frozen(self) -> None:
        r = MobileResult(target="t", platform="p", file_size=0)
        with pytest.raises(AttributeError):
            r.target = "changed"  # type: ignore[misc]

    def test_with_issues(self) -> None:
        r = MobileResult(
            target="app.apk",
            platform="android",
            file_size=1024,
            issues=["No file specified"],
            overall_status="error",
        )
        assert r.overall_status == "error"
        assert len(r.issues) == 1
