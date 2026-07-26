"""Testes do módulo apk_endpoints.py."""

from __future__ import annotations

import zipfile

from mytools.mobile.apk_endpoints import extract_endpoints


class TestExtractEndpoints:
    def test_nonexistent_file(self) -> None:
        result = extract_endpoints("nonexistent.apk")
        assert "error" in result
        assert result["total_endpoints"] == 0

    def test_empty_apk(self, tmp_path) -> None:
        apk_path = tmp_path / "empty.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"no urls here")
        result = extract_endpoints(str(apk_path))
        assert result["total_endpoints"] == 0

    def test_urls_found(self, tmp_path) -> None:
        apk_path = tmp_path / "urls.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr(
                "classes.dex",
                b"https://api.example.com/v1/users https://firebaseio.com/test",
            )
        result = extract_endpoints(str(apk_path))
        assert result["total_endpoints"] > 0
        assert any("example.com" in u for u in result["urls"])

    def test_api_paths_found(self, tmp_path) -> None:
        apk_path = tmp_path / "paths.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"/api/v1/users /graphql /oauth/token")
        result = extract_endpoints(str(apk_path))
        assert len(result["api_paths"]) >= 2

    def test_domains_extracted(self, tmp_path) -> None:
        apk_path = tmp_path / "domains.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"https://api.example.com/test")
        result = extract_endpoints(str(apk_path))
        assert "api.example.com" in result["domains"]
