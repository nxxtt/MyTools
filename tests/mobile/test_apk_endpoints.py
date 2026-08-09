"""Testes do módulo apk_endpoints.py."""

from __future__ import annotations

import zipfile
from unittest.mock import patch

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

    def test_firebase_urls(self, tmp_path) -> None:
        apk_path = tmp_path / "firebase.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr(
                "classes.dex",
                b"https://myapp.firebaseio.com/data https://other.firebaseapp.com "
                b"https://site.web.app/root",
            )
        result = extract_endpoints(str(apk_path))
        assert len(result["firebase_urls"]) == 3

    def test_custom_schemes_extracted(self, tmp_path) -> None:
        apk_path = tmp_path / "schemes.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr(
                "classes.dex",
                b"myapp://open/profile?x=1 com.example.app://deep/link",
            )
        result = extract_endpoints(str(apk_path))
        assert any("myapp://" in s for s in result["schemes"])
        assert any("com.example.app://" in s for s in result["schemes"])

    def test_http_scheme_filtered_from_schemes(self, tmp_path) -> None:
        apk_path = tmp_path / "http.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"https://api.example.com/x http://file.local")
        result = extract_endpoints(str(apk_path))
        assert all(not s.startswith("http") for s in result["schemes"])

    def test_dex_read_error_skipped(self, tmp_path) -> None:
        apk_path = tmp_path / "broken.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"https://api.example.com/ok")
        with patch.object(zipfile.ZipFile, "read", side_effect=RuntimeError("corrupt")):
            result = extract_endpoints(str(apk_path))
        assert result["total_endpoints"] == 0

    def test_urlparse_error_skipped(self, tmp_path) -> None:
        apk_path = tmp_path / "parse.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"https://api.example.com/x")

        def _boom(url: str) -> None:
            raise ValueError("bad url")

        with patch("mytools.mobile.apk_endpoints.urlparse", side_effect=_boom):
            result = extract_endpoints(str(apk_path))
        assert result["total_endpoints"] > 0
        assert result["domains"] == []

    def test_url_without_hostname_skipped(self, tmp_path) -> None:
        apk_path = tmp_path / "nohost.apk"
        with zipfile.ZipFile(str(apk_path), "w") as zf:
            zf.writestr("classes.dex", b"https://?query-only")
        result = extract_endpoints(str(apk_path))
        assert result["total_endpoints"] > 0
        assert result["domains"] == []
