#!/usr/bin/env python3
"""Testes unitarios do modulo File Upload Attacks."""
from __future__ import annotations

import argparse
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mytools.web.fileupload import (
    _ALL_PAYLOADS,
    _BOUNDARY_PAYLOADS,
    _CATEGORY_MAP,
    _CATEGORY_TESTERS,
    _CONTENT_TYPE_PAYLOADS,
    _FILENAME_PAYLOADS,
    _IMAGIC_PAYLOADS,
    _POLYGLOT_PAYLOADS,
    _SVG_XXE_PAYLOADS,
    _ZIP_SLIP_PAYLOADS,
    UploadAttempt,
    UploadResult,
    _check_upload_reflection,
    _find_upload_endpoint,
    _test_content_type_category,
    _test_filename_inject_category,
    _test_imagemagic_category,
    _test_multipart_boundary_category,
    _test_polyglot_category,
    _test_svg_xxe_category,
    _test_zip_slip_category,
    build_parser,
    print_results,
    run_once,
    run_scan,
)

_TARGET = "https://example.com/upload"
_UPLOAD_URL = "https://example.com/upload"


# --- Category map / payload data tests (existing) ---


def test_category_map_has_seven_categories() -> None:
    assert len(_CATEGORY_MAP) == 7


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {
        "polyglot", "svg_xxe", "image_magic", "zip_slip",
        "filename_inject", "content_type", "multipart_boundary",
    }


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 42


def test_polyglot_payloads_count() -> None:
    assert len(_POLYGLOT_PAYLOADS) == 6


def test_svg_xxe_payloads_count() -> None:
    assert len(_SVG_XXE_PAYLOADS) == 6


def test_imagemagic_payloads_count() -> None:
    assert len(_IMAGIC_PAYLOADS) == 6


def test_zip_slip_payloads_count() -> None:
    assert len(_ZIP_SLIP_PAYLOADS) == 6


def test_filename_payloads_count() -> None:
    assert len(_FILENAME_PAYLOADS) == 6


def test_content_type_payloads_count() -> None:
    assert len(_CONTENT_TYPE_PAYLOADS) == 6


def test_boundary_payloads_count() -> None:
    assert len(_BOUNDARY_PAYLOADS) == 6


def test_all_payloads_have_five_elements() -> None:
    all_lists = (
        _POLYGLOT_PAYLOADS + _SVG_XXE_PAYLOADS + _IMAGIC_PAYLOADS
        + _ZIP_SLIP_PAYLOADS + _FILENAME_PAYLOADS + _CONTENT_TYPE_PAYLOADS
    )
    for p in all_lists:
        assert len(p) == 5, f"Payload {p[0]} should have 5 elements"


def test_check_upload_reflection_true() -> None:
    body = '<div><?php system($_GET["c"]); ?></div>'
    assert _check_upload_reflection(body, ["<?php", "system"]) is True


def test_check_upload_reflection_false() -> None:
    body = '<div>safe content</div>'
    assert _check_upload_reflection(body, ["<?php"]) is False


def test_check_upload_reflection_case_insensitive() -> None:
    body = '<div><?PHP SYSTEM() ?></div>'
    assert _check_upload_reflection(body, ["<?php"]) is True


def test_check_upload_reflection_empty_indicators() -> None:
    assert _check_upload_reflection("anything", []) is False


def test_check_upload_reflection_empty_body() -> None:
    assert _check_upload_reflection("", ["indicator"]) is False


def test_attempt_dataclass_frozen() -> None:
    a = UploadAttempt(
        technique="test", category="polyglot",
        filename="test.jpg", content_type="image/jpeg",
        method="POST",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=110,
        status_changed=False, size_changed=True,
        vulnerable=True, details="test", error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False  # type: ignore[reportAttributeAccessIssue]


def test_attempt_dataclass_slots() -> None:
    a = UploadAttempt(
        technique="test", category="polyglot",
        filename="test.jpg", content_type="image/jpeg",
        method="POST",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=110,
        status_changed=False, size_changed=True,
        vulnerable=True, details="test", error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = UploadResult(
        target=_TARGET, tls=True,
        upload_endpoint=None,
        baseline_status=200, baseline_size=100,
        attempts=[], vulnerable_techniques=[],
        blocked_techniques=[], issues=[],
        overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"  # type: ignore[reportAttributeAccessIssue]


def test_result_dataclass_slots() -> None:
    r = UploadResult(
        target=_TARGET, tls=True,
        upload_endpoint=None,
        baseline_status=200, baseline_size=100,
        attempts=[], vulnerable_techniques=[],
        blocked_techniques=[], issues=[],
        overall_status="safe",
    )
    assert not hasattr(r, "__dict__")


def test_no_duplicate_technique_names_across_categories() -> None:
    all_techniques: list[str] = []
    for techs in _CATEGORY_MAP.values():
        all_techniques.extend(techs)
    assert len(all_techniques) == len(set(all_techniques))


def test_no_duplicate_payload_names_across_lists() -> None:
    all_names: list[str] = []
    for lst in (
        _POLYGLOT_PAYLOADS, _SVG_XXE_PAYLOADS, _IMAGIC_PAYLOADS,
        _ZIP_SLIP_PAYLOADS, _FILENAME_PAYLOADS, _CONTENT_TYPE_PAYLOADS,
    ):
        all_names.extend(p[0] for p in lst)
    assert len(all_names) == len(set(all_names))


def test_all_payloads_have_indicators() -> None:
    all_lists = (
        _POLYGLOT_PAYLOADS + _SVG_XXE_PAYLOADS + _IMAGIC_PAYLOADS
        + _ZIP_SLIP_PAYLOADS + _FILENAME_PAYLOADS + _CONTENT_TYPE_PAYLOADS
    )
    for p in all_lists:
        assert len(p[4]) >= 1, f"Payload {p[0]} must have at least 1 indicator"


def test_boundary_payloads_have_four_elements() -> None:
    for p in _BOUNDARY_PAYLOADS:
        assert len(p) == 4, f"Boundary payload {p[0]} should have 4 elements"


def test_all_payloads_mapping_completeness() -> None:
    for cat in _CATEGORY_MAP:
        assert cat in _ALL_PAYLOADS, f"Category {cat} missing from _ALL_PAYLOADS"


def test_category_testers_mapping_completeness() -> None:
    for cat in _CATEGORY_MAP:
        assert cat in _CATEGORY_TESTERS, f"Category {cat} missing from _CATEGORY_TESTERS"


# --- _find_upload_endpoint tests ---


class TestFindUploadEndpoint:
    def test_form_action(self) -> None:
        body = '<form action="/api/upload"><input type="file"></form>'
        result = _find_upload_endpoint("https://example.com", body)
        assert result is not None
        assert "api/upload" in result

    def test_input_type_file(self) -> None:
        body = '<input type="file" name="file">'
        result = _find_upload_endpoint("https://example.com", body)
        assert result is not None
        assert "example.com" in result

    def test_common_path_upload(self) -> None:
        body = '<html><a href="/upload">Upload</a></html>'
        result = _find_upload_endpoint("https://example.com", body)
        assert result is not None
        assert "/upload" in result

    def test_common_path_file_upload(self) -> None:
        body = '<html><p>Go to /attachments</p></html>'
        result = _find_upload_endpoint("https://example.com", body)
        assert result is not None
        assert "/attachments" in result

    def test_no_forms_returns_base_url(self) -> None:
        body = '<html><body>No forms here</body></html>'
        result = _find_upload_endpoint("https://example.com", body)
        assert result == "https://example.com"

    def test_relative_action_path(self) -> None:
        body = '<form action="upload/process">'
        result = _find_upload_endpoint("https://example.com", body)
        assert result is not None
        assert "example.com" in result


# --- Dispatcher tests (parametrized) ---


def _mock_client_post(status_code: int, body: str) -> AsyncMock:
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.text = body
    mock_resp.content = body.encode()
    mock_client.post.return_value = mock_resp
    return mock_client


_DISPATCHER_PARAMS = [
    ("polyglot", _test_polyglot_category),
    ("svg_xxe", _test_svg_xxe_category),
    ("image_magic", _test_imagemagic_category),
    ("zip_slip", _test_zip_slip_category),
    ("filename_inject", _test_filename_inject_category),
    ("content_type", _test_content_type_category),
]


@pytest.mark.parametrize("cat_name,dispatcher", _DISPATCHER_PARAMS)
class TestUploadDispatchers:
    @pytest.mark.asyncio
    async def test_safe_response(self, cat_name: str, dispatcher: object) -> None:
        client = _mock_client_post(403, "Forbidden")
        fn = dispatcher  # type: ignore[misc]
        results = await fn(client, _UPLOAD_URL, 10, 200, 100)  # type: ignore[misc]
        assert len(results) == 6
        assert all(not r.vulnerable for r in results)
        assert all(r.error == "" for r in results)

    @pytest.mark.asyncio
    async def test_vulnerable_response(self, cat_name: str, dispatcher: object) -> None:
        body_map = {
            "polyglot": "<?php system($_GET['c']); ?>",
            "svg_xxe": "xxe file:///etc/passwd",
            "image_magic": "label $(id)",
            "zip_slip": "../../etc/passwd",
            "filename_inject": "`$(whoami)",
            "content_type": "<?php system()",
        }
        client = _mock_client_post(200, body_map.get(cat_name, "match"))
        fn = dispatcher  # type: ignore[misc]
        results = await fn(client, _UPLOAD_URL, 10, 200, 100)  # type: ignore[misc]
        assert any(r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_exception_handling(self, cat_name: str, dispatcher: object) -> None:
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("timeout")
        fn = dispatcher  # type: ignore[misc]
        results = await fn(mock_client, _UPLOAD_URL, 10, 200, 100)  # type: ignore[misc]
        assert len(results) == 6
        assert all(r.error for r in results)
        assert all(not r.vulnerable for r in results)


class TestMultipartBoundary:
    @pytest.mark.asyncio
    async def test_safe_response(self) -> None:
        client = _mock_client_post(200, "OK")
        results = await _test_multipart_boundary_category(
            client, _UPLOAD_URL, 10, 200, 100,
        )
        assert len(results) == 6
        assert all(not r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_vulnerable_response(self) -> None:
        client = _mock_client_post(200, "Content-Disposition: form-data onmouseover=alert(1)")
        results = await _test_multipart_boundary_category(
            client, _UPLOAD_URL, 10, 200, 100,
        )
        assert any(r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_exception_handling(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")
        results = await _test_multipart_boundary_category(
            mock_client, _UPLOAD_URL, 10, 200, 100,
        )
        assert len(results) == 6
        assert all(r.error for r in results)


# --- print_results tests ---


def _make_result(
    attempts: list[UploadAttempt] | None = None,
    issues: list[str] | None = None,
    overall_status: str = "safe",
) -> UploadResult:
    return UploadResult(
        target=_TARGET, tls=True,
        upload_endpoint=_UPLOAD_URL,
        baseline_status=200, baseline_size=100,
        attempts=attempts or [],
        vulnerable_techniques=[],
        blocked_techniques=[],
        issues=issues or [],
        overall_status=overall_status,
    )


def test_print_results_no_vulns(capsys: pytest.CaptureFixture[str]) -> None:
    result = _make_result()
    print_results(result)
    out = capsys.readouterr().out
    assert "Nenhuma vulnerabilidade" in out


def test_print_results_with_vulns(capsys: pytest.CaptureFixture[str]) -> None:
    attempt = UploadAttempt(
        technique="jpg_php", category="polyglot",
        filename="polyglot.jpg.php", content_type="image/jpeg",
        method="POST",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=200,
        status_changed=False, size_changed=True,
        vulnerable=True, details="Polyglot aceito e refletido", error="",
        exploit="polyglot_file_content", tool="curl",
    )
    result = _make_result(attempts=[attempt], overall_status="vulnerable")
    print_results(result)
    out = capsys.readouterr().out
    assert "Vulnerabilidades encontradas" in out
    assert "jpg_php" in out


def test_print_results_with_issues(capsys: pytest.CaptureFixture[str]) -> None:
    result = _make_result(issues=["Endpoint de upload nao detectado"])
    print_results(result)
    out = capsys.readouterr().out
    assert "Observacoes" in out
    assert "upload nao detectado" in out


# --- build_parser tests ---


class TestBuildParser:
    def test_has_url_arg(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com/upload"])
        assert args.url == "https://example.com/upload"

    def test_has_category_arg(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "polyglot"])
        assert args.category == "polyglot"

    def test_default_category_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.category == "all"


# --- run_scan tests ---


class TestRunScan:
    @pytest.mark.asyncio
    async def test_baseline_error_returns_1(self) -> None:
        with patch("mytools.web.fileupload.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.fileupload.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.side_effect = httpx.RequestError("fail")
                result = await run_scan(_TARGET, [], 10, None)
                assert result == 1

    @pytest.mark.asyncio
    async def test_vulnerable_returns_1(self) -> None:
        with patch("mytools.web.fileupload.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.fileupload.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = (200, {}, b"<html>upload</html>", b"")
                with patch("mytools.web.fileupload._CATEGORY_TESTERS") as mock_testers:
                    mock_attempt = UploadAttempt(
                        technique="jpg_php", category="polyglot",
                        filename="polyglot.jpg.php", content_type="image/jpeg",
                        method="POST",
                        status_baseline=200, status_test=200,
                        size_baseline=100, size_test=200,
                        status_changed=False, size_changed=True,
                        vulnerable=True, details="polyglot detected", error="",
                    )
                    mock_testers.get.return_value = AsyncMock(return_value=[mock_attempt])
                    result = await run_scan(_TARGET, ["polyglot"], 10, None)
                    assert result == 1

    @pytest.mark.asyncio
    async def test_safe_returns_0(self) -> None:
        with patch("mytools.web.fileupload.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.fileupload.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = (200, {}, b"<html>safe</html>", b"")
                with patch("mytools.web.fileupload._CATEGORY_TESTERS") as mock_testers:
                    mock_attempt = UploadAttempt(
                        technique="jpg_php", category="polyglot",
                        filename="polyglot.jpg.php", content_type="image/jpeg",
                        method="POST",
                        status_baseline=200, status_test=403,
                        size_baseline=100, size_test=100,
                        status_changed=True, size_changed=False,
                        vulnerable=False, details="", error="",
                    )
                    mock_testers.get.return_value = AsyncMock(return_value=[mock_attempt])
                    result = await run_scan(_TARGET, ["polyglot"], 10, None)
                    assert result == 0

    @pytest.mark.asyncio
    async def test_categories_defaults_to_all(self) -> None:
        with patch("mytools.web.fileupload.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.fileupload.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = (200, {}, b"<html>safe</html>", b"")
                with patch("mytools.web.fileupload._CATEGORY_TESTERS") as mock_testers:
                    mock_testers.get.return_value = AsyncMock(return_value=[])
                    result = await run_scan(_TARGET, [], 10, None)
                    assert result == 0
                    assert mock_testers.get.call_count == 7

    @pytest.mark.asyncio
    async def test_output_file_calls_write(self) -> None:
        with patch("mytools.web.fileupload.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.fileupload.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = (200, {}, b"<html>safe</html>", b"")
                with patch("mytools.web.fileupload._CATEGORY_TESTERS") as mock_testers:
                    mock_testers.get.return_value = AsyncMock(return_value=[])
                    with patch("mytools.web.fileupload.write_output") as mock_write:
                        await run_scan(_TARGET, [], 10, "output.json")
                        mock_write.assert_called_once()


# --- run_once tests ---


class TestRunOnce:
    def test_extracts_single_category(self) -> None:
        args = argparse.Namespace(
            url=_TARGET, category="polyglot",
            timeout=10, output=None,
        )
        with patch("mytools.web.fileupload.run_scan", new_callable=AsyncMock, return_value=0) as mock_scan:
            run_once(args)
            assert mock_scan.call_args.kwargs["categories"] == ["polyglot"]

    def test_all_category_passes_empty_list(self) -> None:
        args = argparse.Namespace(
            url=_TARGET, category="all",
            timeout=10, output=None,
        )
        with patch("mytools.web.fileupload.run_scan", new_callable=AsyncMock, return_value=0) as mock_scan:
            run_once(args)
            assert mock_scan.call_args.kwargs["categories"] == []
