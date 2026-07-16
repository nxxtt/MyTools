#!/usr/bin/env python3
"""Testes unitarios do modulo File Upload Attacks."""
from __future__ import annotations

import pytest

from mytools.web.fileupload import (
    _BOUNDARY_PAYLOADS,
    _CATEGORY_MAP,
    _CONTENT_TYPE_PAYLOADS,
    _FILENAME_PAYLOADS,
    _IMAGIC_PAYLOADS,
    _POLYGLOT_PAYLOADS,
    _SVG_XXE_PAYLOADS,
    _ZIP_SLIP_PAYLOADS,
    UploadAttempt,
    UploadResult,
    _check_upload_reflection,
)

_TARGET = "https://example.com/upload"


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
