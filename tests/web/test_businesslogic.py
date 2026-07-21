#!/usr/bin/env python3
"""Testes unitarios do modulo Business Logic Attack Detection."""
from __future__ import annotations

import argparse
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from mytools.web.businesslogic import (
    _CATEGORY_MAP,
    _CATEGORY_TESTERS,
    _NEGATIVE_QTY_PAYLOADS,
    _OVERFLOW_PAYLOADS,
    BizLogicAttempt,
    BizLogicResult,
    _find_checkout_url,
    _test_integer_overflow_category,
    _test_negative_quantity_category,
    _test_race_condition_category,
    build_parser,
    print_results,
    run_once,
    run_scan,
)

_TARGET = "https://example.com/checkout"
_CHECKOUT_URL = "https://example.com/checkout"


# --- Category map / payload data tests (existing) ---


def test_category_map_has_three_categories() -> None:
    assert len(_CATEGORY_MAP) == 3


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {
        "integer_overflow", "negative_quantity", "race_condition",
    }


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 15


def test_integer_overflow_techniques_count() -> None:
    assert len(_CATEGORY_MAP["integer_overflow"]) == 5


def test_negative_quantity_techniques_count() -> None:
    assert len(_CATEGORY_MAP["negative_quantity"]) == 5


def test_race_condition_techniques_count() -> None:
    assert len(_CATEGORY_MAP["race_condition"]) == 5


def test_overflow_payloads_count() -> None:
    assert len(_OVERFLOW_PAYLOADS) == 5


def test_negative_qty_payloads_count() -> None:
    assert len(_NEGATIVE_QTY_PAYLOADS) == 5


def test_overflow_payloads_have_four_elements() -> None:
    for p in _OVERFLOW_PAYLOADS:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_negative_qty_payloads_have_four_elements() -> None:
    for p in _NEGATIVE_QTY_PAYLOADS:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_no_duplicate_technique_names() -> None:
    all_techniques: list[str] = []
    for techs in _CATEGORY_MAP.values():
        all_techniques.extend(techs)
    assert len(all_techniques) == len(set(all_techniques))


def test_all_techniques_are_strings() -> None:
    for cat, techs in _CATEGORY_MAP.items():
        for t in techs:
            assert isinstance(t, str), f"{cat}/{t} is not a string"


def test_category_testers_mapping() -> None:
    for cat in _CATEGORY_MAP:
        assert cat in _CATEGORY_TESTERS, f"Category {cat} has no tester"


# --- _find_checkout_url (3 existing + 7 new = 10 total) ---


def test_find_checkout_url_with_link() -> None:
    body = '<a href="/checkout">Finalizar compra</a>'
    result = _find_checkout_url("https://example.com", body)
    assert result is not None
    assert "checkout" in result


def test_find_checkout_url_with_action() -> None:
    body = '<form action="/payment/process">'
    result = _find_checkout_url("https://example.com", body)
    assert result is not None


def test_find_checkout_url_not_found() -> None:
    body = '<html><body>Safe page</body></html>'
    result = _find_checkout_url("https://example.com", body)
    assert result is None


def test_find_checkout_url_absolute_href() -> None:
    body = '<a href="https://outro.com/checkout">Buy</a>'
    result = _find_checkout_url("https://example.com", body)
    assert result == "https://outro.com/checkout"


def test_find_checkout_url_cart_path() -> None:
    body = '<a href="/cart/view">Cart</a>'
    result = _find_checkout_url("https://example.com", body)
    assert result is not None
    assert "cart" in result


def test_find_checkout_url_case_insensitive() -> None:
    body = '<a href="/Checkout">Buy</a>'
    result = _find_checkout_url("https://example.com", body)
    assert result is not None
    assert "checkout" in result.lower()


def test_find_checkout_url_relative_path() -> None:
    body = '<a href="/store/checkout">Buy</a>'
    result = _find_checkout_url("https://example.com", body)
    assert result is not None
    assert "example.com" in result
    assert "checkout" in result


def test_find_checkout_url_no_forms() -> None:
    body = '<html><body><p>Hello world</p></body></html>'
    result = _find_checkout_url("https://example.com", body)
    assert result is None


def test_find_checkout_url_action_single_quotes() -> None:
    body = "<form action='/payment/process'>"
    result = _find_checkout_url("https://example.com", body)
    assert result is not None
    assert "payment" in result


def test_find_checkout_url_bare_url_in_text() -> None:
    body = 'Visit https://example.com/checkout?x=1 to buy'
    result = _find_checkout_url("https://example.com", body)
    assert result is not None
    assert "checkout" in result


# --- Dataclass tests (existing) ---


def test_attempt_dataclass_frozen() -> None:
    a = BizLogicAttempt(
        technique="test", category="integer_overflow",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=100,
        status_changed=False, size_changed=False,
        vulnerable=True, details="test", error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False  # type: ignore[reportAttributeAccessIssue]


def test_attempt_dataclass_slots() -> None:
    a = BizLogicAttempt(
        technique="test", category="integer_overflow",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=100,
        status_changed=False, size_changed=False,
        vulnerable=True, details="test", error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = BizLogicResult(
        target=_TARGET, tls=True,
        baseline_status=200, baseline_size=100,
        checkout_url=None, attempts=[],
        vulnerable_techniques=[], blocked_techniques=[],
        issues=[], overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"  # type: ignore[reportAttributeAccessIssue]


def test_result_dataclass_slots() -> None:
    r = BizLogicResult(
        target=_TARGET, tls=True,
        baseline_status=200, baseline_size=100,
        checkout_url=None, attempts=[],
        vulnerable_techniques=[], blocked_techniques=[],
        issues=[], overall_status="safe",
    )
    assert not hasattr(r, "__dict__")


# --- Dispatcher tests ---


def _mock_client_post(status_code: int, body: str) -> AsyncMock:
    mock_client = AsyncMock()
    mock_resp = MagicMock()
    mock_resp.status_code = status_code
    mock_resp.text = body
    mock_client.post.return_value = mock_resp
    return mock_client


class TestIntegerOverflowCategory:
    @pytest.mark.asyncio
    async def test_safe_response(self) -> None:
        client = _mock_client_post(403, "Forbidden")
        results = await _test_integer_overflow_category(
            client, _CHECKOUT_URL, 10, 200, 100,
        )
        assert len(results) == 5
        assert all(not r.vulnerable for r in results)
        assert all(r.error == "" for r in results)

    @pytest.mark.asyncio
    async def test_vulnerable_response(self) -> None:
        client = _mock_client_post(200, "Your total is overflowed")
        results = await _test_integer_overflow_category(
            client, _CHECKOUT_URL, 10, 200, 100,
        )
        assert any(r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_exception_handling(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("timeout")
        results = await _test_integer_overflow_category(
            mock_client, _CHECKOUT_URL, 10, 200, 100,
        )
        assert len(results) == 5
        assert all(r.error for r in results)
        assert all(not r.vulnerable for r in results)


class TestNegativeQuantityCategory:
    @pytest.mark.asyncio
    async def test_safe_response(self) -> None:
        client = _mock_client_post(403, "Forbidden")
        results = await _test_negative_quantity_category(
            client, _CHECKOUT_URL, 10, 200, 100,
        )
        assert len(results) == 5
        assert all(not r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_vulnerable_response(self) -> None:
        client = _mock_client_post(200, "total: -50")
        results = await _test_negative_quantity_category(
            client, _CHECKOUT_URL, 10, 200, 100,
        )
        assert any(r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_exception_handling(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")
        results = await _test_negative_quantity_category(
            mock_client, _CHECKOUT_URL, 10, 200, 100,
        )
        assert len(results) == 5
        assert all(r.error for r in results)


class TestRaceConditionCategory:
    @pytest.mark.asyncio
    async def test_safe_response(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.return_value = httpx.Response(403)
        results = await _test_race_condition_category(
            mock_client, _CHECKOUT_URL, 10, 200, 100,
        )
        assert len(results) == 5
        assert all(not r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_vulnerable_response(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.return_value = httpx.Response(200)
        results = await _test_race_condition_category(
            mock_client, _CHECKOUT_URL, 10, 200, 100,
        )
        assert len(results) == 5
        assert all(r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_exception_handling(self) -> None:
        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.RequestError("fail")
        results = await _test_race_condition_category(
            mock_client, _CHECKOUT_URL, 10, 200, 100,
        )
        assert len(results) == 5
        assert all(not r.vulnerable for r in results)


# --- print_results tests ---


def _make_result(
    attempts: list[BizLogicAttempt] | None = None,
    issues: list[str] | None = None,
    overall_status: str = "safe",
) -> BizLogicResult:
    return BizLogicResult(
        target=_TARGET, tls=True,
        baseline_status=200, baseline_size=100,
        checkout_url=_CHECKOUT_URL,
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
    attempt = BizLogicAttempt(
        technique="price_overflow", category="integer_overflow",
        status_baseline=200, status_test=200,
        size_baseline=100, size_test=120,
        status_changed=False, size_changed=True,
        vulnerable=True, details="overflow detected", error="",
        exploit="price_quantity_manipulation", tool="wfuzz",
    )
    result = _make_result(attempts=[attempt], overall_status="vulnerable")
    print_results(result)
    out = capsys.readouterr().out
    assert "Vulnerabilidades encontradas" in out
    assert "price_overflow" in out


def test_print_results_with_issues(capsys: pytest.CaptureFixture[str]) -> None:
    result = _make_result(issues=["Endpoint de checkout nao detectado"])
    print_results(result)
    out = capsys.readouterr().out
    assert "Observacoes" in out
    assert "checkout nao detectado" in out


# --- build_parser tests ---


class TestBuildParser:
    def test_has_url_arg(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_category_arg(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-c", "integer_overflow"])
        assert args.category == "integer_overflow"

    def test_default_category_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.category == "all"


# --- run_scan tests ---


class TestRunScan:
    @pytest.mark.asyncio
    async def test_baseline_error_returns_1(self) -> None:
        with patch("mytools.web.businesslogic.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.businesslogic.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.side_effect = httpx.RequestError("fail")
                result = await run_scan(_TARGET, [], 10, None)
                assert result == 1

    @pytest.mark.asyncio
    async def test_vulnerable_returns_1(self) -> None:
        with patch("mytools.web.businesslogic.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.businesslogic.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = (200, {}, b"<html>checkout</html>", b"")
                with patch("mytools.web.businesslogic._CATEGORY_TESTERS") as mock_testers:
                    mock_attempt = BizLogicAttempt(
                        technique="price_overflow", category="integer_overflow",
                        status_baseline=200, status_test=200,
                        size_baseline=100, size_test=120,
                        status_changed=False, size_changed=True,
                        vulnerable=True, details="overflow", error="",
                    )
                    mock_testers.get.return_value = AsyncMock(return_value=[mock_attempt])
                    result = await run_scan(_TARGET, ["integer_overflow"], 10, None)
                    assert result == 1

    @pytest.mark.asyncio
    async def test_safe_returns_0(self) -> None:
        with patch("mytools.web.businesslogic.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.businesslogic.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = (200, {}, b"<html>safe</html>", b"")
                with patch("mytools.web.businesslogic._CATEGORY_TESTERS") as mock_testers:
                    mock_attempt = BizLogicAttempt(
                        technique="price_overflow", category="integer_overflow",
                        status_baseline=200, status_test=403,
                        size_baseline=100, size_test=100,
                        status_changed=True, size_changed=False,
                        vulnerable=False, details="", error="",
                    )
                    mock_testers.get.return_value = AsyncMock(return_value=[mock_attempt])
                    result = await run_scan(_TARGET, ["integer_overflow"], 10, None)
                    assert result == 0

    @pytest.mark.asyncio
    async def test_categories_defaults_to_all(self) -> None:
        with patch("mytools.web.businesslogic.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.businesslogic.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = (200, {}, b"<html>safe</html>", b"")
                with patch("mytools.web.businesslogic._CATEGORY_TESTERS") as mock_testers:
                    mock_testers.get.return_value = AsyncMock(return_value=[])
                    result = await run_scan(_TARGET, [], 10, None)
                    assert result == 0
                    assert mock_testers.get.call_count == 3

    @pytest.mark.asyncio
    async def test_no_checkout_url_adds_issue(self) -> None:
        with patch("mytools.web.businesslogic.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.businesslogic.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = (200, {}, b"<html>safe</html>", b"")
                with patch("mytools.web.businesslogic._CATEGORY_TESTERS") as mock_testers:
                    mock_testers.get.return_value = AsyncMock(return_value=[])
                    with (
                        patch("mytools.web.businesslogic._find_checkout_url", return_value=None),
                        patch("mytools.web.businesslogic.write_output") as mock_write,
                    ):
                        await run_scan(_TARGET, [], 10, "output.json")
                        mock_write.assert_called_once()

    @pytest.mark.asyncio
    async def test_output_file_calls_write(self) -> None:
        with patch("mytools.web.businesslogic.create_async_client") as mock_mac:
            mock_client = AsyncMock()
            mock_mac.return_value.__aenter__ = AsyncMock(return_value=mock_client)
            mock_mac.return_value.__aexit__ = AsyncMock(return_value=False)
            with patch("mytools.web.businesslogic.fetch", new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = (200, {}, b"<html>safe</html>", b"")
                with patch("mytools.web.businesslogic._CATEGORY_TESTERS") as mock_testers:
                    mock_testers.get.return_value = AsyncMock(return_value=[])
                    with patch("mytools.web.businesslogic.write_output") as mock_write:
                        await run_scan(_TARGET, [], 10, "output.json")
                        mock_write.assert_called_once()


# --- run_once tests ---


class TestRunOnce:
    def test_extracts_single_category(self) -> None:
        args = argparse.Namespace(
            url=_TARGET, category="integer_overflow",
            timeout=10, output=None,
        )
        with patch("mytools.web.businesslogic.run_scan", new_callable=AsyncMock, return_value=0) as mock_scan:
            run_once(args)
            assert mock_scan.call_args.kwargs["categories"] == ["integer_overflow"]

    def test_all_category_passes_empty_list(self) -> None:
        args = argparse.Namespace(
            url=_TARGET, category="all",
            timeout=10, output=None,
        )
        with patch("mytools.web.businesslogic.run_scan", new_callable=AsyncMock, return_value=0) as mock_scan:
            run_once(args)
            assert mock_scan.call_args.kwargs["categories"] == []
