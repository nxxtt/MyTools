#!/usr/bin/env python3
"""Testes unitarios do modulo Account Abuse Attack Detection."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mytools.web.accountabuse import (
    _CATEGORY_MAP,
    _CATEGORY_TESTERS,
    _COUPON_PAYLOADS,
    _GIFT_CARD_PAYLOADS,
    _LOYALTY_PAYLOADS,
    _REFUND_PAYLOADS,
    _SUBSCRIPTION_PAYLOADS,
    AccountAttempt,
    AccountResult,
    _find_account_url,
    _test_category,
    banner_art,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)

_TARGET = "https://example.com/account"


def test_category_map_has_five_categories() -> None:
    assert len(_CATEGORY_MAP) == 5


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {
        "coupon",
        "loyalty_points",
        "gift_card",
        "refund",
        "subscription",
    }


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 25


def test_coupon_techniques_count() -> None:
    assert len(_CATEGORY_MAP["coupon"]) == 5


def test_loyalty_points_techniques_count() -> None:
    assert len(_CATEGORY_MAP["loyalty_points"]) == 5


def test_gift_card_techniques_count() -> None:
    assert len(_CATEGORY_MAP["gift_card"]) == 5


def test_refund_techniques_count() -> None:
    assert len(_CATEGORY_MAP["refund"]) == 5


def test_subscription_techniques_count() -> None:
    assert len(_CATEGORY_MAP["subscription"]) == 5


def test_coupon_payloads_count() -> None:
    assert len(_COUPON_PAYLOADS) == 5


def test_loyalty_payloads_count() -> None:
    assert len(_LOYALTY_PAYLOADS) == 5


def test_gift_card_payloads_count() -> None:
    assert len(_GIFT_CARD_PAYLOADS) == 5


def test_refund_payloads_count() -> None:
    assert len(_REFUND_PAYLOADS) == 5


def test_subscription_payloads_count() -> None:
    assert len(_SUBSCRIPTION_PAYLOADS) == 5


def test_coupon_payloads_have_four_elements() -> None:
    for p in _COUPON_PAYLOADS:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_loyalty_payloads_have_four_elements() -> None:
    for p in _LOYALTY_PAYLOADS:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_gift_card_payloads_have_four_elements() -> None:
    for p in _GIFT_CARD_PAYLOADS:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_refund_payloads_have_four_elements() -> None:
    for p in _REFUND_PAYLOADS:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_subscription_payloads_have_four_elements() -> None:
    for p in _SUBSCRIPTION_PAYLOADS:
        assert len(p) == 4, f"Payload {p[0]} should have 4 elements"


def test_find_account_url_with_coupon() -> None:
    body = '<a href="/coupon/redeem">Resgatar cupom</a>'
    result = _find_account_url("https://example.com", body)
    assert result is not None
    assert "coupon" in result


def test_find_account_url_with_gift_card() -> None:
    body = '<a href="/gift-card/check">Verificar gift card</a>'
    result = _find_account_url("https://example.com", body)
    assert result is not None
    assert "gift" in result.lower()


def test_find_account_url_with_subscription() -> None:
    body = '<a href="/subscription/manage">Gerenciar assinatura</a>'
    result = _find_account_url("https://example.com", body)
    assert result is not None
    assert "subscription" in result


def test_find_account_url_not_found() -> None:
    body = "<html><body>Safe page</body></html>"
    result = _find_account_url("https://example.com", body)
    assert result is None


def test_attempt_dataclass_frozen() -> None:
    a = AccountAttempt(
        technique="test",
        category="coupon",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=100,
        status_changed=False,
        size_changed=False,
        vulnerable=True,
        details="test",
        error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False  # type: ignore[reportAttributeAccessIssue]


def test_attempt_dataclass_slots() -> None:
    a = AccountAttempt(
        technique="test",
        category="coupon",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=100,
        status_changed=False,
        size_changed=False,
        vulnerable=True,
        details="test",
        error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = AccountResult(
        target=_TARGET,
        tls=True,
        baseline_status=200,
        baseline_size=100,
        account_url=None,
        attempts=[],
        vulnerable_techniques=[],
        blocked_techniques=[],
        issues=[],
        overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"  # type: ignore[reportAttributeAccessIssue]


def test_result_dataclass_slots() -> None:
    r = AccountResult(
        target=_TARGET,
        tls=True,
        baseline_status=200,
        baseline_size=100,
        account_url=None,
        attempts=[],
        vulnerable_techniques=[],
        blocked_techniques=[],
        issues=[],
        overall_status="safe",
    )
    assert not hasattr(r, "__dict__")


def test_no_duplicate_technique_names() -> None:
    all_techniques: list[str] = []
    for techs in _CATEGORY_MAP.values():
        all_techniques.extend(techs)
    assert len(all_techniques) == len(set(all_techniques))


def test_all_techniques_are_strings() -> None:
    for cat, techs in _CATEGORY_MAP.items():
        for t in techs:
            assert isinstance(t, str), f"{cat}/{t} is not a string"


# ─── _find_account_url branches ──────────────────────────────────────────────


def test_find_account_url_no_href_before_indicator() -> None:
    body = "<a>coupon redeem</a>"
    assert _find_account_url("https://example.com", body) is None


def test_find_account_url_unclosed_href() -> None:
    body = '<a href="coupon'
    assert _find_account_url("https://example.com", body) is None


def test_find_account_url_returns_joined_url() -> None:
    body = '<a href="/checkout/coupon/apply">Apply coupon</a>'
    result = _find_account_url("https://example.com/account", body)
    assert result == "https://example.com/checkout/coupon/apply"


# ─── _test_category ──────────────────────────────────────────────────────────


@pytest.mark.asyncio
@respx.mock
async def test_test_category_all_payloads(async_client: httpx.AsyncClient) -> None:
    respx.post(_TARGET).mock(
        return_value=httpx.Response(200, text="coupon discount points")
    )
    results = await _test_category(
        async_client, _TARGET, _COUPON_PAYLOADS, "coupon", 200, 100
    )
    assert len(results) == 5
    assert all(r.vulnerable for r in results)
    assert all(r.status_test == 200 for r in results)
    assert all(r.size_changed for r in results)


@pytest.mark.asyncio
@respx.mock
async def test_test_category_not_reflected(async_client: httpx.AsyncClient) -> None:
    respx.post(_TARGET).mock(return_value=httpx.Response(403, text="forbidden"))
    results = await _test_category(
        async_client, _TARGET, _COUPON_PAYLOADS, "coupon", 403, 50
    )
    assert len(results) == 5
    assert all(not r.vulnerable for r in results)
    assert all(r.status_changed is False for r in results)
    assert all(r.error == "" for r in results)


@pytest.mark.asyncio
@respx.mock
async def test_test_category_connection_error(
    async_client: httpx.AsyncClient,
) -> None:
    respx.post(_TARGET).mock(side_effect=httpx.ConnectError("boom"))
    results = await _test_category(
        async_client, _TARGET, _COUPON_PAYLOADS, "coupon", 200, 100
    )
    assert len(results) == 5
    assert all(r.error for r in results)
    assert all(r.status_test == 0 for r in results)
    assert all(r.vulnerable is False for r in results)


@pytest.mark.asyncio
@respx.mock
async def test_category_testers_all_run(async_client: httpx.AsyncClient) -> None:
    respx.post(_TARGET).mock(
        return_value=httpx.Response(
            200,
            text=(
                "coupon discount points balance transfer card refund amount premium "
                "session"
            ),
        )
    )
    for cat, tester in _CATEGORY_TESTERS.items():
        results = await tester(async_client, _TARGET, 10, 200, 100)
        assert len(results) == 5
        assert all(r.category == cat for r in results)


# ─── print_results ───────────────────────────────────────────────────────────


def _attempt(
    *,
    technique: str = "enumeration",
    category: str = "coupon",
    status_baseline: int = 200,
    status_test: int = 200,
    size_baseline: int = 100,
    size_test: int = 500,
    status_changed: bool = False,
    size_changed: bool = True,
    vulnerable: bool = True,
    details: str = "keywords=['coupon']",
    error: str = "",
    exploit: str = "coupon_bypass_payload",
    tool: str = "wfuzz",
) -> AccountAttempt:
    return AccountAttempt(
        technique=technique,
        category=category,
        status_baseline=status_baseline,
        status_test=status_test,
        size_baseline=size_baseline,
        size_test=size_test,
        status_changed=status_changed,
        size_changed=size_changed,
        vulnerable=vulnerable,
        details=details,
        error=error,
        exploit=exploit,
        tool=tool,
    )


def _result(
    *,
    target: str = _TARGET,
    tls: bool = True,
    baseline_status: int = 200,
    baseline_size: int = 100,
    account_url: str | None = None,
    attempts: list[AccountAttempt] | None = None,
    vulnerable_techniques: list[str] | None = None,
    blocked_techniques: list[str] | None = None,
    issues: list[str] | None = None,
    overall_status: str = "SEGURO",
) -> AccountResult:
    return AccountResult(
        target=target,
        tls=tls,
        baseline_status=baseline_status,
        baseline_size=baseline_size,
        account_url=account_url,
        attempts=attempts or [],
        vulnerable_techniques=vulnerable_techniques or [],
        blocked_techniques=blocked_techniques or [],
        issues=issues or [],
        overall_status=overall_status,
    )


def test_print_results_vulnerable(capsys: pytest.CaptureFixture[str]) -> None:
    vuln = _attempt(status_changed=True)
    errored = _attempt(
        technique="race_refund",
        category="refund",
        vulnerable=False,
        error="connection failed",
        exploit="",
        tool="",
    )
    safe = _attempt(
        technique="balance_check",
        category="gift_card",
        vulnerable=False,
        size_changed=False,
        exploit="",
        tool="",
    )
    result = _result(
        account_url="https://example.com/coupon/redeem",
        attempts=[vuln, errored, safe],
        vulnerable_techniques=["enumeration"],
        issues=["Algum problema"],
        overall_status="VULNERAVEL",
    )
    print_results(result)
    out = capsys.readouterr().out
    assert "VULNERAVEL" in out
    assert "Account URL" in out
    assert "VULN" in out
    assert "ERROR" in out
    assert "SAFE" in out
    assert "Status MUDOU" in out
    assert "Size MUDOU" in out
    assert "Problemas encontrados" in out


def test_print_results_blocked(capsys: pytest.CaptureFixture[str]) -> None:
    blocked = _attempt(vulnerable=False, status_changed=True)
    result = _result(
        attempts=[blocked],
        blocked_techniques=["enumeration"],
        overall_status="BLOQUEADO",
    )
    print_results(result)
    out = capsys.readouterr().out
    assert "BLOQUEADO" in out


def test_print_results_secure(capsys: pytest.CaptureFixture[str]) -> None:
    print_results(_result())
    out = capsys.readouterr().out
    assert "SEGURO" in out
    assert "0 testes" in out


# ─── run_scan ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_run_scan_secure_default_categories() -> None:
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False
    testers: dict[str, object] = {
        cat: AsyncMock(return_value=[]) for cat in _CATEGORY_TESTERS
    }
    with (
        patch("mytools.web.accountabuse.create_async_client", return_value=mock_client),
        patch(
            "mytools.web.accountabuse.fetch",
            new=AsyncMock(return_value=(200, {}, b"<html>no links</html>", {})),
        ),
        patch.dict("mytools.web.accountabuse._CATEGORY_TESTERS", testers),
    ):
        result = await run_scan(_TARGET, [], 10, None)
    assert result.overall_status == "SEGURO"
    assert result.attempts == []
    assert result.account_url is None


@pytest.mark.asyncio
async def test_run_scan_vulnerable_blocked_invalid_and_error(
    tmp_path: Path,
) -> None:
    mock_client = AsyncMock()
    mock_client.__aenter__.return_value = mock_client
    mock_client.__aexit__.return_value = False

    vuln = _attempt(status_changed=True)
    blocked = _attempt(
        technique="balance_check",
        category="gift_card",
        status_baseline=403,
        status_test=200,
        status_changed=True,
        vulnerable=False,
        exploit="",
        tool="",
    )

    testers: dict[str, object] = {
        "coupon": AsyncMock(return_value=[vuln]),
        "gift_card": AsyncMock(return_value=[blocked]),
        "explode": AsyncMock(side_effect=RuntimeError("boom")),
    }

    body = b'<a href="/coupon/redeem">Coupon redeem</a>'
    out_path = tmp_path / "results.json"

    with (
        patch("mytools.web.accountabuse.create_async_client", return_value=mock_client),
        patch(
            "mytools.web.accountabuse.fetch",
            new=AsyncMock(return_value=(200, {}, body, {})),
        ),
        patch.dict("mytools.web.accountabuse._CATEGORY_TESTERS", testers),
    ):
        result = await run_scan(
            _TARGET, ["coupon", "gift_card", "invalid", "explode"], 10, str(out_path)
        )

    assert result.overall_status == "VULNERAVEL"
    assert "enumeration" in result.vulnerable_techniques
    assert "balance_check" in result.blocked_techniques
    assert any("explode" in issue for issue in result.issues)
    assert result.account_url == "https://example.com/coupon/redeem"
    assert out_path.exists()


# ─── banner_art / build_parser / run_once / main ─────────────────────────────


def test_banner_art_runs(capsys: pytest.CaptureFixture[str]) -> None:
    banner_art()
    assert "accountabuse" in capsys.readouterr().out


def test_build_parser_url() -> None:
    parser = build_parser()
    args = parser.parse_args([_TARGET])
    assert args.url == _TARGET


def test_build_parser_category_choices() -> None:
    parser = build_parser()
    for cat in _CATEGORY_MAP:
        args = parser.parse_args([_TARGET, "-c", cat])
        assert args.category == cat


def test_build_parser_default_category() -> None:
    parser = build_parser()
    args = parser.parse_args([_TARGET])
    assert args.category == "all"


def test_build_parser_rejects_invalid_category() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args([_TARGET, "-c", "invalid"])


def test_run_once_returns_1_when_vulnerable() -> None:
    args = MagicMock()
    args.url = _TARGET
    args.category = "coupon"
    args.timeout = 10
    args.output = None
    result = _result(vulnerable_techniques=["enumeration"])
    with patch(
        "mytools.web.accountabuse.run_scan", new=AsyncMock(return_value=result)
    ) as mock_scan:
        assert run_once(args) == 1
        assert mock_scan.call_args.kwargs["categories"] == ["coupon"]


def test_run_once_returns_0_when_secure() -> None:
    args = MagicMock()
    args.url = _TARGET
    args.category = "all"
    args.timeout = 10
    args.output = None
    with patch(
        "mytools.web.accountabuse.run_scan", new=AsyncMock(return_value=_result())
    ) as mock_scan:
        assert run_once(args) == 0
        assert mock_scan.call_args.kwargs["categories"] == []


def test_run_once_category_none_uses_empty_list() -> None:
    args = MagicMock()
    args.url = _TARGET
    args.category = None
    args.timeout = 10
    args.output = None
    with patch(
        "mytools.web.accountabuse.run_scan", new=AsyncMock(return_value=_result())
    ) as mock_scan:
        assert run_once(args) == 0
        assert mock_scan.call_args.kwargs["categories"] == []


def test_main_returns_zero() -> None:
    with (
        patch("sys.argv", ["mytools-accountabuse", _TARGET]),
        patch("mytools.web.accountabuse.run_main_loop", return_value=0) as mock_loop,
    ):
        assert main() == 0
        mock_loop.assert_called_once()


def test_main_guard() -> None:
    with (
        patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
        patch("sys.argv", ["mytools-accountabuse", _TARGET]),
        pytest.raises(SystemExit) as exc_info,
    ):
        import runpy

        runpy.run_module("mytools.web.accountabuse", run_name="__main__")
    assert exc_info.value.code == 0
