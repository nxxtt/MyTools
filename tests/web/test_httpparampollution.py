#!/usr/bin/env python3
"""Testes unitarios do modulo de HTTP Parameter Pollution."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mytools.web.httpparampollution import (
    _BODY_PAYLOADS,
    _BYPASS_PAYLOADS,
    _CATEGORY_MAP,
    _HEADER_PAYLOADS,
    _JSON_PAYLOADS,
    _QUERY_PAYLOADS,
    _SENSITIVE_PATHS,
    HPPAttempt,
    HPPResult,
    _check_hpp_response,
    _check_response_content,
    _test_baseline,
    _test_body,
    _test_bypass,
    _test_header,
    _test_json,
    _test_query,
    banner_art,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)


# ─── Category Map ────────────────────────────────────────────────────────────
class TestCategoryMap:
    def test_has_five_categories(self) -> None:
        assert len(_CATEGORY_MAP) == 5

    def test_categories_are_correct(self) -> None:
        expected = {"query", "body", "header", "json", "bypass"}
        assert set(_CATEGORY_MAP.keys()) == expected

    def test_all_categories_have_payloads(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) > 0, f"Categoria {cat} vazia"

    def test_all_categories_have_5_techniques(self) -> None:
        for cat, techs in _CATEGORY_MAP.items():
            assert len(techs) == 5, f"Categoria {cat} tem {len(techs)} tecnicas"


# ─── Payload Lists ───────────────────────────────────────────────────────────
class TestPayloadLists:
    def test_query_payloads_count(self) -> None:
        assert len(_QUERY_PAYLOADS) == 5

    def test_body_payloads_count(self) -> None:
        assert len(_BODY_PAYLOADS) == 5

    def test_header_payloads_count(self) -> None:
        assert len(_HEADER_PAYLOADS) == 5

    def test_json_payloads_count(self) -> None:
        assert len(_JSON_PAYLOADS) == 5

    def test_bypass_payloads_count(self) -> None:
        assert len(_BYPASS_PAYLOADS) == 5

    def test_sensitive_paths(self) -> None:
        assert len(_SENSITIVE_PATHS) == 10


# ─── Query Payloads ──────────────────────────────────────────────────────────
class TestQueryPayloads:
    def test_all_have_dup_ampersand(self) -> None:
        for _, payload, _, _ in _QUERY_PAYLOADS:
            assert "&" in payload, f"Payload {payload} sem duplicacao"

    def test_all_have_param_name(self) -> None:
        for _, _, param_name, _ in _QUERY_PAYLOADS:
            assert len(param_name) > 0


# ─── Body Payloads ───────────────────────────────────────────────────────────
class TestBodyPayloads:
    def test_all_have_dup_ampersand(self) -> None:
        for _, payload, _, _ in _BODY_PAYLOADS:
            assert "&" in payload


# ─── Header Payloads ─────────────────────────────────────────────────────────
class TestHeaderPayloads:
    def test_all_have_header_name(self) -> None:
        for _, header_name, _, _ in _HEADER_PAYLOADS:
            assert len(header_name) > 0


# ─── JSON Payloads ───────────────────────────────────────────────────────────
class TestJSONPayloads:
    def test_all_have_field_name(self) -> None:
        for _, field_name, _, _ in _JSON_PAYLOADS:
            assert len(field_name) > 0

    def test_all_have_field_value(self) -> None:
        for _, _, field_value, _ in _JSON_PAYLOADS:
            assert field_value is not None


# ─── Bypass Payloads ─────────────────────────────────────────────────────────
class TestBypassPayloads:
    def test_all_have_payload(self) -> None:
        for _, payload, _, _, _ in _BYPASS_PAYLOADS:
            assert len(payload) > 0


# ─── Check HPP Response ─────────────────────────────────────────────────────
class TestCheckHPPResponse:
    def test_status_change_is_vulnerable(self) -> None:
        assert _check_hpp_response(b"ok", 200, 403) is True

    def test_same_status_not_vulnerable(self) -> None:
        assert _check_hpp_response(b"ok", 200, 200) is False

    def test_0_status_not_vulnerable(self) -> None:
        assert _check_hpp_response(b"", 0, 200) is False

    def test_403_to_200_is_vulnerable(self) -> None:
        assert _check_hpp_response(b"ok", 200, 403) is True

    def test_200_to_404_is_vulnerable(self) -> None:
        assert _check_hpp_response(b"not found", 404, 200) is True


# ─── Check Response Content ──────────────────────────────────────────────────
class TestCheckResponseContent:
    def test_match_indicator(self) -> None:
        assert (
            _check_response_content(b"parameter duplicate detected", ["parameter"])
            is True
        )

    def test_no_match(self) -> None:
        assert _check_response_content(b"not found", ["duplicate"]) is False

    def test_empty_body(self) -> None:
        assert _check_response_content(b"", ["test"]) is False

    def test_case_insensitive(self) -> None:
        assert _check_response_content(b"PARAMETER", ["parameter"]) is True


# ─── Dataclasses ─────────────────────────────────────────────────────────────
class TestHPPAttempt:
    def test_frozen(self) -> None:
        a = HPPAttempt(
            technique="test",
            category="query",
            param_name="id",
            payload="id=1&id=2",
            method="GET",
            status_baseline=200,
            status_test=403,
            size_baseline=100,
            size_test=200,
            status_changed=True,
            size_changed=True,
            vulnerable=True,
            details="test",
            error="",
        )
        with pytest.raises(AttributeError):
            a.technique = "other"  # type: ignore[misc]

    def test_slots(self) -> None:
        a = HPPAttempt(
            technique="test",
            category="query",
            param_name="id",
            payload="id=1&id=2",
            method="GET",
            status_baseline=200,
            status_test=403,
            size_baseline=100,
            size_test=200,
            status_changed=True,
            size_changed=True,
            vulnerable=True,
            details="test",
            error="",
        )
        assert not hasattr(a, "__dict__")


class TestHPPResult:
    def test_frozen(self) -> None:
        r = HPPResult(
            target="https://test.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="safe",
        )
        with pytest.raises(AttributeError):
            r.target = "other"  # type: ignore[misc]


# ─── Test Baseline ───────────────────────────────────────────────────────────
class TestBaseline:
    @pytest.mark.asyncio
    async def test_baseline_success(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"ok"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        result = await _test_baseline(mock_client, "https://test.com/admin")
        assert result == (200, 2, b"ok")

    @pytest.mark.asyncio
    async def test_baseline_error(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("fail"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        result = await _test_baseline(mock_client, "https://test.com/admin")
        assert result == (0, 0, b"")


# ─── Test Query ──────────────────────────────────────────────────────────────
class TestQuery:
    @pytest.mark.asyncio
    async def test_vulnerable_query(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.content = b"forbidden"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_query(
            mock_client,
            "https://test.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        vuln = [r for r in results if r.vulnerable]
        assert len(vuln) > 0

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_query(
            mock_client,
            "https://test.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.error for r in results)

    @pytest.mark.asyncio
    async def test_content_indicator(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"duplicate parameter detected"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_query(
            mock_client,
            "https://test.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.vulnerable for r in results)


# ─── Test Body ───────────────────────────────────────────────────────────────
class TestBody:
    @pytest.mark.asyncio
    async def test_vulnerable_body(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.content = b"forbidden"
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_body(
            mock_client,
            "https://test.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.category == "body" for r in results)

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_body(
            mock_client,
            "https://test.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.error for r in results)

    @pytest.mark.asyncio
    async def test_content_indicator(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"duplicate parameter detected"
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_body(
            mock_client,
            "https://test.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.vulnerable for r in results)


# ─── Test Header ─────────────────────────────────────────────────────────────
class TestHeader:
    @pytest.mark.asyncio
    async def test_vulnerable_header(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.content = b"forbidden"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_header(
            mock_client,
            "https://test.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.category == "header" for r in results)

    @pytest.mark.asyncio
    async def test_content_indicator(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"duplicate parameter detected"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_header(
            mock_client,
            "https://test.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_header(
            mock_client,
            "https://test.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.error for r in results)


# ─── Test JSON ───────────────────────────────────────────────────────────────
class TestJSON:
    @pytest.mark.asyncio
    async def test_vulnerable_json(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.content = b"forbidden"
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_json(
            mock_client,
            "https://test.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.category == "json" for r in results)

    @pytest.mark.asyncio
    async def test_content_indicator(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"duplicate parameter detected"
        mock_client = AsyncMock()
        mock_client.post = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_json(
            mock_client,
            "https://test.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.post = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_json(
            mock_client,
            "https://test.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.error for r in results)


# ─── Test Bypass ─────────────────────────────────────────────────────────────
class TestBypass:
    @pytest.mark.asyncio
    async def test_vulnerable_bypass(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_resp.content = b"forbidden"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_bypass(
            mock_client,
            "https://test.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.category == "bypass" for r in results)

    @pytest.mark.asyncio
    async def test_content_indicator(self) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"duplicate parameter detected"
        mock_client = AsyncMock()
        mock_client.get = AsyncMock(return_value=mock_resp)
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_bypass(
            mock_client,
            "https://test.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.vulnerable for r in results)

    @pytest.mark.asyncio
    async def test_error_handling(self) -> None:
        import httpx

        mock_client = AsyncMock()
        mock_client.get = AsyncMock(side_effect=httpx.RequestError("timeout"))
        mock_client.__aenter__ = AsyncMock(return_value=mock_client)
        mock_client.__aexit__ = AsyncMock(return_value=False)

        results = await _test_bypass(
            mock_client,
            "https://test.com",
            (200, 100, b"ok"),
        )
        assert len(results) == 20
        assert all(r.error for r in results)


# ─── Print Results ───────────────────────────────────────────────────────────
class TestPrintResults:
    def test_vulnerable_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = HPPResult(
            target="https://test.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[
                HPPAttempt(
                    technique="dup_id",
                    category="query",
                    param_name="id",
                    payload="id=1&id=2",
                    method="GET",
                    status_baseline=200,
                    status_test=403,
                    size_baseline=100,
                    size_test=200,
                    status_changed=True,
                    size_changed=True,
                    vulnerable=True,
                    details="path=/admin",
                    error="",
                )
            ],
            vulnerable_techniques=["dup_id"],
            blocked_techniques=[],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Vulnerabilidades detectadas" in output
        assert "dup_id" in output

    def test_no_vulns_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = HPPResult(
            target="https://test.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=[],
            overall_status="safe",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Nenhuma HTTP Parameter Pollution detectada" in output

    def test_vulnerable_without_details(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        result = HPPResult(
            target="https://test.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[
                HPPAttempt(
                    technique="dup_id",
                    category="query",
                    param_name="id",
                    payload="id=1&id=2",
                    method="GET",
                    status_baseline=200,
                    status_test=403,
                    size_baseline=100,
                    size_test=200,
                    status_changed=True,
                    size_changed=True,
                    vulnerable=True,
                    details="",
                    error="",
                )
            ],
            vulnerable_techniques=["dup_id"],
            blocked_techniques=[],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "dup_id" in output

    def test_with_issues(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = HPPResult(
            target="https://test.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[],
            vulnerable_techniques=[],
            blocked_techniques=[],
            issues=["Nenhum teste retornou resultado claro"],
            overall_status="unknown",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Observacoes" in output


# ─── Build Parser ────────────────────────────────────────────────────────────
@pytest.mark.smoke
class TestBuildParser:
    def test_has_url(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.url == "https://test.com"

    def test_has_category(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "-c", "query"])
        assert args.category == "query"

    def test_default_category_is_all(self) -> None:
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])
        assert args.category == "all"

    def test_all_categories(self) -> None:
        parser = build_parser()
        for cat in ["all", "query", "body", "header", "json", "bypass"]:
            args = parser.parse_args(["https://test.com", "-c", cat])
            assert args.category == cat


# ─── Run Once ────────────────────────────────────────────────────────────────
class TestRunOnce:
    @patch("mytools.web.httpparampollution.run_scan")
    def test_run_once(self, mock_run: MagicMock) -> None:
        mock_run.return_value = 0
        parser = build_parser()
        args = parser.parse_args(["https://test.com"])

        result = run_once(args)
        assert result == 0
        mock_run.assert_called_once()

    @patch("mytools.web.httpparampollution.run_scan")
    def test_run_once_specific_category(self, mock_run: MagicMock) -> None:
        mock_run.return_value = 1
        parser = build_parser()
        args = parser.parse_args(["https://test.com", "-c", "query"])

        result = run_once(args)
        assert result == 1
        mock_run.assert_called_once()
        assert mock_run.call_args[1]["categories"] == ["query"]


# ─── Run Scan ────────────────────────────────────────────────────────────────


class TestRunScan:
    def _attempt(self, vulnerable: bool, error: str = "") -> HPPAttempt:
        return HPPAttempt(
            technique="dup_id",
            category="query",
            param_name="id",
            payload="id=1&id=2",
            method="GET",
            status_baseline=200,
            status_test=403 if vulnerable else 200,
            size_baseline=100,
            size_test=200 if vulnerable else 100,
            status_changed=vulnerable,
            size_changed=vulnerable,
            vulnerable=vulnerable,
            details="path=/admin" if vulnerable else "",
            error=error,
        )

    def _make_tester(self, attempts: list[HPPAttempt]) -> AsyncMock:
        return AsyncMock(return_value=attempts)

    @pytest.mark.asyncio
    async def test_vulnerable_with_output(self) -> None:
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        tester = self._make_tester([self._attempt(True)])
        with (
            patch(
                "mytools.web.httpparampollution.create_async_client",
                MagicMock(return_value=client),
            ),
            patch(
                "mytools.web.httpparampollution._test_baseline",
                AsyncMock(return_value=(200, 100, b"ok")),
            ),
            patch("mytools.web.httpparampollution._test_query", tester),
            patch("mytools.web.httpparampollution._test_body", tester),
            patch("mytools.web.httpparampollution._test_header", tester),
            patch("mytools.web.httpparampollution._test_json", tester),
            patch("mytools.web.httpparampollution._test_bypass", tester),
            patch("mytools.web.httpparampollution.print_results"),
            patch("mytools.web.httpparampollution.write_output") as mock_write,
        ):
            result = await run_scan(
                "https://test.com",
                ["query", "body", "header", "json", "bypass"],
                5,
                "out.json",
            )
        assert result == 1
        mock_write.assert_called_once()

    @pytest.mark.asyncio
    async def test_blocked_safe(self) -> None:
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        tester = self._make_tester([self._attempt(False)])
        with (
            patch(
                "mytools.web.httpparampollution.create_async_client",
                MagicMock(return_value=client),
            ),
            patch(
                "mytools.web.httpparampollution._test_baseline",
                AsyncMock(return_value=(200, 100, b"ok")),
            ),
            patch("mytools.web.httpparampollution._test_query", tester),
            patch("mytools.web.httpparampollution._test_body", tester),
            patch("mytools.web.httpparampollution._test_header", tester),
            patch("mytools.web.httpparampollution._test_json", tester),
            patch("mytools.web.httpparampollution._test_bypass", tester),
            patch("mytools.web.httpparampollution.print_results"),
        ):
            result = await run_scan("http://test.com", ["query"], 5, None)
        assert result == 0

    @pytest.mark.asyncio
    async def test_unknown_category_skipped(self) -> None:
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        with (
            patch(
                "mytools.web.httpparampollution.create_async_client",
                MagicMock(return_value=client),
            ),
            patch(
                "mytools.web.httpparampollution._test_baseline",
                AsyncMock(return_value=(200, 100, b"ok")),
            ),
            patch("mytools.web.httpparampollution.print_results"),
        ):
            result = await run_scan("http://test.com", ["bogus_cat"], 5, None)
        assert result == 0

    @pytest.mark.asyncio
    async def test_no_clear_result(self) -> None:
        client = MagicMock()
        client.__aenter__ = AsyncMock(return_value=client)
        client.__aexit__ = AsyncMock(return_value=False)
        tester = self._make_tester([])
        with (
            patch(
                "mytools.web.httpparampollution.create_async_client",
                MagicMock(return_value=client),
            ),
            patch(
                "mytools.web.httpparampollution._test_baseline",
                AsyncMock(return_value=(200, 100, b"ok")),
            ),
            patch("mytools.web.httpparampollution._test_query", tester),
            patch("mytools.web.httpparampollution._test_body", tester),
            patch("mytools.web.httpparampollution._test_header", tester),
            patch("mytools.web.httpparampollution._test_json", tester),
            patch("mytools.web.httpparampollution._test_bypass", tester),
            patch("mytools.web.httpparampollution.print_results"),
        ):
            result = await run_scan("http://test.com", [], 5, None)
        assert result == 0


# ─── Banner ──────────────────────────────────────────────────────────────────


class TestBanner:
    def test_banner_art(self) -> None:
        with patch("mytools.web.httpparampollution.create_banner") as mock_banner:
            banner_art()
        mock_banner.return_value.assert_called_once()


# ─── Print Results (extra) ───────────────────────────────────────────────────


class TestPrintResultsExtra:
    def test_dedup_vulnerable(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = HPPResult(
            target="https://test.com",
            baseline_status=200,
            baseline_size=100,
            tls=True,
            attempts=[
                HPPAttempt(
                    technique="dup_id",
                    category="query",
                    param_name="id",
                    payload="id=1&id=2",
                    method="GET",
                    status_baseline=200,
                    status_test=403,
                    size_baseline=100,
                    size_test=200,
                    status_changed=True,
                    size_changed=True,
                    vulnerable=True,
                    details="path=/admin",
                    error="",
                ),
                HPPAttempt(
                    technique="dup_id",
                    category="query",
                    param_name="id",
                    payload="id=1&id=2",
                    method="GET",
                    status_baseline=200,
                    status_test=404,
                    size_baseline=100,
                    size_test=300,
                    status_changed=True,
                    size_changed=True,
                    vulnerable=True,
                    details="path=/admin2",
                    error="",
                ),
            ],
            vulnerable_techniques=["dup_id"],
            blocked_techniques=[],
            issues=[],
            overall_status="vulnerable",
        )
        print_results(result)
        output = capsys.readouterr().out
        assert "Vulnerabilidades detectadas" in output


# ─── Main ────────────────────────────────────────────────────────────────────


class TestMain:
    def test_main(self) -> None:
        with patch(
            "mytools.web.httpparampollution.run_main_loop", return_value=0
        ) as mock_loop:
            assert main() == 0
        mock_loop.assert_called_once()


class TestMainGuard:
    def test_guard(self) -> None:
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-hpp"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.httpparampollution", run_name="__main__")
        assert exc_info.value.code == 0
