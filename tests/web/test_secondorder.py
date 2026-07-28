"""Testes do modulo secondorder.py — Verificacao de Segunda Ordem."""

from __future__ import annotations

import httpx
import pytest
import respx

from mytools.web.secondorder import (
    VERIFY_PAYLOADS,
    check_indicators,
    get_verify_payload,
    verify_positive,
)

# ---------------------------------------------------------------------------
# check_indicators
# ---------------------------------------------------------------------------


class TestCheckIndicators:
    def test_match_found(self) -> None:
        body = b"uid=33(www-data) gid=33(www-data)"
        found, indicator = check_indicators(body, [b"uid=", b"gid="])
        assert found is True
        assert indicator == "uid="

    def test_no_match(self) -> None:
        body = b"<html>not found</html>"
        found, indicator = check_indicators(body, [b"uid=", b"gid="])
        assert found is False
        assert indicator == ""

    def test_empty_body(self) -> None:
        found, _indicator = check_indicators(b"", [b"uid="])
        assert found is False

    def test_empty_indicators(self) -> None:
        found, _indicator = check_indicators(b"uid=33", [])
        assert found is False

    def test_multiple_indicators(self) -> None:
        body = b"root:x:0:0:root:/root:/bin/bash"
        found, indicator = check_indicators(body, [b"daemon:", b"root:"])
        assert found is True
        assert indicator == "root:"


# ---------------------------------------------------------------------------
# get_verify_payload
# ---------------------------------------------------------------------------


class TestGetVerifyPayload:
    def test_payload_exists(self) -> None:
        result = get_verify_payload("cmdinject", "os_command")
        assert result is not None
        payload, indicators = result
        assert payload == "; whoami"
        assert len(indicators) > 0

    def test_no_payload(self) -> None:
        result = get_verify_payload("nonexistent_module", "os_command")
        assert result is None

    def test_no_category(self) -> None:
        result = get_verify_payload("cmdinject", "nonexistent_category")
        assert result is None

    def test_all_modules_present(self) -> None:
        for module in ["cmdinject", "sqliscan", "lfidetect", "sstidetect"]:
            assert module in VERIFY_PAYLOADS

    def test_all_categories_have_tuple(self) -> None:
        for module, categories in VERIFY_PAYLOADS.items():
            for cat, value in categories.items():
                assert isinstance(value, tuple), f"{module}.{cat} is not tuple"
                assert len(value) == 2, f"{module}.{cat} length != 2"
                payload, indicators = value
                assert isinstance(payload, str), f"{module}.{cat} payload is not str"
                assert isinstance(indicators, list), f"{module}.{cat} indicators is not list"


# ---------------------------------------------------------------------------
# verify_positive
# ---------------------------------------------------------------------------


class TestVerifyPositive:
    @respx.mock
    @pytest.mark.asyncio
    async def test_confirmed(self) -> None:
        respx.get("https://example.com/?param=whoami").mock(
            return_value=httpx.Response(200, text="www-data"),
        )
        async with httpx.AsyncClient() as client:
            confirmed, found = await verify_positive(
                client,
                "https://example.com/?param=whoami",
                [b"www-data", b"root"],
            )
            assert confirmed is True
            assert found == "www-data"

    @respx.mock
    @pytest.mark.asyncio
    async def test_not_confirmed(self) -> None:
        respx.get("https://example.com/?param=whoami").mock(
            return_value=httpx.Response(200, text="not found"),
        )
        async with httpx.AsyncClient() as client:
            confirmed, found = await verify_positive(
                client,
                "https://example.com/?param=whoami",
                [b"www-data", b"root"],
            )
            assert confirmed is False
            assert found == ""

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout(self) -> None:
        async def _handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("fail")

        respx.route(method="GET", url="https://example.com/?param=whoami").mock(side_effect=_handler)
        async with httpx.AsyncClient() as client:
            confirmed, found = await verify_positive(
                client,
                "https://example.com/?param=whoami",
                [b"www-data"],
            )
            assert confirmed is False
            assert found == ""

    @respx.mock
    @pytest.mark.asyncio
    async def test_sql_verify(self) -> None:
        respx.get("https://example.com/?param=%22+OR+1%3D1--").mock(
            return_value=httpx.Response(200, text="You have an error in your SQL syntax"),
        )
        async with httpx.AsyncClient() as client:
            confirmed, found = await verify_positive(
                client,
                "https://example.com/?param=%22+OR+1%3D1--",
                [b"error", b"mysql", b"sqlite"],
            )
            assert confirmed is True
            assert "error" in found.lower()

    @respx.mock
    @pytest.mark.asyncio
    async def test_ssti_verify(self) -> None:
        respx.get("https://example.com/?param=%7B%7B7*8%7D%7D").mock(
            return_value=httpx.Response(200, text="<html>56</html>"),
        )
        async with httpx.AsyncClient() as client:
            confirmed, found = await verify_positive(
                client,
                "https://example.com/?param=%7B%7B7*8%7D%7D",
                [b"56"],
            )
            assert confirmed is True
            assert found == "56"


# ---------------------------------------------------------------------------
# VERIFY_PAYLOADS structure
# ---------------------------------------------------------------------------


class TestVerifyPayloadsStructure:
    def test_cmdinject_has_os_command(self) -> None:
        payload, indicators = VERIFY_PAYLOADS["cmdinject"]["os_command"]
        assert payload == "; whoami"
        assert b"www-data" in indicators

    def test_sqliscan_has_error(self) -> None:
        payload, indicators = VERIFY_PAYLOADS["sqliscan"]["error"]
        assert "OR" in payload
        assert len(indicators) > 0

    def test_lfidetect_has_lfi(self) -> None:
        payload, indicators = VERIFY_PAYLOADS["lfidetect"]["lfi"]
        assert "etc/hostname" in payload
        assert len(indicators) > 0

    def test_sstidetect_has_detect(self) -> None:
        payload, indicators = VERIFY_PAYLOADS["sstidetect"]["detect"]
        assert "7*8" in payload
        assert b"56" in indicators
