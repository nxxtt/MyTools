#!/usr/bin/env python3
"""Testes unitarios do modulo OIDC Attack Detection."""

from __future__ import annotations

import json
import runpy
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import respx

from mytools.web.oidc import (
    _CATEGORY_MAP,
    _CATEGORY_TESTERS,
    OIDCAttempt,
    OIDCResult,
    _extract_well_known_url,
    _parse_json_response,
    _test_discovery_category,
    _test_token_substitution_category,
    banner_art,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)

_TARGET = "https://example.com"


def test_category_map_has_two_categories() -> None:
    assert len(_CATEGORY_MAP) == 2


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {"discovery", "token_substitution"}


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 10


def test_discovery_techniques_count() -> None:
    assert len(_CATEGORY_MAP["discovery"]) == 5


def test_token_substitution_techniques_count() -> None:
    assert len(_CATEGORY_MAP["token_substitution"]) == 5


def test_extract_well_known_url_with_path() -> None:
    result = _extract_well_known_url("https://example.com/authorize")
    assert result == "https://example.com"


def test_extract_well_known_url_without_path() -> None:
    result = _extract_well_known_url("https://example.com")
    assert result == "https://example.com"


def test_extract_well_known_url_with_port() -> None:
    result = _extract_well_known_url("https://example.com:8443/auth")
    assert result == "https://example.com:8443"


def test_parse_json_response_valid() -> None:
    data = _parse_json_response('{"issuer": "https://example.com"}')
    assert data is not None
    assert data["issuer"] == "https://example.com"


def test_parse_json_response_invalid() -> None:
    assert _parse_json_response("not json") is None


def test_parse_json_response_array() -> None:
    assert _parse_json_response("[1, 2, 3]") is None


def test_parse_json_response_empty() -> None:
    assert _parse_json_response("") is None


def test_attempt_dataclass_frozen() -> None:
    a = OIDCAttempt(
        technique="test",
        category="discovery",
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
    a = OIDCAttempt(
        technique="test",
        category="discovery",
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
    r = OIDCResult(
        target=_TARGET,
        tls=True,
        baseline_status=200,
        baseline_size=100,
        well_known_url=None,
        well_known_data=None,
        attempts=[],
        vulnerable_techniques=[],
        blocked_techniques=[],
        issues=[],
        overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"  # type: ignore[reportAttributeAccessIssue]


def test_result_dataclass_slots() -> None:
    r = OIDCResult(
        target=_TARGET,
        tls=True,
        baseline_status=200,
        baseline_size=100,
        well_known_url=None,
        well_known_data=None,
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


def _resp(status: int = 200, text: str = "") -> MagicMock:
    response = MagicMock()
    response.status_code = status
    response.text = text
    return response


def _oidc_attempt(
    technique: str,
    vulnerable: bool,
    *,
    details: str = "",
    error: str = "",
    exploit: str = "",
    tool: str = "",
) -> OIDCAttempt:
    return OIDCAttempt(
        technique=technique,
        category="discovery",
        status_baseline=200,
        status_test=200,
        size_baseline=100,
        size_test=100,
        status_changed=False,
        size_changed=False,
        vulnerable=vulnerable,
        details=details,
        error=error,
        exploit=exploit,
        tool=tool,
    )


class TestDiscoveryCategory:
    """Testes para _test_discovery_category."""

    @pytest.mark.asyncio
    async def test_full_metadata(self) -> None:
        wk: dict[str, object] = {
            "issuer": "https://example.com",
            "jwks_uri": "https://example.com/jwks",
            "registration_endpoint": "https://example.com/register",
            "scopes_supported": ["openid", "admin"],
        }
        client = AsyncMock()
        client.get = AsyncMock(
            side_effect=[
                _resp(200, json.dumps(wk)),
                _resp(200, '{"keys": ["k1"]}'),
                _resp(200, "registered"),
            ]
        )
        attempts = await _test_discovery_category(
            client,
            "https://example.com",
            "https://example.com/.well-known/openid-configuration",
            wk,
            5.0,
            200,
            100,
        )
        by_tech = {a.technique: a for a in attempts}
        assert len(attempts) == 5
        assert by_tech["jwks_uri_fetch"].vulnerable is True
        assert by_tech["issuer_mismatch"].vulnerable is False
        assert by_tech["registration_endpoint"].vulnerable is True
        assert by_tech["scopes_supported"].vulnerable is False

    @pytest.mark.asyncio
    async def test_well_known_error_all_missing(self) -> None:
        client = AsyncMock()
        client.get = AsyncMock(side_effect=httpx.ConnectError("boom"))
        attempts = await _test_discovery_category(
            client,
            "https://example.com",
            "https://example.com/.well-known/openid-configuration",
            None,
            5.0,
            200,
            100,
        )
        by_tech = {a.technique: a for a in attempts}
        assert len(attempts) == 5
        assert by_tech["well_known_enumeration"].error
        assert (
            by_tech["jwks_uri_fetch"].details == "jwks_uri nao encontrado no discovery"
        )
        assert by_tech["issuer_mismatch"].details == "issuer ausente no discovery"
        assert (
            by_tech["registration_endpoint"].details == "registration_endpoint ausente"
        )
        assert by_tech["scopes_supported"].details == "scopes_supported ausente"

    @pytest.mark.asyncio
    async def test_jwks_error(self) -> None:
        wk: dict[str, object] = {"jwks_uri": "https://example.com/jwks"}
        client = AsyncMock()
        client.get = AsyncMock(
            side_effect=[
                _resp(200, json.dumps(wk)),
                httpx.ConnectError("boom"),
            ]
        )
        attempts = await _test_discovery_category(
            client,
            "https://example.com",
            "https://example.com/.well-known/openid-configuration",
            wk,
            5.0,
            200,
            100,
        )
        by_tech = {a.technique: a for a in attempts}
        assert by_tech["jwks_uri_fetch"].error

    @pytest.mark.asyncio
    async def test_registration_error(self) -> None:
        wk: dict[str, object] = {
            "registration_endpoint": "https://example.com/register"
        }
        client = AsyncMock()
        client.get = AsyncMock(
            side_effect=[
                _resp(200, json.dumps(wk)),
                httpx.ConnectError("boom"),
            ]
        )
        attempts = await _test_discovery_category(
            client,
            "https://example.com",
            "https://example.com/.well-known/openid-configuration",
            wk,
            5.0,
            200,
            100,
        )
        by_tech = {a.technique: a for a in attempts}
        assert by_tech["registration_endpoint"].error

    @pytest.mark.asyncio
    async def test_registration_405_is_not_vulnerable(self) -> None:
        wk: dict[str, object] = {
            "registration_endpoint": "https://example.com/register"
        }
        client = AsyncMock()
        client.get = AsyncMock(
            side_effect=[
                _resp(200, json.dumps(wk)),
                _resp(405, "method not allowed"),
            ]
        )
        attempts = await _test_discovery_category(
            client,
            "https://example.com",
            "https://example.com/.well-known/openid-configuration",
            wk,
            5.0,
            200,
            100,
        )
        by_tech = {a.technique: a for a in attempts}
        assert by_tech["registration_endpoint"].vulnerable is False

    @pytest.mark.asyncio
    async def test_issuer_mismatch(self) -> None:
        wk: dict[str, object] = {"issuer": "https://evil.com"}
        client = AsyncMock()
        client.get = AsyncMock(return_value=_resp(200, "not json"))
        attempts = await _test_discovery_category(
            client,
            "https://example.com",
            "https://example.com/.well-known/openid-configuration",
            wk,
            5.0,
            200,
            100,
        )
        by_tech = {a.technique: a for a in attempts}
        assert by_tech["issuer_mismatch"].vulnerable is True

    @pytest.mark.asyncio
    async def test_scopes_not_list(self) -> None:
        wk: dict[str, object] = {"scopes_supported": "openid"}
        client = AsyncMock()
        client.get = AsyncMock(return_value=_resp(200, "not json"))
        attempts = await _test_discovery_category(
            client,
            "https://example.com",
            "https://example.com/.well-known/openid-configuration",
            wk,
            5.0,
            200,
            100,
        )
        by_tech = {a.technique: a for a in attempts}
        assert by_tech["scopes_supported"].details == "scopes_supported nao e lista"

    @pytest.mark.asyncio
    async def test_scopes_safe_list(self) -> None:
        wk: dict[str, object] = {"scopes_supported": ["openid", "email"]}
        client = AsyncMock()
        client.get = AsyncMock(return_value=_resp(200, "not json"))
        attempts = await _test_discovery_category(
            client,
            "https://example.com",
            "https://example.com/.well-known/openid-configuration",
            wk,
            5.0,
            200,
            100,
        )
        by_tech = {a.technique: a for a in attempts}
        assert by_tech["scopes_supported"].vulnerable is False
        assert "scopes suportados" in by_tech["scopes_supported"].details


class TestTokenSubstitutionCategory:
    """Testes para _test_token_substitution_category."""

    @pytest.mark.asyncio
    async def test_endpoint_found_vulnerable(self) -> None:
        client = AsyncMock()
        client.post = AsyncMock(side_effect=[_resp(200, '{"access_token": "abc"}')] * 6)
        attempts = await _test_token_substitution_category(
            client, "https://example.com", 5.0, 200, 100
        )
        assert len(attempts) == 5
        assert all(a.vulnerable for a in attempts)

    @pytest.mark.asyncio
    async def test_all_endpoints_404(self) -> None:
        client = AsyncMock()
        client.post = AsyncMock(side_effect=[_resp(404, "not found")] * 9)
        attempts = await _test_token_substitution_category(
            client, "https://example.com", 5.0, 200, 100
        )
        assert len(attempts) == 5
        assert all(not a.vulnerable for a in attempts)

    @pytest.mark.asyncio
    async def test_request_errors(self) -> None:
        client = AsyncMock()
        client.post = AsyncMock(
            side_effect=[httpx.ConnectError("boom")] * 2
            + [_resp(404, "not found")] * 2
            + [httpx.ConnectError("boom")] * 5
        )
        attempts = await _test_token_substitution_category(
            client, "https://example.com", 5.0, 200, 100
        )
        assert len(attempts) == 5
        assert all(a.error for a in attempts)


class TestPrintResults:
    """Testes para print_results."""

    def test_vulnerable_with_errors_and_issues(self, capsys) -> None:
        result = OIDCResult(
            target=_TARGET,
            tls=True,
            baseline_status=200,
            baseline_size=100,
            well_known_url="https://example.com/.well-known/openid-configuration",
            well_known_data={"issuer": "https://example.com"},
            attempts=[
                _oidc_attempt(
                    "jwks_uri_fetch",
                    True,
                    details="chaves expostas",
                    exploit="nonce_replay_payload",
                    tool="curl",
                ),
                _oidc_attempt("jwks_uri_fetch", True),
                _oidc_attempt("issuer_mismatch", True),
                _oidc_attempt("boom", False, error="falhou"),
            ],
            vulnerable_techniques=["jwks_uri_fetch", "issuer_mismatch"],
            blocked_techniques=[],
            issues=["well-known nao acessivel"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr().out
        assert "OIDC Attack Detection" in captured
        assert "jwks_uri_fetch" in captured
        assert "well-known nao acessivel" in captured
        assert "Erros:       1" in captured

    def test_safe_no_issues(self, capsys) -> None:
        result = OIDCResult(
            target=_TARGET,
            tls=False,
            baseline_status=200,
            baseline_size=100,
            well_known_url=None,
            well_known_data=None,
            attempts=[_oidc_attempt("well_known_enumeration", False)],
            vulnerable_techniques=[],
            blocked_techniques=["well_known_enumeration"],
            issues=[],
            overall_status="safe",
        )
        print_results(result)
        captured = capsys.readouterr().out
        assert "Nenhuma vulnerabilidade OIDC detectada" in captured
        assert "Observacoes" not in captured


class TestRunScan:
    """Testes para run_scan."""

    @pytest.mark.asyncio
    @respx.mock
    async def test_connection_error(self) -> None:
        respx.route(url__startswith="https://example.com").mock(
            side_effect=httpx.ConnectError("Connection refused"),
        )
        result = await run_scan("https://example.com", [], 5.0, None)
        assert result == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_full_scan_vulnerable(self) -> None:
        wk_body = json.dumps(
            {
                "issuer": "https://example.com",
                "jwks_uri": "https://example.com/jwks",
                "registration_endpoint": "https://example.com/register",
                "scopes_supported": ["openid", "admin"],
            }
        )

        def handler(request) -> httpx.Response:
            url = str(request.url)
            if url.endswith("/.well-known/openid-configuration"):
                return httpx.Response(200, text=wk_body)
            if url.endswith("/jwks"):
                return httpx.Response(200, text='{"keys": ["k1"]}')
            if url.endswith("/register"):
                return httpx.Response(200, text="ok")
            return httpx.Response(404, text="not found")

        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=handler
        )
        respx.route(method="POST", url__startswith="https://example.com").mock(
            return_value=httpx.Response(200, text='{"access_token": "abc"}')
        )
        result = await run_scan("https://example.com", [], 5.0, None)
        assert result == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_well_known_request_error(self) -> None:
        def handler(request) -> httpx.Response:
            url = str(request.url)
            if url.endswith("/.well-known/openid-configuration"):
                raise httpx.ConnectError("boom")
            return httpx.Response(200, text="baseline")

        respx.route(method="GET", url__startswith="https://example.com").mock(
            side_effect=handler
        )
        result = await run_scan("https://example.com", ["discovery"], 5.0, None)
        assert result == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_well_known_unavailable(self) -> None:
        respx.route(method="GET", url__startswith="https://example.com").mock(
            return_value=httpx.Response(200, text="not json")
        )
        result = await run_scan("https://example.com", ["discovery"], 5.0, None)
        assert result == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_category(self) -> None:
        respx.route(method="GET", url__startswith="https://example.com").mock(
            return_value=httpx.Response(200, text="baseline")
        )
        respx.route(method="POST", url__startswith="https://example.com").mock(
            return_value=httpx.Response(404, text="not found")
        )
        result = await run_scan("https://example.com", ["invalid"], 5.0, None)
        assert result == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_tester_error(self, monkeypatch) -> None:
        respx.route(method="GET", url__startswith="https://example.com").mock(
            return_value=httpx.Response(200, text="baseline")
        )
        respx.route(method="POST", url__startswith="https://example.com").mock(
            return_value=httpx.Response(404, text="not found")
        )

        async def _boom(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setitem(_CATEGORY_TESTERS, "boom", _boom)
        result = await run_scan("https://example.com", ["boom"], 5.0, None)
        assert result == 0

    @pytest.mark.asyncio
    @respx.mock
    async def test_output_file(self, tmp_path) -> None:
        respx.route(method="GET", url__startswith="https://example.com").mock(
            return_value=httpx.Response(200, text="baseline")
        )
        respx.route(method="POST", url__startswith="https://example.com").mock(
            return_value=httpx.Response(404, text="not found")
        )
        out_file = tmp_path / "out.json"
        result = await run_scan(
            "https://example.com", ["discovery"], 5.0, str(out_file)
        )
        assert result == 0
        assert out_file.exists()


class TestBuildParser:
    """Testes para build_parser."""

    def test_parse_url(self) -> None:
        args = build_parser().parse_args([_TARGET])
        assert args.url == _TARGET

    def test_parse_category(self) -> None:
        args = build_parser().parse_args([_TARGET, "-c", "discovery"])
        assert args.category == "discovery"

    def test_parse_proxy(self) -> None:
        args = build_parser().parse_args([_TARGET, "--proxy", "http://proxy:8080"])
        assert args.proxy == "http://proxy:8080"


class TestRunOnce:
    """Testes para run_once."""

    def test_run_once(self) -> None:
        args = MagicMock()
        args.url = _TARGET
        args.category = "discovery"
        args.timeout = 10
        args.output = None
        with patch(
            "mytools.web.oidc.run_scan",
            new_callable=AsyncMock,
            return_value=0,
        ) as mock_scan:
            assert run_once(args) == 0
            mock_scan.assert_called_once()

    def test_run_once_all_categories(self) -> None:
        args = MagicMock()
        args.url = _TARGET
        args.category = "all"
        args.timeout = 10
        args.output = None
        with patch(
            "mytools.web.oidc.run_scan",
            new_callable=AsyncMock,
            return_value=0,
        ):
            assert run_once(args) == 0


class TestMain:
    """Testes para main."""

    def test_main_returns_loop_result(self) -> None:
        with (
            patch("sys.argv", ["mytools-oidc", _TARGET]),
            patch("mytools.web.oidc.run_main_loop", return_value=0) as mock_loop,
        ):
            assert main() == 0
            mock_loop.assert_called_once()


class TestMainGuard:
    """Testes para o guard if __name__ == '__main__'."""

    def test_guard_raises_system_exit(self) -> None:
        with (
            patch("sys.argv", ["mytools-oidc", _TARGET]),
            patch("mytools.core.utils.run_main_loop", return_value=0),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.oidc", run_name="__main__")
        assert exc_info.value.code == 0


class TestBannerArt:
    """Testes para banner_art."""

    def test_runs(self, capsys) -> None:
        banner_art()
        assert "oidc" in capsys.readouterr().out
