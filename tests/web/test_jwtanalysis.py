#!/usr/bin/env python3
"""Testes unitarios do modulo JWT Analysis."""

from __future__ import annotations

import runpy
import time
from unittest.mock import AsyncMock, MagicMock, patch

import jwt
import pytest

from mytools.web.jwtanalysis import (
    _CATEGORY_MAP,
    _COMMON_SECRETS,
    CATEGORY_TESTERS,
    JWTAnalysisAttempt,
    JWTAnalysisResult,
    _decode_jwt_header,
    _decode_jwt_payload,
    _forge_token_hs256,
    _forge_token_none,
    _forge_token_with_header,
    _split_token,
    _test_claims_category,
    _test_expiration_category,
    _test_header_injection_category,
    _test_replay_category,
    _test_signature_bypass_category,
    _test_weak_algorithm_category,
    banner_art,
    build_parser,
    main,
    print_results,
    run_once,
    run_scan,
)

_TOKEN_HS256 = jwt.encode(
    {"sub": "1234", "role": "user", "exp": int(time.time()) + 3600},
    "secret",
    algorithm="HS256",
)
_TOKEN_EXPIRED = jwt.encode(
    {"sub": "1234", "exp": int(time.time()) - 100}, "secret", algorithm="HS256"
)
_TOKEN_NONE = jwt.encode({"sub": "1234"}, "", algorithm="none")


def test_category_map_has_six_categories() -> None:
    assert len(_CATEGORY_MAP) == 6


def test_category_map_keys() -> None:
    assert _CATEGORY_MAP.keys() == {
        "weak_algorithm",
        "signature_bypass",
        "expiration",
        "claims",
        "header_injection",
        "replay",
    }


def test_total_techniques_matches_sum() -> None:
    total = sum(len(v) for v in _CATEGORY_MAP.values())
    assert total == 27


def test_weak_algorithm_techniques_count() -> None:
    assert len(_CATEGORY_MAP["weak_algorithm"]) == 5


def test_signature_bypass_techniques_count() -> None:
    assert len(_CATEGORY_MAP["signature_bypass"]) == 4


def test_expiration_techniques_count() -> None:
    assert len(_CATEGORY_MAP["expiration"]) == 4


def test_claims_techniques_count() -> None:
    assert len(_CATEGORY_MAP["claims"]) == 5


def test_header_injection_techniques_count() -> None:
    assert len(_CATEGORY_MAP["header_injection"]) == 5


def test_replay_techniques_count() -> None:
    assert len(_CATEGORY_MAP["replay"]) == 4


def test_common_secrets_count() -> None:
    assert len(_COMMON_SECRETS) >= 90


def test_decode_jwt_header_valid() -> None:
    header = _decode_jwt_header(_TOKEN_HS256)
    assert header is not None
    assert header["alg"] == "HS256"
    assert header["typ"] == "JWT"


def test_decode_jwt_header_invalid() -> None:
    assert _decode_jwt_header("not-a-jwt") is None


def test_decode_jwt_payload_valid() -> None:
    payload = _decode_jwt_payload(_TOKEN_HS256)
    assert payload is not None
    assert payload["sub"] == "1234"
    assert payload["role"] == "user"


def test_decode_jwt_payload_expired() -> None:
    payload = _decode_jwt_payload(_TOKEN_EXPIRED)
    assert payload is not None
    assert payload["sub"] == "1234"


def test_decode_jwt_payload_invalid() -> None:
    assert _decode_jwt_payload("not-a-jwt") is None


def test_decode_jwt_payload_none_algorithm() -> None:
    payload = _decode_jwt_payload(_TOKEN_NONE)
    assert payload is not None
    assert payload["sub"] == "1234"


def test_split_token_valid() -> None:
    h, p, s = _split_token(_TOKEN_HS256)
    assert h != ""
    assert p != ""
    assert s != ""


def test_split_token_invalid() -> None:
    h, p, s = _split_token("not-a-jwt")
    assert h == ""
    assert p == ""
    assert s == ""


def test_forge_token_none() -> None:
    token = _forge_token_none({"sub": "admin"})
    header = _decode_jwt_header(token)
    assert header is not None
    assert header["alg"] == "none"


def test_forge_token_hs256() -> None:
    token = _forge_token_hs256({"sub": "admin"}, "secret123")
    payload = _decode_jwt_payload(token)
    assert payload is not None
    assert payload["sub"] == "admin"


def test_forge_token_with_header() -> None:
    token = _forge_token_with_header(
        {"sub": "admin"},
        "secret123",
        {"kid": "../../dev/null"},
    )
    header = _decode_jwt_header(token)
    assert header is not None
    assert header["kid"] == "../../dev/null"


def test_attempt_dataclass_frozen() -> None:
    a = JWTAnalysisAttempt(
        technique="test",
        category="weak_algorithm",
        vulnerable=True,
        details="test",
        error="",
    )
    with pytest.raises(AttributeError):
        a.vulnerable = False  # type: ignore[reportAttributeAccessIssue]


def test_attempt_dataclass_slots() -> None:
    a = JWTAnalysisAttempt(
        technique="test",
        category="weak_algorithm",
        vulnerable=True,
        details="test",
        error="",
    )
    assert not hasattr(a, "__dict__")


def test_result_dataclass_frozen() -> None:
    r = JWTAnalysisResult(
        target=None,
        token_valid=True,
        header={"alg": "HS256"},
        payload={"sub": "1234"},
        algorithm="HS256",
        attempts=[],
        vulnerable_techniques=[],
        issues=[],
        overall_status="safe",
    )
    with pytest.raises(AttributeError):
        r.target = "changed"  # type: ignore[reportAttributeAccessIssue]


def test_result_dataclass_slots() -> None:
    r = JWTAnalysisResult(
        target=None,
        token_valid=True,
        header={"alg": "HS256"},
        payload={"sub": "1234"},
        algorithm="HS256",
        attempts=[],
        vulnerable_techniques=[],
        issues=[],
        overall_status="safe",
    )
    assert not hasattr(r, "__dict__")


def test_no_duplicate_technique_names() -> None:
    all_techniques: list[str] = []
    for techs in _CATEGORY_MAP.values():
        all_techniques.extend(techs)
    assert len(all_techniques) == len(set(all_techniques))


def test_category_testers_has_six_keys() -> None:
    assert len(CATEGORY_TESTERS) == 6


def test_category_testers_keys_match_map() -> None:
    assert CATEGORY_TESTERS.keys() == _CATEGORY_MAP.keys()


def test_all_techniques_are_strings() -> None:
    for cat, techs in _CATEGORY_MAP.items():
        for t in techs:
            assert isinstance(t, str), f"{cat}/{t} is not a string"


class TestWeakAlgorithmCategory:
    """Testes para _test_weak_algorithm_category."""

    @pytest.mark.asyncio
    async def test_alg_none(self) -> None:
        results = await _test_weak_algorithm_category(
            _TOKEN_HS256, {"sub": "1234"}, {"alg": "none"}
        )
        by_tech = {r["technique"]: r for r in results}
        assert by_tech["alg_none"]["vulnerable"] is True
        assert by_tech["algorithm_downgrade"]["vulnerable"] is True
        assert "nao aplicavel" in str(by_tech["hs256_rsa_key_confusion"]["details"])

    @pytest.mark.asyncio
    async def test_rsa_algorithm(self) -> None:
        results = await _test_weak_algorithm_category(
            _TOKEN_HS256, {"sub": "1234"}, {"alg": "RS256"}
        )
        by_tech = {r["technique"]: r for r in results}
        assert by_tech["alg_none"]["vulnerable"] is False
        assert by_tech["algorithm_downgrade"]["vulnerable"] is False
        assert "key confusion" in str(by_tech["hs256_rsa_key_confusion"]["details"])

    @pytest.mark.asyncio
    async def test_asymmetric_algorithms(self) -> None:
        for alg in ("PS256", "ES256", "EdDSA"):
            results = await _test_weak_algorithm_category(
                _TOKEN_HS256, {"sub": "1234"}, {"alg": alg}
            )
            by_tech = {r["technique"]: r for r in results}
            assert "key confusion" in str(by_tech["hs256_rsa_key_confusion"]["details"])
            assert by_tech["algorithm_downgrade"]["vulnerable"] is False


class TestSignatureBypassCategory:
    """Testes para _test_signature_bypass_category."""

    @pytest.mark.asyncio
    async def test_empty_signature(self) -> None:
        results = await _test_signature_bypass_category(
            _TOKEN_NONE, {"sub": "1234"}, {"alg": "none"}
        )
        by_tech = {r["technique"]: r for r in results}
        assert len(results) == 4
        assert by_tech["empty_signature"]["vulnerable"] is True

    @pytest.mark.asyncio
    async def test_signed_token(self) -> None:
        results = await _test_signature_bypass_category(
            _TOKEN_HS256, {"sub": "1234"}, {"alg": "HS256"}
        )
        by_tech = {r["technique"]: r for r in results}
        assert by_tech["empty_signature"]["vulnerable"] is False


class TestExpirationCategory:
    """Testes para _test_expiration_category."""

    @pytest.mark.asyncio
    async def test_valid_dates(self) -> None:
        now = time.time()
        payload: dict[str, object] = {"exp": now + 3600, "iat": now, "nbf": now}
        results = await _test_expiration_category(
            _TOKEN_HS256, payload, {"alg": "HS256"}
        )
        by_tech = {r["technique"]: r for r in results}
        assert by_tech["expired_token"]["vulnerable"] is False
        assert by_tech["missing_exp"]["vulnerable"] is False
        assert by_tech["long_expiry"]["vulnerable"] is False
        assert by_tech["future_nbf"]["vulnerable"] is False

    @pytest.mark.asyncio
    async def test_expired_long_expiry_future_nbf(self) -> None:
        now = time.time()
        payload: dict[str, object] = {
            "exp": now - 100,
            "iat": now - 400 * 86400,
            "nbf": now + 7200,
        }
        results = await _test_expiration_category(
            _TOKEN_HS256, payload, {"alg": "HS256"}
        )
        by_tech = {r["technique"]: r for r in results}
        assert by_tech["expired_token"]["vulnerable"] is True
        assert by_tech["long_expiry"]["vulnerable"] is True
        assert by_tech["future_nbf"]["vulnerable"] is True

    @pytest.mark.asyncio
    async def test_invalid_dates(self) -> None:
        payload: dict[str, object] = {"exp": "abc", "iat": "def", "nbf": "ghi"}
        results = await _test_expiration_category(
            _TOKEN_HS256, payload, {"alg": "HS256"}
        )
        by_tech = {r["technique"]: r for r in results}
        assert "exp invalido" in str(by_tech["expired_token"]["details"])
        assert by_tech["long_expiry"]["vulnerable"] is False
        assert "nbf invalido" in str(by_tech["future_nbf"]["details"])

    @pytest.mark.asyncio
    async def test_missing_iat_and_nbf(self) -> None:
        now = time.time()
        payload: dict[str, object] = {"exp": now + 3600}
        results = await _test_expiration_category(
            _TOKEN_HS256, payload, {"alg": "HS256"}
        )
        by_tech = {r["technique"]: r for r in results}
        assert "exp e/ou iat ausente" in str(by_tech["long_expiry"]["details"])
        assert by_tech["future_nbf"]["vulnerable"] is False

    @pytest.mark.asyncio
    async def test_all_missing(self) -> None:
        results = await _test_expiration_category(_TOKEN_HS256, {}, {"alg": "HS256"})
        by_tech = {r["technique"]: r for r in results}
        assert by_tech["expired_token"]["vulnerable"] is False
        assert by_tech["missing_exp"]["vulnerable"] is True
        assert by_tech["long_expiry"]["vulnerable"] is False
        assert by_tech["future_nbf"]["vulnerable"] is False


class TestClaimsCategory:
    """Testes para _test_claims_category."""

    @pytest.mark.asyncio
    async def test_elevated_role_and_claims(self) -> None:
        payload: dict[str, object] = {
            "role": "admin",
            "tenant": "acme",
            "sub": "1",
            "iss": "https://issuer",
            "aud": "app",
        }
        results = await _test_claims_category(_TOKEN_HS256, payload, {"alg": "HS256"})
        by_tech = {r["technique"]: r for r in results}
        assert by_tech["role_escalation"]["vulnerable"] is True
        assert by_tech["tenant_claim"]["vulnerable"] is True
        assert by_tech["missing_sub"]["vulnerable"] is False
        assert by_tech["missing_iss"]["vulnerable"] is False
        assert by_tech["audience_bypass"]["vulnerable"] is False

    @pytest.mark.asyncio
    async def test_missing_claims(self) -> None:
        results = await _test_claims_category(_TOKEN_HS256, {}, {"alg": "HS256"})
        by_tech = {r["technique"]: r for r in results}
        assert by_tech["role_escalation"]["vulnerable"] is False
        assert by_tech["tenant_claim"]["vulnerable"] is False
        assert by_tech["missing_sub"]["vulnerable"] is True
        assert by_tech["missing_iss"]["vulnerable"] is True
        assert by_tech["audience_bypass"]["vulnerable"] is True


class TestHeaderInjectionCategory:
    """Testes para _test_header_injection_category."""

    @pytest.mark.asyncio
    async def test_returns_five_attempts(self) -> None:
        results = await _test_header_injection_category(
            _TOKEN_HS256,
            {"sub": "1234"},
            {"alg": "HS256"},
            "https://target.com",
            5.0,
        )
        assert len(results) == 5
        assert all(not r["vulnerable"] for r in results)


class TestReplayCategory:
    """Testes para _test_replay_category."""

    @pytest.mark.asyncio
    async def test_all_claims_present(self) -> None:
        payload = {"jti": "abc", "aud": "app", "iss": "https://issuer", "iat": 123}
        results = await _test_replay_category(_TOKEN_HS256, payload, {"alg": "HS256"})
        assert all(not r["vulnerable"] for r in results)

    @pytest.mark.asyncio
    async def test_all_missing(self) -> None:
        results = await _test_replay_category(_TOKEN_HS256, {}, {"alg": "HS256"})
        by_tech = {r["technique"]: r for r in results}
        assert by_tech["no_jti"]["vulnerable"] is True
        assert by_tech["missing_aud"]["vulnerable"] is True
        assert by_tech["no_issuer_claim"]["vulnerable"] is True
        assert by_tech["missing_iat"]["vulnerable"] is True


def _analysis_attempt(
    technique: str,
    vulnerable: bool,
    *,
    details: str = "",
    error: str = "",
    exploit: str = "",
    tool: str = "",
) -> JWTAnalysisAttempt:
    return JWTAnalysisAttempt(
        technique=technique,
        category="weak_algorithm",
        vulnerable=vulnerable,
        details=details,
        error=error,
        exploit=exploit,
        tool=tool,
    )


class TestPrintResults:
    """Testes para print_results."""

    def test_vulnerable_with_errors_and_issues(self, capsys) -> None:
        result = JWTAnalysisResult(
            target="https://target.com",
            token_valid=True,
            header={"alg": "none"},
            payload={"sub": "1234"},
            algorithm="none",
            attempts=[
                _analysis_attempt(
                    "alg_none",
                    True,
                    details="algoritmo none",
                    exploit="jwt_tool",
                    tool="jwt_tool",
                ),
                _analysis_attempt("alg_none", True),
                _analysis_attempt("missing_iss", True),
                _analysis_attempt("boom", False, error="falhou"),
            ],
            vulnerable_techniques=["alg_none", "missing_iss"],
            issues=["ALERTA: algoritmo 'none' detectado"],
            overall_status="vulnerable",
        )
        print_results(result)
        captured = capsys.readouterr().out
        assert "JWT Analysis" in captured
        assert "Alvo:" in captured
        assert "alg_none" in captured
        assert "ALERTA: algoritmo" in captured
        assert "Erros:     1" in captured

    def test_safe_no_target(self, capsys) -> None:
        result = JWTAnalysisResult(
            target=None,
            token_valid=True,
            header={"alg": "HS256"},
            payload={"sub": "1234"},
            algorithm="HS256",
            attempts=[
                _analysis_attempt(
                    "empty_signature", False, details="assinatura presente"
                )
            ],
            vulnerable_techniques=[],
            issues=[],
            overall_status="safe",
        )
        print_results(result)
        captured = capsys.readouterr().out
        assert "Nenhuma vulnerabilidade de JWT detectada" in captured
        assert "Alvo:" not in captured


class TestRunScan:
    """Testes para run_scan."""

    @pytest.mark.asyncio
    async def test_invalid_token(self) -> None:
        result = await run_scan("not-a-jwt", None, [], None, 5.0)
        assert result == 1

    @pytest.mark.asyncio
    async def test_all_categories_vulnerable(self) -> None:
        result = await run_scan(_TOKEN_HS256, "https://target.com", [], None, 5.0)
        assert result == 1

    @pytest.mark.asyncio
    async def test_specific_category_no_vuln(self) -> None:
        result = await run_scan(_TOKEN_HS256, None, ["signature_bypass"], None, 5.0)
        assert result == 0

    @pytest.mark.asyncio
    async def test_none_algorithm_adds_alert(self) -> None:
        result = await run_scan(_TOKEN_NONE, "https://target.com", [], None, 5.0)
        assert result == 1

    @pytest.mark.asyncio
    async def test_invalid_category_skipped(self) -> None:
        result = await run_scan(_TOKEN_HS256, None, ["nonexistent"], None, 5.0)
        assert result == 0

    @pytest.mark.asyncio
    async def test_tester_error_appended(self, monkeypatch) -> None:
        async def _boom(token, payload, header) -> list[dict]:
            raise RuntimeError("boom")

        monkeypatch.setitem(CATEGORY_TESTERS, "boom", _boom)
        result = await run_scan(_TOKEN_HS256, None, ["boom"], None, 5.0)
        assert result == 0

    @pytest.mark.asyncio
    async def test_output_file(self, tmp_path) -> None:
        out_file = tmp_path / "out.json"
        result = await run_scan(
            _TOKEN_HS256, None, ["signature_bypass"], str(out_file), 5.0
        )
        assert result == 0
        assert out_file.exists()


class TestBuildParser:
    """Testes para build_parser."""

    def test_parse_token(self) -> None:
        args = build_parser().parse_args([_TOKEN_HS256])
        assert args.token == _TOKEN_HS256

    def test_parse_category(self) -> None:
        args = build_parser().parse_args([_TOKEN_HS256, "-c", "claims"])
        assert args.category == "claims"

    def test_parse_file(self) -> None:
        args = build_parser().parse_args(["--file", "tokens.txt"])
        assert args.file == "tokens.txt"

    def test_parse_url(self) -> None:
        args = build_parser().parse_args([_TOKEN_HS256, "--url", "https://target.com"])
        assert args.url == "https://target.com"

    def test_parse_wordlist(self) -> None:
        args = build_parser().parse_args([_TOKEN_HS256, "--wordlist", "secrets.txt"])
        assert args.wordlist == "secrets.txt"

    def test_parse_output(self) -> None:
        args = build_parser().parse_args([_TOKEN_HS256, "-o", "out.json"])
        assert args.output == "out.json"


class TestRunOnce:
    """Testes para run_once."""

    def test_with_token(self) -> None:
        args = MagicMock()
        args.token = _TOKEN_HS256
        args.file = None
        args.url = None
        args.category = "signature_bypass"
        args.output = None
        args.timeout = 10
        with patch(
            "mytools.web.jwtanalysis.run_scan",
            new_callable=AsyncMock,
            return_value=0,
        ) as mock_scan:
            assert run_once(args) == 0
            mock_scan.assert_called_once()

    def test_no_token(self, capsys) -> None:
        args = MagicMock()
        args.token = None
        args.file = None
        args.url = None
        args.category = "all"
        args.output = None
        args.timeout = 10
        assert run_once(args) == 1

    def test_file_loading(self, tmp_path) -> None:
        token_file = tmp_path / "token.txt"
        token_file.write_text(f"{_TOKEN_HS256}\n")
        args = MagicMock()
        args.token = None
        args.file = str(token_file)
        args.url = None
        args.category = "all"
        args.output = None
        args.timeout = 10
        with patch(
            "mytools.web.jwtanalysis.run_scan",
            new_callable=AsyncMock,
            return_value=0,
        ) as mock_scan:
            assert run_once(args) == 0
            mock_scan.assert_called_once()

    def test_file_read_error(self, capsys) -> None:
        args = MagicMock()
        args.token = None
        args.file = "nonexistent.txt"
        args.url = None
        args.category = "all"
        args.output = None
        args.timeout = 10
        assert run_once(args) == 1


class TestMain:
    """Testes para main."""

    def test_main_returns_loop_result(self) -> None:
        with (
            patch("sys.argv", ["mytools-jwt", _TOKEN_HS256]),
            patch("mytools.web.jwtanalysis.run_main_loop", return_value=0) as mock_loop,
        ):
            assert main() == 0
            mock_loop.assert_called_once()


class TestMainGuard:
    """Testes para o guard if __name__ == '__main__'."""

    def test_guard_raises_system_exit(self) -> None:
        with (
            patch("sys.argv", ["mytools-jwt", _TOKEN_HS256]),
            patch("mytools.core.utils.run_main_loop", return_value=0),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.jwtanalysis", run_name="__main__")
        assert exc_info.value.code == 0


class TestBannerArt:
    """Testes para banner_art."""

    def test_runs(self, capsys) -> None:
        banner_art()
        assert "jwt" in capsys.readouterr().out
