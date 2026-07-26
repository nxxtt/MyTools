"""Testes do módulo oauth2_flows.py."""

from __future__ import annotations

import pytest

from mytools.mobile.oauth2_flows import (
    _make_pkce_pair,
    generate_pkce_flow,
    run_client_credentials,
    validate_jwt,
)


class TestPkcePair:
    def test_generates_pair(self) -> None:
        verifier, challenge = _make_pkce_pair()
        assert len(verifier) > 0
        assert len(challenge) > 0
        assert verifier != challenge

    def test_challenge_is_base64url(self) -> None:
        _, challenge = _make_pkce_pair()
        # Should be valid base64url
        import base64
        # Add padding back
        padded = challenge + "=" * (4 - len(challenge) % 4)
        decoded = base64.urlsafe_b64decode(padded)
        assert len(decoded) == 32  # SHA-256 output


class TestPkceFlow:
    def test_generates_auth_url(self) -> None:
        result = generate_pkce_flow("https://auth.example.com", "client123")
        assert result["flow"] == "authorization_code_pkce"
        assert "auth.example.com" in result["auth_url"]
        assert "client123" in result["auth_url"]
        assert "code_challenge=" in result["auth_url"]
        assert "code_challenge_method=S256" in result["auth_url"]
        assert len(result["code_verifier"]) > 0
        assert len(result["code_challenge"]) > 0
        assert len(result["state"]) > 0

    def test_custom_params(self) -> None:
        result = generate_pkce_flow(
            "https://idp.test.com",
            "my_client",
            redirect_uri="myapp://callback",
            scope="openid email",
        )
        assert "myapp://callback" in result["auth_url"]
        # Scope is URL-encoded with + for spaces in query string
        assert "scope=" in result["auth_url"]


class TestClientCredentials:
    @pytest.mark.network
    def test_invalid_credentials(self) -> None:
        result = run_client_credentials(
            "https://auth.example.com",
            "invalid",
            "invalid",
            timeout=5.0,
        )
        # Should handle gracefully
        assert isinstance(result, dict)
        assert result["flow"] == "client_credentials"

    def test_returns_error_on_failure(self) -> None:
        result = run_client_credentials(
            "https://nonexistent.example.com",
            "client",
            "secret",
            timeout=2.0,
        )
        assert "error" in result


class TestValidateJwt:
    def test_valid_jwt_structure(self) -> None:
        # HS256 JWT with known payload (not verifying signature)
        token = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ."
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        result = validate_jwt(token)
        assert result.get("valid_structure") is True
        assert result["header"]["alg"] == "HS256"
        assert result["payload"]["sub"] == "1234567890"

    def test_none_algorithm_warning(self) -> None:
        import base64
        import json

        header = base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode()).rstrip(b"=").decode()
        payload = base64.urlsafe_b64encode(json.dumps({"sub": "123"}).encode()).rstrip(b"=").decode()
        token = f"{header}.{payload}."
        result = validate_jwt(token)
        assert any("none" in w.lower() for w in result.get("warnings", []))

    def test_invalid_token(self) -> None:
        result = validate_jwt("not.a.jwt")
        assert result.get("valid_structure") is False or "error" in result
