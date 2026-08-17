"""Testes do módulo oauth2_flows.py."""

from __future__ import annotations

import time
from unittest.mock import patch

import httpx
import jwt
import pytest
import respx

from mytools.mobile.oauth2_flows import (
    _make_pkce_pair,
    _run_client_credentials,
    _run_token_introspection,
    generate_pkce_flow,
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
        from urllib.parse import parse_qs, urlparse

        result = generate_pkce_flow(
            "https://idp.test.com",
            "my_client",
            redirect_uri="myapp://callback",
            scope="openid email",
        )
        parsed = urlparse(result["auth_url"])
        params = parse_qs(parsed.query)
        assert params["redirect_uri"] == ["myapp://callback"]
        assert params["scope"] == ["openid email"]
        assert params["client_id"] == ["my_client"]
        assert params["code_challenge_method"] == ["S256"]


class TestClientCredentials:
    @pytest.mark.network
    def test_invalid_credentials(self) -> None:
        result = _run_client_credentials(
            "https://auth.example.com",
            "invalid",
            "invalid",
            timeout=5.0,
        )
        # Should handle gracefully
        assert isinstance(result, dict)
        assert result["flow"] == "client_credentials"

    def test_returns_error_on_failure(self) -> None:
        result = _run_client_credentials(
            "https://nonexistent.example.com",
            "client",
            "secret",
            timeout=2.0,
        )
        assert "error" in result

    @respx.mock
    def test_success_with_audience_and_scope(self) -> None:
        respx.post("https://idp.test/token").mock(
            return_value=httpx.Response(
                200,
                json={
                    "access_token": "TOKENabcdefghijklmnopqrstuvwxyz",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "read write",
                },
            )
        )
        result = _run_client_credentials(
            "https://idp.test",
            "client",
            "secret",
            audience="api",
            scope="read write",
        )
        assert result["status_code"] == 200
        assert result["success"] is True
        assert result["token_preview"] == "TOKENabcdefghijklmno..."
        assert result["token_type"] == "Bearer"
        assert result["expires_in"] == 3600
        assert result["scope"] == "read write"

    @respx.mock
    def test_error_status(self) -> None:
        respx.post("https://idp.test/token").mock(
            return_value=httpx.Response(401, text="unauthorized")
        )
        result = _run_client_credentials("https://idp.test", "client", "secret")
        assert result["success"] is False
        assert result["error"] == "unauthorized"

    def test_httpx_import_error(self) -> None:
        with patch.dict("sys.modules", {"httpx": None}):
            result = _run_client_credentials("https://idp.test", "c", "s")
        assert "error" in result
        assert result["flow"] == "client_credentials"


class TestTokenIntrospection:
    @respx.mock
    def test_success(self) -> None:
        respx.post("https://idp.test/introspect").mock(
            return_value=httpx.Response(
                200,
                json={
                    "active": True,
                    "sub": "user123",
                    "scope": "openid",
                    "client_id": "client",
                    "exp": 1234,
                    "iat": 5678,
                    "iss": "https://idp.test",
                },
            )
        )
        result = _run_token_introspection(
            "https://idp.test", "some.token", client_id="client", client_secret="secret"
        )
        assert result["status_code"] == 200
        assert result["active"] is True
        assert result["sub"] == "user123"
        assert result["scope"] == "openid"
        assert result["client_id"] == "client"
        assert result["exp"] == 1234
        assert result["iat"] == 5678
        assert result["iss"] == "https://idp.test"

    @respx.mock
    def test_success_without_client_id(self) -> None:
        respx.post("https://idp.test/introspect").mock(
            return_value=httpx.Response(200, json={"active": False})
        )
        result = _run_token_introspection("https://idp.test", "token")
        assert result["active"] is False

    @respx.mock
    def test_error_status(self) -> None:
        respx.post("https://idp.test/introspect").mock(
            return_value=httpx.Response(400, text="bad token")
        )
        result = _run_token_introspection("https://idp.test", "token")
        assert result["status_code"] == 400
        assert result["error"] == "bad token"

    def test_httpx_import_error(self) -> None:
        with patch.dict("sys.modules", {"httpx": None}):
            result = _run_token_introspection("https://idp.test", "token")
        assert "error" in result

    @respx.mock
    def test_connection_error(self) -> None:
        respx.post("https://idp.test/introspect").mock(
            side_effect=httpx.ConnectError("refused")
        )
        result = _run_token_introspection("https://idp.test", "token")
        assert "error" in result


class TestValidateJwt:
    def test_valid_jwt_structure(self) -> None:
        # HS256 JWT with known payload (not verifying signature)
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = validate_jwt(token)
        assert result.get("valid_structure") is True
        assert result["header"]["alg"] == "HS256"
        assert result["payload"]["sub"] == "1234567890"

    def test_none_algorithm_warning(self) -> None:
        import base64
        import json

        header = (
            base64.urlsafe_b64encode(json.dumps({"alg": "none"}).encode())
            .rstrip(b"=")
            .decode()
        )
        payload = (
            base64.urlsafe_b64encode(json.dumps({"sub": "123"}).encode())
            .rstrip(b"=")
            .decode()
        )
        token = f"{header}.{payload}."
        result = validate_jwt(token)
        assert any("none" in w.lower() for w in result.get("warnings", []))

    def test_invalid_token(self) -> None:
        result = validate_jwt("not.a.jwt")
        assert result.get("valid_structure") is False or "error" in result

    def test_expired_token(self) -> None:
        token = jwt.encode(
            {"sub": "123", "exp": int(time.time()) - 3600}, "secret", algorithm="HS256"
        )
        result = validate_jwt(token)
        assert result["is_expired"] is True
        assert any("EXPIRED" in w for w in result["warnings"])

    def test_future_iat(self) -> None:
        token = jwt.encode(
            {"sub": "123", "iat": int(time.time()) + 3600}, "secret", algorithm="HS256"
        )
        result = validate_jwt(token)
        assert any("FUTURE" in w for w in result["warnings"])

    def test_pyjwt_import_error(self) -> None:
        with patch.dict("sys.modules", {"jwt": None}):
            result = validate_jwt("token")
        assert "error" in result

    def test_rs256_no_symmetric_warning(self) -> None:
        import base64
        import json

        header = (
            base64.urlsafe_b64encode(json.dumps({"alg": "RS256"}).encode())
            .rstrip(b"=")
            .decode()
        )
        payload = (
            base64.urlsafe_b64encode(json.dumps({"sub": "123"}).encode())
            .rstrip(b"=")
            .decode()
        )
        token = f"{header}.{payload}."
        result = validate_jwt(token)
        assert result.get("valid_structure") is True
        assert result["warnings"] == []
