"""OAuth2 mobile flow testing via HTTP."""

from __future__ import annotations

import base64
import hashlib
import logging
import secrets
from typing import Any

logger = logging.getLogger("mytools.mobile.oauth2_flows")


def _make_pkce_pair() -> tuple[str, str]:
    """Gera par code_verifier/code_challenge para PKCE."""
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest()).rstrip(b"=").decode("ascii")
    return verifier, challenge


def generate_pkce_flow(
    idp_url: str,
    client_id: str,
    redirect_uri: str = "com.app:/callback",
    scope: str = "openid profile",
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Testa Authorization Code + PKCE flow.

    Gera code_verifier/code_challenge e monta URL de autorização.
    Não executa o request — retorna os parâmetros para uso manual.

    Returns:
        Dict com keys: auth_url, code_verifier, code_challenge, state.
    """
    verifier, challenge = _make_pkce_pair()
    state = secrets.token_urlsafe(32)

    auth_url = (
        f"{idp_url}/authorize?"
        f"client_id={client_id}"
        f"&response_type=code"
        f"&redirect_uri={redirect_uri}"
        f"&scope={scope}"
        f"&state={state}"
        f"&code_challenge={challenge}"
        f"&code_challenge_method=S256"
    )

    return {
        "flow": "authorization_code_pkce",
        "auth_url": auth_url,
        "code_verifier": verifier,
        "code_challenge": challenge,
        "state": state,
        "instructions": (
            "1. Open auth_url in browser/device\n"
            "2. Complete authorization\n"
            "3. Extract code from callback redirect\n"
            "4. Exchange code at token endpoint with code_verifier"
        ),
    }


def run_client_credentials(
    idp_url: str,
    client_id: str,
    client_secret: str,
    audience: str = "",
    scope: str = "",
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Testa Client Credentials flow (M2M).

    Returns:
        Dict com keys: token_url, status, response, token_preview.
    """
    try:
        import httpx

        token_url = f"{idp_url}/token"
        data: dict[str, str] = {
            "grant_type": "client_credentials",
        }
        if audience:
            data["audience"] = audience
        if scope:
            data["scope"] = scope

        resp = httpx.post(
            token_url,
            data=data,
            auth=(client_id, client_secret),
            timeout=timeout,
            follow_redirects=True,
        )

        result: dict[str, Any] = {
            "flow": "client_credentials",
            "token_url": token_url,
            "status_code": resp.status_code,
            "success": resp.status_code == 200,
        }

        if resp.status_code == 200:
            token_data = resp.json()
            token = token_data.get("access_token", "")
            result["token_preview"] = token[:20] + "..." if len(token) > 20 else token
            result["token_type"] = token_data.get("token_type", "")
            result["expires_in"] = token_data.get("expires_in", 0)
            result["scope"] = token_data.get("scope", "")
        else:
            result["error"] = resp.text[:200]

        return result

    except ImportError:
        return {"error": "httpx not installed", "flow": "client_credentials"}
    except Exception as e:
        return {"error": str(e)[:200], "flow": "client_credentials"}


def run_token_introspection(
    idp_url: str,
    token: str,
    client_id: str = "",
    client_secret: str = "",
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Testa token introspection (RFC 7662).

    Returns:
        Dict com keys: endpoint, status, active, claims.
    """
    try:
        import httpx

        endpoint = f"{idp_url}/introspect"
        data: dict[str, str] = {
            "token": token,
            "token_type_hint": "access_token",
        }
        auth = (client_id, client_secret) if client_id else None

        resp = httpx.post(
            endpoint,
            data=data,
            auth=auth,
            timeout=timeout,
            follow_redirects=True,
        )

        result: dict[str, Any] = {
            "endpoint": endpoint,
            "status_code": resp.status_code,
        }

        if resp.status_code == 200:
            info = resp.json()
            result["active"] = info.get("active", False)
            result["sub"] = info.get("sub", "")
            result["scope"] = info.get("scope", "")
            result["client_id"] = info.get("client_id", "")
            result["exp"] = info.get("exp", 0)
            result["iat"] = info.get("iat", 0)
            result["iss"] = info.get("iss", "")
        else:
            result["error"] = resp.text[:200]

        return result

    except ImportError:
        return {"error": "httpx not installed"}
    except Exception as e:
        return {"error": str(e)[:200]}


def validate_jwt(token: str) -> dict[str, Any]:
    """Decodifica e valida JWT sem verificar assinatura.

    Returns:
        Dict com keys: header, payload, is_expired, warnings.
    """
    try:
        import jwt

        # Decode without verification to inspect
        unverified = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256", "RS256", "ES256"])

        header = jwt.get_unverified_header(token)

        warnings: list[str] = []

        # Check alg
        alg = header.get("alg", "")
        if alg == "none":
            warnings.append("CRITICAL: alg=none (signature bypass)")
        elif alg.startswith("HS"):
            warnings.append(f"INFO: Symmetric algorithm {alg} (may use weak secret)")

        # Check expiry
        import time

        exp = unverified.get("exp", 0)
        is_expired = exp < time.time() if exp else False
        if is_expired:
            warnings.append("Token is EXPIRED")

        # Check iat
        iat = unverified.get("iat", 0)
        if iat and iat > time.time():
            warnings.append("Token issued in the FUTURE")

        return {
            "header": header,
            "payload": unverified,
            "is_expired": is_expired,
            "warnings": warnings,
            "valid_structure": True,
        }

    except ImportError:
        return {"error": "pyjwt not installed"}
    except Exception as e:
        return {"error": str(e)[:200], "valid_structure": False}
