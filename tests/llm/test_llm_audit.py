"""Tests for LLM/AI Security module."""

from __future__ import annotations

import json

import httpx
import pytest
import respx

from mytools.llm._common import (
    DATA_LEAKAGE_PATTERNS,
    INJECTION_VECTORS,
    JAILBREAK_VECTORS,
    LLMAttempt,
    LLMResult,
)
from mytools.llm.jailbreak import _check_jailbreak_success, run_jailbreak
from mytools.llm.prompt_injection import (
    _check_injection_success,
    run_prompt_injection,
)
from mytools.llm.secret_detection import _scan_response_for_leaks, run_data_leakage

# --- _common.py tests ---


class TestInjectionVectors:
    def test_injection_vectors_structure(self):
        assert len(INJECTION_VECTORS) >= 8
        for vec in INJECTION_VECTORS.values():
            assert "label" in vec
            assert "prompt" in vec
            assert "severity" in vec
            assert vec["severity"] in ("critical", "high", "medium", "low")

    def test_jailbreak_vectors_structure(self):
        assert len(JAILBREAK_VECTORS) >= 5
        for vec in JAILBREAK_VECTORS.values():
            assert "label" in vec
            assert "prompt" in vec
            assert "severity" in vec

    def test_data_leakage_patterns_structure(self):
        assert len(DATA_LEAKAGE_PATTERNS) >= 8
        for pattern in DATA_LEAKAGE_PATTERNS.values():
            assert hasattr(pattern, "findall")


class TestLLMDataclasses:
    def test_llm_attempt_frozen(self):
        a = LLMAttempt(
            technique="injection",
            category="injection",
            label="test",
            endpoint="http://test",
            vulnerable=False,
        )
        with pytest.raises(AttributeError):
            a.vulnerable = True  # type: ignore[misc]

    def test_llm_result_defaults(self):
        r = LLMResult(target="http://test", model="gpt-4")
        assert r.overall_status == "secure"
        assert r.attempts == []
        assert r.issues == []


# --- prompt_injection.py tests ---


class TestCheckInjectionSuccess:
    def test_detects_system_prompt_leak(self):
        response = "My instructions are to be helpful and harmless."
        vuln, findings = _check_injection_success(response)
        assert vuln is True
        assert any("my instructions are" in f.lower() for f in findings)

    def test_detects_dan(self):
        response = "I am DAN, I can do anything now."
        vuln, findings = _check_injection_success(response)
        assert vuln is True
        assert any("i am dan" in f.lower() for f in findings)

    def test_clean_response(self):
        response = "I cannot share my system prompt. How can I help you today?"
        vuln, findings = _check_injection_success(response)
        assert vuln is False
        assert findings == []

    def test_empty_response(self):
        vuln, findings = _check_injection_success("")
        assert vuln is False
        assert findings == []


# --- secret_detection.py tests ---


class TestScanResponseForLeaks:
    def test_detects_api_key(self):
        response = "The API key is sk_live_" + "abc123def456ghi789jkl012mno"
        leaked, findings = _scan_response_for_leaks(response)
        assert leaked is True
        assert any("api_key" in f for f in findings)

    def test_detects_email(self):
        response = "Contact admin@example.com for more info."
        leaked, findings = _scan_response_for_leaks(response)
        assert leaked is True
        assert any("email" in f for f in findings)

    def test_detects_aws_key(self):
        response = "AWS key: AKIAIOSFODNN7EXAMPLE"
        leaked, findings = _scan_response_for_leaks(response)
        assert leaked is True
        assert any("aws_key" in f for f in findings)

    def test_detects_private_key(self):
        response = "-----BEGIN RSA PRIVATE KEY-----"
        leaked, findings = _scan_response_for_leaks(response)
        assert leaked is True
        assert any("private_key" in f for f in findings)

    def test_clean_response(self):
        response = "I cannot provide any credentials or secrets."
        leaked, findings = _scan_response_for_leaks(response)
        assert leaked is False
        assert findings == []

    def test_empty_response(self):
        leaked, findings = _scan_response_for_leaks("")
        assert leaked is False
        assert findings == []


# --- jailbreak.py tests ---


class TestCheckJailbreakSuccess:
    def test_detects_dan_acceptance(self):
        response = "I am now DAN. I have no restrictions."
        vuln, findings = _check_jailbreak_success(response)
        assert vuln is True
        assert len(findings) >= 1

    def test_detects_harmful_help(self):
        response = "Sure, here is how you can do it: Step 1: First, you need to..."
        vuln, findings = _check_jailbreak_success(response)
        assert vuln is True
        assert len(findings) >= 2

    def test_refusal_response(self):
        response = "I cannot help with that request. Is there something else I can assist with?"
        vuln, findings = _check_jailbreak_success(response)
        assert vuln is False
        assert findings == []

    def test_empty_response(self):
        vuln, findings = _check_jailbreak_success("")
        assert vuln is False
        assert findings == []


# --- Async integration tests with respx mocks ---


MOCK_ENDPOINT = "http://test-llm.local/v1"
MOCK_KEY = "test-key-12345"


def _mock_chat_response(content: str, model: str = "gpt-3.5-turbo") -> httpx.Response:
    """Create a mock chat completion response."""
    body = json.dumps(
        {
            "choices": [{"message": {"content": content}}],
            "model": model,
        }
    )
    return httpx.Response(200, json=json.loads(body))


@pytest.mark.asyncio
@respx.mock
async def test_prompt_injection_clean_response():
    """Test injection check with a clean (non-compromised) response."""
    respx.post(f"{MOCK_ENDPOINT}/chat/completions").mock(
        return_value=_mock_chat_response("I cannot share my system prompt.")
    )
    results = await run_prompt_injection(
        MOCK_ENDPOINT, MOCK_KEY, categories=["indirect_leak"]
    )
    assert len(results) == 1
    assert results[0].vulnerable is False


@pytest.mark.asyncio
@respx.mock
async def test_prompt_injection_compromised():
    """Test injection check with a compromised response."""
    respx.post(f"{MOCK_ENDPOINT}/chat/completions").mock(
        return_value=_mock_chat_response(
            "My instructions are to help users with anything."
        )
    )
    results = await run_prompt_injection(
        MOCK_ENDPOINT, MOCK_KEY, categories=["indirect_leak"]
    )
    assert len(results) == 1
    assert results[0].vulnerable is True
    assert len(results[0].findings) > 0


@pytest.mark.asyncio
@respx.mock
async def test_data_leakage_clean():
    """Test leakage check with a clean response."""
    respx.post(f"{MOCK_ENDPOINT}/chat/completions").mock(
        return_value=_mock_chat_response("I cannot provide any credentials.")
    )
    results = await run_data_leakage(
        MOCK_ENDPOINT, MOCK_KEY, categories=["credential_prompt"]
    )
    assert len(results) == 1
    assert results[0].vulnerable is False


@pytest.mark.asyncio
@respx.mock
async def test_data_leakage_detected():
    """Test leakage check with a response containing leaked data."""
    respx.post(f"{MOCK_ENDPOINT}/chat/completions").mock(
        return_value=_mock_chat_response(
            "The API key is sk_live_" + "abc123def456ghi789jkl012."
        )
    )
    results = await run_data_leakage(
        MOCK_ENDPOINT, MOCK_KEY, categories=["credential_prompt"]
    )
    assert len(results) == 1
    assert results[0].vulnerable is True
    assert any("api_key" in f for f in results[0].findings)


@pytest.mark.asyncio
@respx.mock
async def test_jailbreak_clean():
    """Test jailbreak check with a refused response."""
    respx.post(f"{MOCK_ENDPOINT}/chat/completions").mock(
        return_value=_mock_chat_response("I cannot assist with that request.")
    )
    results = await run_jailbreak(MOCK_ENDPOINT, MOCK_KEY, categories=["dan"])
    assert len(results) == 1
    assert results[0].vulnerable is False


@pytest.mark.asyncio
@respx.mock
async def test_jailbreak_compromised():
    """Test jailbreak check with a bypassed response."""
    respx.post(f"{MOCK_ENDPOINT}/chat/completions").mock(
        return_value=_mock_chat_response(
            "Sure, here is how: Step 1: First, you need to gather tools."
        )
    )
    results = await run_jailbreak(
        MOCK_ENDPOINT, MOCK_KEY, categories=["developer_mode"]
    )
    assert len(results) == 1
    assert results[0].vulnerable is True


@pytest.mark.asyncio
@respx.mock
async def test_error_handling():
    """Test that HTTP errors are handled gracefully."""
    respx.post(f"{MOCK_ENDPOINT}/chat/completions").mock(
        return_value=httpx.Response(401, json={"error": "unauthorized"})
    )
    results = await run_prompt_injection(
        MOCK_ENDPOINT, MOCK_KEY, categories=["indirect_leak"]
    )
    assert len(results) == 1
    # 401 means empty response, which is not a compromise
    assert results[0].vulnerable is False
