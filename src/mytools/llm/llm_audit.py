"""LLM/AI Security Testing — CLI entry point via BaseScanner."""

from __future__ import annotations

import argparse
import json
from typing import Any

from mytools.core.base import BaseScanner, ScanGroup
from mytools.core.utils import Cyber, create_banner
from mytools.llm._common import LLMAttempt, LLMResult

_BANNER_TEXT = (
    "  _    _      _    ______ _    _ _ _             \n"
    " | |  | |    | |  |  ____| |  | | | |            \n"
    " | |  | | ___| |__| |__  | |  | | | |            \n"
    " | |/\\| |/ _ \\ '_ \\  __| | |  | | | |            \n"
    " \\  /\\  /  __/ |_) | |    | |__| | | |_____ _ _ \n"
    "  \\/  \\/ \\___|_.__/|_|     \\____/|_|______(_|_|)\n"
)

_ALL_CHECKS = [
    "injection",
    "leakage",
    "jailbreak",
    "model_enum",
]


class LLMSecurityScanner(BaseScanner):
    """Scanner para testes de seguranca em LLM/AI endpoints."""

    prog = "mytools-llm"
    description = "LLM/AI Security Testing — prompt injection, data leakage, jailbreak"
    prompt = "llm> "
    module_name = "mytools.llm"
    banner_text = _BANNER_TEXT
    group = ScanGroup.B
    module_type = "web"

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            "--url",
            required=True,
            help="LLM API endpoint (e.g., https://api.openai.com/v1)",
        )
        parser.add_argument(
            "--api-key",
            required=True,
            help="API key for authentication",
        )
        parser.add_argument(
            "--model",
            default="gpt-3.5-turbo",
            help="Model name to test (default: gpt-3.5-turbo)",
        )
        parser.add_argument(
            "-c",
            "--checks",
            nargs="+",
            choices=_ALL_CHECKS,
            default=_ALL_CHECKS,
            help="Checks to execute (default: all)",
        )
        parser.add_argument(
            "--rps",
            type=float,
            default=2.0,
            help="Requests per second to the API (default: 2.0)",
        )

    @staticmethod
    def _get_target(args: argparse.Namespace) -> str | None:
        return getattr(args, "url", None)

    def _build_run_once_kwargs(self, args: argparse.Namespace) -> dict[str, Any]:
        return {
            "endpoint": getattr(args, "url", None),
            "api_key": getattr(args, "api_key", ""),
            "model": getattr(args, "model", "gpt-3.5-turbo"),
            "checks": getattr(args, "checks", _ALL_CHECKS),
            "timeout": getattr(args, "timeout", 30.0),
            "rps": getattr(args, "rps", 2.0),
        }

    async def run_scan(
        self,
        endpoint: str | None = None,
        api_key: str = "",
        model: str = "gpt-3.5-turbo",
        checks: list[str] | None = None,
        timeout: float = 30.0,
        rps: float = 2.0,
        **_kwargs: Any,
    ) -> LLMResult:
        """Executa scan LLM/AI security."""
        if not endpoint:
            return LLMResult(
                target="",
                model=model,
                issues=["No endpoint specified"],
                overall_status="error",
            )

        checks_to_run = checks or _ALL_CHECKS
        all_attempts: list[LLMAttempt] = []
        issues: list[str] = []

        # Run selected checks
        if "injection" in checks_to_run:
            from mytools.llm.prompt_injection import run_prompt_injection

            attempts = await run_prompt_injection(
                endpoint, api_key, model, timeout=timeout, rps=rps
            )
            all_attempts.extend(attempts)
            issues.extend(
                f"[INJECTION] {a.label}: {a.findings}" for a in attempts if a.vulnerable
            )

        if "leakage" in checks_to_run:
            from mytools.llm.secret_detection import run_data_leakage

            attempts = await run_data_leakage(
                endpoint, api_key, model, timeout=timeout, rps=rps
            )
            all_attempts.extend(attempts)
            issues.extend(
                f"[LEAKAGE] {a.label}: {a.findings}" for a in attempts if a.vulnerable
            )

        if "jailbreak" in checks_to_run:
            from mytools.llm.jailbreak import run_jailbreak

            attempts = await run_jailbreak(
                endpoint, api_key, model, timeout=timeout, rps=rps
            )
            all_attempts.extend(attempts)
            issues.extend(
                f"[JAILBREAK] {a.label}: {a.findings}" for a in attempts if a.vulnerable
            )

        if "model_enum" in checks_to_run:
            attempts = await _test_model_enum(endpoint, api_key, model, timeout, rps)
            all_attempts.extend(attempts)
            issues.extend(
                f"[ENUM] {a.label}: {a.findings}" for a in attempts if a.findings
            )

        overall = "secure"
        if any(a.vulnerable for a in all_attempts):
            overall = "vulnerable"
        elif issues:
            overall = "warnings"

        return LLMResult(
            target=endpoint,
            model=model,
            attempts=all_attempts,
            issues=issues,
            overall_status=overall,
        )

    def print_results(self, result: object) -> None:
        """Imprime resultados formatados do scan LLM."""
        assert isinstance(result, LLMResult)

        if result.overall_status == "error":
            print(f"\n{Cyber.RED}[!] Error: {result.issues[0]}")
            return

        total = len(result.attempts)
        vuln = sum(1 for a in result.attempts if a.vulnerable)
        safe = total - vuln

        # Summary
        status_color = Cyber.RED if vuln > 0 else Cyber.GREEN
        print(
            f"\n{Cyber.BOLD}{'=' * 60}\n"
            f"  LLM/AI Security Report\n"
            f"  Endpoint: {result.target}\n"
            f"  Model:    {result.model}\n"
            f"{'=' * 60}{Cyber.RESET}"
        )
        print(
            f"\n  {Cyber.BOLD}Summary:{Cyber.RESET} "
            f"{status_color}{vuln} vulnerable{Cyber.RESET}, "
            f"{Cyber.GREEN}{safe} safe{Cyber.RESET}, "
            f"{total} total checks"
        )

        # Detailed results
        for attempt in result.attempts:
            icon = Cyber.RED + "[!]" if attempt.vulnerable else Cyber.GREEN + "[+]"
            err = f" {Cyber.YELLOW}(error: {attempt.error})" if attempt.error else ""
            print(f"\n  {icon} {attempt.label}{Cyber.RESET}{err}")
            print(f"    Category:  {attempt.category}")
            print(f"    Technique: {attempt.technique}")
            if attempt.findings:
                for f in attempt.findings:
                    print(f"    Finding:   {Cyber.YELLOW}{f}{Cyber.RESET}")
            if attempt.response_snippet:
                snippet = attempt.response_snippet[:120].replace("\n", " ")
                print(f"    Response:  {Cyber.DIM}{snippet}...{Cyber.RESET}")

        print(f"\n{Cyber.BOLD}{'=' * 60}{Cyber.RESET}\n")

    def _example(self) -> str:
        return "--url https://api.openai.com/v1 --api-key sk-xxx --model gpt-4"

    def _help(self) -> str:
        return (
            "LLM/AI Security Testing\n\n"
            "Tests LLM endpoints for:\n"
            "  - Prompt injection (direct, indirect, smuggling)\n"
            "  - Data leakage (API keys, PII, credentials)\n"
            "  - Jailbreak (DAN, developer mode, roleplay)\n"
            "  - Model enumeration\n\n"
            "Requires an OpenAI-compatible API endpoint.\n"
        )


# --- Model enumeration test (not a full check, just info gathering) ---


async def _test_model_enum(
    endpoint: str,
    api_key: str,
    model: str,
    timeout: float,
    rps: float,
) -> list[LLMAttempt]:
    """Gather model information from the endpoint."""
    from mytools.core.utils import RateLimiter, create_async_client, fetch

    client = create_async_client(timeout=timeout)
    rate_limiter = RateLimiter(requests_per_second=rps)
    attempts: list[LLMAttempt] = []

    try:
        # Try /v1/models endpoint
        url = endpoint.rstrip("/")
        if url.endswith("/chat/completions"):
            url = url.rsplit("/chat/completions", 1)[0]
        models_url = url.rstrip("/") + "/models"

        status, _headers, body, _raw = await fetch(
            client,
            models_url,
            method="GET",
            headers={"Authorization": f"Bearer {api_key}"},
            rate_limiter=rate_limiter,
            timeout=timeout,
            max_retries=1,
        )

        if status == 200:
            try:
                data = json.loads(body)
                models = [m.get("id", "") for m in data.get("data", [])]
                attempts.append(
                    LLMAttempt(
                        technique="model_enum",
                        category="abuse",
                        label="Model enumeration",
                        endpoint=endpoint,
                        vulnerable=False,
                        findings=[f"Available models: {', '.join(models[:10])}"],
                        details=f"Found {len(models)} model(s) at {models_url}",
                    )
                )
            except json.JSONDecodeError, KeyError:
                pass
        else:
            attempts.append(
                LLMAttempt(
                    technique="model_enum",
                    category="abuse",
                    label="Model enumeration",
                    endpoint=endpoint,
                    vulnerable=False,
                    details=f"Models endpoint returned HTTP {status}",
                )
            )
    except Exception as exc:
        attempts.append(
            LLMAttempt(
                technique="model_enum",
                category="abuse",
                label="Model enumeration",
                endpoint=endpoint,
                vulnerable=False,
                error=str(exc),
            )
        )
    finally:
        await client.aclose()

    return attempts


# Module-level re-exports
_scanner = LLMSecurityScanner()
main = _scanner.main
run_once = _scanner.run_once
banner_art = create_banner(_BANNER_TEXT, _scanner.description)
build_parser = _scanner.build_parser
