"""Mobile API Testing — CLI entry point via BaseScanner."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Any

from mytools.core.base import BaseScanner, ScanGroup
from mytools.core.utils import Cyber, color, create_banner
from mytools.mobile._common import MobileAttempt, MobileResult

logger = logging.getLogger("mytools.mobile")

_BANNER_TEXT = (
    "  __  __ _       _                \n"
    " |  \\/  (_)_ __ (_) ___ ___ _ __ \n"
    " | |\\/| | | '_ \\| |/ __/ _ \\ '__|\n"
    " | |  | | | | | | | (_|  __/ |   \n"
    " |_|  |_|_|_| |_|_|\\___\\___|_|   \n"
)


def _is_apk(file_path: str) -> bool:
    return file_path.lower().endswith(".apk")


def _is_ipa(file_path: str) -> bool:
    return file_path.lower().endswith(".ipa")


class MobileAuditScanner(BaseScanner):
    """Scanner para análise estática de APK/IPA + OAuth2."""

    prog = "mytools-mobile"
    description = "Mobile API Testing — APK/IPA static analysis + OAuth2"
    prompt = "mobile> "
    module_name = "mytools.mobile"
    banner_text = _BANNER_TEXT
    group = ScanGroup.B

    def _add_arguments(self, parser: argparse.ArgumentParser) -> None:
        parser.add_argument("file_path", nargs="?", help="Caminho para APK ou IPA")
        parser.add_argument(
            "-c",
            "--checks",
            nargs="+",
            choices=[
                "apk_metadata",
                "apk_pinning",
                "apk_endpoints",
                "apk_secrets",
                "apk_nsc",
                "apk_sdk",
                "ipa_metadata",
                "ipa_provisioning",
                "ipa_macho",
                "ipa_secrets",
                "oauth2_test",
                "jwt_validate",
            ],
            help="Checks para executar (default: todos do platform)",
        )
        parser.add_argument("--idp", help="URL do Identity Provider (para oauth2)")
        parser.add_argument("--client-id", help="OAuth2 client_id")
        parser.add_argument("--client-secret", default="", help="OAuth2 client_secret")
        parser.add_argument("--jwt", help="JWT token para validação")

    @staticmethod
    def _get_target(args: argparse.Namespace) -> str | None:
        return getattr(args, "file_path", None)

    def _build_run_once_kwargs(self, args: argparse.Namespace) -> dict[str, Any]:
        return {
            "file_path": self._get_target(args),
            "checks": getattr(args, "checks", None),
            "idp": getattr(args, "idp", None),
            "client_id": getattr(args, "client_id", None),
            "client_secret": getattr(args, "client_secret", ""),
            "jwt": getattr(args, "jwt", None),
        }

    async def run_scan(
        self,
        file_path: str | None = None,
        checks: list[str] | None = None,
        idp: str | None = None,
        client_id: str | None = None,
        client_secret: str = "",
        jwt_token: str | None = None,
        **_kwargs: Any,
    ) -> MobileResult:
        """Executa scan mobile."""
        if not file_path:
            return MobileResult(
                target="",
                platform="unknown",
                file_size=0,
                issues=["No file specified"],
                overall_status="error",
            )

        if not Path(file_path).is_file():  # noqa: ASYNC240
            return MobileResult(
                target=file_path,
                platform="unknown",
                file_size=0,
                issues=[f"File not found: {file_path}"],
                overall_status="error",
            )

        is_apk = _is_apk(file_path)
        is_ipa = _is_ipa(file_path)

        if not is_apk and not is_ipa:
            return MobileResult(
                target=file_path,
                platform="unknown",
                file_size=Path(file_path).stat().st_size,  # noqa: ASYNC240
                issues=["Unsupported file type (use .apk or .ipa)"],
                overall_status="error",
            )

        platform = "android" if is_apk else "ios"
        file_size = Path(file_path).stat().st_size  # noqa: ASYNC240
        all_attempts: list[MobileAttempt] = []
        issues: list[str] = []

        # Determine checks to run
        if is_apk:
            default_checks = [
                "apk_metadata",
                "apk_pinning",
                "apk_endpoints",
                "apk_secrets",
                "apk_nsc",
                "apk_sdk",
            ]
        else:
            default_checks = [
                "ipa_metadata",
                "ipa_provisioning",
                "ipa_macho",
                "ipa_secrets",
            ]

        checks_to_run = checks if checks else default_checks

        # Add oauth2/jwt checks if requested
        if "oauth2_test" in (checks or []):
            checks_to_run.append("oauth2_test")
        if "jwt_validate" in (checks or []):
            checks_to_run.append("jwt_validate")

        # Run checks
        for check in checks_to_run:
            try:
                attempt = _run_check(check, file_path, platform, idp, client_id, client_secret, jwt_token)
                all_attempts.append(attempt)
                if attempt.error:
                    issues.append(f"{check}: {attempt.error}")
            except Exception as e:
                issues.append(f"{check}: {str(e)[:100]}")

        # Classify
        vuln_count = sum(1 for a in all_attempts if a.vulnerable)
        overall = "vulnerable" if vuln_count > 0 else "secure"

        return MobileResult(
            target=file_path,
            platform=platform,
            file_size=file_size,
            attempts=all_attempts,
            issues=issues,
            overall_status=overall,
        )

    def print_results(self, result: object) -> None:
        """Imprime resultados formatados."""
        assert isinstance(result, MobileResult)

        print()
        print(color("[*]", Cyber.CYAN, Cyber.BOLD), "Mobile API Testing")
        print(color("[*]", Cyber.CYAN), f"File: {result.target}")
        print(color("[*]", Cyber.CYAN), f"Platform: {result.platform} ({result.file_size} bytes)")
        print()

        if result.issues:
            print(color("[!]", Cyber.YELLOW, Cyber.BOLD), "Issues:")
            for issue in result.issues:
                print(color("    -", Cyber.YELLOW), issue)
            print()

        for attempt in result.attempts:
            if attempt.vulnerable:
                print(color("[!]", Cyber.RED, Cyber.BOLD), f"{attempt.check}: VULNERABLE")
                for finding in attempt.findings[:10]:
                    print(color("    [-]", Cyber.RED), finding)
            elif attempt.findings:
                print(color("[*]", Cyber.CYAN), f"{attempt.check}: {len(attempt.findings)} finding(s)")
                for finding in attempt.findings[:5]:
                    print(color("    [-]", Cyber.CYAN), finding)
            else:
                print(color("[+]", Cyber.GREEN), f"{attempt.check}: secure")

        print()
        if result.overall_status == "vulnerable":
            print(color("[!]", Cyber.RED, Cyber.BOLD), "VULNERABLE — Security issues found!")
        else:
            print(color("[+]", Cyber.GREEN, Cyber.BOLD), "SECURE — No issues detected")
        print()

    def _example(self) -> str:
        return "scan app.apk"

    def _help(self) -> str:
        return (
            "Mobile API Testing — análise estática de APK/IPA.\n"
            "\n"
            "Uso:\n"
            "  scan app.apk              Análise completa APK\n"
            "  scan MyApp.ipa            Análise completa IPA\n"
            "  scan app.apk -c apk_pinning apk_secrets   Só checks específicos\n"
            "\n"
            "Checks Android: apk_metadata, apk_pinning, apk_endpoints,\n"
            "  apk_secrets, apk_nsc, apk_sdk\n"
            "Checks iOS: ipa_metadata, ipa_provisioning, ipa_macho, ipa_secrets\n"
            "Checks OAuth2 (requer rede): oauth2_test, jwt_validate"
        )


# ─── Check Dispatch ──────────────────────────────────────────────────────────


def _run_check(
    check: str,
    file_path: str,
    platform: str,
    idp: str | None,
    client_id: str | None,
    client_secret: str,
    jwt_token: str | None,
) -> MobileAttempt:
    """Executa um check individual."""
    if check == "apk_metadata":
        from mytools.mobile.apk_analyzer import analyze_apk

        data = analyze_apk(file_path)
        findings = []
        if "error" in data:
            return MobileAttempt(
                technique="metadata", platform="android", check=check,
                file_path=file_path, vulnerable=False, error=data["error"],
            )
        findings.append(f"Package: {data.get('package', '')}")
        findings.append(f"Version: {data.get('version_name', '')} ({data.get('version_code', '')})")
        findings.append(f"Target SDK: {data.get('target_sdk', '')}")
        findings.append(f"Min SDK: {data.get('min_sdk', '')}")
        findings.append(f"Permissions: {data.get('permissions_count', 0)}")
        findings.append(f"Exported: {len(data.get('activities', []))} activities, {len(data.get('services', []))} services")
        if data.get("sdk_fingerprints"):
            findings.append(f"SDKs: {', '.join(data['sdk_fingerprints'])}")
        return MobileAttempt(
            technique="metadata", platform="android", check=check,
            file_path=file_path, vulnerable=False, findings=findings,
        )

    if check == "apk_pinning":
        from mytools.mobile.apk_pinning import detect_pinning

        data = detect_pinning(file_path)
        techniques = data.get("techniques", [])
        findings = [f"Technique: {t}" for t in techniques]
        if data.get("nsc_indicators"):
            findings.extend([f"NSC: {n}" for n in data["nsc_indicators"]])
        return MobileAttempt(
            technique="pinning", platform="android", check=check,
            file_path=file_path, vulnerable=data.get("vulnerable", False),
            findings=findings, details=f"{len(techniques)} pinning technique(s) detected",
        )

    if check == "apk_endpoints":
        from mytools.mobile.apk_endpoints import extract_endpoints

        data = extract_endpoints(file_path)
        findings = []
        for url in data.get("urls", [])[:20]:
            findings.append(f"URL: {url}")
        for path in data.get("api_paths", [])[:20]:
            findings.append(f"API: {path}")
        for fb in data.get("firebase_urls", [])[:5]:
            findings.append(f"Firebase: {fb}")
        for scheme in data.get("schemes", [])[:10]:
            findings.append(f"Scheme: {scheme}")
        return MobileAttempt(
            technique="endpoints", platform="android", check=check,
            file_path=file_path, vulnerable=False, findings=findings,
            details=f"{data.get('total_endpoints', 0)} endpoint(s) found",
        )

    if check == "apk_secrets":
        from mytools.mobile.apk_secrets import detect_secrets

        data = detect_secrets(file_path)
        findings = [
            f"{f['pattern']}: {f['value'][:40]}..." if len(f["value"]) > 40 else f"{f['pattern']}: {f['value']}"
            for f in data.get("findings", [])
        ]
        return MobileAttempt(
            technique="secrets", platform="android", check=check,
            file_path=file_path, vulnerable=data.get("total_secrets", 0) > 0,
            findings=findings, details=f"{data.get('total_secrets', 0)} secret(s) found",
        )

    if check == "apk_nsc":
        from mytools.mobile.apk_nsc import analyze_nsc

        data = analyze_nsc(file_path)
        findings = data.get("findings", [])
        return MobileAttempt(
            technique="nsc", platform="android", check=check,
            file_path=file_path,
            vulnerable=data.get("risk_score", 0) > 0,
            findings=findings,
            details=f"NSC risk score: {data.get('risk_score', 0)}",
        )

    if check == "apk_sdk":
        from mytools.mobile.apk_analyzer import analyze_apk

        data = analyze_apk(file_path)
        sdks = data.get("sdk_fingerprints", [])
        findings = [f"SDK: {s}" for s in sdks]
        return MobileAttempt(
            technique="sdk", platform="android", check=check,
            file_path=file_path, vulnerable=False, findings=findings,
            details=f"{len(sdks)} SDK(s) detected",
        )

    if check == "ipa_metadata":
        from mytools.mobile.ipa_analyzer import analyze_ipa

        data = analyze_ipa(file_path)
        findings = []
        if data.get("bundle_id"):
            findings.append(f"Bundle ID: {data['bundle_id']}")
        if data.get("display_name"):
            findings.append(f"Name: {data['display_name']}")
        if data.get("version"):
            findings.append(f"Version: {data['version']} ({data.get('build', '')})")
        if data.get("min_os_version"):
            findings.append(f"Min OS: {data['min_os_version']}")
        if data.get("url_schemes"):
            findings.extend([f"URL Scheme: {s}" for s in data["url_schemes"]])
        if data.get("ats_settings", {}).get("allows_insecure_http"):
            findings.append("ATS: Allows arbitrary HTTP loads!")
        return MobileAttempt(
            technique="metadata", platform="ios", check=check,
            file_path=file_path, vulnerable=data.get("ats_settings", {}).get("allows_insecure_http", False),
            findings=findings,
        )

    if check == "ipa_provisioning":
        from mytools.mobile.ipa_analyzer import analyze_ipa

        data = analyze_ipa(file_path)
        prov = data.get("provisioning", {})
        findings = []
        if prov.get("name"):
            findings.append(f"Profile: {prov['name']}")
        if prov.get("team_name"):
            findings.append(f"Team: {prov['team_name']}")
        if prov.get("expires"):
            findings.append(f"Expires: {prov['expires']}")
        if prov.get("devices"):
            findings.append(f"Provisioned devices: {prov['devices']}")
        ent = data.get("entitlements", {})
        if ent:
            findings.extend([f"Entitlement: {k}" for k in list(ent.keys())[:10]])
        return MobileAttempt(
            technique="provisioning", platform="ios", check=check,
            file_path=file_path, vulnerable=False, findings=findings,
        )

    if check == "ipa_macho":
        from mytools.mobile.ipa_analyzer import analyze_ipa

        data = analyze_ipa(file_path)
        macho = data.get("macho", {})
        findings = []
        if macho.get("name"):
            findings.append(f"Binary: {macho['name']}")
        if macho.get("libraries"):
            findings.extend([f"Lib: {lib}" for lib in macho["libraries"][:20]])
        if macho.get("rpaths"):
            findings.extend([f"RPath: {r}" for r in macho["rpaths"]])
        findings.append(f"Exported: {macho.get('exported_count', 0)} functions")
        findings.append(f"Symbols: {macho.get('symbol_count', 0)}")
        return MobileAttempt(
            technique="macho", platform="ios", check=check,
            file_path=file_path, vulnerable=False, findings=findings,
        )

    if check == "ipa_secrets":
        from mytools.mobile.ipa_secrets import detect_ipa_secrets

        data = detect_ipa_secrets(file_path)
        findings = [
            f"{f['pattern']}: {f['value'][:40]}..." if len(f["value"]) > 40 else f"{f['pattern']}: {f['value']}"
            for f in data.get("findings", [])
        ]
        return MobileAttempt(
            technique="secrets", platform="ios", check=check,
            file_path=file_path, vulnerable=data.get("total_secrets", 0) > 0,
            findings=findings, details=f"{data.get('total_secrets', 0)} secret(s) found",
        )

    if check == "oauth2_test":
        if not idp or not client_id:
            return MobileAttempt(
                technique="oauth2", platform="oauth2", check=check,
                file_path=file_path, vulnerable=False,
                error="Requires --idp and --client-id",
            )
        from mytools.mobile.oauth2_flows import generate_pkce_flow

        data = generate_pkce_flow(idp, client_id)
        findings = [f"{k}: {v[:60]}" for k, v in data.items() if k != "instructions"]
        return MobileAttempt(
            technique="pkce", platform="oauth2", check=check,
            file_path=file_path, vulnerable=False, findings=findings,
            details="PKCE flow parameters generated",
        )

    if check == "jwt_validate":
        if not jwt_token:
            return MobileAttempt(
                technique="jwt", platform="oauth2", check=check,
                file_path=file_path, vulnerable=False,
                error="Requires --jwt token",
            )
        from mytools.mobile.oauth2_flows import validate_jwt

        data = validate_jwt(jwt_token)
        if "error" in data:
            return MobileAttempt(
                technique="jwt", platform="oauth2", check=check,
                file_path=file_path, vulnerable=False, error=data["error"],
            )
        findings = [f"Warning: {w}" for w in data.get("warnings", [])]
        findings.append(f"Algorithm: {data.get('header', {}).get('alg', 'unknown')}")
        return MobileAttempt(
            technique="jwt", platform="oauth2", check=check,
            file_path=file_path,
            vulnerable=bool(data.get("warnings")),
            findings=findings,
        )

    return MobileAttempt(
        technique=check, platform=platform, check=check,
        file_path=file_path, vulnerable=False,
        error=f"Unknown check: {check}",
    )


# ─── Module-level re-exports ────────────────────────────────────────────────

_scanner = MobileAuditScanner()
main = _scanner.main
run_once = _scanner.run_once
banner_art = create_banner(_BANNER_TEXT, _scanner.description)
build_parser = _scanner.build_parser
