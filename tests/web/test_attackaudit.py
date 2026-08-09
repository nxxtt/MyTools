import argparse
import re
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest
import respx

from mytools.core.utils import Cyber, RateLimiter, severity_color
from mytools.web.attackaudit import (
    _ERROR_INFO_SEVERITY,
    _JS_ENDPOINT_PATTERNS,
    _JS_SECRET_PATTERNS,
    _SENSITIVE_HIDDEN_FIELDS,
    _SENSITIVE_VALUE_PATTERNS,
    _URL_PARAM_NAMES,
    _VERBOSE_ERROR_HEADERS,
    _WAF_SIGNATURES,
    CSRF_FIELD_NAMES_LOWER,
    DEFAULT_INJECT_PARAMS,
    ERROR_INFO_PATTERNS,
    METHODS_TO_TEST,
    RISK_WEIGHTS,
    SECURITY_HEADERS_RECS,
    SQL_ERROR_PATTERNS,
    SQLI_PAYLOADS,
    AuditResult,
    Finding,
    MethodResult,
    PageParser,
    Probe,
    TLSVersionResult,
    _async_run_once,
    _check_tls_versions_sync,
    _extract_query_params,
    _extract_session_id,
    _resolve_ip_sync,
    _run_single,
    _save_audit_output,
    _tls_info_sync,
    analyze_error_response,
    analyze_headers_findings,
    analyze_hidden_fields,
    analyze_js_content,
    analyze_js_files,
    analyze_url_params,
    build_findings,
    build_parser,
    check_session_fixation,
    check_sqli_errors,
    check_tls_versions,
    check_xss_reflection,
    load_paths_from_file,
    normalize_url,
    parse_allowed_methods,
    print_result,
    probe_path,
    resolve_ip,
    risk_score,
    run_audit,
    run_once,
    scan_paths,
    tls_info,
)
from mytools.web.attackaudit import (
    test_http_methods as module_test_http_methods,
)

pytestmark = pytest.mark.integration


class TestNormalizeUrl:
    def test_with_scheme(self):
        assert normalize_url("https://example.com") == "https://example.com"

    def test_without_scheme_adds_https(self):
        result = normalize_url("example.com")
        assert result == "https://example.com"

    def test_strips_trailing_slash(self):
        assert normalize_url("https://example.com/") == "https://example.com"

    def test_strips_whitespace(self):
        assert normalize_url("  https://example.com  ") == "https://example.com"

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            normalize_url("")

    def test_invalid_scheme_raises(self):
        with pytest.raises(ValueError):
            normalize_url("ftp://example.com")


class TestRiskScore:
    def test_empty_findings(self):
        assert risk_score([]) == 0

    def test_single_critical(self):
        findings = [Finding("critical", "cat", "item", "evidence", "rec")]
        assert risk_score(findings) == RISK_WEIGHTS["critical"]

    def test_mixed_severities(self):
        findings = [
            Finding("critical", "cat", "item", "evidence", "rec"),
            Finding("low", "cat", "item", "evidence", "rec"),
            Finding("info", "cat", "item", "evidence", "rec"),
        ]
        expected = RISK_WEIGHTS["critical"] + RISK_WEIGHTS["low"] + RISK_WEIGHTS["info"]
        assert risk_score(findings) == expected


class TestSeverityColor:
    def test_critical_is_red(self):
        assert severity_color("critical") == Cyber.RED

    def test_high_is_orange(self):
        assert severity_color("high") == Cyber.ORANGE

    def test_medium_is_yellow(self):
        assert severity_color("medium") == Cyber.YELLOW

    def test_low_is_blue(self):
        assert severity_color("low") == Cyber.BLUE

    def test_info_is_gray(self):
        assert severity_color("info") == Cyber.GRAY

    def test_unknown_is_gray(self):
        assert severity_color("unknown") == Cyber.GRAY

    def test_all_severities_return_strings(self):
        for sev in ("critical", "high", "medium", "low", "info", "unknown"):
            result = severity_color(sev)
            assert isinstance(result, str)
            assert len(result) > 0


class TestPageParser:
    def test_title(self):
        parser = PageParser()
        parser.feed("<html><title>My Title</title></html>")
        assert parser.title == "My Title"

    def test_forms_count(self):
        parser = PageParser()
        parser.feed("<form><input type='text'></form><form></form>")
        assert parser.forms == 2

    def test_password_inputs(self):
        parser = PageParser()
        parser.feed("<input type='password'><input type='text'><input type='password'>")
        assert parser.password_inputs == 2

    def test_external_scripts(self):
        parser = PageParser()
        parser.feed("<script src='app.js'></script><script src='lib.js'></script>")
        assert len(parser.external_scripts) == 2

    def test_comments(self):
        parser = PageParser()
        parser.feed("<!-- TODO: fix this -->")
        assert len(parser.comments) == 1
        assert "TODO" in parser.comments[0]

    def test_empty_comment_ignored(self):
        parser = PageParser()
        parser.feed("<!--   -->")
        assert len(parser.comments) == 0

    def test_no_title(self):
        parser = PageParser()
        parser.feed("<html><body>no title</body></html>")
        assert parser.title == ""


class TestPageParserCSRF:
    def test_form_with_csrf_token(self):
        parser = PageParser()
        parser.feed(
            '<form method="POST"><input type="hidden" name="csrf_token" value="abc123"><input type="text" name="user"></form>'
        )
        assert parser.forms == 1
        assert parser.forms_missing_csrf == 0

    def test_form_without_csrf_token(self):
        parser = PageParser()
        parser.feed('<form method="POST"><input type="text" name="user"></form>')
        assert parser.forms == 1
        assert parser.forms_missing_csrf == 1

    def test_multiple_forms_mixed(self):
        parser = PageParser()
        parser.feed(
            '<form method="POST"><input type="hidden" name="_token" value="x"></form>'
        )
        parser.feed('<form method="POST"><input type="text" name="data"></form>')
        assert parser.forms == 2
        assert parser.forms_missing_csrf == 1

    def test_csrf_field_names_detected(self):
        for field_name in [
            "csrf_token",
            "_csrf",
            "_token",
            "authenticity_token",
            "csrfmiddlewaretoken",
        ]:
            parser = PageParser()
            parser.feed(
                f'<form><input type="hidden" name="{field_name}" value="x"></form>'
            )
            assert parser.forms_missing_csrf == 0, f"Failed for {field_name}"


class TestProbeDataclass:
    def test_creation(self):
        p = Probe(url="http://x.com/.env", status=200, size=50, location="")
        assert p.status == 200

    def test_frozen(self):
        p = Probe(url="http://x.com/.env", status=200, size=50, location="")
        with pytest.raises(AttributeError):
            p.status = 404  # type: ignore[reportAttributeAccessIssue]


class TestFindingDataclass:
    def test_creation(self):
        f = Finding("high", "transport", "item", "evidence", "rec")
        assert f.severity == "high"

    def test_frozen(self):
        f = Finding("high", "transport", "item", "evidence", "rec")
        with pytest.raises(AttributeError):
            f.severity = "low"  # type: ignore[reportAttributeAccessIssue]


class TestTLSVersionResult:
    def test_creation(self):
        r = TLSVersionResult(protocol="TLS 1.2", supported=True)
        assert r.protocol == "TLS 1.2"
        assert r.supported is True
        assert r.reason == ""

    def test_unsupported(self):
        r = TLSVersionResult(protocol="SSLv3", supported=False, reason="disabled")
        assert r.supported is False
        assert r.reason == "disabled"

    def test_frozen(self):
        r = TLSVersionResult(protocol="TLS 1.3", supported=True)
        with pytest.raises(AttributeError):
            r.supported = False  # type: ignore[reportAttributeAccessIssue]


class TestAuditResultDataclass:
    def test_creation(self):
        r = AuditResult(
            target="https://example.com",
            final_url="https://example.com",
            status=200,
            title="",
            ip="1.2.3.4",
            tls_subject="example.com",
            tls_issuer="Let's Encrypt",
            tls_not_after="Dec 31",
            allowed_methods=["GET"],
            forms=0,
            password_inputs=0,
            probes=[],
            findings=[],
            risk_score=0,
            elapsed=1.0,
        )
        assert r.status == 200
        assert r.risk_score == 0

    def test_optional_tls_versions(self):
        r = AuditResult(
            target="https://example.com",
            final_url="https://example.com",
            status=200,
            title="",
            ip="",
            tls_subject="",
            tls_issuer="",
            tls_not_after="",
            allowed_methods=[],
            forms=0,
            password_inputs=0,
            probes=[],
            findings=[],
            risk_score=0,
            elapsed=1.0,
        )
        assert r.tls_versions == []
        assert r.xss_reflected is False
        assert r.sqli_errors == []
        assert r.csrf_missing == 0


class TestBuildFindings:
    def test_http_finds_high(self):
        parser = PageParser()
        findings = build_findings("http://example.com", 200, {}, parser, [], [], "")
        severities = [f.severity for f in findings]
        assert "high" in severities

    def test_missing_security_headers(self):
        parser = PageParser()
        findings = build_findings(
            "https://example.com", 200, {}, parser, [], [], "example.com"
        )
        headers_findings = [f for f in findings if f.category == "headers"]
        assert len(headers_findings) == len(SECURITY_HEADERS_RECS)

    def test_security_header_present(self):
        parser = PageParser()
        headers = {"strict-transport-security": "max-age=31536000"}
        findings = build_findings(
            "https://example.com", 200, headers, parser, [], [], "example.com"
        )
        headers_findings = [f for f in findings if f.category == "headers"]
        assert len(headers_findings) == len(SECURITY_HEADERS_RECS) - 1

    def test_cors_wildcard(self):
        parser = PageParser()
        headers = {"access-control-allow-origin": "*"}
        findings = build_findings(
            "https://example.com", 200, headers, parser, [], [], "example.com"
        )
        cors_findings = [f for f in findings if f.category == "cors"]
        assert len(cors_findings) == 1

    def test_dangerous_methods(self):
        parser = PageParser()
        findings = build_findings(
            "https://example.com",
            200,
            {},
            parser,
            ["GET", "PUT", "DELETE"],
            [],
            "example.com",
        )
        methods_findings = [f for f in findings if f.category == "methods"]
        assert len(methods_findings) == 1

    def test_password_on_http_critical(self):
        parser = PageParser()
        parser.feed("<input type='password'>")
        findings = build_findings("http://example.com", 200, {}, parser, [], [], "")
        auth_findings = [f for f in findings if f.category == "auth"]
        assert len(auth_findings) == 1
        assert auth_findings[0].severity == "critical"

    def test_5xx_error(self):
        parser = PageParser()
        findings = build_findings(
            "https://example.com", 500, {}, parser, [], [], "example.com"
        )
        stability = [f for f in findings if f.category == "stability"]
        assert len(stability) == 1

    def test_sensitive_probe_200_high(self):
        parser = PageParser()
        probes = [
            Probe(url="https://example.com/.env", status=200, size=50, location="")
        ]
        findings = build_findings(
            "https://example.com", 200, {}, parser, [], probes, "example.com"
        )
        exposure = [f for f in findings if f.category == "exposure"]
        assert len(exposure) == 1
        assert exposure[0].severity == "high"

    def test_sensitive_probe_403_medium(self):
        parser = PageParser()
        probes = [
            Probe(url="https://example.com/.git/HEAD", status=403, size=50, location="")
        ]
        findings = build_findings(
            "https://example.com", 200, {}, parser, [], probes, "example.com"
        )
        exposure = [f for f in findings if f.category == "exposure"]
        assert len(exposure) == 1
        assert exposure[0].severity == "medium"

    def test_server_exposed(self):
        parser = PageParser()
        headers = {"server": "nginx/1.20"}
        findings = build_findings(
            "https://example.com", 200, headers, parser, [], [], "example.com"
        )
        fp = [f for f in findings if f.category == "fingerprint"]
        assert any("Server" in f.item for f in fp)

    def test_cookie_missing_flags(self):
        parser = PageParser()
        headers = {"Set-Cookie": "session=abc123"}
        raw_headers = {"set-cookie": ["session=abc123"]}
        findings = build_findings(
            "https://example.com",
            200,
            headers,
            parser,
            [],
            [],
            "example.com",
            raw_headers=raw_headers,
        )
        cookie_findings = [f for f in findings if f.category == "cookies"]
        assert len(cookie_findings) == 1
        assert "httponly" in cookie_findings[0].evidence.lower()

    def test_cookie_all_flags_present(self):
        parser = PageParser()
        headers = {"Set-Cookie": "session=abc123; Secure; HttpOnly; SameSite=Strict"}
        raw_headers = {
            "set-cookie": ["session=abc123; Secure; HttpOnly; SameSite=Strict"]
        }
        findings = build_findings(
            "https://example.com",
            200,
            headers,
            parser,
            [],
            [],
            "example.com",
            raw_headers=raw_headers,
        )
        cookie_findings = [f for f in findings if f.category == "cookies"]
        assert len(cookie_findings) == 0

    def test_cookie_multiple_set_cookie(self):
        parser = PageParser()
        headers = {"Set-Cookie": "session=abc123"}
        raw_headers = {"set-cookie": ["session=abc123", "analytics=xyz"]}
        findings = build_findings(
            "https://example.com",
            200,
            headers,
            parser,
            [],
            [],
            "example.com",
            raw_headers=raw_headers,
        )
        cookie_findings = [f for f in findings if f.category == "cookies"]
        assert len(cookie_findings) == 2

    def test_no_tls_subject(self):
        parser = PageParser()
        findings = build_findings("https://example.com", 200, {}, parser, [], [], "")
        transport = [f for f in findings if f.category == "transport"]
        assert any("TLS nao validado" in f.item for f in transport)

    def test_html_comments(self):
        parser = PageParser()
        parser.feed("<!-- secret config -->")
        findings = build_findings(
            "https://example.com", 200, {}, parser, [], [], "example.com"
        )
        content = [f for f in findings if f.category == "content"]
        assert len(content) == 1
        assert "comentario" in content[0].item.lower()


class TestBuildFindingsPhase7:
    def test_weak_tls_version(self):
        parser = PageParser()
        tls_versions = [
            TLSVersionResult(protocol="TLS 1.2", supported=True),
            TLSVersionResult(protocol="TLS 1.1", supported=True),
        ]
        findings = build_findings(
            "https://example.com",
            200,
            {},
            parser,
            [],
            [],
            "example.com",
            tls_versions=tls_versions,
        )
        transport = [f for f in findings if f.category == "transport"]
        assert any("TLS 1.1" in f.item for f in transport)

    def test_all_strong_tls(self):
        parser = PageParser()
        tls_versions = [
            TLSVersionResult(protocol="TLS 1.2", supported=True),
            TLSVersionResult(protocol="TLS 1.3", supported=True),
        ]
        findings = build_findings(
            "https://example.com",
            200,
            {},
            parser,
            [],
            [],
            "example.com",
            tls_versions=tls_versions,
        )
        transport = [
            f for f in findings if f.category == "transport" and "obsoleta" in f.item
        ]
        assert len(transport) == 0

    def test_xss_reflected_finding(self):
        parser = PageParser()
        findings = build_findings(
            "https://example.com",
            200,
            {},
            parser,
            [],
            [],
            "example.com",
            xss_reflected=True,
            xss_evidence="refletido em html_body",
        )
        xss = [f for f in findings if f.category == "xss"]
        assert len(xss) == 1
        assert xss[0].severity == "high"

    def test_no_xss_no_finding(self):
        parser = PageParser()
        findings = build_findings(
            "https://example.com",
            200,
            {},
            parser,
            [],
            [],
            "example.com",
            xss_reflected=False,
        )
        xss = [f for f in findings if f.category == "xss"]
        assert len(xss) == 0

    def test_sqli_error_finding(self):
        parser = PageParser()
        findings = build_findings(
            "https://example.com",
            200,
            {},
            parser,
            [],
            [],
            "example.com",
            sqli_databases=["mysql"],
        )
        sqli = [f for f in findings if f.category == "sqli"]
        assert len(sqli) == 1
        assert sqli[0].severity == "critical"
        assert "mysql" in sqli[0].evidence

    def test_sqli_multiple_databases(self):
        parser = PageParser()
        findings = build_findings(
            "https://example.com",
            200,
            {},
            parser,
            [],
            [],
            "example.com",
            sqli_databases=["mysql", "postgresql"],
        )
        sqli = [f for f in findings if f.category == "sqli"]
        assert len(sqli) == 1
        assert "mysql" in sqli[0].evidence
        assert "postgresql" in sqli[0].evidence

    def test_csrf_missing_finding(self):
        parser = PageParser()
        parser.feed('<form method="POST"><input type="text" name="data"></form>')
        findings = build_findings(
            "https://example.com", 200, {}, parser, [], [], "example.com"
        )
        csrf = [f for f in findings if f.category == "csrf"]
        assert len(csrf) == 1
        assert "1" in csrf[0].evidence


class TestSQLiPatterns:
    def test_mysql_patterns_exist(self):
        assert "mysql" in SQL_ERROR_PATTERNS
        assert len(SQL_ERROR_PATTERNS["mysql"]) > 0

    def test_postgresql_patterns_exist(self):
        assert "postgresql" in SQL_ERROR_PATTERNS

    def test_mssql_patterns_exist(self):
        assert "mssql" in SQL_ERROR_PATTERNS

    def test_oracle_patterns_exist(self):
        assert "oracle" in SQL_ERROR_PATTERNS

    def test_sqlite_patterns_exist(self):
        assert "sqlite" in SQL_ERROR_PATTERNS

    def test_patterns_are_regex(self):
        for patterns in SQL_ERROR_PATTERNS.values():
            for pattern in patterns:
                assert isinstance(pattern, re.Pattern)


class TestSQLIPayloads:
    def test_not_empty(self):
        assert len(SQLI_PAYLOADS) > 0

    def test_contains_single_quote(self):
        assert "'" in SQLI_PAYLOADS


class TestCSIFFieldNames:
    def test_not_empty(self):
        assert len(CSRF_FIELD_NAMES_LOWER) > 0

    def test_contains_common_names(self):
        for name in [
            "csrf_token",
            "_csrf",
            "_token",
            "authenticity_token",
            "csrfmiddlewaretoken",
        ]:
            assert name in CSRF_FIELD_NAMES_LOWER


class TestErrorInfoPatterns:
    def test_all_categories_have_patterns(self):
        assert len(ERROR_INFO_PATTERNS) == 5
        for category in (
            "stack_trace",
            "framework_version",
            "internal_path",
            "database_error",
            "config_leak",
        ):
            assert category in ERROR_INFO_PATTERNS
            assert len(ERROR_INFO_PATTERNS[category]) > 0

    def test_patterns_are_regex(self):
        for patterns in ERROR_INFO_PATTERNS.values():
            for pattern in patterns:
                assert isinstance(pattern, re.Pattern)

    def test_severity_has_all_categories(self):
        for category in ERROR_INFO_PATTERNS:
            assert category in _ERROR_INFO_SEVERITY

    def test_severity_values_are_valid(self):
        for severity in _ERROR_INFO_SEVERITY.values():
            assert severity in ("critical", "high", "medium", "low", "info")


class TestAnalyzeErrorResponse:
    def test_java_stack_trace(self):
        body = "java.lang.NullPointerException\n\tat com.app.Main(Main.java:42)"
        findings = analyze_error_response(body)
        assert any(
            f.category == "info_leak" and "stack_trace" in f.item for f in findings
        )

    def test_python_traceback(self):
        body = 'Traceback (most recent call last):\n  File "app.py", line 10'
        findings = analyze_error_response(body)
        assert any("stack_trace" in f.item for f in findings)

    def test_php_fatal_error(self):
        body = "Fatal error: Uncaught Exception in /var/www/app.php on line 42"
        findings = analyze_error_response(body)
        assert any("stack_trace" in f.item for f in findings)

    def test_framework_version_nginx(self):
        body = "nginx/1.18.0 (Ubuntu)"
        findings = analyze_error_response(body)
        assert any("framework_version" in f.item for f in findings)

    def test_internal_path(self):
        body = "Error reading file /var/www/html/config.php"
        findings = analyze_error_response(body)
        assert any("internal_path" in f.item for f in findings)

    def test_database_error(self):
        body = "MySQL error: Connection refused"
        findings = analyze_error_response(body)
        assert any("database_error" in f.item for f in findings)

    def test_config_leak_aws_key(self):
        body = "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE"
        findings = analyze_error_response(body)
        assert any("config_leak" in f.item for f in findings)
        assert any(
            f.severity == "critical" for f in findings if "config_leak" in f.item
        )

    def test_config_leak_jdbc(self):
        body = "jdbc:mysql://localhost:3306/mydb"
        findings = analyze_error_response(body)
        assert any("config_leak" in f.item for f in findings)

    def test_clean_body_no_findings(self):
        body = "<html><body>Hello World</body></html>"
        findings = analyze_error_response(body)
        assert len(findings) == 0

    def test_multiple_categories(self):
        body = "Traceback (most recent call last):\nnginx/1.18.0\n/var/www/app.py"
        findings = analyze_error_response(body)
        categories = [f.item for f in findings]
        assert any("stack_trace" in c for c in categories)
        assert any("framework_version" in c for c in categories)
        assert any("internal_path" in c for c in categories)

    def test_snippet_is_truncated(self):
        body = "A" * 500 + "Traceback (most recent call last):" + "B" * 500
        findings = analyze_error_response(body)
        assert len(findings) > 0
        assert len(findings[0].evidence) <= 200


class TestAnalyzeHeadersFindings:
    def test_cloudflare_waf_detected(self):
        headers = {"cf-ray": "abc123", "server": "cloudflare"}
        findings = analyze_headers_findings(headers)
        assert any(f.category == "waf" and "cloudflare" in f.item for f in findings)

    def test_aws_cloudfront_detected(self):
        headers = {"via": "1.1 cloudfront (CloudFront)", "x-amz-cf-id": "xyz"}
        findings = analyze_headers_findings(headers)
        assert any(f.category == "waf" and "cloudfront" in f.item for f in findings)

    def test_sucuri_waf_detected(self):
        headers = {"x-sucuri-id": "12345", "server": "Sucuri/CloudProxy"}
        findings = analyze_headers_findings(headers)
        assert any(f.category == "waf" and "sucuri" in f.item for f in findings)

    def test_waf_via_cookies(self):
        raw = {"set-cookie": ["incap_ses_123=abc; path=/"]}
        findings = analyze_headers_findings({}, raw)
        assert any(f.category == "waf" and "incapsula" in f.item for f in findings)

    def test_no_waf_clean_headers(self):
        headers = {"server": "nginx/1.18.0", "content-type": "text/html"}
        findings = analyze_headers_findings(headers)
        waf_findings = [f for f in findings if f.category == "waf"]
        assert len(waf_findings) == 0

    def test_x_debug_header(self):
        headers = {"x-debug": "true"}
        findings = analyze_headers_findings(headers)
        assert any(f.category == "info_leak" and "x-debug" in f.item for f in findings)

    def test_x_debug_toolbar_high_severity(self):
        headers = {"x-debug-toolbar": "http://debug.local"}
        findings = analyze_headers_findings(headers)
        toolbar = [f for f in findings if "x-debug-toolbar" in f.item]
        assert len(toolbar) == 1
        assert toolbar[0].severity == "high"

    def test_x_aspnet_version(self):
        headers = {"x-aspnet-version": "4.0.30319"}
        findings = analyze_headers_findings(headers)
        assert any("x-aspnet-version" in f.item for f in findings)

    def test_x_powered_by(self):
        headers = {"x-powered-by": "Express"}
        findings = analyze_headers_findings(headers)
        assert any("x-powered-by" in f.item for f in findings)

    def test_clean_headers_no_findings(self):
        headers = {"content-type": "text/html", "content-length": "1234"}
        findings = analyze_headers_findings(headers)
        assert len(findings) == 0

    def test_waf_and_debug_combined(self):
        headers = {"cf-ray": "abc", "x-debug": "1"}
        findings = analyze_headers_findings(headers)
        waf = [f for f in findings if f.category == "waf"]
        debug = [f for f in findings if f.category == "info_leak"]
        assert len(waf) >= 1
        assert len(debug) >= 1

    def test_case_insensitive_header_match(self):
        headers = {"X-Debug-Token": "abc123"}
        findings = analyze_headers_findings(headers)
        assert any("x-debug-token" in f.item for f in findings)

    def test_waf_signatures_structure(self):
        assert isinstance(_WAF_SIGNATURES, dict)
        for rules in _WAF_SIGNATURES.values():
            assert "headers" in rules or "cookies" in rules

    def test_verbose_error_headers_structure(self):
        assert isinstance(_VERBOSE_ERROR_HEADERS, dict)
        for sev, cat, rec in _VERBOSE_ERROR_HEADERS.values():
            assert sev in ("low", "medium", "high", "critical", "info")
            assert cat in ("fingerprint", "info_leak")
            assert isinstance(rec, str)


class TestAnalyzeHiddenFields:
    def test_credential_field_name_detected(self):
        fields = [("password", "hunter2")]
        findings = analyze_hidden_fields(fields)
        assert any("password" in f.item for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_api_key_field_name_detected(self):
        fields = [("api_key", "")]
        findings = analyze_hidden_fields(fields)
        assert any("api_key" in f.item for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_token_field_name_detected(self):
        fields = [("auth_token", "abc123")]
        findings = analyze_hidden_fields(fields)
        assert any("auth_token" in f.item for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_private_key_field_detected(self):
        fields = [("private_key", "")]
        findings = analyze_hidden_fields(fields)
        assert any("private_key" in f.item for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_internal_id_field_low_severity(self):
        fields = [("user_id", "12345")]
        findings = analyze_hidden_fields(fields)
        assert any("user_id" in f.item for f in findings)
        assert any(f.severity == "low" for f in findings)

    def test_jwt_value_detected(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        fields = [("token", jwt)]
        findings = analyze_hidden_fields(fields)
        assert any("jwt" in f.evidence.lower() for f in findings)

    def test_aws_key_value_detected(self):
        fields = [("access", "AKIAIOSFODNN7EXAMPLE")]
        findings = analyze_hidden_fields(fields)
        assert any("aws" in f.evidence.lower() for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_hardcoded_password_value_detected(self):
        fields = [("secret", "changeme")]
        findings = analyze_hidden_fields(fields)
        assert any(
            "hidden" in f.item.lower() or "valor" in f.item.lower() for f in findings
        )

    def test_clean_hidden_fields_no_findings(self):
        fields = [("csrf_token", "abc123"), ("form_id", "login")]
        findings = analyze_hidden_fields(fields)
        assert len(findings) == 0

    def test_multiple_sensitive_fields(self):
        fields = [("password", "test"), ("api_key", "")]
        findings = analyze_hidden_fields(fields)
        assert len(findings) >= 2

    def test_no_duplicate_per_field_type(self):
        fields = [("password", "a"), ("passwd", "b"), ("pwd", "c")]
        findings = analyze_hidden_fields(fields)
        name_findings = [f for f in findings if "Campo hidden" in f.item]
        assert len(name_findings) == 1

    def test_empty_fields_no_findings(self):
        findings = analyze_hidden_fields([])
        assert len(findings) == 0

    def test_sensitive_structure(self):
        assert isinstance(_SENSITIVE_HIDDEN_FIELDS, dict)
        for sev, cat, patterns in _SENSITIVE_HIDDEN_FIELDS.values():
            assert sev in ("low", "medium", "high", "critical", "info")
            assert cat in ("exposure", "info_leak")
            assert len(patterns) > 0

    def test_value_patterns_structure(self):
        assert isinstance(_SENSITIVE_VALUE_PATTERNS, dict)
        for sev, cat, _pattern in _SENSITIVE_VALUE_PATTERNS.values():
            assert sev in ("low", "medium", "high", "critical", "info")
            assert cat in ("exposure", "info_leak")


class TestPageParserHiddenFields:
    def test_collects_hidden_field(self):
        parser = PageParser()
        parser.feed('<form><input type="hidden" name="token" value="abc"></form>')
        assert len(parser.hidden_fields) == 1
        assert parser.hidden_fields[0] == ("token", "abc")

    def test_collects_multiple_hidden_fields(self):
        parser = PageParser()
        parser.feed(
            '<form><input type="hidden" name="a" value="1"><input type="hidden" name="b" value="2"></form>'
        )
        assert len(parser.hidden_fields) == 2

    def test_ignores_non_hidden_inputs(self):
        parser = PageParser()
        parser.feed(
            '<form><input type="text" name="user"><input type="hidden" name="token" value="x"></form>'
        )
        assert len(parser.hidden_fields) == 1

    def test_hidden_csrf_still_tracked(self):
        parser = PageParser()
        parser.feed(
            '<form method="POST"><input type="hidden" name="csrf_token" value="abc"></form>'
        )
        assert parser.forms_missing_csrf == 0
        assert len(parser.hidden_fields) == 1


class TestCheckTLSVersions:
    @pytest.mark.asyncio
    async def test_http_url_returns_empty(self):
        result = await check_tls_versions("http://example.com", 5.0)
        assert result == []

    @pytest.mark.asyncio
    async def test_https_returns_list(self):
        mock_result = [
            TLSVersionResult(protocol="TLS 1.2", supported=True),
            TLSVersionResult(protocol="TLS 1.3", supported=True),
        ]
        with patch(
            "mytools.web.attackaudit._check_tls_versions_sync", return_value=mock_result
        ):
            result = await check_tls_versions("https://example.com", 2.0)
            assert isinstance(result, list)
            assert len(result) == 2
            for item in result:
                assert isinstance(item, TLSVersionResult)


class TestCheckXSSReflection:
    @respx.mock
    @pytest.mark.asyncio
    async def test_marker_reflected(self, async_client):
        def handler(request):
            url = str(request.url)
            from urllib.parse import parse_qs, urlparse

            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            marker = params.get("q", [""])[0]
            return httpx.Response(
                200, text=f"<html><body>Search results for: {marker}</body></html>"
            )

        respx.route(url__regex=r"https://example\.com/search.*").mock(
            side_effect=handler
        )
        client = async_client
        reflected, evidence = await check_xss_reflection(
            client, "https://example.com/search", 5.0
        )
        assert reflected is True
        assert "refletido" in evidence

    @respx.mock
    @pytest.mark.asyncio
    async def test_marker_not_reflected(self, async_client):
        respx.route(url__regex=r"https://example\.com.*").mock(
            return_value=httpx.Response(
                200, text="<html><body>Hello World</body></html>"
            )
        )
        client = async_client
        reflected, _evidence = await check_xss_reflection(
            client, "https://example.com/search", 5.0
        )
        assert reflected is False


class TestCheckSQLiErrors:
    @respx.mock
    @pytest.mark.asyncio
    async def test_mysql_error_detected(self, async_client):
        respx.route(url__regex=r"https://example\.com.*").mock(
            return_value=httpx.Response(
                200, text="You have an error in your SQL syntax near ''"
            )
        )
        client = async_client
        result = await check_sqli_errors(client, "https://example.com/page?id=1", 5.0)
        assert "mysql" in result

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_error_detected(self, async_client):
        respx.route(url__regex=r"https://example\.com.*").mock(
            return_value=httpx.Response(200, text="<html>Normal page</html>")
        )
        client = async_client
        result = await check_sqli_errors(client, "https://example.com/page?id=1", 5.0)
        assert result == []


class TestBuildParser:
    def test_returns_argparse(self):
        parser = build_parser()
        assert isinstance(parser, argparse.ArgumentParser)

    def test_has_url_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.url == "https://example.com"

    def test_has_deep_flag(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--deep"])
        assert args.deep is True

    def test_has_test_vulns_flag(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--test-vulns"])
        assert args.test_vulns is True

    def test_default_test_vulns_false(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.test_vulns is False

    def test_default_concurrency(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.concurrency == 20

    def test_has_proxy_argument(self):
        parser = build_parser()
        args = parser.parse_args(
            ["https://example.com", "--proxy", "http://proxy:8080"]
        )
        assert args.proxy == "http://proxy:8080"

    def test_has_delay_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--delay", "5"])
        assert args.delay == 5.0

    def test_has_verbose_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-v"])
        assert args.verbose is True

    def test_default_verbose_false(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.verbose is False

    def test_has_log_file_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--log-file", "audit.log"])
        assert args.log_file == "audit.log"


class TestSecurityHeadersConstant:
    def test_has_all_expected(self):
        expected = {
            "strict-transport-security",
            "content-security-policy",
            "x-frame-options",
            "x-content-type-options",
            "referrer-policy",
            "permissions-policy",
        }
        assert set(SECURITY_HEADERS_RECS.keys()) == expected

    def test_values_are_strings(self):
        for rec in SECURITY_HEADERS_RECS.values():
            assert isinstance(rec, str)
            assert len(rec) > 0


class TestRiskWeightsConstant:
    def test_has_all_severities(self):
        for sev in ("critical", "high", "medium", "low", "info"):
            assert sev in RISK_WEIGHTS

    def test_ordering(self):
        assert (
            RISK_WEIGHTS["critical"]
            > RISK_WEIGHTS["high"]
            > RISK_WEIGHTS["medium"]
            > RISK_WEIGHTS["low"]
            > RISK_WEIGHTS["info"]
        )


class TestBuildParserV3:
    def test_has_list_argument(self):
        parser = build_parser()
        args = parser.parse_args(["-l", "targets.txt"])
        assert args.target_list == "targets.txt"

    def test_has_output_dir_argument(self):
        parser = build_parser()
        args = parser.parse_args(["--output-dir", "results/"])
        assert args.output_dir == "results/"

    def test_has_quiet_flag(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "-q"])
        assert args.quiet is True

    def test_default_quiet_false(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.quiet is False

    def test_has_auth_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--auth", "admin:secret"])
        assert args.auth is not None
        assert "Authorization" in args.auth

    def test_has_bearer_token_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--bearer-token", "tok123"])
        assert args.bearer_token == "tok123"

    def test_has_cookie_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--cookie", "session=abc"])
        assert args.cookie == "session=abc"

    def test_has_header_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--header", "X-Token: abc"])
        assert args.header == ["X-Token: abc"]

    def test_has_test_methods_flag(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--test-methods"])
        assert args.test_methods is True

    def test_default_test_methods_false(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.test_methods is False


class TestMethodResultDataclass:
    def test_creation(self):
        r = MethodResult(
            url="https://example.com/api", method="PUT", status=200, size=150
        )
        assert r.method == "PUT"
        assert r.status == 200

    def test_frozen(self):
        r = MethodResult(
            url="https://example.com/api", method="DELETE", status=204, size=0
        )
        with pytest.raises(AttributeError):
            r.status = 404  # type: ignore[reportAttributeAccessIssue]


class TestMethodsToTest:
    def test_contains_dangerous_methods(self):
        assert "PUT" in METHODS_TO_TEST
        assert "DELETE" in METHODS_TO_TEST
        assert "TRACE" in METHODS_TO_TEST

    def test_contains_standard_methods(self):
        assert "OPTIONS" in METHODS_TO_TEST
        assert "HEAD" in METHODS_TO_TEST
        assert "PATCH" in METHODS_TO_TEST

    def test_all_strings(self):
        assert all(isinstance(m, str) for m in METHODS_TO_TEST)


class TestBuildFindingsMethodResults:
    def test_put_200_high_finding(self):
        parser = PageParser()
        mr = [MethodResult("https://example.com/upload", "PUT", 200, 500)]
        findings = build_findings(
            "https://example.com",
            200,
            {},
            parser,
            [],
            [],
            "example.com",
            method_results=mr,
        )
        method_findings = [
            f for f in findings if f.category == "methods" and "PUT" in f.item
        ]
        assert len(method_findings) == 1
        assert method_findings[0].severity == "high"

    def test_delete_200_high_finding(self):
        parser = PageParser()
        mr = [MethodResult("https://example.com/api", "DELETE", 200, 0)]
        findings = build_findings(
            "https://example.com",
            200,
            {},
            parser,
            [],
            [],
            "example.com",
            method_results=mr,
        )
        method_findings = [
            f for f in findings if f.category == "methods" and "DELETE" in f.item
        ]
        assert len(method_findings) == 1
        assert method_findings[0].severity == "high"

    def test_trace_200_high_finding(self):
        parser = PageParser()
        mr = [MethodResult("https://example.com/", "TRACE", 200, 100)]
        findings = build_findings(
            "https://example.com",
            200,
            {},
            parser,
            [],
            [],
            "example.com",
            method_results=mr,
        )
        method_findings = [
            f for f in findings if f.category == "methods" and "TRACE" in f.item
        ]
        assert len(method_findings) == 1

    def test_patch_200_medium_finding(self):
        parser = PageParser()
        mr = [MethodResult("https://example.com/api", "PATCH", 200, 200)]
        findings = build_findings(
            "https://example.com",
            200,
            {},
            parser,
            [],
            [],
            "example.com",
            method_results=mr,
        )
        method_findings = [
            f for f in findings if f.category == "methods" and "PATCH" in f.item
        ]
        assert len(method_findings) == 1
        assert method_findings[0].severity == "medium"

    def test_no_method_results_no_findings(self):
        parser = PageParser()
        findings = build_findings(
            "https://example.com", 200, {}, parser, [], [], "example.com"
        )
        method_findings = [
            f for f in findings if f.category == "methods" and "aceito" in f.item
        ]
        assert len(method_findings) == 0

    def test_method_403_no_finding(self):
        parser = PageParser()
        mr = [MethodResult("https://example.com/admin", "PUT", 403, 0)]
        findings = build_findings(
            "https://example.com",
            200,
            {},
            parser,
            [],
            [],
            "example.com",
            method_results=mr,
        )
        method_findings = [
            f for f in findings if f.category == "methods" and "PUT" in f.item
        ]
        assert len(method_findings) == 0

    def test_multiple_method_results(self):
        parser = PageParser()
        mr = [
            MethodResult("https://example.com/api", "PUT", 200, 500),
            MethodResult("https://example.com/api", "DELETE", 200, 0),
            MethodResult("https://example.com/api", "TRACE", 200, 100),
        ]
        findings = build_findings(
            "https://example.com",
            200,
            {},
            parser,
            [],
            [],
            "example.com",
            method_results=mr,
        )
        method_findings = [f for f in findings if f.category == "methods"]
        assert len(method_findings) == 3


class TestAuditResultMethodResults:
    def test_default_none(self):
        r = AuditResult(
            target="https://example.com",
            final_url="https://example.com",
            status=200,
            title="",
            ip="",
            tls_subject="",
            tls_issuer="",
            tls_not_after="",
            allowed_methods=[],
            forms=0,
            password_inputs=0,
            probes=[],
            findings=[],
            risk_score=0,
            elapsed=1.0,
        )
        assert r.method_results == []

    def test_with_method_results(self):
        mr = [MethodResult("https://example.com/api", "PUT", 200, 500)]
        r = AuditResult(
            target="https://example.com",
            final_url="https://example.com",
            status=200,
            title="",
            ip="",
            tls_subject="",
            tls_issuer="",
            tls_not_after="",
            allowed_methods=[],
            forms=0,
            password_inputs=0,
            probes=[],
            findings=[],
            risk_score=0,
            elapsed=1.0,
            method_results=mr,
        )
        assert r.method_results is not None
        assert len(r.method_results) == 1


class TestCheckXSSReflectionEdgeCases:
    @respx.mock
    @pytest.mark.asyncio
    async def test_connection_refused_returns_false(self, async_client):
        respx.route(url__regex=r"https://example\.com.*").mock(
            side_effect=httpx.ConnectError("refused")
        )
        reflected, evidence = await check_xss_reflection(
            async_client, "https://example.com/search", 1.0
        )
        assert reflected is False
        assert evidence == ""

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout_returns_false(self, async_client):
        respx.route(url__regex=r"https://example\.com.*").mock(
            side_effect=httpx.TimeoutException("timeout")
        )
        reflected, _evidence = await check_xss_reflection(
            async_client, "https://example.com/search", 0.1
        )
        assert reflected is False

    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_body_not_reflected(self, async_client):
        respx.route(url__regex=r"https://example\.com.*").mock(
            return_value=httpx.Response(200, text="")
        )
        reflected, _evidence = await check_xss_reflection(
            async_client, "https://example.com/search", 5.0
        )
        assert reflected is False


class TestCheckSQLiErrorsEdgeCases:
    @respx.mock
    @pytest.mark.asyncio
    async def test_connection_refused_returns_empty(self, async_client):
        respx.route(url__regex=r"https://example\.com.*").mock(
            side_effect=httpx.ConnectError("refused")
        )
        result = await check_sqli_errors(
            async_client, "https://example.com/page?id=1", 1.0
        )
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_timeout_returns_empty(self, async_client):
        respx.route(url__regex=r"https://example\.com.*").mock(
            side_effect=httpx.TimeoutException("timeout")
        )
        result = await check_sqli_errors(
            async_client, "https://example.com/page?id=1", 0.1
        )
        assert result == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_postgresql_error_detected(self, async_client):
        respx.route(url__regex=r"https://example\.com.*").mock(
            return_value=httpx.Response(200, text='ERROR: syntax error at or near "1"')
        )
        result = await check_sqli_errors(
            async_client, "https://example.com/page?id=1", 5.0
        )
        assert any("postgresql" in r for r in result) or len(result) > 0


class TestExtractQueryParams:
    def test_empty_url(self):
        assert _extract_query_params("https://example.com") == []

    def test_single_param(self):
        result = _extract_query_params("https://example.com?page=1")
        assert "page" in result

    def test_multiple_params(self):
        result = _extract_query_params("https://example.com?q=hello&id=42")
        assert "q" in result
        assert "id" in result

    def test_empty_param_value(self):
        result = _extract_query_params("https://example.com?q=")
        assert "q" in result

    def test_complex_query(self):
        result = _extract_query_params(
            "https://example.com?search=test&page=2&sort=name"
        )
        assert len(result) == 3


class TestDefaultInjectParams:
    def test_contains_common_params(self):
        assert "q" in DEFAULT_INJECT_PARAMS
        assert "id" in DEFAULT_INJECT_PARAMS
        assert "search" in DEFAULT_INJECT_PARAMS

    def test_is_tuple(self):
        assert isinstance(DEFAULT_INJECT_PARAMS, tuple)

    def test_not_empty(self):
        assert len(DEFAULT_INJECT_PARAMS) > 0


class TestCheckXSSWithCustomParams:
    @respx.mock
    @pytest.mark.asyncio
    async def test_custom_param_reflected(self, async_client):
        def handler(request):
            url = str(request.url)
            from urllib.parse import parse_qs, urlparse

            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            marker = params.get("search", [""])[0]
            return httpx.Response(
                200, text=f"<html><body>Results: {marker}</body></html>"
            )

        respx.route(url__regex=r"https://example\.com.*").mock(side_effect=handler)
        reflected, evidence = await check_xss_reflection(
            async_client, "https://example.com/search", 5.0, inject_params=["search"]
        )
        assert reflected is True
        assert "param=search" in evidence

    @respx.mock
    @pytest.mark.asyncio
    async def test_auto_detect_from_url(self, async_client):
        def handler(request):
            url = str(request.url)
            from urllib.parse import parse_qs, urlparse

            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            marker = params.get("user", [""])[0]
            return httpx.Response(200, text=f"<html>Hello {marker}</html>")

        respx.route(url__regex=r"https://example\.com.*").mock(side_effect=handler)
        reflected, evidence = await check_xss_reflection(
            async_client, "https://example.com/profile?user=1", 5.0
        )
        assert reflected is True
        assert "param=user" in evidence

    @respx.mock
    @pytest.mark.asyncio
    async def test_fallback_to_defaults(self, async_client):
        def handler(request):
            url = str(request.url)
            from urllib.parse import parse_qs, urlparse

            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            marker = params.get("q", [""])[0]
            return httpx.Response(200, text=f"<html>{marker}</html>")

        respx.route(url__regex=r"https://example\.com.*").mock(side_effect=handler)
        reflected, _evidence = await check_xss_reflection(
            async_client, "https://example.com", 5.0
        )
        assert reflected is True


class TestCheckSQLiWithCustomParams:
    @respx.mock
    @pytest.mark.asyncio
    async def test_custom_param_sqli(self, async_client):
        respx.route(url__regex=r"https://example\.com.*").mock(
            return_value=httpx.Response(
                200, text="You have an error in your SQL syntax"
            )
        )
        result = await check_sqli_errors(
            async_client,
            "https://example.com/page?search=test",
            5.0,
            inject_params=["search"],
        )
        assert "mysql" in result

    @respx.mock
    @pytest.mark.asyncio
    async def test_auto_detect_from_url(self, async_client):
        respx.route(url__regex=r"https://example\.com.*").mock(
            return_value=httpx.Response(
                200, text="You have an error in your SQL syntax"
            )
        )
        result = await check_sqli_errors(
            async_client, "https://example.com/page?item=1", 5.0
        )
        assert "mysql" in result

    @respx.mock
    @pytest.mark.asyncio
    async def test_no_params_fallback(self, async_client):
        respx.route(url__regex=r"https://example\.com.*").mock(
            return_value=httpx.Response(200, text="Normal page")
        )
        result = await check_sqli_errors(async_client, "https://example.com/page", 5.0)
        assert result == []


class TestBuildParserParams:
    def test_has_params_argument(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--params", "q,search,id"])
        assert args.params == "q,search,id"

    def test_default_params_none(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.params is None


class TestDryRun:
    def test_dry_run_flag_exists_in_parser(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--dry-run"])
        assert args.dry_run is True

    def test_dry_run_default_false(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        assert args.dry_run is False

    @pytest.mark.asyncio
    async def test_dry_run_returns_zero(self, capsys):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--dry-run"])
        result = await _async_run_once(args)
        assert result == 0

    @pytest.mark.asyncio
    async def test_dry_run_outputs_info(self, caplog):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--dry-run"])
        with caplog.at_level("WARNING", logger="mytools.attackaudit"):
            await _async_run_once(args)
        assert any("Nenhuma requisicao" in r.message for r in caplog.records)


class TestMain:
    @patch("mytools.core.utils.run_interactive_shell")
    def test_no_target_shells_interactive(self, mock_shell):
        mock_shell.return_value = 0
        from mytools.web.attackaudit import main

        args = argparse.Namespace(
            url=None,
            target_list=None,
            quiet=False,
            output=None,
            verbose=False,
            color=None,
            log_file=None,
            timeout=5.0,
            deep=False,
            test_vulns=False,
            test_methods=False,
            paths_file=None,
            params=None,
            retries=3,
            dry_run=False,
            verify=False,
            proxy=None,
            auth=None,
            bearer_token=None,
            cookie=None,
            header=[],
            delay=0.0,
            cve=False,
            nvd_api_key=None,
        )
        with patch(
            "mytools.web.attackaudit.argparse.ArgumentParser.parse_args",
            return_value=args,
        ):
            result = main()
            assert result == 0
            mock_shell.assert_called_once()

    def test_quiet_without_output_returns_1(self):
        from mytools.web.attackaudit import main

        args = argparse.Namespace(
            url="https://example.com",
            target_list=None,
            quiet=True,
            output=None,
            verbose=False,
            color=None,
            log_file=None,
            timeout=5.0,
            deep=False,
            test_vulns=False,
            test_methods=False,
            paths_file=None,
            params=None,
            retries=3,
            dry_run=False,
            verify=False,
            proxy=None,
            auth=None,
            bearer_token=None,
            cookie=None,
            header=[],
            delay=0.0,
            cve=False,
            nvd_api_key=None,
        )
        with patch(
            "mytools.web.attackaudit.argparse.ArgumentParser.parse_args",
            return_value=args,
        ):
            result = main()
            assert result == 1

    @patch("mytools.web.attackaudit.run_once")
    def test_valid_url_calls_run_once(self, mock_run_once):
        mock_run_once.return_value = 0
        from mytools.web.attackaudit import main

        args = argparse.Namespace(
            url="https://example.com",
            target_list=None,
            quiet=False,
            output=None,
            verbose=False,
            color=None,
            log_file=None,
            timeout=5.0,
            deep=False,
            test_vulns=False,
            test_methods=False,
            paths_file=None,
            params=None,
            retries=3,
            dry_run=False,
            verify=False,
            proxy=None,
            auth=None,
            bearer_token=None,
            cookie=None,
            header=[],
            delay=0.0,
            cve=False,
            nvd_api_key=None,
        )
        with patch(
            "mytools.web.attackaudit.argparse.ArgumentParser.parse_args",
            return_value=args,
        ):
            result = main()
            assert result == 0
            mock_run_once.assert_called_once()

    @patch("mytools.web.attackaudit.run_once")
    def test_exception_returns_1(self, mock_run_once):
        mock_run_once.side_effect = RuntimeError("fail")
        from mytools.web.attackaudit import main

        args = argparse.Namespace(
            url="https://example.com",
            target_list=None,
            quiet=False,
            output=None,
            verbose=False,
            color=None,
            log_file=None,
            timeout=5.0,
            deep=False,
            test_vulns=False,
            test_methods=False,
            paths_file=None,
            params=None,
            retries=3,
            dry_run=False,
            verify=False,
            proxy=None,
            auth=None,
            bearer_token=None,
            cookie=None,
            header=[],
            delay=0.0,
            cve=False,
            nvd_api_key=None,
        )
        with patch(
            "mytools.web.attackaudit.argparse.ArgumentParser.parse_args",
            return_value=args,
        ):
            result = main()
            assert result == 1


class TestJsSecretPatterns:
    def test_patterns_exist(self):
        assert len(_JS_SECRET_PATTERNS) == 8

    def test_all_are_compiled_regex(self):
        for secret_type, (severity, category, pattern) in _JS_SECRET_PATTERNS.items():
            assert isinstance(pattern, re.Pattern), f"{secret_type} is not compiled"
            assert severity in ("critical", "high", "medium", "low", "info")
            assert isinstance(category, str)

    def test_google_api_key(self):
        pattern = _JS_SECRET_PATTERNS["google_api_key"][2]
        assert pattern.search("AIzaSyD_example_key_35_chars_paddi00000")

    def test_github_token(self):
        pattern = _JS_SECRET_PATTERNS["github_token"][2]
        assert pattern.search("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijij")

    def test_stripe_key(self):
        pattern = _JS_SECRET_PATTERNS["stripe_key"][2]
        assert pattern.search("sk_live_" + "a" * 24)

    def test_jwt_token(self):
        pattern = _JS_SECRET_PATTERNS["jwt_token"][2]
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456ghi789jkl012mno345pqr"
        assert pattern.search(jwt)

    def test_hardcoded_secret(self):
        pattern = _JS_SECRET_PATTERNS["hardcoded_secret"][2]
        assert pattern.search('password = "supersecretpassword123"')
        assert pattern.search("apiKey: 'my_secret_key_value'")
        assert pattern.search('token: "abc123456789"')


class TestJsEndpointPatterns:
    def test_patterns_exist(self):
        assert len(_JS_ENDPOINT_PATTERNS) == 6

    def test_fetch_api(self):
        pattern = _JS_ENDPOINT_PATTERNS[0][1]
        match = pattern.search("fetch('/api/users')")
        assert match
        assert match.group(1) == "/api/users"

    def test_axios_api(self):
        pattern = _JS_ENDPOINT_PATTERNS[1][1]
        match = pattern.search('axios.get("/api/data")')
        assert match
        assert match.group(1) == "/api/data"

    def test_api_endpoint(self):
        pattern = _JS_ENDPOINT_PATTERNS[3][1]
        matches = pattern.findall('"/api/v2/users" "/graphql" "/v1/auth"')
        assert len(matches) >= 2

    def test_websocket_url(self):
        pattern = _JS_ENDPOINT_PATTERNS[4][1]
        match = pattern.search('new WebSocket("wss://example.com/ws")')
        assert match

    def test_internal_url(self):
        pattern = _JS_ENDPOINT_PATTERNS[5][1]
        match = pattern.search('"/admin/panel"')
        assert match


class TestAnalyzeJsContent:
    def test_finds_google_api_key(self):
        js = 'const key = "AIzaSyD_example_key_35_chars_padding000"'
        findings = analyze_js_content(js, "test.js")
        assert any("google_api_key" in f.item for f in findings)

    def test_finds_github_token(self):
        js = 'const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"'
        findings = analyze_js_content(js, "test.js")
        assert any("github_token" in f.item for f in findings)

    def test_finds_endpoint(self):
        js = 'fetch("/api/users")'
        findings = analyze_js_content(js, "test.js")
        assert any("endpoint" in f.item.lower() for f in findings)

    def test_clean_js_no_findings(self):
        js = 'console.log("hello world"); var x = 42;'
        findings = analyze_js_content(js, "test.js")
        assert len(findings) == 0

    def test_multiple_secrets(self):
        js = """
        const google = "AIzaSyD_example_key_35_chars_padding000";
        const token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij";
        """
        findings = analyze_js_content(js, "test.js")
        secret_items = [f for f in findings if f.category == "exposure"]
        assert len(secret_items) >= 2

    def test_snippet_truncation(self):
        long_value = "x" * 200
        js = f'const key = "AIzaSyD_example_key_35_chars_padding000{long_value}"'
        findings = analyze_js_content(js, "test.js")
        assert all(len(f.evidence) <= 250 for f in findings)

    def test_source_label_in_evidence(self):
        js = 'const key = "AIzaSyD_example_key_35_chars_padding000"'
        findings = analyze_js_content(js, "app.js")
        assert any("app.js" in f.evidence for f in findings)

    def test_inline_source_label(self):
        js = 'const key = "AIzaSyD_example_key_35_chars_padding000"'
        findings = analyze_js_content(js)
        assert any("inline" in f.evidence for f in findings)

    def test_endpoint_limit(self):
        js = " ".join(f'fetch("/api/{i}")' for i in range(20))
        findings = analyze_js_content(js, "test.js")
        endpoint_findings = [f for f in findings if f.category == "info_leak"]
        assert len(endpoint_findings) <= 5

    def test_severity_values(self):
        js = 'const key = "AIzaSyD_example_key_35_chars_padding000"'
        findings = analyze_js_content(js)
        for f in findings:
            assert f.severity in ("critical", "high", "medium", "low", "info")


class TestPageParserInlineScripts:
    def test_captures_inline_script(self):
        parser = PageParser()
        parser.feed("<html><script>var x = 1;</script></html>")
        assert len(parser.inline_scripts) == 1
        assert "var x = 1;" in parser.inline_scripts[0]

    def test_ignores_external_script(self):
        parser = PageParser()
        parser.feed('<script src="app.js"></script>')
        assert len(parser.inline_scripts) == 0
        assert len(parser.external_scripts) == 1

    def test_mixed_inline_and_external(self):
        parser = PageParser()
        parser.feed('<script src="lib.js"></script><script>var y = 2;</script>')
        assert len(parser.external_scripts) == 1
        assert len(parser.inline_scripts) == 1

    def test_empty_inline_script(self):
        parser = PageParser()
        parser.feed("<script></script>")
        assert len(parser.inline_scripts) == 0

    def test_script_content_truncated(self):
        long_js = "var x = " + "'a'" * 3000 + ";"
        parser = PageParser()
        parser.feed(f"<script>{long_js}</script>")
        assert len(parser.inline_scripts[0]) <= 2000


class TestUrlParamNames:
    def test_has_expected_keys(self):
        expected = {
            "api_key",
            "apikey",
            "key",
            "token",
            "access_token",
            "bearer",
            "auth_token",
            "secret",
            "password",
            "session_id",
        }
        assert set(_URL_PARAM_NAMES.keys()) == expected

    def test_values_are_tuples(self):
        for key, val in _URL_PARAM_NAMES.items():
            assert isinstance(val, tuple) and len(val) == 3, (
                f"{key} must be (severity, category, recommendation)"
            )
            severity, category, recommendation = val
            assert severity in {"critical", "high", "medium", "low", "info"}
            assert isinstance(category, str)
            assert isinstance(recommendation, str) and len(recommendation) > 10


class TestAnalyzeUrlParams:
    def test_api_key_in_param_name(self):
        findings = analyze_url_params("https://example.com/api?key=abc123")
        assert any(
            "api_key" in f.item.lower() or "key" in f.item.lower() for f in findings
        )

    def test_token_in_param_name(self):
        findings = analyze_url_params("https://example.com/?token=xyz789")
        assert any("token" in f.item.lower() for f in findings)

    def test_secret_in_param_name(self):
        findings = analyze_url_params("https://example.com/?secret=mysecretvalue123")
        assert any(f.severity == "critical" for f in findings)

    def test_password_in_param_name(self):
        findings = analyze_url_params("https://example.com/?password=hunter2")
        assert any(f.severity == "critical" for f in findings)

    def test_jwt_in_param_value(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        findings = analyze_url_params(f"https://example.com/?q={jwt}")
        assert any(
            "jwt" in f.item.lower() or "jwt" in f.evidence.lower() for f in findings
        )

    def test_aws_key_in_param_value(self):
        findings = analyze_url_params("https://example.com/?key=AKIAIOSFODNN7EXAMPLE")
        assert any(
            "aws" in f.evidence.lower() or "aws" in f.item.lower() for f in findings
        )

    def test_clean_url_no_findings(self):
        findings = analyze_url_params("https://example.com/page?q=search&page=2")
        assert findings == []

    def test_no_query_string(self):
        findings = analyze_url_params("https://example.com/page")
        assert findings == []

    def test_empty_query_string(self):
        findings = analyze_url_params("https://example.com/page?")
        assert findings == []

    def test_multiple_params_mixed(self):
        findings = analyze_url_params("https://example.com/?token=abc123&q=search&id=5")
        assert len(findings) >= 1

    def test_dedup_by_value_type(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        findings = analyze_url_params(f"https://example.com/?a={jwt}&b={jwt}")
        jwt_findings = [
            f
            for f in findings
            if "jwt" in f.evidence.lower() or "jwt" in f.item.lower()
        ]
        assert len(jwt_findings) <= 2

    def test_short_value_ignored(self):
        findings = analyze_url_params("https://example.com/?q=abc")
        assert findings == []

    def test_base64_token_in_value(self):
        long_b64 = "A" * 50 + "=="
        findings = analyze_url_params(f"https://example.com/?data={long_b64}")
        assert any(
            "base64" in f.evidence.lower() or "base64" in f.item.lower()
            for f in findings
        )


class TestExtractSessionId:
    def test_php_session(self):
        raw = {"set-cookie": ["PHPSESSID=abc123def456; Path=/"]}
        from mytools.web.attackaudit import _extract_session_id

        result = _extract_session_id(raw)
        assert "PHPSESSID=abc123def456" in result

    def test_jsessionid(self):
        raw = {"set-cookie": ["JSESSIONID=node0abc123; Path=/"]}
        from mytools.web.attackaudit import _extract_session_id

        result = _extract_session_id(raw)
        assert "JSESSIONID=node0abc123" in result

    def test_asp_session(self):
        raw = {"set-cookie": ["ASP.NET_SessionId=abc123; Path=/"]}
        from mytools.web.attackaudit import _extract_session_id

        result = _extract_session_id(raw)
        assert "ASP.NET_SessionId=abc123" in result

    def test_no_session_cookie(self):
        raw = {"set-cookie": ["theme=dark; Path=/"]}
        from mytools.web.attackaudit import _extract_session_id

        result = _extract_session_id(raw)
        assert result == ""

    def test_empty_headers(self):
        raw: dict[str, list[str]] = {}
        from mytools.web.attackaudit import _extract_session_id

        result = _extract_session_id(raw)
        assert result == ""


class TestCheckSessionFixation:
    @pytest.mark.asyncio
    async def test_vulnerable_fixation(self):
        from mytools.web.attackaudit import check_session_fixation

        async with httpx.AsyncClient() as client:
            with patch("mytools.web.attackaudit.fetch") as mock_fetch:
                mock_fetch.return_value = (
                    200,
                    {},
                    b"ok",
                    {"set-cookie": ["PHPSESSID=abc123; Path=/"]},
                )
                vuln, details = await check_session_fixation(
                    client,
                    "https://test.com",
                    "/login",
                    timeout=5.0,
                )
                assert vuln is True
                assert "fixo" in details.lower()

    @pytest.mark.asyncio
    async def test_no_session_id(self):
        from mytools.web.attackaudit import check_session_fixation

        async with httpx.AsyncClient() as client:
            with patch("mytools.web.attackaudit.fetch") as mock_fetch:
                mock_fetch.return_value = (
                    200,
                    {},
                    b"ok",
                    {"set-cookie": ["theme=dark"]},
                )
                vuln, details = await check_session_fixation(
                    client,
                    "https://test.com",
                    "/login",
                    timeout=5.0,
                )
                assert vuln is False
                assert "nenhum session" in details.lower()

    @pytest.mark.asyncio
    async def test_session_changed(self):
        from mytools.web.attackaudit import check_session_fixation

        async with httpx.AsyncClient() as client:
            with patch("mytools.web.attackaudit.fetch") as mock_fetch:
                call_count = 0

                def side_effect(*args, **kwargs):
                    nonlocal call_count
                    call_count += 1
                    if call_count == 1:
                        return (
                            200,
                            {},
                            b"ok",
                            {"set-cookie": ["PHPSESSID=abc123; Path=/"]},
                        )
                    return (
                        200,
                        {},
                        b"ok",
                        {"set-cookie": ["PHPSESSID=xyz789; Path=/"]},
                    )

                mock_fetch.side_effect = side_effect
                vuln, details = await check_session_fixation(
                    client,
                    "https://test.com",
                    "/login",
                    timeout=5.0,
                )
                assert vuln is False
                assert "alterou" in details.lower()


class _FakeCM:
    def __init__(self, obj):
        self._obj = obj

    async def __aenter__(self):
        return self._obj

    async def __aexit__(self, *exc):
        return False


class TestAnalyzeJsFiles:
    @respx.mock
    @pytest.mark.asyncio
    async def test_finds_secret_in_js_file(self, async_client):
        respx.get("https://example.com/app.js").mock(
            return_value=httpx.Response(
                200, text='var key = "AIzaSyD_example_key_35_chars_padding000";'
            )
        )
        findings = await analyze_js_files(
            async_client, "https://example.com", ["/app.js"], 5.0
        )
        assert any("google_api_key" in f.item for f in findings)

    @respx.mock
    @pytest.mark.asyncio
    async def test_non_200_skips_file(self, async_client):
        respx.get("https://example.com/missing.js").mock(
            return_value=httpx.Response(404)
        )
        findings = await analyze_js_files(
            async_client, "https://example.com", ["/missing.js"], 5.0
        )
        assert findings == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_fetch_error_is_ignored(self, async_client):
        respx.get("https://example.com/broken.js").mock(
            side_effect=httpx.ConnectError("refused")
        )
        findings = await analyze_js_files(
            async_client, "https://example.com", ["/broken.js"], 5.0
        )
        assert findings == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_only_first_five_scripts(self, async_client):
        for i in range(7):
            respx.get(f"https://example.com/s{i}.js").mock(
                return_value=httpx.Response(200, text="console.log(1);")
            )
        findings = await analyze_js_files(
            async_client,
            "https://example.com",
            [f"/s{i}.js" for i in range(7)],
            5.0,
        )
        assert respx.get("https://example.com/s0.js").called is True
        assert respx.get("https://example.com/s6.js").called is False
        assert findings == []


class TestLoadPathsFromFile:
    def test_empty_file_raises(self, tmp_path):
        p = tmp_path / "paths.txt"
        p.write_text("# apenas comentario\n\n", encoding="utf-8")
        with pytest.raises(ValueError):
            load_paths_from_file(str(p))

    def test_valid_paths(self, tmp_path):
        p = tmp_path / "paths.txt"
        p.write_text("/admin\n# comment\n/api\n/api\n", encoding="utf-8")
        assert load_paths_from_file(str(p)) == ["/admin", "/api"]


class TestResolveIP:
    @pytest.mark.asyncio
    async def test_success(self, monkeypatch):
        monkeypatch.setattr(
            "mytools.web.attackaudit.socket.gethostbyname", lambda _: "1.2.3.4"
        )
        assert await resolve_ip("example.com") == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_oserror_returns_empty(self, monkeypatch):
        def _boom(_hostname):
            raise OSError("no such host")

        monkeypatch.setattr("mytools.web.attackaudit.socket.gethostbyname", _boom)
        assert await resolve_ip("nonexistent.invalid") == ""

    def test_sync_oserror_returns_empty(self, monkeypatch):
        def _boom(_hostname):
            raise OSError("no such host")

        monkeypatch.setattr("mytools.web.attackaudit.socket.gethostbyname", _boom)
        assert _resolve_ip_sync("nonexistent.invalid") == ""


class TestTlsInfoSync:
    @staticmethod
    def _install_fakes(monkeypatch, *, cert=None, tls_error=None, sock_error=None):
        class FakeSock:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class FakeTLS:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def getpeercert(self):
                if tls_error is not None:
                    raise tls_error
                return cert

        class FakeCtx:
            def wrap_socket(self, sock, server_hostname=None):
                return FakeTLS()

        def _create_connection(*args, **kwargs):
            if sock_error is not None:
                raise sock_error
            return FakeSock()

        monkeypatch.setattr(
            "mytools.web.attackaudit.socket.create_connection", _create_connection
        )
        monkeypatch.setattr(
            "mytools.web.attackaudit.ssl.create_default_context", lambda: FakeCtx()
        )

    def test_success(self, monkeypatch):
        cert = {
            "subject": (
                (("commonName", "example.com"),),
                (("organizationName", "Example Org"),),
            ),
            "issuer": ((("commonName", "Example CA"),),),
            "notAfter": "Dec 31 00:00:00 2025 GMT",
        }
        self._install_fakes(monkeypatch, cert=cert)
        subject, issuer, not_after = _tls_info_sync("https://example.com", 5.0)
        assert "example.com" in subject
        assert "Example Org" in subject
        assert "Example CA" in issuer
        assert not_after == "Dec 31 00:00:00 2025 GMT"

    def test_flatten_name_variants(self, monkeypatch):
        cert = {
            "subject": [
                (("commonName", "example.com"),),
            ],
            "issuer": (
                "cert-authority",
                (("countryName", "US"), ("commonName", "Example CA")),
            ),
            "notAfter": "Dec 31 00:00:00 2025 GMT",
        }
        self._install_fakes(monkeypatch, cert=cert)
        subject, issuer, not_after = _tls_info_sync("https://example.com", 5.0)
        assert subject == ""
        assert issuer == "Example CA"
        assert not_after == "Dec 31 00:00:00 2025 GMT"

    def test_cert_none(self, monkeypatch):
        self._install_fakes(monkeypatch, cert=None)
        assert _tls_info_sync("https://example.com", 5.0) == ("", "", "")

    def test_oserror(self, monkeypatch):
        self._install_fakes(monkeypatch, sock_error=OSError("conn refused"))
        assert _tls_info_sync("https://example.com", 5.0) == ("", "", "")

    def test_ssl_error(self, monkeypatch):
        import ssl as ssl_mod

        self._install_fakes(monkeypatch, tls_error=ssl_mod.SSLError("bad cert"))
        assert _tls_info_sync("https://example.com", 5.0) == ("", "", "")

    def test_timeout_error(self, monkeypatch):
        self._install_fakes(monkeypatch, tls_error=TimeoutError("timed out"))
        assert _tls_info_sync("https://example.com", 5.0) == ("", "", "")

    def test_http_scheme_returns_empty(self, monkeypatch):
        self._install_fakes(monkeypatch)
        assert _tls_info_sync("http://example.com", 5.0) == ("", "", "")


class TestTlsInfo:
    @pytest.mark.asyncio
    async def test_returns_tls_info(self):
        with patch(
            "mytools.web.attackaudit._tls_info_sync",
            return_value=("example.com", "Issuer", "Dec 31"),
        ):
            assert await tls_info("https://example.com", 5.0) == (
                "example.com",
                "Issuer",
                "Dec 31",
            )


class TestCheckTlsVersionsSync:
    @staticmethod
    def _install_fakes(
        monkeypatch,
        *,
        fail_at: object | None = None,
        fail_type: type[BaseException] | None = None,
    ):
        import ssl as ssl_mod

        class FakeSock:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        class FakeTLS:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def version(self):
                return "TLSv1.3"

        class FakeCtx:
            check_hostname = True
            verify_mode = None
            minimum_version = None
            maximum_version = None

            def wrap_socket(self, sock, server_hostname=None):
                if fail_at is not None and self.minimum_version == fail_at:
                    assert fail_type is not None
                    raise fail_type("tls handshake failed")
                return FakeTLS()

        def _create_connection(*args, **kwargs):
            return FakeSock()

        monkeypatch.setattr(
            "mytools.web.attackaudit.socket.create_connection", _create_connection
        )
        monkeypatch.setattr(
            "mytools.web.attackaudit.ssl.SSLContext", lambda *_a, **_k: FakeCtx()
        )
        return ssl_mod

    def test_http_returns_empty(self, monkeypatch):
        self._install_fakes(monkeypatch)
        assert _check_tls_versions_sync("http://example.com", 5.0) == []

    def test_all_available_supported(self, monkeypatch):
        import ssl as ssl_mod

        class FakeTLSVersion:
            TLSv1_2 = object()
            TLSv1_3 = object()

        monkeypatch.setattr(ssl_mod, "TLSVersion", FakeTLSVersion)
        self._install_fakes(monkeypatch)
        results = _check_tls_versions_sync("https://example.com", 5.0)
        by_proto = {r.protocol: r for r in results}
        assert by_proto["TLS 1.2"].supported is True
        assert by_proto["TLS 1.3"].supported is True
        for name in ("SSLv3", "TLS 1.0", "TLS 1.1"):
            assert by_proto[name].supported is False
            assert by_proto[name].reason == "nao disponivel no Python"

    def test_ssl_error_marks_unsupported(self, monkeypatch):
        import ssl as ssl_mod

        self._install_fakes(
            monkeypatch, fail_at=ssl_mod.TLSVersion.TLSv1_2, fail_type=ssl_mod.SSLError
        )
        results = _check_tls_versions_sync("https://example.com", 5.0)
        tls12 = next(r for r in results if r.protocol == "TLS 1.2")
        assert tls12.supported is False
        assert "tls handshake failed" in tls12.reason

    def test_timeout_error_marks_unsupported(self, monkeypatch):
        import ssl as ssl_mod

        self._install_fakes(
            monkeypatch, fail_at=ssl_mod.TLSVersion.TLSv1_3, fail_type=TimeoutError
        )
        results = _check_tls_versions_sync("https://example.com", 5.0)
        tls13 = next(r for r in results if r.protocol == "TLS 1.3")
        assert tls13.supported is False

    def test_oserror_marks_unsupported(self, monkeypatch):
        import ssl as ssl_mod

        self._install_fakes(
            monkeypatch, fail_at=ssl_mod.TLSVersion.TLSv1_2, fail_type=OSError
        )
        results = _check_tls_versions_sync("https://example.com", 5.0)
        tls12 = next(r for r in results if r.protocol == "TLS 1.2")
        assert tls12.supported is False


class TestParseAllowedMethods:
    @respx.mock
    @pytest.mark.asyncio
    async def test_allow_header(self, async_client):
        respx.route(method="OPTIONS", url="https://example.com").mock(
            return_value=httpx.Response(200, headers={"Allow": "GET, post, DELETE"})
        )
        methods = await parse_allowed_methods(async_client, "https://example.com", 5.0)
        assert methods == ["DELETE", "GET", "POST"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_access_control_allow_methods(self, async_client):
        respx.route(method="OPTIONS", url="https://example.com").mock(
            return_value=httpx.Response(
                200, headers={"Access-Control-Allow-Methods": "GET, OPTIONS"}
            )
        )
        methods = await parse_allowed_methods(async_client, "https://example.com", 5.0)
        assert methods == ["GET", "OPTIONS"]

    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_header(self, async_client):
        respx.route(method="OPTIONS", url="https://example.com").mock(
            return_value=httpx.Response(200)
        )
        methods = await parse_allowed_methods(async_client, "https://example.com", 5.0)
        assert methods == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_fetch_error_returns_empty(self, async_client):
        respx.route(method="OPTIONS", url="https://example.com").mock(
            side_effect=httpx.ConnectError("refused")
        )
        methods = await parse_allowed_methods(async_client, "https://example.com", 5.0)
        assert methods == []


class TestProbePath:
    @respx.mock
    @pytest.mark.asyncio
    async def test_200_returns_probe(self, async_client):
        respx.get("https://example.com/.env").mock(
            return_value=httpx.Response(
                200, content=b"SECRET", headers={"location": "/redirect"}
            )
        )
        probe = await probe_path(
            async_client, RateLimiter(0), "https://example.com", ".env", 5.0
        )
        assert probe is not None
        assert probe.status == 200
        assert probe.size == 6
        assert probe.location == "/redirect"

    @respx.mock
    @pytest.mark.asyncio
    async def test_404_returns_none(self, async_client):
        respx.get("https://example.com/nope").mock(return_value=httpx.Response(404))
        probe = await probe_path(
            async_client, RateLimiter(0), "https://example.com", "nope", 5.0
        )
        assert probe is None

    @respx.mock
    @pytest.mark.asyncio
    async def test_fetch_error_returns_none(self, async_client):
        respx.get("https://example.com/err").mock(
            side_effect=httpx.ConnectError("refused")
        )
        probe = await probe_path(
            async_client, RateLimiter(0), "https://example.com", "err", 5.0
        )
        assert probe is None


class TestScanPaths:
    @respx.mock
    @pytest.mark.asyncio
    async def test_returns_sorted_probes(self, async_client):
        respx.get(url__regex=r"https://example\.com/.+").mock(
            return_value=httpx.Response(200, content=b"ok")
        )
        probes = await scan_paths(
            async_client, RateLimiter(0), "https://example.com", 5.0, 5, ["/b", "/a"]
        )
        assert [p.url for p in probes] == [
            "https://example.com/a",
            "https://example.com/b",
        ]

    @respx.mock
    @pytest.mark.asyncio
    async def test_spa_detection_filters_probes(self, async_client):
        def handler(request):
            if request.url.path == "/unique":
                return httpx.Response(200, content=b"different content here")
            return httpx.Response(200, content=b"shell")

        respx.get(url__regex=r"https://example\.com/.+").mock(side_effect=handler)
        probes = await scan_paths(
            async_client,
            RateLimiter(0),
            "https://example.com",
            5.0,
            5,
            ["/a", "/b", "/c", "/d", "/e", "/unique"],
        )
        urls = [p.url for p in probes]
        assert "https://example.com/unique" in urls
        assert "https://example.com/a" not in urls

    @respx.mock
    @pytest.mark.asyncio
    async def test_spa_detection_removes_all_probes(self, async_client):
        respx.get(url__regex=r"https://example\.com/.+").mock(
            return_value=httpx.Response(200, content=b"shell")
        )
        probes = await scan_paths(
            async_client,
            RateLimiter(0),
            "https://example.com",
            5.0,
            5,
            ["/a", "/b", "/c", "/d", "/e", "/f"],
        )
        assert probes == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_fetch_error_probe_dropped(self, async_client):
        def handler(request):
            if request.url.path == "/broken":
                raise httpx.ConnectError("refused")
            return httpx.Response(200, content=b"ok")

        respx.get(url__regex=r"https://example\.com/.+").mock(side_effect=handler)
        probes = await scan_paths(
            async_client,
            RateLimiter(0),
            "https://example.com",
            5.0,
            2,
            ["/ok", "/broken"],
        )
        assert [p.url for p in probes] == ["https://example.com/ok"]


class TestHttpMethods:
    @respx.mock
    @pytest.mark.asyncio
    async def test_dangerous_methods_detected(self, async_client):
        def handler(request):
            return httpx.Response(200, content=b"allowed")

        respx.route(method="PUT", url="https://example.com/x").mock(side_effect=handler)
        respx.route(method="DELETE", url="https://example.com/x").mock(
            return_value=httpx.Response(404)
        )
        respx.route(method="PATCH", url="https://example.com/x").mock(
            side_effect=handler
        )
        respx.route(method="TRACE", url="https://example.com/x").mock(
            side_effect=handler
        )
        probes = [
            Probe(url="https://example.com/x", status=200, size=3, location=""),
        ]
        results = await module_test_http_methods(
            async_client,
            probes,
            5.0,
            RateLimiter(0),
            methods=["PUT", "DELETE", "PATCH", "TRACE"],
        )
        methods = {(r.method, r.status) for r in results}
        assert ("PUT", 200) in methods
        assert ("PATCH", 200) in methods
        assert ("TRACE", 200) in methods
        assert ("DELETE", 404) not in methods

    @respx.mock
    @pytest.mark.asyncio
    async def test_skips_non_interesting_probe_status(self, async_client):
        probes = [Probe(url="https://example.com/x", status=302, size=3, location="")]
        results = await module_test_http_methods(
            async_client, probes, 5.0, RateLimiter(0)
        )
        assert results == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_deduplicates_pairs(self, async_client):
        respx.route(method="PUT", url="https://example.com/x").mock(
            return_value=httpx.Response(200, content=b"ok")
        )
        probes = [
            Probe(url="https://example.com/x", status=200, size=3, location=""),
            Probe(url="https://example.com/x", status=200, size=3, location=""),
        ]
        results = await module_test_http_methods(
            async_client, probes, 5.0, RateLimiter(0), methods=["PUT"]
        )
        assert len(results) == 1

    @respx.mock
    @pytest.mark.asyncio
    async def test_fetch_error_returns_none(self, async_client):
        respx.route(method="PUT", url="https://example.com/x").mock(
            side_effect=httpx.ConnectError("refused")
        )
        probes = [Probe(url="https://example.com/x", status=200, size=3, location="")]
        results = await module_test_http_methods(
            async_client, probes, 5.0, RateLimiter(0), methods=["PUT"]
        )
        assert results == []

    @respx.mock
    @pytest.mark.asyncio
    async def test_non_success_status_kept(self, async_client):
        respx.route(method="PUT", url="https://example.com/x").mock(
            return_value=httpx.Response(500, content=b"err")
        )
        probes = [Probe(url="https://example.com/x", status=200, size=3, location="")]
        results = await module_test_http_methods(
            async_client, probes, 5.0, RateLimiter(0), methods=["PUT"]
        )
        assert [r.status for r in results] == [500]


class TestExtractSessionIdExtra:
    def test_session_word_match(self):
        raw = {"set-cookie": ["global_session=abc123; Path=/"]}
        assert _extract_session_id(raw) == "global_session=abc123"

    def test_sid_word_match(self):
        raw = {"set-cookie": ["player_sid=xyz789; Path=/"]}
        assert _extract_session_id(raw) == "player_sid=xyz789"


class TestCheckSessionFixationExtra:
    @pytest.mark.asyncio
    async def test_no_session_after_login(self):
        client = AsyncMock()
        client.post = AsyncMock()
        call_count = 0

        def side_effect(*args, **kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return (200, {}, b"ok", {"set-cookie": ["PHPSESSID=abc123; Path=/"]})
            return (200, {}, b"ok", {"set-cookie": ["theme=dark"]})

        with patch("mytools.web.attackaudit.fetch", side_effect=side_effect):
            vuln, details = await check_session_fixation(
                client, "https://test.com", "/login", timeout=5.0
            )
        assert vuln is False
        assert "pos-login" in details.lower()

    @pytest.mark.asyncio
    async def test_fetch_error_returns_false(self):
        from mytools.core.utils import FetchError

        client = AsyncMock()
        client.post = AsyncMock()

        def _boom(*args, **kwargs):
            raise FetchError(
                url="https://test.com", attempts=3, last_error=ValueError("x")
            )

        with patch("mytools.web.attackaudit.fetch", side_effect=_boom):
            vuln, details = await check_session_fixation(
                client, "https://test.com", "/login", timeout=5.0
            )
        assert vuln is False
        assert "erro ao acessar" in details.lower()


class TestBuildFindingsExtra:
    def test_password_input_https_info(self):
        parser = PageParser()
        parser.feed("<input type='password'>")
        findings = build_findings(
            "https://example.com", 200, {}, parser, [], [], "example.com"
        )
        auth = [f for f in findings if f.category == "auth"]
        assert any("Formulario de login" in f.item for f in auth)
        assert any(f.severity == "info" for f in auth)

    def test_dump_backup_phpinfo_actuator_probes(self):
        parser = PageParser()
        probes = [
            Probe(url="https://example.com/dump.sql", status=200, size=1, location=""),
            Probe(
                url="https://example.com/backup.zip", status=200, size=1, location=""
            ),
            Probe(
                url="https://example.com/phpinfo.php", status=200, size=1, location=""
            ),
            Probe(
                url="https://example.com/actuator/env", status=200, size=1, location=""
            ),
        ]
        findings = build_findings(
            "https://example.com", 200, {}, parser, [], probes, "example.com"
        )
        exploits = " ".join(f.exploit for f in findings)
        assert "vazamento de banco de dados" in exploits
        assert "vazamento de banco de dados" in exploits
        assert "modulos, configs" in exploits
        assert "actuator" in exploits.lower()

    def test_config_probe_no_specific_hint(self):
        parser = PageParser()
        probes = [
            Probe(
                url="https://example.com/config.yaml", status=200, size=1, location=""
            )
        ]
        findings = build_findings(
            "https://example.com", 200, {}, parser, [], probes, "example.com"
        )
        exposure = [f for f in findings if f.category == "exposure"]
        assert len(exposure) == 1
        assert exposure[0].exploit == "curl -s https://example.com/config.yaml"

    def test_body_text_analyzed(self):
        parser = PageParser()
        findings = build_findings(
            "https://example.com",
            200,
            {},
            parser,
            [],
            [],
            "example.com",
            body_text="Traceback (most recent call last):\n  File app.py line 10",
        )
        assert any("stack_trace" in f.item for f in findings)


def _enter_run_audit_patches(stack, overrides=None, side_effects=None):
    overrides = overrides or {}
    side_effects = side_effects or {}
    defaults = {
        "fetch": (200, {"content-type": "text/html"}, b"<html></html>", {}),
        "resolve_ip": "1.2.3.4",
        "tls_info": ("example.com", "Issuer", "Dec 31"),
        "check_tls_versions": [TLSVersionResult("TLS 1.3", supported=True)],
        "parse_allowed_methods": ["GET", "POST"],
        "check_xss_reflection": (False, ""),
        "check_sqli_errors": [],
        "test_http_methods": [],
        "analyze_js_files": [],
        "check_session_fixation": (False, "nao fixo"),
        "scan_paths": [],
    }
    stack.enter_context(
        patch(
            "mytools.web.attackaudit.create_async_client",
            return_value=_FakeCM(AsyncMock()),
        )
    )
    stack.enter_context(
        patch(
            "mytools.web.attackaudit.apply_session_auth_async", new_callable=AsyncMock
        )
    )
    for name, value in defaults.items():
        if name in side_effects:
            stack.enter_context(
                patch(
                    f"mytools.web.attackaudit.{name}",
                    new_callable=AsyncMock,
                    side_effect=side_effects[name],
                )
            )
        else:
            stack.enter_context(
                patch(
                    f"mytools.web.attackaudit.{name}",
                    new_callable=AsyncMock,
                    return_value=overrides.get(name, value),
                )
            )


class TestRunAudit:
    @pytest.mark.asyncio
    async def test_basic_https(self):
        from contextlib import ExitStack

        with ExitStack() as stack:
            _enter_run_audit_patches(
                stack,
                overrides={
                    "fetch": (
                        200,
                        {"content-type": "text/html"},
                        b"<html><body><input type='password'></body></html>",
                        {},
                    ),
                },
            )
            result = await run_audit(
                "https://example.com",
                5.0,
                "TestAgent/1.0",
                20,
                deep=False,
            )
        assert result.status == 200
        assert result.ip == "1.2.3.4"
        assert result.tls_subject == "example.com"
        assert result.password_inputs == 1
        assert result.allowed_methods == ["GET", "POST"]
        assert result.elapsed >= 0

    @pytest.mark.asyncio
    async def test_ip_not_resolved(self):
        from contextlib import ExitStack

        with ExitStack() as stack:
            _enter_run_audit_patches(stack, overrides={"resolve_ip": ""})
            result = await run_audit("https://example.com", 5.0, "UA", 20, deep=False)
        assert result.ip == ""

    @pytest.mark.asyncio
    async def test_http_no_tls_versions(self):
        from contextlib import ExitStack

        with ExitStack() as stack:
            _enter_run_audit_patches(stack)
            result = await run_audit("http://example.com", 5.0, "UA", 20, deep=False)
        assert result.tls_versions == []

    @pytest.mark.asyncio
    async def test_non_html_content(self):
        from contextlib import ExitStack

        with ExitStack() as stack:
            _enter_run_audit_patches(
                stack,
                overrides={
                    "fetch": (
                        200,
                        {"content-type": "application/json"},
                        b'{"a": 1}',
                        {},
                    )
                },
            )
            result = await run_audit("https://example.com", 5.0, "UA", 20, deep=False)
        assert result.title == ""
        assert result.forms == 0

    @pytest.mark.asyncio
    async def test_deep_and_methods(self):
        from contextlib import ExitStack

        with ExitStack() as stack:
            _enter_run_audit_patches(
                stack,
                overrides={
                    "scan_paths": [Probe("https://example.com/.env", 200, 50, "")],
                    "test_http_methods": [
                        MethodResult("https://example.com/.env", "PUT", 200, 50)
                    ],
                },
            )
            result = await run_audit(
                "https://example.com",
                5.0,
                "UA",
                20,
                deep=True,
                test_methods=True,
            )
        assert len(result.probes) == 1
        assert result.method_results[0].method == "PUT"

    @pytest.mark.asyncio
    async def test_methods_no_results_logs(self, caplog):
        from contextlib import ExitStack

        with ExitStack() as stack:
            _enter_run_audit_patches(
                stack,
                overrides={
                    "scan_paths": [Probe("https://example.com/.env", 200, 50, "")],
                    "test_http_methods": [],
                },
            )
            with caplog.at_level("INFO", logger="mytools.attackaudit"):
                result = await run_audit(
                    "https://example.com",
                    5.0,
                    "UA",
                    20,
                    deep=True,
                    test_methods=True,
                )
        assert result.method_results == []
        assert any("Nenhum metodo perigoso" in r.message for r in caplog.records)

    @pytest.mark.asyncio
    async def test_vulns_and_external_scripts(self):
        from contextlib import ExitStack

        with ExitStack() as stack:
            _enter_run_audit_patches(
                stack,
                overrides={
                    "fetch": (
                        200,
                        {"content-type": "text/html"},
                        b"<html><script src='/app.js'></script></html>",
                        {},
                    ),
                    "check_xss_reflection": (True, "refletido em html_body"),
                    "check_sqli_errors": ["mysql"],
                    "analyze_js_files": [
                        Finding(
                            "low", "info_leak", "Endpoint exposto em JS", "ev", "rec"
                        )
                    ],
                },
            )
            result = await run_audit(
                "https://example.com",
                5.0,
                "UA",
                20,
                deep=False,
                test_vulns=True,
            )
        assert result.xss_reflected is True
        assert result.sqli_errors == ["mysql"]
        assert any("Endpoint exposto em JS" in f.item for f in result.findings)

    @pytest.mark.asyncio
    async def test_safe_handlers_catch_exceptions(self):
        from contextlib import ExitStack

        with ExitStack() as stack:
            _enter_run_audit_patches(
                stack,
                overrides={
                    "fetch": (
                        200,
                        {"content-type": "text/html"},
                        b"<html><script src='/app.js'></script></html>",
                        {},
                    ),
                    "scan_paths": [Probe("https://example.com/.env", 200, 50, "")],
                },
                side_effects={
                    "check_xss_reflection": RuntimeError("boom"),
                    "check_sqli_errors": RuntimeError("boom"),
                    "test_http_methods": RuntimeError("boom"),
                    "analyze_js_files": RuntimeError("boom"),
                },
            )
            result = await run_audit(
                "https://example.com",
                5.0,
                "UA",
                20,
                deep=True,
                test_vulns=True,
                test_methods=True,
            )
        assert result.xss_reflected is False
        assert result.sqli_errors == []
        assert result.method_results == []

    @pytest.mark.asyncio
    async def test_session_fixation_vulnerable(self):
        from contextlib import ExitStack

        with ExitStack() as stack:
            _enter_run_audit_patches(
                stack,
                overrides={
                    "check_session_fixation": (True, "Session ID fixo apos login: abc")
                },
            )
            result = await run_audit(
                "https://example.com",
                5.0,
                "UA",
                20,
                deep=False,
                login_url="/login",
            )
        assert result.session_fixation is True

    @pytest.mark.asyncio
    async def test_session_fixation_secure(self, caplog):
        from contextlib import ExitStack

        with ExitStack() as stack:
            _enter_run_audit_patches(
                stack,
                overrides={
                    "check_session_fixation": (False, "Session ID alterou apos login")
                },
            )
            with caplog.at_level("INFO", logger="mytools.attackaudit"):
                result = await run_audit(
                    "https://example.com",
                    5.0,
                    "UA",
                    20,
                    deep=False,
                    login_url="/login",
                )
        assert result.session_fixation is False

    @pytest.mark.asyncio
    async def test_custom_paths_and_inject_params(self):
        from contextlib import ExitStack

        with ExitStack() as stack:
            _enter_run_audit_patches(
                stack,
                overrides={"scan_paths": [Probe("https://example.com/x", 200, 1, "")]},
            )
            result = await run_audit(
                "https://example.com",
                5.0,
                "UA",
                20,
                deep=True,
                paths=["/custom"],
                inject_params=["q"],
            )
        assert result.status == 200


def _make_audit_result(**overrides: object) -> AuditResult:
    defaults: dict[str, Any] = dict(
        target="https://example.com",
        final_url="https://example.com",
        status=200,
        title="My Site",
        ip="1.2.3.4",
        tls_subject="example.com",
        tls_issuer="Example CA",
        tls_not_after="Dec 31 2025",
        allowed_methods=["GET", "POST"],
        forms=2,
        password_inputs=1,
        probes=[],
        findings=[],
        risk_score=0,
        elapsed=1.0,
    )
    defaults.update(overrides)
    return AuditResult(**defaults)


class TestPrintResult:
    def test_empty_result(self, capsys):
        result = _make_audit_result(findings=[])
        print_result(result)
        captured = capsys.readouterr()
        assert "Nenhum finding relevante" in captured.out

    def test_full_result(self, capsys):
        result = _make_audit_result(
            tls_versions=[
                TLSVersionResult("TLS 1.1", supported=True),
                TLSVersionResult("TLS 1.3", supported=True),
            ],
            allowed_methods=["GET", "PUT"],
            xss_reflected=True,
            sqli_errors=["mysql"],
            csrf_missing=2,
            session_fixation=True,
            method_results=[
                MethodResult("https://example.com/up", "PUT", 200, 100),
                MethodResult("https://example.com/tr", "TRACE", 403, 0),
            ],
            findings=[
                Finding(
                    "critical",
                    "sqli",
                    "Possivel injecao SQL",
                    "banco",
                    "use prepared statements",
                    "curl -X PUT",
                ),
                Finding("info", "waf", "WAF detectado", "cloudflare", "considere", ""),
            ],
        )
        print_result(result)
        captured = capsys.readouterr()
        assert "example.com" in captured.out
        assert "TLS versions" in captured.out
        assert "PUT" in captured.out
        assert "SQLi erros" in captured.out
        assert "CSRF ausente" in captured.out
        assert "Session Fixation" in captured.out
        assert "Possivel injecao SQL" in captured.out

    def test_strong_only_tls_versions(self, capsys):
        result = _make_audit_result(
            tls_versions=[
                TLSVersionResult("TLS 1.2", supported=True),
                TLSVersionResult("TLS 1.3", supported=True),
            ]
        )
        print_result(result)
        captured = capsys.readouterr()
        assert "TLS versions" in captured.out
        assert "TLS 1.2" in captured.out
        assert "TLS 1.3" in captured.out

    def test_no_allowed_methods(self, capsys):
        result = _make_audit_result(allowed_methods=[])
        print_result(result)
        captured = capsys.readouterr()
        assert "Metodos:" not in captured.out

    def test_no_tls_subject(self, capsys):
        result = _make_audit_result(tls_subject="", title="")
        print_result(result)
        captured = capsys.readouterr()
        assert "Resumo" in captured.out


class TestSaveAuditOutput:
    def test_writes_output(self):
        result = _make_audit_result()
        with patch("mytools.web.attackaudit.write_output") as mock_write:
            _save_audit_output("out.json", result)
        mock_write.assert_called_once()
        assert mock_write.call_args.args[0] == "out.json"


class TestRunSingle:
    @pytest.mark.asyncio
    async def test_defaults(self):
        result = _make_audit_result()
        args = argparse.Namespace(
            url="https://example.com",
            paths_file=None,
            params=None,
            timeout=5.0,
            user_agent="UA",
            concurrency=20,
            deep=False,
            proxy=None,
            verify=False,
            delay=0.0,
            test_vulns=False,
            test_methods=False,
            auth=None,
            bearer_token=None,
            cookie=None,
            header=None,
            login_url=None,
        )
        with (
            patch(
                "mytools.web.attackaudit.run_audit",
                new_callable=AsyncMock,
                return_value=result,
            ) as mock_audit,
            patch("mytools.web.attackaudit.print_result") as mock_print,
        ):
            out = await _run_single("https://example.com", args, quiet=True)
        assert out is result
        mock_audit.assert_awaited_once()
        mock_print.assert_not_called()

    @pytest.mark.asyncio
    async def test_paths_file_and_params(self, tmp_path):
        result = _make_audit_result()
        p = tmp_path / "paths.txt"
        p.write_text("/a\n/b\n", encoding="utf-8")
        args = argparse.Namespace(
            url="https://example.com",
            paths_file=str(p),
            params="q,id",
            timeout=5.0,
            user_agent="UA",
            concurrency=20,
            deep=False,
            proxy=None,
            verify=False,
            delay=0.0,
            test_vulns=False,
            test_methods=False,
            auth=None,
            bearer_token=None,
            cookie=None,
            header=None,
            login_url=None,
        )
        with patch(
            "mytools.web.attackaudit.run_audit",
            new_callable=AsyncMock,
            return_value=result,
        ) as mock_audit:
            await _run_single("https://example.com", args, quiet=True)
        await_args = mock_audit.await_args
        assert await_args is not None
        kwargs = await_args.kwargs
        assert kwargs["paths"] == ["/a", "/b"]
        assert kwargs["inject_params"] == ["q", "id"]

    @pytest.mark.asyncio
    async def test_not_quiet_prints(self):
        result = _make_audit_result()
        args = argparse.Namespace(
            url="https://example.com",
            paths_file=None,
            params=None,
            timeout=5.0,
            user_agent="UA",
            concurrency=20,
            deep=False,
            proxy=None,
            verify=False,
            delay=0.0,
            test_vulns=False,
            test_methods=False,
            auth=None,
            bearer_token=None,
            cookie=None,
            header=None,
            login_url=None,
        )
        with (
            patch(
                "mytools.web.attackaudit.run_audit",
                new_callable=AsyncMock,
                return_value=result,
            ),
            patch("mytools.web.attackaudit.print_result") as mock_print,
        ):
            await _run_single("https://example.com", args, quiet=False)
        mock_print.assert_called_once()


class TestAsyncRunOnceExtra:
    @pytest.mark.asyncio
    async def test_paths_file_sets_deep(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "https://example.com",
                "--dry-run",
                "--paths-file",
                "x.txt",
                "--params",
                "q",
                "--test-vulns",
                "--test-methods",
                "--deep",
            ]
        )
        with patch("mytools.web.attackaudit.load_paths_from_file", return_value=["/a"]):
            result = await _async_run_once(args)
        assert result == 0
        assert args.deep is True

    @pytest.mark.asyncio
    async def test_zero_concurrency_raises(self):
        parser = build_parser()
        args = parser.parse_args(["https://example.com", "--concurrency", "0"])
        with pytest.raises(ValueError):
            await _async_run_once(args)

    @pytest.mark.asyncio
    async def test_dry_run_feature_flags(self, caplog):
        parser = build_parser()
        args = parser.parse_args(
            [
                "https://example.com",
                "--dry-run",
                "--deep",
                "--test-vulns",
                "--test-methods",
                "--params",
                "q,id",
            ]
        )
        with caplog.at_level("INFO", logger="mytools.attackaudit"):
            result = await _async_run_once(args)
        assert result == 0
        messages = " ".join(r.message for r in caplog.records)
        assert "path probing" in messages
        assert "XSS/SQLi tests" in messages
        assert "HTTP method tests" in messages
        assert "params=q,id" in messages

    @pytest.mark.asyncio
    async def test_full_run_with_outputs(self, tmp_path):
        result = _make_audit_result()
        parser = build_parser()
        out_dir = str(tmp_path / "out")
        args = parser.parse_args(
            [
                "https://example.com",
                "--output-dir",
                out_dir,
                "-o",
                str(tmp_path / "all.json"),
            ]
        )
        with (
            patch(
                "mytools.web.attackaudit.resolve_target_urls",
                return_value=["https://example.com"],
            ),
            patch(
                "mytools.web.attackaudit._run_single",
                new_callable=AsyncMock,
                side_effect=lambda u, args, quiet: result,
            ),
            patch("mytools.web.attackaudit._save_audit_output") as mock_save,
            patch("mytools.web.attackaudit.write_output") as mock_write,
        ):
            code = await _async_run_once(args)
        assert code == 0
        assert mock_save.called
        assert not mock_write.called

    @pytest.mark.asyncio
    async def test_full_run_multiple_results(self, tmp_path):
        result = _make_audit_result()
        parser = build_parser()
        args = parser.parse_args(
            ["https://example.com", "-o", str(tmp_path / "all.json")]
        )
        with (
            patch(
                "mytools.web.attackaudit.resolve_target_urls",
                return_value=["https://a.com", "https://b.com"],
            ),
            patch(
                "mytools.web.attackaudit._run_single",
                new_callable=AsyncMock,
                side_effect=lambda u, args, quiet: result,
            ),
            patch("mytools.web.attackaudit._save_audit_output"),
            patch("mytools.web.attackaudit.write_output") as mock_write,
        ):
            code = await _async_run_once(args)
        assert code == 0
        assert mock_write.called

    @pytest.mark.asyncio
    async def test_full_run_without_output(self):
        result = _make_audit_result()
        parser = build_parser()
        args = parser.parse_args(["https://example.com"])
        with (
            patch(
                "mytools.web.attackaudit.resolve_target_urls",
                return_value=["https://example.com"],
            ),
            patch(
                "mytools.web.attackaudit._run_single",
                new_callable=AsyncMock,
                side_effect=lambda u, args, quiet: result,
            ),
            patch("mytools.web.attackaudit._save_audit_output") as mock_save,
            patch("mytools.web.attackaudit.write_output") as mock_write,
        ):
            code = await _async_run_once(args)
        assert code == 0
        assert not mock_save.called
        assert not mock_write.called


class TestRunOnce:
    def test_returns_zero(self):
        args = argparse.Namespace()
        with patch("mytools.web.attackaudit._async_run_once", return_value=0):
            result = run_once(args)
        assert result == 0


class TestAttackAuditMainGuard:
    def test_main_guard(self):
        import runpy

        with (
            patch("mytools.core.utils.run_main_loop", side_effect=SystemExit(0)),
            patch("sys.argv", ["mytools-attackaudit"]),
            pytest.raises(SystemExit) as exc_info,
        ):
            runpy.run_module("mytools.web.attackaudit", run_name="__main__")
        assert exc_info.value.code == 0
