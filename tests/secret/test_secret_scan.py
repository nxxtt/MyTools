"""Tests para Secret Scanning module."""

from __future__ import annotations

from pathlib import Path

import pytest

from mytools.secret._common import SECRET_PATTERNS, SecretAttempt, SecretResult


class TestSecretPatterns:
    """Testa padroes de deteccao de segredos."""

    def test_patterns_not_empty(self):
        assert len(SECRET_PATTERNS) > 0

    def test_aws_access_key(self):
        m = SECRET_PATTERNS["aws_access_key"].search("AKIAIOSFODNN7EXAMPLE")
        assert m is not None

    def test_aws_access_key_no_match(self):
        m = SECRET_PATTERNS["aws_access_key"].search("AKIA12345")
        assert m is None

    def test_github_token(self):
        m = SECRET_PATTERNS["github_token"].search(
            "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij"
        )
        assert m is not None

    def test_github_token_no_match(self):
        m = SECRET_PATTERNS["github_token"].search("ghp_short")
        assert m is None

    def test_private_key_block(self):
        text = "-----BEGIN RSA PRIVATE KEY-----"
        m = SECRET_PATTERNS["private_key_block"].search(text)
        assert m is not None

    def test_slack_token(self):
        m = SECRET_PATTERNS["slack_token"].search(
            "xoxb-1234567890-1234567890123-abcdefghij"
        )
        assert m is not None

    def test_stripe_key(self):
        m = SECRET_PATTERNS["stripe_key"].search(
            "sk_live_" + "abcdefghijklmnopqrstuvwx"
        )
        assert m is not None

    def test_password_assign(self):
        text = 'password = "SuperSecret123"'
        m = SECRET_PATTERNS["password_assign"].search(text)
        assert m is not None
        assert "SuperSecret123" in m.group(1)

    def test_api_key_assign(self):
        text = 'API_KEY: "my-secret-api-key-value"'
        m = SECRET_PATTERNS["api_key_assign"].search(text)
        assert m is not None

    def test_connection_string(self):
        text = "postgres://user:pass@localhost:5432/db"
        m = SECRET_PATTERNS["connection_string"].search(text)
        assert m is not None

    def test_openai_key(self):
        m = SECRET_PATTERNS["openai_key"].search(
            "sk-abcdefghijklmnopqrstuvwxABCDEFGHIJKLMNOPQRSTUVWXYZ12"
        )
        assert m is not None

    def test_anthropic_key(self):
        m = SECRET_PATTERNS["anthropic_key"].search(
            "sk-ant-abcdefghijklmnopqrstuvwxABCDEFGHIJKLMNOP"
        )
        assert m is not None

    def test_huggingface_token(self):
        m = SECRET_PATTERNS["huggingface_token"].search(
            "hf_abcdefghijklmnopqrstuvwxABCDEFGHIJKLMN"
        )
        assert m is not None

    def test_jwt_token(self):
        text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123"
        m = SECRET_PATTERNS["jwt_token"].search(text)
        assert m is not None

    def test_bearer_token(self):
        text = "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abc123"
        m = SECRET_PATTERNS["bearer_token"].search(text)
        assert m is not None

    def test_gitlab_token(self):
        m = SECRET_PATTERNS["gitlab_token"].search("glpat-abcdefghijklmn123456")
        assert m is not None

    def test_npm_token(self):
        m = SECRET_PATTERNS["npm_token"].search(
            "npm_abcdefghijklmnopqrstuvwxABCDEFGHIJKLMNop"
        )
        assert m is not None

    def test_pypi_token(self):
        m = SECRET_PATTERNS["pypi_token"].search(
            "pypi-ABCDEFGHijklmnopqrstuvwxzy0123456789abcdefghijABCD"
        )
        assert m is not None


class TestSecretDataclasses:
    """Testa dataclasses do secret scanning."""

    def test_secret_attempt(self):
        att = SecretAttempt(
            file_path="src/config.py",
            line_number=42,
            pattern_name="aws_access_key",
            secret_type="aws_access_key",
            match_preview="AKIA...",
            severity="critical",
        )
        assert att.file_path == "src/config.py"
        assert att.line_number == 42
        assert att.severity == "critical"

    def test_secret_result(self):
        result = SecretResult(
            target="/path/to/project",
            total_files=100,
            scanned_files=50,
            skipped_files=50,
            attempts=[],
            issues=[],
            overall_status="clean",
        )
        assert result.target == "/path/to/project"
        assert result.scanned_files == 50
        assert result.overall_status == "clean"

    def test_secret_result_with_issues(self):
        att = SecretAttempt(
            file_path="config.py",
            line_number=1,
            pattern_name="aws_access_key",
            secret_type="aws_access_key",
            match_preview="AKIA...",
            severity="critical",
        )
        result = SecretResult(
            target=".",
            total_files=10,
            scanned_files=5,
            skipped_files=5,
            attempts=[att],
            issues=["1 critical secret(s)"],
            overall_status="found",
        )
        assert len(result.attempts) == 1
        assert result.overall_status == "found"


class TestScanFile:
    """Testa escaneamento de arquivos individuais."""

    @pytest.mark.asyncio
    async def test_scan_clean_file(self, tmp_path: Path):
        from mytools.secret.secret_scan import scan_file

        f = tmp_path / "clean.py"
        f.write_text("print('hello world')\nx = 42\n")
        attempts = await scan_file(f, SECRET_PATTERNS, tmp_path)
        assert len(attempts) == 0

    @pytest.mark.asyncio
    async def test_scan_file_with_aws_key(self, tmp_path: Path):
        from mytools.secret.secret_scan import scan_file

        f = tmp_path / "config.py"
        f.write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
        attempts = await scan_file(f, SECRET_PATTERNS, tmp_path)
        assert len(attempts) >= 1
        assert attempts[0].pattern_name == "aws_access_key"

    @pytest.mark.asyncio
    async def test_scan_file_with_password(self, tmp_path: Path):
        from mytools.secret.secret_scan import scan_file

        f = tmp_path / "settings.py"
        f.write_text('DB_PASSWORD = "hunter2pass"\n')
        attempts = await scan_file(f, SECRET_PATTERNS, tmp_path)
        assert len(attempts) >= 1

    @pytest.mark.asyncio
    async def test_scan_file_with_private_key(self, tmp_path: Path):
        from mytools.secret.secret_scan import scan_file

        f = tmp_path / "key.pem"
        f.write_text("-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n")
        attempts = await scan_file(f, SECRET_PATTERNS, tmp_path)
        assert len(attempts) >= 1
        assert attempts[0].pattern_name == "private_key_block"

    @pytest.mark.asyncio
    async def test_scan_file_with_github_token(self, tmp_path: Path):
        from mytools.secret.secret_scan import scan_file

        f = tmp_path / "env.sh"
        f.write_text("export GITHUB_TOKEN=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij\n")
        attempts = await scan_file(f, SECRET_PATTERNS, tmp_path)
        assert len(attempts) >= 1
        assert attempts[0].pattern_name == "github_token"


class TestRunSecretScan:
    """Testa escaneamento de diretorio completo."""

    @pytest.mark.asyncio
    async def test_scan_empty_directory(self, tmp_path: Path):
        from mytools.secret.secret_scan import run_secret_scan

        result = await run_secret_scan(str(tmp_path))
        assert result.overall_status == "clean"
        assert result.total_files == 0

    @pytest.mark.asyncio
    async def test_scan_directory_with_secrets(self, tmp_path: Path):
        from mytools.secret.secret_scan import run_secret_scan

        f1 = tmp_path / "config.py"
        f1.write_text("AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
        f2 = tmp_path / "settings.py"
        f2.write_text('password = "hunter2pass"\n')
        result = await run_secret_scan(str(tmp_path))
        assert result.overall_status == "found"
        assert len(result.attempts) >= 1

    @pytest.mark.asyncio
    async def test_scan_directory_clean(self, tmp_path: Path):
        from mytools.secret.secret_scan import run_secret_scan

        f = tmp_path / "main.py"
        f.write_text("def hello():\n    return 'world'\n")
        result = await run_secret_scan(str(tmp_path))
        assert result.overall_status == "clean"

    @pytest.mark.asyncio
    async def test_scan_nonexistent_target(self):
        from mytools.secret.secret_scan import run_secret_scan

        result = await run_secret_scan("/nonexistent/path/12345")
        assert result.overall_status == "error"

    @pytest.mark.asyncio
    async def test_scan_with_categories_filter(self, tmp_path: Path):
        from mytools.secret.secret_scan import run_secret_scan

        f = tmp_path / "config.py"
        f.write_text(
            "AWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\nGH_TOKEN = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij'\n"
        )
        result = await run_secret_scan(str(tmp_path), categories=["cloud"])
        assert result.overall_status == "found"
        assert all("aws" in a.pattern_name for a in result.attempts)

    @pytest.mark.asyncio
    async def test_scan_skips_non_text_files(self, tmp_path: Path):
        from mytools.secret.secret_scan import run_secret_scan

        f = tmp_path / "image.png"
        f.write_bytes(b"\x89PNG\r\n\x1a\n")
        result = await run_secret_scan(str(tmp_path))
        assert result.skipped_files >= 1

    @pytest.mark.asyncio
    async def test_scan_min_severity(self, tmp_path: Path):
        from mytools.secret.secret_scan import run_secret_scan

        f = tmp_path / "config.py"
        f.write_text('password = "hunter2pass"\n')
        result_critical = await run_secret_scan(str(tmp_path), min_severity="critical")
        result_low = await run_secret_scan(str(tmp_path), min_severity="low")
        assert len(result_critical.attempts) <= len(result_low.attempts)


class TestParser:
    """Testa o parser de argumentos."""

    def test_parser_default_args(self):
        from mytools.secret.secret_scan import build_parser

        p = build_parser()
        args = p.parse_args(["."])
        assert args.target == "."
        assert args.min_severity == "low"
        assert args.exclude_dirs == []
        assert args.max_file_size == 1_048_576

    def test_parser_with_categories(self):
        from mytools.secret.secret_scan import build_parser

        p = build_parser()
        args = p.parse_args([".", "-c", "cloud", "saas"])
        assert args.categories == ["cloud", "saas"]

    def test_parser_with_min_severity(self):
        from mytools.secret.secret_scan import build_parser

        p = build_parser()
        args = p.parse_args([".", "--min-severity", "high"])
        assert args.min_severity == "high"

    def test_parser_with_exclude_dirs(self):
        from mytools.secret.secret_scan import build_parser

        p = build_parser()
        args = p.parse_args([".", "--exclude-dirs", "tests", "docs"])
        assert args.exclude_dirs == ["tests", "docs"]
