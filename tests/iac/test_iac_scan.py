"""Tests para IaC Static Scan module."""

from __future__ import annotations

from pathlib import Path

import pytest

from mytools.iac._common import (
    CLOUDFORMATION_RULES,
    DOCKERFILE_RULES,
    K8S_RULES,
    TERRAFORM_RULES,
    IacAttempt,
    IacResult,
)
from mytools.iac.cloudformation_scan import scan_cloudformation_file
from mytools.iac.dockerfile_scan import scan_dockerfile
from mytools.iac.iac_scan import IacScanScanner, _classify_file, run_iac_scan
from mytools.iac.kubernetes_scan import scan_kubernetes_file
from mytools.iac.terraform_scan import scan_terraform_file

# --- _common.py tests ---


class TestIacAttempt:
    def test_frozen(self) -> None:
        att = IacAttempt(
            file_path="main.tf",
            line_number=1,
            check_name="test",
            file_type="terraform",
            vulnerable=True,
        )
        with pytest.raises(AttributeError):
            att.file_path = "other.tf"  # type: ignore[misc]

    def test_default_severity(self) -> None:
        att = IacAttempt(
            file_path="f.tf",
            line_number=1,
            check_name="x",
            file_type="terraform",
            vulnerable=True,
        )
        assert att.severity == "medium"

    def test_default_description(self) -> None:
        att = IacAttempt(
            file_path="f.tf",
            line_number=1,
            check_name="x",
            file_type="terraform",
            vulnerable=True,
        )
        assert att.description == ""


class TestIacResult:
    def test_frozen(self) -> None:
        r = IacResult(
            target=".",
            total_files=1,
            scanned_files=1,
            skipped_files=0,
        )
        with pytest.raises(AttributeError):
            r.target = "other"  # type: ignore[misc]

    def test_default_status(self) -> None:
        r = IacResult(
            target=".",
            total_files=0,
            scanned_files=0,
            skipped_files=0,
        )
        assert r.overall_status == "clean"

    def test_defaults(self) -> None:
        r = IacResult(
            target=".",
            total_files=0,
            scanned_files=0,
            skipped_files=0,
        )
        assert r.attempts == []
        assert r.issues == []


class TestRulePatterns:
    def test_terraform_rules_have_patterns(self) -> None:
        for name, rule in TERRAFORM_RULES.items():
            assert "pattern" in rule, f"{name} missing pattern"
            assert "severity" in rule, f"{name} missing severity"
            assert "description" in rule, f"{name} missing description"

    def test_k8s_rules_have_patterns(self) -> None:
        for name, rule in K8S_RULES.items():
            assert "pattern" in rule, f"{name} missing pattern"
            assert "severity" in rule, f"{name} missing severity"

    def test_dockerfile_rules_have_patterns(self) -> None:
        for name, rule in DOCKERFILE_RULES.items():
            assert "pattern" in rule, f"{name} missing pattern"
            assert "severity" in rule, f"{name} missing severity"

    def test_cloudformation_rules_have_patterns(self) -> None:
        for name, rule in CLOUDFORMATION_RULES.items():
            assert "pattern" in rule, f"{name} missing pattern"
            assert "severity" in rule, f"{name} missing severity"


# --- Terraform scanner tests ---


class TestTerraformScan:
    def test_public_cidr(self, tmp_path: Path) -> None:
        tf = tmp_path / "main.tf"
        tf.write_text(
            'resource "aws_security_group" "sg" {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
        )
        attempts = scan_terraform_file(tf, tmp_path)
        assert len(attempts) >= 1
        assert any(a.check_name == "public_cidr" for a in attempts)

    def test_no_issues(self, tmp_path: Path) -> None:
        tf = tmp_path / "main.tf"
        tf.write_text('resource "aws_instance" "web" {\n  ami = "ami-123"\n}\n')
        attempts = scan_terraform_file(tf, tmp_path)
        assert len(attempts) == 0

    def test_hardcoded_password(self, tmp_path: Path) -> None:
        tf = tmp_path / "vars.tf"
        tf.write_text('db_password = "SuperSecret123"\n')
        attempts = scan_terraform_file(tf, tmp_path)
        assert any(a.check_name == "hardcoded_password" for a in attempts)

    def test_custom_rules(self, tmp_path: Path) -> None:
        import re

        tf = tmp_path / "main.tf"
        tf.write_text("something_bad = true\n")
        custom = {
            "custom": {
                "pattern": re.compile(r"something_bad"),
                "severity": "high",
                "description": "Custom check",
            }
        }
        attempts = scan_terraform_file(tf, tmp_path, rules=custom)
        assert len(attempts) == 1
        assert attempts[0].check_name == "custom"
        assert attempts[0].severity == "high"


# --- Kubernetes scanner tests ---


class TestKubernetesScan:
    def test_privileged_container(self, tmp_path: Path) -> None:
        yml = tmp_path / "pod.yaml"
        yml.write_text(
            "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n    securityContext:\n      privileged: true\n"
        )
        attempts = scan_kubernetes_file(yml, tmp_path)
        assert any(a.check_name == "privileged_container" for a in attempts)

    def test_host_network(self, tmp_path: Path) -> None:
        yml = tmp_path / "pod.yaml"
        yml.write_text("apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n")
        attempts = scan_kubernetes_file(yml, tmp_path)
        assert any(a.check_name == "host_network" for a in attempts)

    def test_latest_tag(self, tmp_path: Path) -> None:
        yml = tmp_path / "deploy.yaml"
        yml.write_text("containers:\n- image: nginx:latest\n")
        attempts = scan_kubernetes_file(yml, tmp_path)
        assert any(a.check_name == "latest_tag" for a in attempts)

    def test_no_issues(self, tmp_path: Path) -> None:
        yml = tmp_path / "pod.yaml"
        yml.write_text(
            "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: app\n"
        )
        attempts = scan_kubernetes_file(yml, tmp_path)
        assert len(attempts) == 0


# --- Dockerfile scanner tests ---


class TestDockerfileScan:
    def test_run_as_root(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM ubuntu\nRUN apt-get update\nUSER root\n")
        attempts = scan_dockerfile(df, tmp_path)
        assert any(a.check_name == "run_as_root" for a in attempts)

    def test_curl_pipe_bash(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM alpine\nRUN curl https://example.com/install.sh | bash\n")
        attempts = scan_dockerfile(df, tmp_path)
        assert any(a.check_name == "curl_pipe_bash" for a in attempts)

    def test_exposed_secrets(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM alpine\nENV DB_PASSWORD=supersecret123\n")
        attempts = scan_dockerfile(df, tmp_path)
        assert any(a.check_name == "exposed_secrets" for a in attempts)

    def test_no_user_defined(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM alpine\nRUN echo hello\n")
        attempts = scan_dockerfile(df, tmp_path)
        assert any(a.check_name == "no_user_defined" for a in attempts)

    def test_user_defined(self, tmp_path: Path) -> None:
        df = tmp_path / "Dockerfile"
        df.write_text("FROM alpine\nUSER nobody\n")
        attempts = scan_dockerfile(df, tmp_path)
        assert not any(a.check_name == "no_user_defined" for a in attempts)


# --- CloudFormation scanner tests ---


class TestCloudFormationScan:
    def test_public_s3(self, tmp_path: Path) -> None:
        tpl = tmp_path / "template.yaml"
        tpl.write_text(
            "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Bucket:\n    Type: AWS::S3::Bucket\n    Properties:\n      AccessControl: PublicRead\n"
        )
        attempts = scan_cloudformation_file(tpl, tmp_path)
        assert any(a.check_name == "public_s3_bucket" for a in attempts)

    def test_open_sg(self, tmp_path: Path) -> None:
        tpl = tmp_path / "template.yaml"
        tpl.write_text(
            "AWSTemplateFormatVersion: '2010-09-09'\nSecurityGroupIngress:\n  CidrIp: 0.0.0.0/0\n"
        )
        attempts = scan_cloudformation_file(tpl, tmp_path)
        assert any(a.check_name == "open_security_group" for a in attempts)

    def test_no_issues(self, tmp_path: Path) -> None:
        tpl = tmp_path / "template.yaml"
        tpl.write_text("AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n")
        attempts = scan_cloudformation_file(tpl, tmp_path)
        assert len(attempts) == 0


# --- classify_file tests ---


class TestClassifyFile:
    def test_terraform(self, tmp_path: Path) -> None:
        f = tmp_path / "main.tf"
        f.write_text("")
        assert _classify_file(f) == "terraform"

    def test_hcl(self, tmp_path: Path) -> None:
        f = tmp_path / "main.hcl"
        f.write_text("")
        assert _classify_file(f) == "terraform"

    def test_dockerfile(self, tmp_path: Path) -> None:
        f = tmp_path / "Dockerfile"
        f.write_text("")
        assert _classify_file(f) == "dockerfile"

    def test_kubernetes(self, tmp_path: Path) -> None:
        f = tmp_path / "pod.yaml"
        f.write_text("apiVersion: v1\nkind: Pod\n")
        assert _classify_file(f) == "kubernetes"

    def test_cloudformation(self, tmp_path: Path) -> None:
        f = tmp_path / "template.yaml"
        f.write_text("AWSTemplateFormatVersion: '2010-09-09'\n")
        assert _classify_file(f) == "cloudformation"

    def test_unknown(self, tmp_path: Path) -> None:
        f = tmp_path / "readme.md"
        f.write_text("# Hello")
        assert _classify_file(f) is None

    def test_json_kubernetes(self, tmp_path: Path) -> None:
        f = tmp_path / "pod.json"
        f.write_text('{"apiVersion":"v1","kind":"Pod"}')
        assert _classify_file(f) == "kubernetes"


# --- run_iac_scan integration tests ---


class TestRunIacScan:
    def test_empty_dir(self, tmp_path: Path) -> None:
        import asyncio

        result = asyncio.run(run_iac_scan(target=str(tmp_path)))
        assert result.overall_status == "clean"
        assert result.total_files == 0

    def test_nonexistent_dir(self, tmp_path: Path) -> None:
        import asyncio

        result = asyncio.run(run_iac_scan(target=str(tmp_path / "nope")))
        assert result.overall_status == "error"

    def test_mixed_files(self, tmp_path: Path) -> None:
        import asyncio

        (tmp_path / "main.tf").write_text('cidr_blocks = ["0.0.0.0/0"]\n')
        (tmp_path / "Dockerfile").write_text("FROM ubuntu\nUSER root\n")
        (tmp_path / "pod.yaml").write_text(
            "apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n"
        )
        (tmp_path / "readme.md").write_text("# Hello")
        result = asyncio.run(run_iac_scan(target=str(tmp_path)))
        assert result.overall_status == "found"
        assert result.scanned_files >= 3
        assert len(result.attempts) >= 3

    def test_category_filter(self, tmp_path: Path) -> None:
        import asyncio

        (tmp_path / "main.tf").write_text('cidr_blocks = ["0.0.0.0/0"]\n')
        (tmp_path / "Dockerfile").write_text("FROM ubuntu\nUSER root\n")
        result = asyncio.run(
            run_iac_scan(target=str(tmp_path), categories=["terraform"])
        )
        assert result.scanned_files == 1

    def test_min_severity(self, tmp_path: Path) -> None:
        import asyncio

        (tmp_path / "main.tf").write_text("logging = false\n")
        result = asyncio.run(
            run_iac_scan(target=str(tmp_path), min_severity="critical")
        )
        assert len(result.attempts) == 0

    def test_exclude_dirs(self, tmp_path: Path) -> None:
        import asyncio

        sub = tmp_path / "vendor"
        sub.mkdir()
        (sub / "main.tf").write_text('cidr_blocks = ["0.0.0.0/0"]\n')
        result = asyncio.run(
            run_iac_scan(target=str(tmp_path), exclude_dirs=["vendor"])
        )
        assert result.scanned_files == 0


# --- Scanner class tests ---


class TestIacScanScanner:
    def test_build_parser(self) -> None:
        scanner = IacScanScanner()
        parser = scanner.build_parser()
        args = parser.parse_args([])
        assert args.target is None
        assert args.min_severity == "low"

    def test_build_parser_with_args(self) -> None:
        scanner = IacScanScanner()
        parser = scanner.build_parser()
        args = parser.parse_args(["./infra", "-c", "terraform", "k8s"])
        assert args.target == "./infra"
        assert args.categories == ["terraform", "k8s"]

    def test_get_target(self) -> None:
        import argparse

        ns = argparse.Namespace(target="./infra")
        assert IacScanScanner._get_target(ns) == "./infra"

    def test_get_target_default(self) -> None:
        import argparse

        ns = argparse.Namespace()
        assert IacScanScanner._get_target(ns) is None

    def test_module_level_exports(self) -> None:
        from mytools.iac.iac_scan import build_parser, main, run_once

        assert callable(build_parser)
        assert callable(main)
        assert callable(run_once)
