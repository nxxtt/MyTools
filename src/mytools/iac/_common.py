"""Tipos e padroes compartilhados para IaC Static Scan."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

__all__ = [
    "CLOUDFORMATION_RULES",
    "DOCKERFILE_RULES",
    "K8S_RULES",
    "TERRAFORM_RULES",
    "IacAttempt",
    "IacResult",
]

TERRAFORM_RULES: dict[str, dict[str, object]] = {
    "public_cidr": {
        "pattern": re.compile(r"cidr_blocks\s*=\s*\[?\s*\"0\.0\.0\.0/0\""),
        "severity": "critical",
        "description": "CIDR 0.0.0.0/0 expoe recurso publicamente",
    },
    "unencrypted_ebs": {
        "pattern": re.compile(r"encrypted\s*=\s*false"),
        "severity": "high",
        "description": "EBS volume sem criptografia",
    },
    "public_acl": {
        "pattern": re.compile(r"acl\s*=\s*\"public-read(-write)?\""),
        "severity": "critical",
        "description": "S3 bucket com ACL publica",
    },
    "hardcoded_password": {
        "pattern": re.compile(
            r"(?i)(?:password|db_password|admin_password)\s*=\s*\"[^\"]{8,}\""
        ),
        "severity": "critical",
        "description": "Senha hardcoded em Terraform",
    },
    "hardcoded_secret": {
        "pattern": re.compile(
            r"(?i)(?:secret_key|api_key|access_key)\s*=\s*\"[^\"]{8,}\""
        ),
        "severity": "high",
        "description": "Chave/secreto hardcoded em Terraform",
    },
    "no_logging": {
        "pattern": re.compile(r"logging\s*=\s*false"),
        "severity": "medium",
        "description": "Logging desabilitado",
    },
    "public_rds": {
        "pattern": re.compile(r"publicly_accessible\s*=\s*true"),
        "severity": "critical",
        "description": "RDS acessivel publicamente",
    },
    "no_deletion_protection": {
        "pattern": re.compile(r"deletion_protection\s*=\s*false"),
        "severity": "medium",
        "description": "Deletion protection desabilitado",
    },
    "open_security_group": {
        "pattern": re.compile(
            r"cidr_blocks\s*=\s*\[?\s*\"0\.0\.0\.0/0\"\s*\]?"
            r".*?from_port\s*=\s*(?:0|22|3389|80|443)",
            re.DOTALL,
        ),
        "severity": "high",
        "description": "Security group aberto para 0.0.0.0/0",
    },
    "weak_password_policy": {
        "pattern": re.compile(r"minimum_password_length\s*=\s*([0-9]+)"),
        "severity": "medium",
        "description": "Politica de senha fraca no IAM",
    },
}

K8S_RULES: dict[str, dict[str, object]] = {
    "privileged_container": {
        "pattern": re.compile(r"privileged\s*:\s*true"),
        "severity": "critical",
        "description": "Container com privilegios elevados",
    },
    "host_network": {
        "pattern": re.compile(r"hostNetwork\s*:\s*true"),
        "severity": "high",
        "description": "Pod usando host network",
    },
    "host_pid": {
        "pattern": re.compile(r"hostPID\s*:\s*true"),
        "severity": "high",
        "description": "Pod usando host PID namespace",
    },
    "host_ipc": {
        "pattern": re.compile(r"hostIPC\s*:\s*true"),
        "severity": "high",
        "description": "Pod usando host IPC namespace",
    },
    "no_resource_limits": {
        "pattern": re.compile(r"(?:resources|limits)\s*:\s*\n\s*cpu:"),
        "severity": "medium",
        "description": "Container sem resource limits definidos",
    },
    "latest_tag": {
        "pattern": re.compile(r"image\s*:\s*[^\s:]+:latest"),
        "severity": "medium",
        "description": "Usando tag :latest em imagem",
    },
    "no_read_only_rootfs": {
        "pattern": re.compile(r"readOnlyRootFilesystem\s*:\s*false"),
        "severity": "medium",
        "description": "Root filesystem nao e read-only",
    },
    "allow_privilege_escalation": {
        "pattern": re.compile(r"allowPrivilegeEscalation\s*:\s*true"),
        "severity": "high",
        "description": "Permitindo escalacao de privilegios",
    },
    "run_as_root": {
        "pattern": re.compile(r"runAsNonRoot\s*:\s*false"),
        "severity": "high",
        "description": "Container rodando como root",
    },
    "node_port_service": {
        "pattern": re.compile(r"type\s*:\s*NodePort"),
        "severity": "medium",
        "description": "Servico exposto via NodePort",
    },
}

DOCKERFILE_RULES: dict[str, dict[str, object]] = {
    "run_as_root": {
        "pattern": re.compile(r"^USER\s+(?:root|0)\s*$", re.MULTILINE),
        "severity": "high",
        "description": "Rodando como root (USER root/0)",
    },
    "no_user_defined": {
        "pattern": re.compile(r"^USER\s+", re.MULTILINE),
        "severity": "medium",
        "description": "Nenhum USER definido (root implicito)",
        "negate": True,
    },
    "add_instead_of_copy": {
        "pattern": re.compile(r"^ADD\s+\S+\s+\S+\s*$", re.MULTILINE),
        "severity": "low",
        "description": "Usando ADD ao inves de COPY",
    },
    "no_healthcheck": {
        "pattern": re.compile(r"^HEALTHCHECK\s+", re.MULTILINE),
        "severity": "medium",
        "description": "Nenhum HEALTHCHECK definido",
        "negate": True,
    },
    "exposed_secrets": {
        "pattern": re.compile(
            r"(?i)^(?:ENV|ARG)\s+(?:\w*(?:password|secret|key|token)\w*)\s*=\s*\S+",
            re.MULTILINE,
        ),
        "severity": "critical",
        "description": "Segredo exposto via ENV/ARG no Dockerfile",
    },
    "apt_no_clean": {
        "pattern": re.compile(r"apt-get\s+install.*(?:&&|$)", re.MULTILINE),
        "severity": "low",
        "description": "apt-get install sem limpeza de cache",
    },
    "curl_pipe_bash": {
        "pattern": re.compile(r"curl\s+.*\|\s*(?:ba)?sh", re.MULTILINE),
        "severity": "high",
        "description": "curl | bash — execucao remota perigosa",
    },
    "latest_base_image": {
        "pattern": re.compile(r"^FROM\s+\S+:latest\s*$", re.MULTILINE),
        "severity": "medium",
        "description": "Base image usando tag :latest",
    },
    "sensitive_copy": {
        "pattern": re.compile(
            r"(?i)^COPY\s+.*(?:\.env|\.pem|\.key|id_rsa|credentials|secret)",
            re.MULTILINE,
        ),
        "severity": "critical",
        "description": "Copiando arquivo sensivel para imagem",
    },
}

CLOUDFORMATION_RULES: dict[str, dict[str, object]] = {
    "public_s3_bucket": {
        "pattern": re.compile(
            r"AccessControl\s*:\s*PublicRead(?:Write)?", re.IGNORECASE
        ),
        "severity": "critical",
        "description": "S3 bucket com acesso publico",
    },
    "open_security_group": {
        "pattern": re.compile(r"CidrIp\s*:\s*0\.0\.0\.0/0", re.IGNORECASE),
        "severity": "high",
        "description": "Security group aberto para 0.0.0.0/0",
    },
    "hardcoded_credentials": {
        "pattern": re.compile(
            r"(?i)(?:Password|SecretKey|AccessKey)\s*:\s*\S{8,}",
        ),
        "severity": "critical",
        "description": "Credenciais hardcoded no template",
    },
    "unencrypted_storage": {
        "pattern": re.compile(r"Encrypted\s*:\s*false", re.IGNORECASE),
        "severity": "high",
        "description": "Storage sem criptografia",
    },
    "public_database": {
        "pattern": re.compile(r"PubliclyAccessible\s*:\s*true", re.IGNORECASE),
        "severity": "critical",
        "description": "RDS acessivel publicamente",
    },
}


@dataclass(frozen=True, slots=True)
class IacAttempt:
    """Tentativa individual de check IaC."""

    file_path: str
    line_number: int
    check_name: str
    file_type: str
    vulnerable: bool
    severity: str = "medium"
    description: str = ""
    details: str = ""


@dataclass(frozen=True, slots=True)
class IacResult:
    """Resultado consolidado do scan IaC."""

    target: str
    total_files: int
    scanned_files: int
    skipped_files: int
    attempts: list[IacAttempt] = field(default_factory=list)
    issues: list[str] = field(default_factory=list)
    overall_status: str = "clean"
