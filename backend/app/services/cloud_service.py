import re
from typing import List, Dict, Any

class CloudAuditEngine:
    """Motor de Auditoria de Postura em Nuvem (CSPM-lite) para NeuroSec."""

    CLOUD_MISCONFIG_PATTERNS = [
        {
            "id": "NS-CLOUD-001",
            "name": "AWS S3 Bucket com Leitura Pública Aberta",
            "severity": "CRITICAL",
            "cvss": 9.3,
            "owasp": "A05:2021 - Security Misconfiguration",
            "regex": r"(acl\s*=\s*['\"]public-read['\"]|Principal\s*:\s*['\"]\*['\"].*?Action|s3:GetObject.*?['\"]\*['\"])",
            "description": "Política de Bucket AWS S3 concedendo permissão de listagem ou download a qualquer usuário não autenticado."
        },
        {
            "id": "NS-CLOUD-002",
            "name": "IAM Policy com Privilégios Excessivos (Wildcard Administrator)",
            "severity": "CRITICAL",
            "cvss": 9.6,
            "owasp": "A01:2021 - Broken Access Control",
            "regex": r"Action\s*:\s*['\"]\*['\"].*?Resource\s*:\s*['\"]\*['\"]",
            "description": "Política IAM concedendo acesso irrestrito (Action: * em Resource: *), violando o Princípio do Menor Privilégio."
        },
        {
            "id": "NS-CLOUD-003",
            "name": "Armazenamento RDS / EBS sem Criptografia em Repouso",
            "severity": "HIGH",
            "cvss": 7.4,
            "owasp": "A02:2021 - Cryptographic Failures",
            "regex": r"(storage_encrypted\s*=\s*false|encrypted\s*=\s*false|kms_key_id\s*=\s*null)",
            "description": "Volumes de banco de dados ou discos virtuais configurados sem criptografia AES-256 em repouso."
        },
        {
            "id": "NS-CLOUD-004",
            "name": "Grupo de Segurança (Security Group) com Porta SSH/RDP 0.0.0.0/0",
            "severity": "HIGH",
            "cvss": 8.6,
            "owasp": "A05:2021 - Security Misconfiguration",
            "regex": r"(from_port\s*=\s*(22|3389).*?cidr_blocks\s*=\s*\[\s*['\"]0\.0\.0\.0/0['\"]\])",
            "description": "Porta de gerenciamento administrativo (SSH:22 ou RDP:3389) aberta diretamente para a Internet pública."
        }
    ]

    @classmethod
    def audit_iac_text(cls, text: str, asset_name: str = "main.tf / cloud-config.json") -> List[Dict[str, Any]]:
        """Analisa arquivos de infraestrutura como código (Terraform, CloudFormation, JSON) em busca de brechas de postura."""
        findings = []
        lines = text.splitlines()

        for idx, line in enumerate(lines):
            line_num = idx + 1
            for rule in cls.CLOUD_MISCONFIG_PATTERNS:
                if re.search(rule["regex"], line, re.IGNORECASE) or re.search(rule["regex"], text, re.IGNORECASE):
                    findings.append({
                        "vuln_type": rule["name"],
                        "severity": rule["severity"],
                        "cvss_score": rule["cvss"],
                        "owasp_category": rule["owasp"],
                        "line_number": line_num,
                        "asset_name": asset_name,
                        "asset_type": "CLOUD",
                        "description": rule["description"],
                        "code_snippet": line.strip() if line.strip() else "Configuração detectada no bloco IaC"
                    })
                    break
        return findings
