import re
from typing import List, Dict, Any

class ScaEngine:
    """Motor de Análise de Dependências / Supply Chain & SBOM (SCA) para NeuroSec."""

    # Base de conhecimento de CVEs e bibliotecas vulneráveis conhecidas
    VULNERABLE_PACKAGES_DB = {
        "requests": {
            "vuln_versions": ["<2.31.0", "==2.28.0", "==2.27.0", "==2.26.0"],
            "cve": "CVE-2023-32681",
            "severity": "HIGH",
            "cvss": 7.5,
            "description": "Vazamento inadvertido de Proxy-Authorization header em redirecionamentos HTTPS."
        },
        "urllib3": {
            "vuln_versions": ["<1.26.18", "<2.0.7"],
            "cve": "CVE-2023-45803",
            "severity": "MEDIUM",
            "cvss": 6.8,
            "description": "Descarte indevido de headers em redirect permitindo vazamento de credenciais HTTP."
        },
        "flask": {
            "vuln_versions": ["<2.2.5", "==1.1.2", "==1.0.2"],
            "cve": "CVE-2023-30861",
            "severity": "HIGH",
            "cvss": 7.8,
            "description": "Geração inadequada de cookie de sessão permitindo bypass de autenticação."
        },
        "django": {
            "vuln_versions": ["<4.2.14", "<5.0.7", "==3.2.0"],
            "cve": "CVE-2024-38875",
            "severity": "CRITICAL",
            "cvss": 9.1,
            "description": "Denial of Service (DoS) em urls decoradas com @sensitive_post_parameters."
        },
        "sqlalchemy": {
            "vuln_versions": ["<1.4.49", "<2.0.0b1"],
            "cve": "CVE-2021-2009",
            "severity": "MEDIUM",
            "cvss": 6.5,
            "description": "Injeção de parâmetros em ordens específicas de dialetos PostgreSQL/Oracle."
        },
        "jinja2": {
            "vuln_versions": ["<3.1.3", "==2.11.3"],
            "cve": "CVE-2024-22195",
            "severity": "HIGH",
            "cvss": 8.0,
            "description": "SSTI (Server-Side Template Injection) e XSS em templates compilados com xmlattr."
        },
        "fastapi": {
            "vuln_versions": ["<0.65.2"],
            "cve": "CVE-2021-32677",
            "severity": "MEDIUM",
            "cvss": 5.3,
            "description": "Status code de validação Swagger inconsistente permitindo bypass de filtro."
        },
        "pyyaml": {
            "vuln_versions": ["<5.4", "==5.3.1", "==3.13"],
            "cve": "CVE-2020-14343",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "description": "RCE via YAML deserialization em yaml.load()."
        },
        "cryptography": {
            "vuln_versions": ["<41.0.6", "==3.4.7"],
            "cve": "CVE-2023-49083",
            "severity": "HIGH",
            "cvss": 7.5,
            "description": "Crash de ponteiro nulo em PKCS7 parsing permitindo negação de serviço."
        }
    }

    @classmethod
    def scan_manifest_text(cls, content: str, filename: str = "requirements.txt") -> List[Dict[str, Any]]:
        """Lê o arquivo de dependências e mapeia pacotes desatualizados ou com CVEs ativas."""
        findings = []
        lines = content.splitlines()

        for idx, line in enumerate(lines):
            line_num = idx + 1
            line_clean = line.strip()
            if not line_clean or line_clean.startswith("#"):
                continue

            # Extrai pacote e versão (ex: requests==2.28.0 ou django>=3.2)
            match = re.match(r"^([a-zA-Z0-9_\-]+)\s*([=><~]=?)\s*([0-9\.\w]+)", line_clean)
            if match:
                pkg_name = match.group(1).lower()
                op = match.group(2)
                version = match.group(3)

                if pkg_name in cls.VULNERABLE_PACKAGES_DB:
                    vuln_info = cls.VULNERABLE_PACKAGES_DB[pkg_name]
                    findings.append({
                        "vuln_type": f"Biblioteca Vulnerável: {pkg_name} ({version})",
                        "severity": vuln_info["severity"],
                        "cvss_score": vuln_info["cvss"],
                        "cve_id": vuln_info["cve"],
                        "owasp_category": "A06:2021 - Vulnerable and Outdated Components",
                        "line_number": line_num,
                        "asset_name": filename,
                        "asset_type": "DEPENDENCY",
                        "description": f"[{vuln_info['cve']}] {vuln_info['description']}",
                        "code_snippet": line_clean
                    })
        return findings
