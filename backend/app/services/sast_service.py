import re
import ast
import os
from typing import List, Dict, Any

class SastEngine:
    """Motor de Análise Estática de Código (SAST) Enterprise para NeuroSec."""

    RULES = [
        {
            "id": "NS-SAST-001",
            "name": "SQL Injection",
            "owasp": "A03:2021 - Injection",
            "severity": "HIGH",
            "cvss": 8.5,
            "regex": r"(\.execute\s*\(|cursor\.execute\s*\().*?(\+|%|\.format\(|f[\"'])",
            "description": "Concatenação ou interpolação direta de variáveis em queries SQL sem bind parameters."
        },
        {
            "id": "NS-SAST-002",
            "name": "Hardcoded Secrets & API Keys",
            "owasp": "A07:2021 - Identification and Authentication Failures",
            "severity": "CRITICAL",
            "cvss": 9.2,
            "regex": r"(password|passwd|db_password|api_key|secret_key|groq_key|aws_secret|token)\s*=\s*['\"][a-zA-Z0-9_\-\.\/]{8,}['\"]",
            "description": "Credenciais, senhas ou chaves de API sensíveis gravadas em texto plano no código-fonte."
        },
        {
            "id": "NS-SAST-003",
            "name": "Command Injection (OS Execution)",
            "owasp": "A03:2021 - Injection",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "regex": r"(os\.system\s*\(|subprocess\.Popen\s*\(.*?shell\s*=\s*True|subprocess\.call\s*\(.*?shell\s*=\s*True)",
            "description": "Execução de comandos do sistema operacional com shell=True ou sem sanitização de entrada."
        },
        {
            "id": "NS-SAST-004",
            "name": "Insecure Deserialization (Pickle/YAML)",
            "owasp": "A08:2021 - Software and Data Integrity Failures",
            "severity": "HIGH",
            "cvss": 8.1,
            "regex": r"(pickle\.loads?\s*\(|yaml\.load\s*\([^,)]*\)|_pickle\.loads?\s*\()",
            "description": "Desserialização insegura de dados externos permitindo execução remota de código (RCE)."
        },
        {
            "id": "NS-SAST-005",
            "name": "Insecure Cryptographic Hash (MD5 / SHA1)",
            "owasp": "A02:2021 - Cryptographic Failures",
            "severity": "MEDIUM",
            "cvss": 5.9,
            "regex": r"(hashlib\.md5\s*\(|hashlib\.sha1\s*\(|DES\.new\s*\()",
            "description": "Uso de algoritmo criptográfico obsoleto e vulnerável a colisões para integridade ou autenticação."
        },
        {
            "id": "NS-SAST-006",
            "name": "Dynamic Code Evaluation (Eval / Exec)",
            "owasp": "A03:2021 - Injection",
            "severity": "CRITICAL",
            "cvss": 9.5,
            "regex": r"(eval\s*\(|exec\s*\(|compile\s*\(.*?eval)",
            "description": "Execução dinâmica de código via eval()/exec(), possibilitando escape e injeção de comandos arbitrários."
        },
        {
            "id": "NS-SAST-007",
            "name": "Cross-Site Scripting (Reflected XSS / Unsafe HTML)",
            "owasp": "A03:2021 - Injection",
            "severity": "HIGH",
            "cvss": 7.5,
            "regex": r"(render_template_string\s*\(|Markup\s*\(|dangerouslySetInnerHTML|innerHTML\s*=)",
            "description": "Renderização direta de HTML ou templates sem escape adequado de caracteres especiais."
        },
        {
            "id": "NS-SAST-008",
            "name": "Permissive CORS Wildcard",
            "owasp": "A05:2021 - Security Misconfiguration",
            "severity": "LOW",
            "cvss": 3.7,
            "regex": r"(allow_origins\s*=\s*\[\s*['\"]\*['\"]\s*\]\s*,\s*allow_credentials\s*=\s*True)",
            "description": "Política de CORS permissiva combinando wildcard (*) com allow_credentials=True."
        }
    ]

    @classmethod
    def scan_code_string(cls, code: str, filename: str = "snippet.py") -> List[Dict[str, Any]]:
        """Analisa uma string de código e retorna a lista de vulnerabilidades encontradas."""
        findings = []
        lines = code.splitlines()

        for idx, line in enumerate(lines):
            line_num = idx + 1
            line_clean = line.strip()
            
            # Ignora linhas comentadas puras
            if line_clean.startswith("#") or line_clean.startswith("//"):
                continue

            for rule in cls.RULES:
                if re.search(rule["regex"], line, re.IGNORECASE):
                    # Validação especial para evitar falsos positivos de os.getenv em secrets
                    if rule["id"] == "NS-SAST-002" and "os.getenv" in line:
                        continue
                    
                    findings.append({
                        "rule_id": rule["id"],
                        "vuln_type": rule["name"],
                        "severity": rule["severity"],
                        "cvss_score": rule["cvss"],
                        "owasp_category": rule["owasp"],
                        "line_number": line_num,
                        "asset_name": filename,
                        "asset_type": "CODE",
                        "description": rule["description"],
                        "code_snippet": line_clean
                    })
        return findings

    @classmethod
    def scan_directory(cls, directory_path: str = ".") -> List[Dict[str, Any]]:
        """Varre arquivos no diretório ignorando pastas virtuais e bibliotecas."""
        all_findings = []
        ignored_dirs = {".venv", "venv", ".git", "__pycache__", "node_modules", "dist", "build"}
        ignored_files = {"main.py", "database.py", "models.py", "config.py", "sast_service.py"}

        for root, dirs, files in os.walk(directory_path):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            for file in files:
                if file.endswith((".py", ".js", ".ts", ".php", ".env")) and file not in ignored_files:
                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                            rel_path = os.path.relpath(full_path, directory_path)
                            findings = cls.scan_code_string(content, filename=rel_path)
                            all_findings.extend(findings)
                    except Exception:
                        continue
        return all_findings
