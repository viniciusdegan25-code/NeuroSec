import httpx
from typing import List, Dict, Any

class DastEngine:
    """Motor de Varredura DAST & Infraestrutura Web para NeuroSec."""

    SECURITY_HEADERS = [
        {
            "header": "Content-Security-Policy",
            "name": "Ausência de Content Security Policy (CSP)",
            "severity": "HIGH",
            "cvss": 7.2,
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": "CSP não configurado. Permite injeção de scripts maliciosos e ataques XSS/Data Injection.",
            "recommended": "Content-Security-Policy: default-src 'self'; script-src 'self' https://trusted.cdn;"
        },
        {
            "header": "Strict-Transport-Security",
            "name": "Ausência de HSTS (Strict-Transport-Security)",
            "severity": "MEDIUM",
            "cvss": 6.1,
            "owasp": "A02:2021 - Cryptographic Failures",
            "description": "HSTS desabilitado. Conexões ficam vulneráveis a ataques Man-in-the-Middle (SSL Stripping).",
            "recommended": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
        },
        {
            "header": "X-Frame-Options",
            "name": "Ausência de Proteção contra Clickjacking (X-Frame-Options)",
            "severity": "MEDIUM",
            "cvss": 5.4,
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": "X-Frame-Options ausente. O site pode ser embutido em iframes maliciosos para captura de cliques.",
            "recommended": "X-Frame-Options: DENY"
        },
        {
            "header": "X-Content-Type-Options",
            "name": "Ausência de X-Content-Type-Options (MIME-Sniffing)",
            "severity": "LOW",
            "cvss": 3.8,
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": "Navegadores podem interpretar arquivos de forma diferente do Content-Type declarado.",
            "recommended": "X-Content-Type-Options: nosniff"
        },
        {
            "header": "Referrer-Policy",
            "name": "Política de Referrer Indefinida",
            "severity": "LOW",
            "cvss": 3.1,
            "owasp": "A01:2021 - Broken Access Control",
            "description": "URLs completas contendo tokens ou dados sensíveis podem vazar para servidores de terceiros.",
            "recommended": "Referrer-Policy: strict-origin-when-cross-origin"
        },
        {
            "header": "Permissions-Policy",
            "name": "Permissions-Policy Ausente",
            "severity": "LOW",
            "cvss": 2.5,
            "owasp": "A05:2021 - Security Misconfiguration",
            "description": "Recursos do navegador como câmera, microfone e geolocalização não estão restritos.",
            "recommended": "Permissions-Policy: camera=(), microphone=(), geolocation=()"
        }
    ]

    @classmethod
    async def scan_url(cls, url: str) -> Dict[str, Any]:
        """Executa requisição assíncrona para coletar headers e auditar a postura de segurança web."""
        if not url.startswith("http://") and not url.startswith("https://"):
            url = f"https://{url}"

        findings = []
        raw_headers = {}
        server_banner = ""
        is_https = url.startswith("https://")
        status_code = 0

        try:
            async with httpx.AsyncClient(timeout=12.0, follow_redirects=True) as client:
                response = await client.get(url)
                status_code = response.status_code
                raw_headers = dict(response.headers)
                server_banner = raw_headers.get("server", "")

                # 1. Checagem de HTTPS
                if not is_https:
                    findings.append({
                        "vuln_type": "Comunicação em Texto Claro (Insecure HTTP)",
                        "severity": "HIGH",
                        "cvss_score": 7.5,
                        "owasp_category": "A02:2021 - Cryptographic Failures",
                        "line_number": 0,
                        "asset_name": url,
                        "asset_type": "URL",
                        "description": "O alvo respondeu via protocolo HTTP não criptografado, expondo dados a interceptação.",
                        "code_snippet": "Protocolo: HTTP"
                    })

                # 2. Checagem de Headers de Segurança
                for sec in cls.SECURITY_HEADERS:
                    if sec["header"].lower() not in [h.lower() for h in raw_headers.keys()]:
                        findings.append({
                            "vuln_type": sec["name"],
                            "severity": sec["severity"],
                            "cvss_score": sec["cvss"],
                            "owasp_category": sec["owasp"],
                            "line_number": 0,
                            "asset_name": url,
                            "asset_type": "URL",
                            "description": sec["description"],
                            "code_snippet": f"Header Ausente: {sec['header']} (Recomendado: {sec['recommended']})"
                        })

                # 3. Checagem de Exposição de Banner de Servidor
                if server_banner and any(token in server_banner.lower() for token in ["apache/", "nginx/", "iis/", "express", "php/"]):
                    findings.append({
                        "vuln_type": "Divulgação de Versão de Servidor (Banner Disclosure)",
                        "severity": "LOW",
                        "cvss_score": 3.4,
                        "owasp_category": "A05:2021 - Security Misconfiguration",
                        "line_number": 0,
                        "asset_name": url,
                        "asset_type": "URL",
                        "description": f"O cabeçalho 'Server' expõe a tecnologia e versão exata: {server_banner}",
                        "code_snippet": f"Server: {server_banner}"
                    })

            return {
                "target_url": url,
                "status_code": status_code,
                "is_https": is_https,
                "server_banner": server_banner,
                "raw_headers": raw_headers,
                "findings": findings
            }

        except Exception as e:
            return {
                "target_url": url,
                "error": str(e),
                "findings": []
            }
