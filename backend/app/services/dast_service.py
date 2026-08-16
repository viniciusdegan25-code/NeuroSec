import httpx
from typing import List, Dict, Any

class DastEngine:
    """Motor de Varredura DAST & Infraestrutura Web para NeuroSec com Bypass de Bloqueio WAF/CDN."""

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

    BROWSER_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7",
        "Sec-Ch-Ua": '"Not)A;Brand";v="99", "Google Chrome";v="127", "Chromium";v="127"',
        "Sec-Ch-Ua-Mobile": "?0",
        "Sec-Ch-Ua-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1"
    }

    @classmethod
    async def scan_url(cls, url: str) -> Dict[str, Any]:
        """Executa requisição com cabeçalhos de browser reais para contornar WAFs (Cloudflare/Azion/Akamai)."""
        url_clean = url.strip()
        if not url_clean.startswith("http://") and not url_clean.startswith("https://"):
            url_clean = f"https://{url_clean}"

        findings = []
        raw_headers = {}
        server_banner = ""
        is_https = url_clean.startswith("https://")
        status_code = 0

        try:
            async with httpx.AsyncClient(
                timeout=18.0, 
                follow_redirects=True, 
                headers=cls.BROWSER_HEADERS, 
                verify=False
            ) as client:
                response = await client.get(url_clean)
                status_code = response.status_code
                raw_headers = {k.lower(): v for k, v in response.headers.items()}
                server_banner = raw_headers.get("server", "")

                # 1. Checagem de HTTPS
                if not is_https:
                    findings.append({
                        "vuln_type": "Comunicação em Texto Claro (Insecure HTTP)",
                        "severity": "HIGH",
                        "cvss_score": 7.5,
                        "owasp_category": "A02:2021 - Cryptographic Failures",
                        "line_number": 0,
                        "asset_name": url_clean,
                        "asset_type": "URL",
                        "description": "O alvo respondeu via protocolo HTTP não criptografado, expondo dados a interceptação.",
                        "code_snippet": "Protocolo: HTTP"
                    })

                # 2. Checagem de Headers de Segurança
                for sec in cls.SECURITY_HEADERS:
                    h_lower = sec["header"].lower()
                    if h_lower not in raw_headers:
                        findings.append({
                            "vuln_type": sec["name"],
                            "severity": sec["severity"],
                            "cvss_score": sec["cvss"],
                            "owasp_category": sec["owasp"],
                            "line_number": 0,
                            "asset_name": url_clean,
                            "asset_type": "URL",
                            "description": sec["description"],
                            "code_snippet": f"Header Ausente: {sec['header']} (Recomendado: {sec['recommended']})"
                        })

                # 3. Checagem de Exposição de Banner de Servidor
                if server_banner and any(token in server_banner.lower() for token in ["apache/", "nginx/", "iis/", "express", "php/", "openresty"]):
                    findings.append({
                        "vuln_type": "Divulgação de Versão de Servidor (Banner Disclosure)",
                        "severity": "LOW",
                        "cvss_score": 3.4,
                        "owasp_category": "A05:2021 - Security Misconfiguration",
                        "line_number": 0,
                        "asset_name": url_clean,
                        "asset_type": "URL",
                        "description": f"O cabeçalho 'Server' expõe a tecnologia e versão exata: {server_banner}",
                        "code_snippet": f"Server: {server_banner}"
                    })

            return {
                "target_url": url_clean,
                "status_code": status_code,
                "is_https": is_https,
                "server_banner": server_banner,
                "raw_headers": raw_headers,
                "findings": findings
            }

        except Exception as e:
            return {
                "target_url": url_clean,
                "error": str(e),
                "findings": []
            }
