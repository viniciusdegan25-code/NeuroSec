# 🛡️ NeuroSec — Enterprise AI-Powered ASPM Platform

[![FastAPI](https://img.shields.io/badge/FastAPI-0.115.0-009688.svg?style=flat&logo=fastapi)](https://fastapi.tiangolo.com)
[![Python](https://img.shields.io/badge/Python-3.11+-3776AB.svg?style=flat&logo=python)](https://python.org)
[![Groq AI](https://img.shields.io/badge/AI%20Engine-Llama--3.1--8b-f97316.svg?style=flat)](https://groq.com)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-2088FF.svg?logo=github-actions)](.github/workflows/ci.yml)

> **NeuroSec** é uma plataforma corporativa de **Application Security Posture Management (ASPM)** projetada para unificar visibilidade de riscos em código-fonte, infraestrutura web, dependências de software e configurações em nuvem, acelerando o ciclo de remediação através de Inteligência Artificial autônoma.

---

## 🌟 Diferenciais de Mercado & Benchmark

| Capacidade | BonSec IA (Referência) | **NeuroSec ASPM (Nossa Plataforma)** |
| :--- | :--- | :--- |
| **Arquitetura** | Landing page estática com simulações | **Plataforma SaaS real desacoplada (FastAPI + SPA Moderna)** |
| **Banco de Dados** | Não possui / Mock | **SQLite/PostgreSQL com ACID e histórico transacional** |
| **Scanners Ativos** | Apenas textos demonstrativos | **SAST, DAST, SCA (SBOM) e Cloud Audit em tempo real** |
| **Remediação de Código** | Não gera código corrigido nem diff | **Geração de Patch de Código + Diff Viewer + Aprovação** |
| **Security Scorecard** | Inexistente | **Score 0-100 dinâmico ponderado + Cálculo de Prejuízo Evitado (R$)** |
| **Governança & Compliance** | Inexistente | **Trilha de Auditoria imutável (Audit Trail) para aprovações** |
| **Relatórios Executivos** | Inexistente | **Emissão e download de Relatório Executivo C-Level em PDF** |
| **Terminal CLI** | Mock com 3 abas estáticas | **Terminal CLI interativo funcional com comandos de scan e status** |
| **AI Copilot** | Chat simples em caixa de texto | **Copilot lateral integrado com contexto do inventário de falhas** |
| **Deploy em Nuvem** | Vercel (apenas frontend) | **Dual Deploy: Frontend na Vercel + Backend no Render com CI/CD** |

---

## 🚀 Arquitetura e Módulos

```text
NeuroSec/
├── backend/                  # API REST em FastAPI + SQLAlchemy + Motores de Cibersegurança
│   ├── app/
│   │   ├── api/v1/          # Endpoints REST (SAST, DAST, SCA, Cloud, AI, Scorecard, Audit, Reports)
│   │   ├── core/            # Configurações com Pydantic Settings e blindagem de .env
│   │   ├── db/              # Conexão e modelos relacionais (Vulnerability, AuditLog, ScanHistory)
│   │   ├── schemas/         # Validação de I/O com Pydantic
│   │   └── services/        # Motores SAST, DAST, SCA, Cloud, Groq AI, Scorecard e PDF
│   ├── main.py              # Ponto de entrada FastAPI com CORS e Swagger (/docs)
│   ├── requirements.txt     # Dependências Python
│   ├── Dockerfile           # Imagem para containerização em nuvem
│   └── render.yaml          # Blueprint de deploy no Render/Railway
│
└── frontend/                 # Single Page Application (SPA) Enterprise
    ├── index.html           # Dashboard Executivo e Central de Segurança
    ├── css/styles.css       # Design System Cybersec Dark Glassmorphism
    ├── js/                  # Módulos JS desacoplados (api, scorecard, scanners, remediation, copilot, terminal, audit)
    └── vercel.json          # Configuração de hospedagem na Vercel
```

---

## 🛠️ Como Executar Localmente

### 1. Inicializar o Backend

```bash
cd backend
python -m venv .venv
source .venv/Scripts/activate  # No Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

- Acesso ao Swagger / OpenAPI Docs: `http://127.0.0.1:8000/docs`
- Acesso à API REST: `http://127.0.0.1:8000/api/v1`

### 2. Acessar a Interface Web (Frontend)

Com o backend rodando, a interface completa pode ser aberta diretamente no navegador em:
👉 `http://127.0.0.1:8000/` ou abrindo o arquivo `frontend/index.html` via Live Server.

---

## 🔐 Variáveis de Ambiente (.env)

Crie o arquivo `backend/.env` com:

```env
GROQ_API_KEY=gsk_...
GROQ_MODEL=llama-3.1-8b-instant
DATABASE_URL=sqlite:///./neurosec.db
PORT=8000
ENVIRONMENT=development
CORS_ORIGINS=*
```

---

## 🏆 Para Apresentação Executiva e LinkedIn

### Texto Sugerido para Publicação:
> 🚀 *Orgulho em apresentar o **NeuroSec**, uma plataforma corporativa de **Application Security Posture Management (ASPM)** desenvolvida do zero! Diferente de protótipos acadêmicos simplificados, o NeuroSec integra análise estática (SAST), varredura dinâmica de infraestrutura (DAST), auditoria de dependências (SCA/SBOM) e postura em nuvem (CSPM), tudo orquestrado por agentes de IA com Groq (Llama-3.1). Com cálculo em tempo real de Security Scorecard (0-100), estimativa de prejuízo financeiro evitado (ROI), visualizador de diff de patches e governança com trilha de auditoria.*
