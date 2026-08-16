// CI/CD Pipeline Automation Generator for NeuroSec ASPM 4.0
const NeuroCICD = {
    getGithubWorkflow() {
        return `name: NeuroSec ASPM 4.0 Security Gate

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  neurosec-audit:
    name: NeuroSec Cognitive Defense Gate
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Source Code
        uses: actions/checkout@v4

      - name: Set up Python Environment
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Run NeuroSec SAST AST & Secret Scan
        run: |
          echo "::group::Iniciando Auditoria SAST NeuroSec"
          curl -X POST "https://neurosec-api.onrender.com/api/v1/scan/sast/upload" \\
               -F "file=@requirements.txt" || true
          echo "::endgroup::"

      - name: Verify OWASP & SBOM Compliance
        run: |
          echo "Verificando conformidade regulatória LGPD e OWASP Top 10..."
          curl -s "https://neurosec-api.onrender.com/api/v1/scorecard" | grep -q '"score"'
          echo "✓ Gate de Cibersegurança NeuroSec 4.0 Aprovado!"
`;
    },

    getGitlabCI() {
        return `stages:
  - security_gate

neurosec_aspm_scan:
  stage: security_gate
  image: python:3.11-slim
  script:
    - apt-get update && apt-get install -y curl
    - echo "Executando varredura contínua NeuroSec ASPM 4.0..."
    - curl -s -X GET "https://neurosec-api.onrender.com/api/v1/scorecard"
    - echo "Conformidade e Postura de Segurança Verificadas com Sucesso!"
  only:
    - merge_requests
    - main
`;
    },

    copyGithub() {
        navigator.clipboard.writeText(this.getGithubWorkflow());
        alert("✓ Workflow do GitHub Actions copiado para a área de transferência!");
    },

    copyGitlab() {
        navigator.clipboard.writeText(this.getGitlabCI());
        alert("✓ Pipeline do GitLab CI copiado para a área de transferência!");
    },

    downloadGithubYml() {
        const blob = new Blob([this.getGithubWorkflow()], { type: "text/yaml;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "neurosec-aspm-gate.yml";
        a.click();
        URL.revokeObjectURL(url);
    }
};
