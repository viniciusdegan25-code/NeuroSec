// NeuroSec Central de Varreduras (SAST, DAST, SCA, Cloud)
const NeuroScanners = {
    async runSast() {
        const input = document.getElementById("sastCodeInput");
        const code = input ? input.value : "";
        const filename = "snippet.py";

        if (!code.trim()) {
            NeuroUI.toast("Cole um trecho de código para análise SAST.", "error");
            return;
        }

        const box = document.getElementById("sastResultsBox");
        if (box) {
            box.style.display = "block";
            box.innerHTML = `<div style="color:var(--cyan-neon);">Analisando AST e padrões de vulnerabilidade com motor SAST...</div>`;
        }

        try {
            const res = await NeuroAPI.post("/scan/sast/snippet", { code, filename });
            NeuroUI.toast(`Scan SAST concluído: ${res.new_findings} nova(s) falha(s) identificada(s)!`, "success");
            this.renderScanResults(res.findings, "sastResultsBox");
            NeuroDashboard.refreshAll();
        } catch (err) {
            NeuroUI.toast("Falha na varredura SAST: " + err.message, "error");
        }
    },

    async runDast() {
        const input = document.getElementById("dastUrlInput");
        const url = input ? input.value.trim() : "";

        if (!url) {
            NeuroUI.toast("Informe uma URL válida para scan DAST.", "error");
            return;
        }

        const box = document.getElementById("dastResultsBox");
        if (box) {
            box.style.display = "block";
            box.innerHTML = `<div style="color:var(--cyan-neon);">Conectando ao alvo com Enterprise Browser Headers & auditoria RFC...</div>`;
        }

        try {
            const res = await NeuroAPI.post("/scan/dast/url", { url });
            NeuroUI.toast(`Reconhecimento DAST finalizado: ${res.new_findings} nova(s) brecha(s)!`, "success");
            this.renderScanResults(res.findings, "dastResultsBox");
            NeuroDashboard.refreshAll();
        } catch (err) {
            NeuroUI.toast("Falha ao analisar a URL: " + err.message, "error");
        }
    },

    async runSca() {
        const input = document.getElementById("scaInput");
        const content = input ? input.value : "";
        const filename = "requirements.txt";

        if (!content.trim()) {
            NeuroUI.toast("Insira o manifesto de dependências para análise SCA.", "error");
            return;
        }

        const box = document.getElementById("scaResultsBox");
        if (box) {
            box.style.display = "block";
            box.innerHTML = `<div style="color:var(--cyan-neon);">Cruzando dependências contra o banco de CVEs 2026...</div>`;
        }

        try {
            const res = await NeuroAPI.post("/scan/sca/file", { content, filename });
            NeuroUI.toast(`Scan SCA concluído: ${res.new_findings} pacote(s) vulnerável(is)!`, "success");
            this.renderScanResults(res.findings, "scaResultsBox");
            NeuroDashboard.refreshAll();
        } catch (err) {
            NeuroUI.toast("Falha ao auditar dependências: " + err.message, "error");
        }
    },

    async runCloud() {
        const input = document.getElementById("cloudInput");
        const config_text = input ? input.value : "";
        const provider = "AWS";

        if (!config_text.trim()) {
            NeuroUI.toast("Insira a configuração IaC (Terraform) para auditoria Cloud.", "error");
            return;
        }

        const box = document.getElementById("cloudResultsBox");
        if (box) {
            box.style.display = "block";
            box.innerHTML = `<div style="color:var(--cyan-neon);">Auditando postura de nuvem contra políticas IAM e S3...</div>`;
        }

        try {
            const res = await NeuroAPI.post("/scan/cloud/audit", { config_text, provider });
            NeuroUI.toast(`Auditoria Cloud finalizada: ${res.new_findings} desvios de postura!`, "success");
            this.renderScanResults(res.findings, "cloudResultsBox");
            NeuroDashboard.refreshAll();
        } catch (err) {
            NeuroUI.toast("Falha na auditoria de nuvem: " + err.message, "error");
        }
    },

    renderScanResults(findings, targetContainerId) {
        const box = document.getElementById(targetContainerId);
        if (!box) return;

        if (!findings || findings.length === 0) {
            box.innerHTML = `<div style="padding: 16px; color: var(--matrix-green); font-weight:600;">✨ Nenhuma vulnerabilidade encontrada. Ativo em total conformidade!</div>`;
            return;
        }

        let html = `<div style="display:flex; flex-direction:column; gap:10px; margin-top:14px;">`;
        findings.forEach(f => {
            let badgeStyle = "background:rgba(234,179,8,0.15); color:#EAB308; border:1px solid rgba(234,179,8,0.3);";
            if (f.severity === "CRITICAL") badgeStyle = "background:rgba(239,68,68,0.15); color:#EF4444; border:1px solid rgba(239,68,68,0.3);";
            if (f.severity === "HIGH") badgeStyle = "background:rgba(249,115,22,0.15); color:#F97316; border:1px solid rgba(249,115,22,0.3);";
            if (f.severity === "LOW") badgeStyle = "background:rgba(16,185,129,0.15); color:#10B981; border:1px solid rgba(16,185,129,0.3);";

            html += `
                <div class="pulse-card" style="padding:14px;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                        <span style="font-size:11px; font-weight:700; padding:3px 8px; border-radius:4px; ${badgeStyle}">${f.severity}</span>
                        <span style="font-size:12px; color:var(--text-dim); font-family:var(--font-mono);">${f.asset} ${f.line > 0 ? ':L' + f.line : ''}</span>
                    </div>
                    <div style="font-weight:700; font-size:14px; color:#ffffff; margin-bottom:4px;">${f.type}</div>
                    <div style="font-size:12px; color:var(--text-muted);">${f.description}</div>
                    ${f.code_snippet ? `<pre style="background:#040711; padding:8px; border-radius:6px; font-family:var(--font-mono); font-size:11px; color:#00FF41; margin-top:8px; overflow-x:auto;"><code>${f.code_snippet}</code></pre>` : ''}
                </div>
            `;
        });
        html += `</div>`;
        box.innerHTML = html;
    }
};

function loadSastSample(type) {
    const input = document.getElementById("sastCodeInput");
    if (!input) return;

    if (type === "sqli") {
        input.value = 'def login(user, password):\n    # Vulnerável: concatenação direta de query\n    query = f"SELECT * FROM users WHERE username=\'{user}\' AND pass=\'{password}\'"\n    cursor.execute(query)\n';
    } else if (type === "secrets") {
        input.value = 'class AWSConfig:\n    # Vulnerável: credenciais em texto plano\n    api_key = "AKIA-PROD-SECRET-KEY-2026"\n    db_password = "SuperSecretMasterPass!"\n';
    } else if (type === "rce") {
        input.value = 'import os\n\ndef run_diagnostics(target_ip):\n    # Vulnerável: injeção de comando shell\n    os.system(f"ping -c 4 {target_ip}")\n';
    }
}
