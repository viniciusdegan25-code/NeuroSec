// AI Remediation Studio & Diff Approver
const NeuroRemediation = {
    currentVulnId: null,

    async openModal(internalId) {
        this.currentVulnId = internalId;
        const modal = document.getElementById("remediationModal");
        if (!modal) return;

        modal.classList.add("open");

        // Preenche com loading
        document.getElementById("modalVulnTitle").innerText = `Análise e Remediação com NeuroSec IA — ID #${internalId}`;
        document.getElementById("modalDiagnosisBox").innerHTML = `<div style="color:var(--cyan-neon);">Conectando à NeuroSec IA para diagnóstico e geração de patch...</div>`;
        document.getElementById("modalDiffContainer").innerHTML = `<div style="color:var(--text-muted);">Aguardando geração do patch...</div>`;
        
        try {
            const res = await NeuroAPI.post(`/remediate/${internalId}`, { internal_id: internalId });
            
            // Diagnóstico
            document.getElementById("modalDiagnosisBox").innerHTML = `
                <div style="font-size:13px; line-height:1.6; color:#e2e8f0; white-space:pre-wrap;">${this.formatMarkdown(res.diagnosis)}</div>
            `;

            // Renderiza Diff
            this.renderDiff(res.diff);

            NeuroUI.toast("Patch de segurança gerado com sucesso pela NeuroSec IA!", "success");
        } catch (err) {
            document.getElementById("modalDiagnosisBox").innerHTML = `<div style="color:var(--crimson-crit);">Erro ao gerar remediação: ${err.message}</div>`;
        }
    },

    renderDiff(diffText) {
        const container = document.getElementById("modalDiffContainer");
        if (!container) return;

        if (!diffText) {
            container.innerHTML = `<div style="color:var(--text-muted);">Nenhuma alteração de diff disponível.</div>`;
            return;
        }

        const lines = diffText.split("\n");
        let html = `<div class="diff-container">`;
        lines.forEach(line => {
            if (line.startsWith("+") && !line.startsWith("+++")) {
                html += `<div class="diff-line diff-add">${this.escapeHtml(line)}</div>`;
            } else if (line.startsWith("-") && !line.startsWith("---")) {
                html += `<div class="diff-line diff-del">${this.escapeHtml(line)}</div>`;
            } else if (line.startsWith("@@")) {
                html += `<div class="diff-line diff-info">${this.escapeHtml(line)}</div>`;
            } else {
                html += `<div class="diff-line">${this.escapeHtml(line)}</div>`;
            }
        });
        html += `</div>`;
        container.innerHTML = html;
    },

    async approveCurrent() {
        if (!this.currentVulnId) return;
        const operator = document.getElementById("remediationOperatorInput")?.value || "SecOps Lead";
        
        try {
            await NeuroAPI.post(`/remediate/${this.currentVulnId}/approve?operator=${encodeURIComponent(operator)}`);
            NeuroUI.toast(`Patch #${this.currentVulnId} aprovado e registrado em auditoria!`, "success");
            this.closeModal();
            NeuroApp.refreshAll();
        } catch (err) {
            NeuroUI.toast("Falha ao aprovar patch.", "error");
        }
    },

    async approveDirect(internalId) {
        try {
            await NeuroAPI.post(`/remediate/${internalId}/approve?operator=SecOps%20Lead`);
            NeuroUI.toast(`Patch #${internalId} aprovado com sucesso!`, "success");
            NeuroApp.refreshAll();
        } catch (err) {
            NeuroUI.toast("Falha ao aprovar.", "error");
        }
    },

    closeModal() {
        const modal = document.getElementById("remediationModal");
        if (modal) modal.classList.remove("open");
    },

    escapeHtml(str) {
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    },

    formatMarkdown(text) {
        if (!text) return "";
        let escaped = this.escapeHtml(text);
        escaped = escaped.replace(/```([\s\S]*?)```/g, '<pre style="background:rgba(0,0,0,0.5); padding:8px; border-radius:6px; font-family:monospace; margin:6px 0; overflow-x:auto;"><code>$1</code></pre>');
        escaped = escaped.replace(/`([^`]+)`/g, '<code style="background:rgba(0,0,0,0.4); padding:2px 5px; border-radius:4px; font-family:monospace; color:var(--cyan-neon);">$1</code>');
        escaped = escaped.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
        escaped = escaped.replace(/\n/g, '<br>');
        return escaped;
    }
};
