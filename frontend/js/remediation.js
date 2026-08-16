// AI Remediation Studio & Deep Dossier Engine
const NeuroRemediation = {
    currentVulnId: null,
    currentDossier: null,

    async openModal(internalId) {
        this.currentVulnId = internalId;
        const modal = document.getElementById("remediationModal");
        if (!modal) return;

        modal.classList.add("open");

        // Preenche com loading
        document.getElementById("modalVulnTitle").innerText = `Remediação Inteligente com NeuroSec IA — ID #${internalId}`;
        document.getElementById("modalDiagnosisBox").innerHTML = `<div style="color:var(--matrix-green); font-family:var(--font-mono);">⚡ Conectando à NeuroSec IA para análise de causa raiz e geração do Unified Diff...</div>`;
        document.getElementById("modalDiffContainer").innerHTML = `<div style="color:var(--text-muted);">Aguardando geração do patch...</div>`;
        
        try {
            const res = await NeuroAPI.post(`/remediate/${internalId}`, { internal_id: internalId });
            
            // Diagnóstico
            document.getElementById("modalDiagnosisBox").innerHTML = `
                <div style="font-size:13px; line-height:1.6; color:#e2e8f0; white-space:pre-wrap;">${this.formatMarkdown(res.diagnosis)}</div>
            `;

            // Renderiza Diff
            this.renderDiff(res.diff);

            if (typeof NeuroUI !== "undefined") {
                NeuroUI.toast("Patch de segurança gerado com sucesso pela NeuroSec IA!", "success");
            }
        } catch (err) {
            document.getElementById("modalDiagnosisBox").innerHTML = `<div style="color:var(--crit-red);">Erro ao gerar remediação: ${err.message}</div>`;
        }
    },

    async openDossierModal(internalId) {
        this.currentVulnId = internalId;
        const modal = document.getElementById("dossierModal");
        if (!modal) return;

        modal.classList.add("open");

        const bodyEl = document.getElementById("dossierModalBody");
        if (bodyEl) {
            bodyEl.innerHTML = `<div style="text-align:center; padding:50px; color:var(--matrix-green); font-family:var(--font-mono);">⚡ Compilando Dossiê Técnico Completo de Causa Raiz, Vetor de Exploit e Mitigações com a NeuroSec IA...</div>`;
        }

        try {
            const data = await NeuroAPI.get(`/remediate/${internalId}/dossier`);
            this.currentDossier = data;

            let badgeStyle = "background:rgba(239,68,68,0.15); color:#EF4444; border:1px solid rgba(239,68,68,0.3);";
            if (data.severity === "HIGH") badgeStyle = "background:rgba(249,115,22,0.15); color:#F97316; border:1px solid rgba(249,115,22,0.3);";
            if (data.severity === "MEDIUM") badgeStyle = "background:rgba(234,179,8,0.15); color:#EAB308; border:1px solid rgba(234,179,8,0.3);";

            bodyEl.innerHTML = `
                <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:20px; border-bottom:1px solid var(--border-subtle); padding-bottom:16px;">
                    <div>
                        <div style="font-size:11px; font-weight:700; color:var(--matrix-green); text-transform:uppercase; letter-spacing:0.1em; margin-bottom:4px;">// DOSSIÊ TÉCNICO DE RESOLUÇÃO AUTÔNOMA</div>
                        <h2 style="font-size:20px; font-weight:800; color:#fff;">${data.vuln_type}</h2>
                        <div style="font-size:13px; color:var(--text-muted); font-family:var(--font-mono); margin-top:4px;">Ativo: <span style="color:#00F0FF;">${data.asset_name}</span> | CVE: <span style="color:#A5B4FC;">${data.cve_id}</span></div>
                    </div>
                    <span style="font-size:12px; font-weight:700; padding:4px 10px; border-radius:6px; ${badgeStyle}">${data.severity}</span>
                </div>

                <!-- Accordion 1: Causa Raiz & Classificação -->
                <div style="background:rgba(17,24,39,0.7); border:1px solid var(--border-subtle); border-radius:10px; padding:16px; margin-bottom:14px;">
                    <div style="font-size:14px; font-weight:700; color:var(--matrix-green); margin-bottom:8px;">1. Diagnóstico & Causa Raiz da Falha</div>
                    <div style="font-size:13px; color:#cbd5e1; line-height:1.6;">
                        A vulnerabilidade decorre da falta de sanitização e ausência de controles defensivos estritos. 
                        Classificação <strong>${data.owasp_category}</strong> e padrão <strong>${data.cwe_id}</strong>.
                    </div>
                </div>

                <!-- Accordion 2: Simulação do Vetor de Ataque (PoC Exploit) -->
                <div style="background:rgba(239,68,68,0.06); border:1px solid rgba(239,68,68,0.25); border-radius:10px; padding:16px; margin-bottom:14px;">
                    <div style="font-size:14px; font-weight:700; color:#EF4444; margin-bottom:8px;">🚨 2. Simulação do Vetor de Ataque (Proof of Concept Didático)</div>
                    <div style="font-size:13px; color:#e2e8f0; margin-bottom:8px;">${data.poc_description}</div>
                    <div style="background:#07090E; border:1px solid rgba(239,68,68,0.3); border-radius:6px; padding:10px 14px; font-family:var(--font-mono); font-size:12px; color:#FCA5A5;">
                        <strong>Payload de Exploração Simulado:</strong> <code>${this.escapeHtml(data.poc_payload)}</code>
                    </div>
                </div>

                <!-- Accordion 3: Matriz de 3 Estratégias de Mitigação -->
                <div style="background:rgba(17,24,39,0.7); border:1px solid var(--border-subtle); border-radius:10px; padding:16px; margin-bottom:14px;">
                    <div style="font-size:14px; font-weight:700; color:#FFFFFF; margin-bottom:12px;">🛡️ 3. Matriz de Abordagens de Mitigação</div>
                    <div style="display:flex; flex-direction:column; gap:10px; font-size:13px;">
                        <div style="padding:10px 12px; background:rgba(0,255,65,0.06); border-left:3px solid var(--matrix-green); border-radius:4px;">
                            <strong style="color:var(--matrix-green);">🔹 Estratégia 1 (Hotfix de Código Imediato):</strong>
                            <div style="color:#cbd5e1; margin-top:2px;">${data.strategies.hotfix}</div>
                        </div>
                        <div style="padding:10px 12px; background:rgba(99,102,241,0.06); border-left:3px solid var(--indigo-ai); border-radius:4px;">
                            <strong style="color:#A5B4FC;">🔹 Estratégia 2 (Refatoração de Arquitetura):</strong>
                            <div style="color:#cbd5e1; margin-top:2px;">${data.strategies.architecture}</div>
                        </div>
                        <div style="padding:10px 12px; background:rgba(245,158,11,0.06); border-left:3px solid var(--warn-orange); border-radius:4px;">
                            <strong style="color:#FDE047;">🔹 Estratégia 3 (Defesa em Profundidade / WAF & Infra):</strong>
                            <div style="color:#cbd5e1; margin-top:2px;">${data.strategies.infrastructure}</div>
                        </div>
                    </div>
                </div>

                <!-- Accordion 4: Código Corrigido e Unified Diff -->
                <div style="background:rgba(17,24,39,0.7); border:1px solid var(--border-subtle); border-radius:10px; padding:16px; margin-bottom:14px;">
                    <div style="font-size:14px; font-weight:700; color:var(--matrix-green); margin-bottom:8px;">💻 4. Patch de Código Blindado & Unified Diff</div>
                    <div style="background:#07090E; border:1px solid var(--border-subtle); border-radius:6px; padding:12px; overflow-x:auto;">
                        <pre style="font-family:var(--font-mono); font-size:12px; color:#A7F3D0; margin:0;">${this.escapeHtml(data.fixed_code)}</pre>
                    </div>
                </div>

                <!-- Accordion 5: Teste Unitário Defensivo -->
                <div style="background:rgba(17,24,39,0.7); border:1px solid var(--border-subtle); border-radius:10px; padding:16px; margin-bottom:14px;">
                    <div style="font-size:14px; font-weight:700; color:#00F0FF; margin-bottom:8px;">🧪 5. Teste Unitário Defensivo (Validação Automatizada)</div>
                    <div style="background:#07090E; border:1px solid var(--border-subtle); border-radius:6px; padding:12px; overflow-x:auto;">
                        <pre style="font-family:var(--font-mono); font-size:12px; color:#E2E8F0; margin:0;">${this.escapeHtml(data.unit_test_code)}</pre>
                    </div>
                </div>
            `;
        } catch (err) {
            bodyEl.innerHTML = `<div style="color:var(--crit-red); padding:30px;">Erro ao carregar dossiê técnico: ${err.message}</div>`;
        }
    },

    downloadDossierMarkdown() {
        if (!this.currentDossier || !this.currentDossier.markdown_dossier) return;
        const blob = new Blob([this.currentDossier.markdown_dossier], { type: "text/markdown;charset=utf-8" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `dossie_tecnico_neurosec_id_${this.currentVulnId}.md`;
        a.click();
        URL.revokeObjectURL(url);
    },

    renderDiff(diffText) {
        const container = document.getElementById("modalDiffContainer");
        if (!container) return;

        if (!diffText) {
            container.innerHTML = `<div style="color:var(--text-muted);">Nenhuma alteração de diff disponível.</div>`;
            return;
        }

        const lines = diffText.split("\n");
        let html = `<div style="background:#07090E; border:1px solid var(--border-subtle); border-radius:8px; padding:12px; font-family:var(--font-mono); font-size:12px; line-height:1.5; max-height:280px; overflow-y:auto;">`;
        lines.forEach(line => {
            if (line.startsWith("+") && !line.startsWith("+++")) {
                html += `<div style="background:rgba(0,255,65,0.15); color:#00FF41; padding:2px 6px;">${this.escapeHtml(line)}</div>`;
            } else if (line.startsWith("-") && !line.startsWith("---")) {
                html += `<div style="background:rgba(239,68,68,0.15); color:#EF4444; padding:2px 6px;">${this.escapeHtml(line)}</div>`;
            } else if (line.startsWith("@@")) {
                html += `<div style="color:#00F0FF; padding:2px 6px; font-weight:700;">${this.escapeHtml(line)}</div>`;
            } else {
                html += `<div style="color:#94A3B8; padding:2px 6px;">${this.escapeHtml(line)}</div>`;
            }
        });
        html += `</div>`;
        container.innerHTML = html;
    },

    async approveCurrent() {
        if (!this.currentVulnId) return;

        try {
            await NeuroAPI.post(`/remediate/${this.currentVulnId}/approve`, {});
            this.closeModal();
            this.closeDossierModal();

            if (typeof NeuroInventory !== "undefined") await NeuroInventory.render();
            if (typeof NeuroScorecard !== "undefined") await NeuroScorecard.render();
            if (typeof NeuroAudit !== "undefined") await NeuroAudit.render();

            alert(`✓ Patch #${this.currentVulnId} aprovado e aplicado com sucesso! Postura de segurança atualizada.`);
        } catch (err) {
            alert(`Erro ao aprovar patch: ${err.message}`);
        }
    },

    async approveDirect(internalId) {
        try {
            await NeuroAPI.post(`/remediate/${internalId}/approve`, {});
            if (typeof NeuroInventory !== "undefined") await NeuroInventory.render();
            if (typeof NeuroScorecard !== "undefined") await NeuroScorecard.render();
            if (typeof NeuroAudit !== "undefined") await NeuroAudit.render();

            alert(`✓ Vulnerabilidade #${internalId} aprovada e remediada.`);
        } catch (err) {
            alert(`Erro ao aprovar: ${err.message}`);
        }
    },

    closeModal() {
        const modal = document.getElementById("remediationModal");
        if (modal) modal.classList.remove("open");
    },

    closeDossierModal() {
        const modal = document.getElementById("dossierModal");
        if (modal) modal.classList.remove("open");
    },

    formatMarkdown(text) {
        if (!text) return "";
        return text
            .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
            .replace(/`([^`]+)`/g, '<code style="background:rgba(255,255,255,0.08); padding:2px 6px; border-radius:4px; font-family:var(--font-mono); color:var(--matrix-green);">$1</code>');
    },

    escapeHtml(str) {
        if (!str) return "";
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }
};
