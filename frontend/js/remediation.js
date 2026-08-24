// AI Remediation Studio & Deep Dossier Engine
const NeuroRemediation = {
    currentVulnId: null,
    currentDossier: null,

    async loadDossierTab(internalId) {
        this.currentVulnId = internalId;
        
        // 1. Chaveia imediatamente para a aba dedicada de Dossiê
        if (typeof NeuroDashboard !== "undefined") {
            NeuroDashboard.switchTab("tab-dossier");
        }

        const titleEl = document.getElementById("dossierMainTitle");
        const tagEl = document.getElementById("dossierTagBadge");
        const contentEl = document.getElementById("dossierFullContent");

        if (titleEl) titleEl.innerText = `Carregando Dossiê Técnico #${internalId}...`;
        if (contentEl) {
            contentEl.innerHTML = `
                <div style="text-align:center; padding:60px; color:var(--matrix-green); font-family:var(--font-mono);">
                    <div class="cobra-badge" data-cobra-shield="36" style="margin:0 auto 18px auto;"></div>
                    <div style="font-size:16px; font-weight:700;">⚡ Gerando Dossiê Cognitivo com a NeuroSec IA...</div>
                    <div style="font-size:12px; color:var(--text-muted); margin-top:6px;">Calculando causa raiz CWE, exploit didático, matriz de mitigações e testes unitários.</div>
                </div>
            `;
        }

        try {
            const data = await NeuroAPI.get(`/remediate/${internalId}/dossier`);
            this.currentDossier = data;

            let badgeColor = "var(--crit-red)";
            if (data.severity === "HIGH") badgeColor = "var(--warn-orange)";
            if (data.severity === "MEDIUM") badgeColor = "var(--amber-gold)";

            if (titleEl) titleEl.innerText = `${data.vuln_type} — ID #${data.internal_id}`;
            if (tagEl) tagEl.innerText = `// DOSSIÊ TÉCNICO AUTÔNOMO // CVSS ${data.cvss_score} (${data.severity})`;

            if (contentEl) {
                contentEl.innerHTML = `
                    <!-- Header Meta Strip -->
                    <div style="display:flex; justify-content:space-between; align-items:center; background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); border-radius:8px; padding:14px 18px; margin-bottom:20px; flex-wrap:wrap; gap:12px;">
                        <div style="display:flex; align-items:center; gap:16px; font-family:var(--font-mono); font-size:12px;">
                            <span>📦 Ativo: <strong style="color:var(--cyan-neon);">${data.asset_name}</strong></span>
                            <span>🏷️ CVE: <strong style="color:#A5B4FC;">${data.cve_id}</strong></span>
                            <span>📋 OWASP: <strong style="color:#FDE047;">${data.owasp_category}</strong></span>
                            <span>🛡️ CWE: <strong style="color:#CBD5E1;">${data.cwe_id}</strong></span>
                        </div>
                        <div style="display:flex; align-items:center; gap:8px;">
                            <span style="font-size:11px; font-weight:800; padding:4px 10px; border-radius:4px; background:rgba(239,68,68,0.15); color:${badgeColor}; border:1px solid ${badgeColor};">
                                ${data.severity} (CVSS ${data.cvss_score})
                            </span>
                            <span style="font-size:11px; font-weight:700; padding:4px 10px; border-radius:4px; background:rgba(0,255,65,0.1); color:var(--matrix-green); border:1px solid rgba(0,255,65,0.3);">
                                STATUS: ${data.status.toUpperCase()}
                            </span>
                        </div>
                    </div>

                    <!-- Grid com as 5 Seções Estruturadas -->
                    <div style="display:flex; flex-direction:column; gap:16px;">
                        
                        <!-- 1. Causa Raiz & Diagnóstico Técnico -->
                        <div style="background:#07090E; border:1px solid var(--border-subtle); border-radius:8px; padding:18px;">
                            <div style="font-size:14px; font-weight:700; color:var(--matrix-green); margin-bottom:10px; display:flex; align-items:center; gap:8px;">
                                <span>🔍</span> <span>1. Diagnóstico de Causa Raiz & Falha de Projeto</span>
                            </div>
                            <div style="font-size:13px; color:#E2E8F0; line-height:1.6;">
                                ${this.formatMarkdown(data.diagnosis || "Vulnerabilidade identificada na esteira de código.")}
                            </div>
                        </div>

                        <!-- 2. Simulação de Exploit / PoC Didático -->
                        <div style="background:rgba(239,68,68,0.04); border:1px solid rgba(239,68,68,0.25); border-radius:8px; padding:18px;">
                            <div style="font-size:14px; font-weight:700; color:#EF4444; margin-bottom:10px; display:flex; align-items:center; gap:8px;">
                                <span>⚔️</span> <span>2. Simulação do Vetor de Exploração (Proof of Concept Didático)</span>
                            </div>
                            <div style="font-size:13px; color:#E2E8F0; margin-bottom:10px; line-height:1.5;">
                                ${data.poc_description}
                            </div>
                            <div style="background:#030712; border:1px solid rgba(239,68,68,0.3); border-radius:6px; padding:12px; font-family:var(--font-mono); font-size:12px; color:#FCA5A5;">
                                <span style="color:#94A3B8; display:block; font-size:10px; margin-bottom:4px;">// PAYLOAD DE TESTE DE SEGURANÇA</span>
                                <code>${this.escapeHtml(data.poc_payload)}</code>
                            </div>
                        </div>

                        <!-- 3. Matriz de 3 Estratégias de Mitigação -->
                        <div style="background:#07090E; border:1px solid var(--border-subtle); border-radius:8px; padding:18px;">
                            <div style="font-size:14px; font-weight:700; color:#FFFFFF; margin-bottom:14px; display:flex; align-items:center; gap:8px;">
                                <span>🛡️</span> <span>3. Matriz Comparativa de Abordagens de Mitigação</span>
                            </div>
                            <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:12px;">
                                <div style="padding:12px; background:rgba(0,255,65,0.05); border:1px solid rgba(0,255,65,0.25); border-radius:6px;">
                                    <div style="font-size:12px; font-weight:700; color:var(--matrix-green); margin-bottom:4px;">Estratégia 1: Hotfix de Código</div>
                                    <div style="font-size:12px; color:#CBD5E1; line-height:1.5;">${data.strategies.hotfix}</div>
                                </div>
                                <div style="padding:12px; background:rgba(99,102,241,0.05); border:1px solid rgba(99,102,241,0.25); border-radius:6px;">
                                    <div style="font-size:12px; font-weight:700; color:#A5B4FC; margin-bottom:4px;">Estratégia 2: Refatoração</div>
                                    <div style="font-size:12px; color:#CBD5E1; line-height:1.5;">${data.strategies.architecture}</div>
                                </div>
                                <div style="padding:12px; background:rgba(234,179,8,0.05); border:1px solid rgba(234,179,8,0.25); border-radius:6px;">
                                    <div style="font-size:12px; font-weight:700; color:#FDE047; margin-bottom:4px;">Estratégia 3: WAF & Nuvem</div>
                                    <div style="font-size:12px; color:#CBD5E1; line-height:1.5;">${data.strategies.infrastructure}</div>
                                </div>
                            </div>
                        </div>

                        <!-- 4. Patch de Código Seguro & Side-by-Side Diff -->
                        <div style="background:#07090E; border:1px solid var(--border-subtle); border-radius:8px; padding:18px;">
                            <div style="font-size:14px; font-weight:700; color:var(--matrix-green); margin-bottom:12px; display:flex; align-items:center; gap:8px;">
                                <span>💻</span> <span>4. Código Seguro Implementado & Unified Git Diff</span>
                            </div>
                            <div style="display:grid; grid-template-columns:1fr 1fr; gap:12px; margin-bottom:12px;">
                                <div>
                                    <div style="font-size:11px; font-weight:700; color:#EF4444; margin-bottom:4px; font-family:var(--font-mono);">❌ CÓDIGO VULNERÁVEL ORIGINAL</div>
                                    <div style="background:#030712; border:1px solid rgba(239,68,68,0.3); border-radius:6px; padding:10px; font-family:var(--font-mono); font-size:12px; color:#FCA5A5; overflow-x:auto;">
                                        <pre style="margin:0;">${this.escapeHtml(data.original_code)}</pre>
                                    </div>
                                </div>
                                <div>
                                    <div style="font-size:11px; font-weight:700; color:var(--matrix-green); margin-bottom:4px; font-family:var(--font-mono);">✓ CÓDIGO BLINDADO (PATCH IA)</div>
                                    <div style="background:#030712; border:1px solid rgba(0,255,65,0.3); border-radius:6px; padding:10px; font-family:var(--font-mono); font-size:12px; color:#86EFAC; overflow-x:auto;">
                                        <pre style="margin:0;">${this.escapeHtml(data.fixed_code)}</pre>
                                    </div>
                                </div>
                            </div>
                        </div>

                        <!-- 5. Teste Unitário Defensivo -->
                        <div style="background:#07090E; border:1px solid var(--border-subtle); border-radius:8px; padding:18px;">
                            <div style="font-size:14px; font-weight:700; color:var(--cyan-neon); margin-bottom:10px; display:flex; align-items:center; gap:8px;">
                                <span>🧪</span> <span>5. Teste Automatizado de Regressão Defensiva (Pytest / Jest)</span>
                            </div>
                            <div style="background:#030712; border:1px solid var(--border-subtle); border-radius:6px; padding:12px; font-family:var(--font-mono); font-size:12px; color:#A5B4FC; overflow-x:auto;">
                                <pre style="margin:0;">${this.escapeHtml(data.unit_test_code)}</pre>
                            </div>
                        </div>
                    </div>
                `;
            }
        } catch (err) {
            if (contentEl) contentEl.innerHTML = `<div style="color:var(--crit-red); padding:30px;">Erro ao gerar Dossiê: ${err.message}</div>`;
        }
    },

    async openDossierModal(internalId) {
        // Redireciona diretamente para a aba dedicada sem abrir modal pop-up
        this.loadDossierTab(internalId);
    },

    async openModal(internalId) {
        // Redireciona diretamente para a aba dedicada
        this.loadDossierTab(internalId);
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
