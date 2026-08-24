// NeuroSec ASPM 4.5 — Gestão de Clientes & Cockpit 360° Unificado (Multi-Tenant Hub)
const NeuroClients = {
    allClients: [],
    currentClientId: null,

    async render() {
        try {
            const summary = await NeuroAPI.get("/clients/summary");
            if (!summary) return;

            this.allClients = summary.clients || [];

            // 1. Renderiza KPIs Executivos com Métricas Financeiras
            const totalEl = document.getElementById("clientStatTotal");
            if (totalEl) totalEl.innerText = summary.total_clients;

            const lossAvoidedEl = document.getElementById("clientStatLossAvoided");
            if (lossAvoidedEl) {
                lossAvoidedEl.innerText = `R$ ${summary.total_financial_loss_avoided_brl.toLocaleString('pt-BR', { minimumFractionDigits: 2 })}`;
            }

            const exposureEl = document.getElementById("clientStatExposure");
            if (exposureEl) {
                exposureEl.innerText = `R$ ${summary.total_financial_exposure_risk_brl.toLocaleString('pt-BR', { minimumFractionDigits: 2 })}`;
            }

            const avgScoreEl = document.getElementById("clientStatAvgScore");
            if (avgScoreEl) {
                avgScoreEl.innerText = `${summary.average_score}/100`;
                avgScoreEl.style.color = summary.average_score >= 80 ? "var(--matrix-green)" : (summary.average_score >= 60 ? "var(--warn-orange)" : "var(--crit-red)");
            }

            // 2. Renderiza Tabela Dinâmica com Botão Único 360°
            this.filterAndRenderTable();

            // 3. Renderiza Diretório de Usuários / CISOs
            this.renderUsersList();
        } catch (err) {
            console.error("Erro ao carregar clientes:", err);
        }
    },

    filter() {
        this.filterAndRenderTable();
    },

    filterAndRenderTable() {
        const searchVal = (document.getElementById("clientSearchInput")?.value || "").toLowerCase();
        const industryVal = document.getElementById("clientIndustryFilter")?.value || "ALL";
        const slaVal = document.getElementById("clientSlaFilter")?.value || "ALL";

        const tbody = document.getElementById("clientsTableBody");
        if (!tbody) return;

        const filtered = this.allClients.filter(c => {
            const matchSearch = c.name.toLowerCase().includes(searchVal) ||
                                (c.cnpj && c.cnpj.toLowerCase().includes(searchVal)) ||
                                c.contact_name.toLowerCase().includes(searchVal) ||
                                c.contact_email.toLowerCase().includes(searchVal);
            const matchInd = industryVal === "ALL" || c.industry === industryVal;
            const matchSla = slaVal === "ALL" || c.sla_tier === slaVal;
            return matchSearch && matchInd && matchSla;
        });

        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">Nenhum cliente corporativo encontrado com os filtros selecionados.</td></tr>`;
            return;
        }

        tbody.innerHTML = filtered.map(c => {
            let scoreColor = "var(--matrix-green)";
            if (c.security_score < 75) scoreColor = "var(--warn-orange)";
            if (c.security_score < 50) scoreColor = "var(--crit-red)";

            const revenueFormatted = (c.annual_revenue_brl || 50000000).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL', maximumFractionDigits: 0 });
            const recordsFormatted = (c.sensitive_records_count || 100000).toLocaleString('pt-BR');
            const exposureFormatted = (c.financial_exposure_risk_brl || 0).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
            const lossAvoidedFormatted = (c.financial_loss_avoided_brl || 0).toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });

            return `
                <tr style="border-bottom: 1px solid var(--border-subtle);">
                    <td style="padding:16px 12px;">
                        <div style="font-weight:800; color:#fff; font-size:14px;">${c.name}</div>
                        <div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono); margin-top:2px;">
                            CNPJ: ${c.cnpj || 'N/A'} | Setor: <span style="color:var(--cyan-neon); font-weight:600;">${c.industry}</span>
                        </div>
                    </td>
                    <td style="padding:16px 12px;">
                        <div style="color:#E2E8F0; font-size:13px; font-weight:600;">${c.contact_name}</div>
                        <div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono);">${c.contact_email}</div>
                    </td>
                    <td style="padding:16px 12px;">
                        <div style="font-family:var(--font-mono); font-size:12px; color:#FDE047; font-weight:700;">${revenueFormatted}/ano</div>
                        <div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono); margin-top:2px;">👥 ${recordsFormatted} titulares LGPD</div>
                    </td>
                    <td style="padding:16px 12px;">
                        <div style="font-family:var(--font-mono); font-size:13px; font-weight:800; color:#EF4444;">${exposureFormatted}</div>
                        <div style="font-size:10px; color:var(--text-muted); font-family:var(--font-mono);">${c.open_vulns_count} falhas ativas</div>
                    </td>
                    <td style="padding:16px 12px;">
                        <div style="font-family:var(--font-mono); font-size:13px; font-weight:800; color:var(--matrix-green);">${lossAvoidedFormatted}</div>
                        <div style="font-size:10px; color:var(--text-muted); font-family:var(--font-mono);">Economia por remediação</div>
                    </td>
                    <td style="padding:16px 12px; text-align:center;">
                        <span style="font-family:var(--font-mono); font-size:18px; font-weight:900; color:${scoreColor};">${c.security_score}</span>
                        <span style="font-size:11px; color:var(--text-muted);">/100</span>
                    </td>
                    <td style="padding:16px 12px; text-align:right;">
                        <div style="display:inline-flex; gap:8px; align-items:center;">
                            <button class="btn-primary-matrix" style="padding:7px 14px; font-size:12px; font-weight:700; display:flex; align-items:center; gap:6px; box-shadow:0 0 10px rgba(0,255,65,0.2);" onclick="NeuroClients.openClientCockpit(${c.id})" title="Acessar o Painel Executivo 360°, Scorecard e Dossiê Financeiro">
                                <span>📊</span>
                                <span>Acessar Cockpit 360°</span>
                            </button>
                            <button class="btn-secondary-dark" style="padding:7px 10px; font-size:12px; color:#EF4444; border-color:rgba(239,68,68,0.3);" onclick="NeuroClients.deleteClient(${c.id}, '${c.name}')" title="Excluir Organização">
                                🗑️
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join("");
    },

    renderUsersList() {
        const container = document.getElementById("clientUsersList");
        if (!container) return;

        if (!this.allClients || this.allClients.length === 0) {
            container.innerHTML = `<div style="color:var(--text-muted); font-size:12px;">Nenhum usuário CISO registrado.</div>`;
            return;
        }

        container.innerHTML = this.allClients.map(c => `
            <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); border-radius:8px; padding:14px; display:flex; flex-direction:column; gap:6px;">
                <div style="display:flex; justify-content:space-between; align-items:flex-start;">
                    <div style="font-weight:700; color:#fff; font-size:13px;">${c.contact_name}</div>
                    <span style="font-size:10px; font-weight:700; padding:2px 6px; border-radius:4px; background:rgba(0,255,65,0.1); color:var(--matrix-green); border:1px solid rgba(0,255,65,0.25);">CISO LEAD</span>
                </div>
                <div style="font-size:11px; color:var(--cyan-neon); font-family:var(--font-mono);">${c.contact_email}</div>
                <div style="font-size:11px; color:var(--text-muted);">🏢 ${c.name}</div>
                <div style="font-size:10px; color:var(--text-dim); margin-top:4px;">SLA: ${c.sla_tier} | Telefone: ${c.contact_phone || '+55 (11) 90000-0000'}</div>
            </div>
        `).join("");
    },

    async openClientCockpit(clientId) {
        this.currentClientId = clientId;
        const portfolioSec = document.getElementById("clientPortfolioSection");
        const cockpitSec = document.getElementById("clientCockpitSection");

        if (portfolioSec) portfolioSec.style.display = "none";
        if (cockpitSec) {
            cockpitSec.style.display = "block";
            cockpitSec.scrollIntoView({ behavior: "smooth", block: "start" });
        }

        try {
            NeuroUI.toast("Carregando Cockpit 360° e Dossiê Financeiro...", "info");
            const [clientData, finData] = await Promise.all([
                NeuroAPI.get(`/clients/${clientId}`),
                NeuroAPI.get(`/clients/${clientId}/financial-analysis`)
            ]);

            const c = clientData.client;
            const assets = clientData.assets || [];
            const vulns = clientData.vulnerabilities || [];

            // 1. Preenche Banner de Perfil Corporativo
            document.getElementById("cockpitClientName").innerText = c.name;
            document.getElementById("cockpitClientCnpj").innerText = c.cnpj || 'N/A';
            document.getElementById("cockpitClientIndustry").innerText = c.industry;
            document.getElementById("cockpitClientSla").innerText = c.sla_tier;
            document.getElementById("cockpitContactName").innerText = c.contact_name;
            document.getElementById("cockpitContactEmail").innerText = c.contact_email;
            document.getElementById("cockpitContactPhone").innerText = c.contact_phone || '+55 (11) 90000-0000';

            // 2. Scorecard Gauge & Classificação
            const scoreDisplay = document.getElementById("cockpitScoreDisplay");
            const gradeDisplay = document.getElementById("cockpitGradeDisplay");
            const postureStatus = document.getElementById("cockpitPostureStatus");

            if (scoreDisplay) scoreDisplay.innerText = finData.security_score;
            if (gradeDisplay) {
                gradeDisplay.innerText = `Classificação: Nível ${finData.grade}`;
                const gradeColor = finData.security_score >= 80 ? "var(--matrix-green)" : (finData.security_score >= 60 ? "var(--warn-orange)" : "#EF4444");
                scoreDisplay.style.color = gradeColor;
                gradeDisplay.style.color = gradeColor;
            }
            if (postureStatus) {
                postureStatus.innerText = finData.security_score >= 80 ? "Postura Forte & Blindada" : (finData.security_score >= 60 ? "Postura Moderada (Atenção)" : "Risco Crítico Imediato");
            }

            // 3. Big KPIs
            document.getElementById("cockpitLossAvoided").innerText = finData.financial_loss_avoided_brl.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
            document.getElementById("cockpitRemediatedCount").innerText = finData.remediated_vulns_count;

            document.getElementById("cockpitExposure").innerText = finData.financial_exposure_risk_brl.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
            document.getElementById("cockpitOpenVulnsCount").innerText = finData.open_vulns_count;

            document.getElementById("cockpitAssetsCount").innerText = assets.length;
            document.getElementById("cockpitAnnualRevenue").innerText = finData.annual_revenue_brl.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL', maximumFractionDigits: 0 });
            document.getElementById("cockpitSensitiveRecords").innerText = finData.sensitive_records_count.toLocaleString('pt-BR');

            // 4. Decomposição das Perdas por Vetor (FAIR/NIST/LGPD)
            const vectorsContainer = document.getElementById("cockpitFinancialVectors");
            if (vectorsContainer) {
                vectorsContainer.innerHTML = `
                    <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); padding:14px; border-radius:8px;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span style="font-size:12px; font-weight:700; color:#E2E8F0;">1. Risco LGPD (Vazamento)</span>
                            <span style="font-family:var(--font-mono); font-weight:800; color:#EF4444; font-size:13px;">${finData.data_breach_risk_brl.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' })}</span>
                        </div>
                        <p style="font-size:11px; color:var(--text-muted); margin-top:4px;">Custo médio setorial de R$ ${finData.cost_per_record_brl.toFixed(2)} por registro vazado (${c.industry}).</p>
                    </div>

                    <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); padding:14px; border-radius:8px;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span style="font-size:12px; font-weight:700; color:#E2E8F0;">2. Risco de Interrupção / Downtime</span>
                            <span style="font-family:var(--font-mono); font-weight:800; color:#F97316; font-size:13px;">${finData.downtime_risk_brl.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' })}</span>
                        </div>
                        <p style="font-size:11px; color:var(--text-muted); margin-top:4px;">Custo de paralisação de R$ ${finData.downtime_cost_per_hour.toLocaleString('pt-BR')}/hora por RCE ou Cloud.</p>
                    </div>

                    <div style="background:rgba(255,255,255,0.02); border:1px solid var(--border-subtle); padding:14px; border-radius:8px;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <span style="font-size:12px; font-weight:700; color:#E2E8F0;">3. Sanções & Multas Regulatórias</span>
                            <span style="font-family:var(--font-mono); font-weight:800; color:#EAB308; font-size:13px;">${finData.regulatory_fine_risk_brl.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' })}</span>
                        </div>
                        <p style="font-size:11px; color:var(--text-muted); margin-top:4px;">Proporcional ao faturamento com teto legal de R$ 50 Milhões (ANPD / BACEN).</p>
                    </div>
                `;
            }

            // 5. Ativos Monitorados
            document.getElementById("cockpitAssetsHeaderCount").innerText = `${assets.length} ativos`;
            const assetsList = document.getElementById("cockpitAssetsList");
            if (assetsList) {
                assetsList.innerHTML = assets.length > 0 ? assets.map(a => `
                    <div style="display:flex; justify-content:space-between; align-items:center; background:#030712; border:1px solid var(--border-subtle); padding:10px 14px; border-radius:6px; font-family:var(--font-mono); font-size:12px;">
                        <div style="display:flex; align-items:center; gap:8px;">
                            <span style="color:#00F0FF;">${a.name}</span>
                        </div>
                        <span style="color:var(--text-muted); font-size:11px; background:rgba(255,255,255,0.04); padding:2px 8px; border-radius:4px;">[${a.asset_type}] ${a.criticality}</span>
                    </div>
                `).join("") : `<div style="color:var(--text-muted); font-size:12px; padding:10px;">Nenhum ativo associado diretamente.</div>`;
            }

            // 6. Vulnerabilidades Detectadas
            document.getElementById("cockpitVulnsHeaderCount").innerText = `${vulns.length} falhas`;
            const vulnsList = document.getElementById("cockpitVulnsList");
            if (vulnsList) {
                vulnsList.innerHTML = vulns.length > 0 ? vulns.map(v => `
                    <div style="display:flex; justify-content:space-between; align-items:center; background:#030712; border:1px solid var(--border-subtle); padding:10px 14px; border-radius:6px; font-size:12px;">
                        <div>
                            <div style="color:#fff; font-weight:700;">${v.vuln_type}</div>
                            <span style="display:block; font-size:11px; color:var(--text-muted); font-family:var(--font-mono); margin-top:2px;">${v.asset_name}</span>
                        </div>
                        <div style="text-align:right;">
                            <span style="font-size:11px; font-weight:700; color:${v.severity === 'CRITICAL' ? '#EF4444' : (v.severity === 'HIGH' ? '#F97316' : '#EAB308')};">${v.severity}</span>
                            <span style="display:block; font-size:10px; color:var(--text-dim); text-transform:uppercase;">${v.status}</span>
                        </div>
                    </div>
                `).join("") : `<div style="color:var(--matrix-green); font-size:12px; padding:10px; font-weight:700;">✓ Nenhuma vulnerabilidade crítica pendente para esta organização.</div>`;
            }

        } catch (err) {
            NeuroUI.toast("Erro ao carregar Cockpit 360°: " + err.message, "error");
        }
    },

    closeClientCockpit() {
        this.currentClientId = null;
        const portfolioSec = document.getElementById("clientPortfolioSection");
        const cockpitSec = document.getElementById("clientCockpitSection");

        if (cockpitSec) cockpitSec.style.display = "none";
        if (portfolioSec) {
            portfolioSec.style.display = "block";
            portfolioSec.scrollIntoView({ behavior: "smooth", block: "start" });
        }
        this.render();
    },

    async triggerCockpitScan() {
        if (!this.currentClientId) return;
        const btn = document.getElementById("btnCockpitTriggerScan");
        if (btn) btn.disabled = true;

        try {
            NeuroUI.toast("Iniciando varredura profunda de segurança (SAST, DAST, SCA, Cloud)...", "info");
            const res = await NeuroAPI.post(`/clients/${this.currentClientId}/scan`, {});
            NeuroUI.toast(res.message, "success");
            await this.openClientCockpit(this.currentClientId);
        } catch (err) {
            NeuroUI.toast("Erro na varredura: " + err.message, "error");
        } finally {
            if (btn) btn.disabled = false;
        }
    },

    exportCurrentClientReport() {
        if (!this.currentClientId) return;
        const clientName = document.getElementById("cockpitClientName")?.innerText || "Cliente";
        window.open(`/api/v1/reports/export/pdf`, "_blank");
        NeuroUI.toast(`Gerando Dossiê Executivo de Postura em PDF para '${clientName}'...`, "success");
    },

    toggleCreateForm(forceState) {
        const card = document.getElementById("clientInlineCreateCard");
        const btnText = document.getElementById("btnToggleCreateText");
        if (!card) return;

        const isVisible = card.style.display !== "none";
        const newState = forceState !== undefined ? forceState : !isVisible;

        card.style.display = newState ? "block" : "none";
        if (btnText) {
            btnText.innerText = newState ? "✕ Fechar Formulário" : "+ Cadastrar Nova Empresa";
        }

        if (newState) {
            card.scrollIntoView({ behavior: "smooth", block: "start" });
        }
    },

    toggleUsersSection() {
        const sec = document.getElementById("clientUsersSection");
        if (sec) {
            sec.scrollIntoView({ behavior: "smooth", block: "center" });
        }
    },

    async saveClient() {
        const name = document.getElementById("clientFormName")?.value.trim();
        const cnpj = document.getElementById("clientFormCnpj")?.value.trim();
        const contact_name = document.getElementById("clientFormContactName")?.value.trim();
        const contact_email = document.getElementById("clientFormContactEmail")?.value.trim();
        const contact_phone = document.getElementById("clientFormContactPhone")?.value.trim();
        const sla_tier = document.getElementById("clientFormSla")?.value;
        const industry = document.getElementById("clientFormIndustry")?.value;
        const annual_revenue_brl = parseFloat(document.getElementById("clientFormRevenue")?.value || "50000000");
        const sensitive_records_count = parseInt(document.getElementById("clientFormRecords")?.value || "100000");
        const downtime_cost_per_hour = parseFloat(document.getElementById("clientFormDowntime")?.value || "25000");
        const notes = document.getElementById("clientFormNotes")?.value.trim();

        if (!name || !contact_name || !contact_email) {
            NeuroUI.toast("Preencha o Nome da Empresa, Responsável e E-mail de Contato.", "error");
            return;
        }

        try {
            await NeuroAPI.post("/clients", {
                name, cnpj, contact_name, contact_email, contact_phone, sla_tier, industry,
                annual_revenue_brl, sensitive_records_count, downtime_cost_per_hour, notes
            });
            this.toggleCreateForm(false);
            NeuroUI.toast(`Cliente corporativo '${name}' cadastrado com sucesso!`, "success");
            await this.render();
        } catch (err) {
            NeuroUI.toast("Erro ao cadastrar cliente: " + err.message, "error");
        }
    },

    async deleteClient(clientId, clientName) {
        if (!confirm(`Deseja realmente remover a organização '${clientName}' da plataforma?`)) return;
        try {
            await NeuroAPI.delete(`/clients/${clientId}`);
            NeuroUI.toast(`Cliente '${clientName}' removido com sucesso.`, "success");
            await this.render();
        } catch (err) {
            NeuroUI.toast("Erro ao remover: " + err.message, "error");
        }
    }
};

document.addEventListener("DOMContentLoaded", () => {
    if (document.getElementById("tab-clients")) {
        NeuroClients.render();
    }
});
