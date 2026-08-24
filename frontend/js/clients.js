// NeuroSec ASPM 4.0 — Gestão de Clientes & Ambientes Corporativos (Multi-Tenant Hub)
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

            // 2. Renderiza Tabela Dinâmica
            this.filterAndRenderTable();
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
                    <td style="padding:14px 12px;">
                        <div style="font-weight:700; color:#fff; font-size:14px;">${c.name}</div>
                        <div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono); margin-top:2px;">
                            CNPJ: ${c.cnpj || 'N/A'} | Setor: <span style="color:var(--cyan-neon); font-weight:600;">${c.industry}</span>
                        </div>
                    </td>
                    <td style="padding:14px 12px;">
                        <div style="color:#E2E8F0; font-size:13px; font-weight:600;">${c.contact_name}</div>
                        <div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono);">${c.contact_email}</div>
                    </td>
                    <td style="padding:14px 12px;">
                        <div style="font-family:var(--font-mono); font-size:12px; color:#FDE047; font-weight:700;">${revenueFormatted}/ano</div>
                        <div style="font-size:11px; color:var(--text-muted); font-family:var(--font-mono); margin-top:2px;">👥 ${recordsFormatted} titulares LGPD</div>
                    </td>
                    <td style="padding:14px 12px;">
                        <div style="font-family:var(--font-mono); font-size:13px; font-weight:800; color:#EF4444;">${exposureFormatted}</div>
                        <div style="font-size:10px; color:var(--text-muted); font-family:var(--font-mono);">${c.open_vulns_count} falhas ativas</div>
                    </td>
                    <td style="padding:14px 12px;">
                        <div style="font-family:var(--font-mono); font-size:13px; font-weight:800; color:var(--matrix-green);">${lossAvoidedFormatted}</div>
                        <div style="font-size:10px; color:var(--text-muted); font-family:var(--font-mono);">Economia por remediação</div>
                    </td>
                    <td style="padding:14px 12px; text-align:center;">
                        <span style="font-family:var(--font-mono); font-size:16px; font-weight:800; color:${scoreColor};">${c.security_score}</span>
                        <span style="font-size:11px; color:var(--text-muted);">/100</span>
                    </td>
                    <td style="padding:14px 12px; text-align:right;">
                        <div style="display:inline-flex; gap:6px;">
                            <button class="btn-primary-matrix" style="padding:5px 9px; font-size:11px;" onclick="NeuroClients.triggerScan(${c.id}, '${c.name}')" title="Disparar Varredura Autônoma para o Cliente">
                                ⚡ Scan
                            </button>
                            <button class="btn-ai-indigo" style="padding:5px 9px; font-size:11px;" onclick="NeuroClients.openFinancialModal(${c.id})" title="Ver Dossiê e Breakdown de Risco Financeiro">
                                💰 Análise Financeira
                            </button>
                            <button class="btn-secondary-dark" style="padding:5px 9px; font-size:11px; border-color:rgba(0,240,255,0.3); color:var(--cyan-neon);" onclick="NeuroClients.openDetailsModal(${c.id})" title="Ver Ativos e Postura do Cliente">
                                🔍 Ativos
                            </button>
                            <button class="btn-secondary-dark" style="padding:5px 9px; font-size:11px; color:#EF4444; border-color:rgba(239,68,68,0.3);" onclick="NeuroClients.deleteClient(${c.id}, '${c.name}')" title="Excluir Cliente">
                                🗑️
                            </button>
                        </div>
                    </td>
                </tr>
            `;
        }).join("");
    },

    openCreateModal() {
        const modal = document.getElementById("clientModal");
        if (!modal) return;
        document.getElementById("clientModalTitle").innerText = "Cadastrar Novo Cliente Corporativo";
        document.getElementById("clientFormId").value = "";
        document.getElementById("clientFormName").value = "";
        document.getElementById("clientFormCnpj").value = "";
        document.getElementById("clientFormContactName").value = "";
        document.getElementById("clientFormContactEmail").value = "";
        document.getElementById("clientFormContactPhone").value = "";
        document.getElementById("clientFormRevenue").value = "50000000";
        document.getElementById("clientFormRecords").value = "100000";
        document.getElementById("clientFormDowntime").value = "25000";
        document.getElementById("clientFormNotes").value = "";
        modal.classList.add("open");
    },

    closeModal() {
        const modal = document.getElementById("clientModal");
        if (modal) modal.classList.remove("open");
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
            this.closeModal();
            NeuroUI.toast(`Cliente corporativo '${name}' cadastrado com sucesso!`, "success");
            await this.render();
        } catch (err) {
            NeuroUI.toast("Erro ao cadastrar cliente: " + err.message, "error");
        }
    },

    async triggerScan(clientId, clientName) {
        try {
            NeuroUI.toast(`Iniciando varredura em lote nos ativos de '${clientName}'...`, "info");
            const res = await NeuroAPI.post(`/clients/${clientId}/scan`, {});
            NeuroUI.toast(res.message, "success");
            await this.render();
            if (typeof NeuroScorecard !== "undefined") NeuroScorecard.render();
        } catch (err) {
            NeuroUI.toast("Erro na varredura: " + err.message, "error");
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
    },

    async openFinancialModal(clientId) {
        const modal = document.getElementById("clientFinancialModal");
        if (!modal) return;
        modal.classList.add("open");

        const body = document.getElementById("clientFinancialBody");
        const title = document.getElementById("clientFinancialTitle");

        if (body) {
            body.innerHTML = `<div style="text-align:center; padding:30px; color:var(--matrix-green); font-family:var(--font-mono);">Calculando modelo financeiro FAIR / NIST SP 800-30 para a empresa...</div>`;
        }

        try {
            const data = await NeuroAPI.get(`/clients/${clientId}/financial-analysis`);
            if (title) title.innerText = `Dossiê de Impacto Financeiro // ${data.client_name}`;

            const revenueFormatted = data.annual_revenue_brl.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
            const exposureFormatted = data.financial_exposure_risk_brl.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
            const lossAvoidedFormatted = data.financial_loss_avoided_brl.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
            const dataBreachFormatted = data.data_breach_risk_brl.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
            const downtimeFormatted = data.downtime_risk_brl.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });
            const regFineFormatted = data.regulatory_fine_risk_brl.toLocaleString('pt-BR', { style: 'currency', currency: 'BRL' });

            body.innerHTML = `
                <!-- Top Header KPI Summary -->
                <div style="display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-bottom:20px;">
                    <div style="background:rgba(239,68,68,0.06); border:1px solid rgba(239,68,68,0.3); border-radius:8px; padding:16px;">
                        <span style="font-size:11px; font-weight:700; color:#EF4444; text-transform:uppercase;">Exposição Financeira em Risco</span>
                        <div style="font-size:24px; font-weight:800; color:#EF4444; font-family:var(--font-mono); margin:4px 0;">${exposureFormatted}</div>
                        <span style="font-size:12px; color:var(--text-muted);">${data.open_vulns_count} vulnerabilidades ativas no ambiente</span>
                    </div>

                    <div style="background:rgba(0,255,65,0.06); border:1px solid rgba(0,255,65,0.3); border-radius:8px; padding:16px;">
                        <span style="font-size:11px; font-weight:700; color:var(--matrix-green); text-transform:uppercase;">Prejuízo Financeiro Evitado (ROI)</span>
                        <div style="font-size:24px; font-weight:800; color:var(--matrix-green); font-family:var(--font-mono); margin:4px 0;">${lossAvoidedFormatted}</div>
                        <span style="font-size:12px; color:var(--text-muted);">${data.remediated_vulns_count} falhas remediadas e blindadas</span>
                    </div>
                </div>

                <!-- Structural Parameters of the Company -->
                <div style="background:#07090E; border:1px solid var(--border-subtle); border-radius:8px; padding:16px; margin-bottom:16px;">
                    <div style="font-size:12px; font-weight:700; color:var(--cyan-neon); text-transform:uppercase; margin-bottom:10px;">📋 Parâmetros Estruturais da Empresa</div>
                    <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:12px; font-size:12px; font-family:var(--font-mono);">
                        <div>
                            <span style="color:var(--text-muted); display:block;">Faturamento Anual:</span>
                            <strong style="color:#fff;">${revenueFormatted}</strong>
                        </div>
                        <div>
                            <span style="color:var(--text-muted); display:block;">Registros / Titulares LGPD:</span>
                            <strong style="color:#fff;">${data.sensitive_records_count.toLocaleString('pt-BR')} registros</strong>
                        </div>
                        <div>
                            <span style="color:var(--text-muted); display:block;">Custo Downtime:</span>
                            <strong style="color:#fff;">R$ ${data.downtime_cost_per_hour.toLocaleString('pt-BR')}/hora</strong>
                        </div>
                    </div>
                </div>

                <!-- Breakdown by Risk Vector -->
                <div style="background:#07090E; border:1px solid var(--border-subtle); border-radius:8px; padding:16px; margin-bottom:16px;">
                    <div style="font-size:12px; font-weight:700; color:#fff; text-transform:uppercase; margin-bottom:12px;">📊 Decomposição das Perdas por Vetor de Ataque</div>
                    
                    <div style="display:flex; flex-direction:column; gap:10px; font-size:12px;">
                        <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 12px; background:rgba(255,255,255,0.02); border-radius:6px;">
                            <div>
                                <span style="font-weight:700; color:#E2E8F0;">1. Risco de Vazamento de Dados Sensíveis (LGPD)</span>
                                <div style="font-size:11px; color:var(--text-muted);">Custo médio de R$ ${data.cost_per_record_brl.toFixed(2)} por registro vazado (Setor: ${data.industry})</div>
                            </div>
                            <span style="font-family:var(--font-mono); font-weight:700; color:#EF4444;">${dataBreachFormatted}</span>
                        </div>

                        <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 12px; background:rgba(255,255,255,0.02); border-radius:6px;">
                            <div>
                                <span style="font-weight:700; color:#E2E8F0;">2. Custo de Interrupção Operacional & Downtime</span>
                                <div style="font-size:11px; color:var(--text-muted);">Horas estimadas de paralisação por RCE, indisponibilidade ou falhas de Cloud</div>
                            </div>
                            <span style="font-family:var(--font-mono); font-weight:700; color:#F97316;">${downtimeFormatted}</span>
                        </div>

                        <div style="display:flex; justify-content:space-between; align-items:center; padding:8px 12px; background:rgba(255,255,255,0.02); border-radius:6px;">
                            <div>
                                <span style="font-weight:700; color:#E2E8F0;">3. Risco de Multas Regulatórias & Sanções (ANPD / BACEN)</span>
                                <div style="font-size:11px; color:var(--text-muted);">Multas proporcionais ao faturamento com teto legal de R$ 50 Milhões</div>
                            </div>
                            <span style="font-family:var(--font-mono); font-weight:700; color:#EAB308;">${regFineFormatted}</span>
                        </div>
                    </div>
                </div>

                <!-- Methodology Note -->
                <div style="font-size:11px; color:var(--text-muted); line-height:1.5; font-style:italic;">
                    📌 ${data.methodology}
                </div>
            `;
        } catch (err) {
            body.innerHTML = `<div style="color:var(--crit-red); padding:20px;">Erro ao carregar análise financeira: ${err.message}</div>`;
        }
    },

    closeFinancialModal() {
        const modal = document.getElementById("clientFinancialModal");
        if (modal) modal.classList.remove("open");
    },

    async openDetailsModal(clientId) {
        const modal = document.getElementById("clientDetailsModal");
        if (!modal) return;
        modal.classList.add("open");

        const body = document.getElementById("clientDetailsBody");
        if (body) {
            body.innerHTML = `<div style="text-align:center; padding:30px; color:var(--matrix-green); font-family:var(--font-mono);">Carregando inventário de ativos e vulnerabilidades do cliente...</div>`;
        }

        try {
            const data = await NeuroAPI.get(`/clients/${clientId}`);
            const c = data.client;
            const assets = data.assets || [];
            const vulns = data.vulnerabilities || [];

            body.innerHTML = `
                <div style="margin-bottom:20px; border-bottom:1px solid var(--border-subtle); padding-bottom:14px;">
                    <div style="font-size:11px; font-weight:700; color:var(--matrix-green); text-transform:uppercase;">// AMBIENTE DEDICADO DO CLIENTE</div>
                    <h2 style="font-size:20px; font-weight:800; color:#fff;">${c.name}</h2>
                    <div style="font-size:12px; color:var(--text-muted); margin-top:4px;">
                        CNPJ: <span style="color:#cbd5e1;">${c.cnpj || 'N/A'}</span> | 
                        CISO Responsável: <span style="color:var(--cyan-neon);">${c.contact_name}</span> (${c.contact_email}) | 
                        Score Atual: <strong style="color:var(--matrix-green);">${c.security_score}/100</strong>
                    </div>
                </div>

                <div style="margin-bottom:16px;">
                    <h3 style="font-size:14px; font-weight:700; color:#fff; margin-bottom:8px;">📦 Ativos Vinculados em Monitoramento (${assets.length})</h3>
                    <div style="display:flex; flex-direction:column; gap:6px;">
                        ${assets.length > 0 ? assets.map(a => `
                            <div style="display:flex; justify-content:space-between; align-items:center; background:#07090E; border:1px solid var(--border-subtle); padding:8px 12px; border-radius:6px; font-family:var(--font-mono); font-size:12px;">
                                <span style="color:#00F0FF;">${a.name}</span>
                                <span style="color:var(--text-muted); font-size:11px;">[${a.asset_type}] ${a.criticality}</span>
                            </div>
                        `).join("") : '<div style="color:var(--text-muted); font-size:12px;">Nenhum ativo associado diretamente ainda.</div>'}
                    </div>
                </div>

                <div>
                    <h3 style="font-size:14px; font-weight:700; color:#fff; margin-bottom:8px;">🛡️ Ameaças & Vulnerabilidades do Cliente (${vulns.length})</h3>
                    <div style="display:flex; flex-direction:column; gap:6px;">
                        ${vulns.length > 0 ? vulns.map(v => `
                            <div style="display:flex; justify-content:space-between; align-items:center; background:#07090E; border:1px solid var(--border-subtle); padding:8px 12px; border-radius:6px; font-size:12px;">
                                <div>
                                    <span style="color:#fff; font-weight:600;">${v.vuln_type}</span>
                                    <span style="display:block; font-size:11px; color:var(--text-muted); font-family:var(--font-mono);">${v.asset_name}</span>
                                </div>
                                <span style="font-size:11px; font-weight:700; color:${v.severity === 'CRITICAL' ? '#EF4444' : '#F97316'};">${v.severity} (${v.status})</span>
                            </div>
                        `).join("") : '<div style="color:var(--matrix-green); font-size:12px;">✓ Nenhuma vulnerabilidade crítica pendente para este cliente.</div>'}
                    </div>
                </div>
            `;
        } catch (err) {
            body.innerHTML = `<div style="color:var(--crit-red); padding:20px;">Erro ao carregar detalhes: ${err.message}</div>`;
        }
    },

    closeDetailsModal() {
        const modal = document.getElementById("clientDetailsModal");
        if (modal) modal.classList.remove("open");
    }
};

document.addEventListener("DOMContentLoaded", () => {
    // Carrega clientes se estiver na página dashboard
    if (document.getElementById("tab-clients")) {
        NeuroClients.render();
    }
});
