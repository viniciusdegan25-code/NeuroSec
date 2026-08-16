// Threat & Vulnerability Inventory Management
const NeuroInventory = {
    allVulns: [],

    async render() {
        try {
            const data = await NeuroAPI.get("/vulnerabilities");
            this.allVulns = data || [];
            this.filterAndRenderTable();
        } catch (err) {
            console.error("Erro ao carregar inventário:", err);
        }
    },

    filter() {
        this.filterAndRenderTable();
    },

    filterAndRenderTable() {
        const searchVal = (document.getElementById("inventorySearch")?.value || document.getElementById("invSearchInput")?.value || "").toLowerCase();
        const sevVal = (document.getElementById("inventorySeverityFilter")?.value || document.getElementById("invFilterSev")?.value || "ALL").toUpperCase();
        const statusVal = document.getElementById("invFilterStatus")?.value || "ALL";

        const tbody = document.getElementById("inventoryTableBody");
        if (!tbody) return;

        const filtered = this.allVulns.filter(v => {
            const matchSearch = v.asset_name.toLowerCase().includes(searchVal) ||
                                v.vuln_type.toLowerCase().includes(searchVal) ||
                                (v.cve_id && v.cve_id.toLowerCase().includes(searchVal));
            
            const matchSev = sevVal === "ALL" || v.severity.toUpperCase() === sevVal;
            const matchStatus = statusVal === "ALL" || v.status === statusVal;

            return matchSearch && matchSev && matchStatus;
        });

        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">Nenhuma vulnerabilidade correspondente aos filtros.</td></tr>`;
            return;
        }

        tbody.innerHTML = filtered.map(v => {
            let badgeStyle = "background:rgba(234,179,8,0.15); color:#EAB308; border:1px solid rgba(234,179,8,0.3);";
            if (v.severity === "CRITICAL") badgeStyle = "background:rgba(239,68,68,0.15); color:#EF4444; border:1px solid rgba(239,68,68,0.3);";
            if (v.severity === "HIGH") badgeStyle = "background:rgba(249,115,22,0.15); color:#F97316; border:1px solid rgba(249,115,22,0.3);";
            if (v.severity === "LOW") badgeStyle = "background:rgba(16,185,129,0.15); color:#10B981; border:1px solid rgba(16,185,129,0.3);";

            let statusHtml = `<span style="font-size:11px; padding:3px 8px; border-radius:4px; background:rgba(239,68,68,0.1); color:#EF4444; border:1px solid rgba(239,68,68,0.3);">Aberto</span>`;
            if (v.status === "patch_ready") statusHtml = `<span style="font-size:11px; padding:3px 8px; border-radius:4px; background:rgba(99,102,241,0.15); color:#A5B4FC; border:1px solid rgba(99,102,241,0.3);">Patch Pronto</span>`;
            if (v.status === "remediated") statusHtml = `<span style="font-size:11px; padding:3px 8px; border-radius:4px; background:rgba(16,185,129,0.15); color:#10B981; border:1px solid rgba(16,185,129,0.3);">Remediado</span>`;

            return `
                <tr style="border-bottom: 1px solid var(--border-subtle);">
                    <td style="padding:12px; font-family:var(--font-mono); font-weight:700; color:var(--matrix-green);">#${v.internal_id}</td>
                    <td style="padding:12px; font-weight:600; color:#fff;">
                        ${v.vuln_type}
                        ${v.cve_id ? `<span style="display:block; font-size:11px; color:var(--cyan-neon); font-family:var(--font-mono);">${v.cve_id}</span>` : ''}
                    </td>
                    <td style="padding:12px; font-family:var(--font-mono); font-size:12px; color:var(--text-muted);">${v.asset_name} ${v.line_number > 0 ? ':L' + v.line_number : ''}</td>
                    <td style="padding:12px;"><span style="font-size:11px; font-weight:700; padding:3px 8px; border-radius:4px; ${badgeStyle}">${v.severity}</span></td>
                    <td style="padding:12px; font-family:var(--font-mono); color:#cbd5e1;">${v.cvss_score ? v.cvss_score.toFixed(1) : '5.0'}</td>
                    <td style="padding:12px;">${statusHtml}</td>
                    <td style="padding:12px; text-align:right;">
                        <div style="display:inline-flex; gap:6px;">
                            <button class="btn-ai-indigo" style="padding:6px 12px; font-size:11px;" onclick="NeuroRemediation.openModal(${v.internal_id})">
                                🤖 Remediar
                            </button>
                            ${v.status !== 'remediated' ? `
                                <button class="btn-primary-matrix" style="padding:6px 10px; font-size:11px;" onclick="NeuroRemediation.approveDirect(${v.internal_id})">
                                    ✓
                                </button>
                            ` : ''}
                        </div>
                    </td>
                </tr>
            `;
        }).join("");
    }
};
