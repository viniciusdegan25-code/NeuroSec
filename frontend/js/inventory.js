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

    filterAndRenderTable() {
        const searchVal = (document.getElementById("invSearchInput")?.value || "").toLowerCase();
        const sevVal = document.getElementById("invFilterSev")?.value || "ALL";
        const statusVal = document.getElementById("invFilterStatus")?.value || "ALL";
        const typeVal = document.getElementById("invFilterType")?.value || "ALL";

        const tbody = document.getElementById("inventoryTableBody");
        if (!tbody) return;

        const filtered = this.allVulns.filter(v => {
            const matchSearch = v.asset_name.toLowerCase().includes(searchVal) ||
                                v.vuln_type.toLowerCase().includes(searchVal) ||
                                (v.cve_id && v.cve_id.toLowerCase().includes(searchVal));
            
            const matchSev = sevVal === "ALL" || v.severity.toUpperCase() === sevVal;
            const matchStatus = statusVal === "ALL" || v.status === statusVal;
            const matchType = typeVal === "ALL" || v.asset_type === typeVal;

            return matchSearch && matchSev && matchStatus && matchType;
        });

        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding:30px; color:var(--text-muted);">Nenhuma vulnerabilidade correspondente aos filtros.</td></tr>`;
            return;
        }

        tbody.innerHTML = filtered.map(v => {
            let sevClass = "badge-medium";
            if (v.severity === "CRITICAL") sevClass = "badge-critical";
            if (v.severity === "HIGH") sevClass = "badge-high";
            if (v.severity === "LOW") sevClass = "badge-low";

            let statusBadge = `<span class="badge badge-high">Aberto</span>`;
            if (v.status === "patch_ready") statusBadge = `<span class="badge badge-medium">Patch Pronto</span>`;
            if (v.status === "remediated") statusBadge = `<span class="badge badge-safe">Remediado</span>`;

            return `
                <tr>
                    <td style="font-family:var(--font-mono); font-weight:700; color:var(--cyan-neon);">#${v.internal_id}</td>
                    <td><span class="badge" style="background:rgba(255,255,255,0.06);">${v.asset_type}</span></td>
                    <td style="font-weight:600;">
                        ${v.vuln_type}
                        ${v.cve_id ? `<span style="display:block; font-size:11px; color:var(--cyan-neon); font-family:var(--font-mono);">${v.cve_id}</span>` : ''}
                    </td>
                    <td style="font-family:var(--font-mono); font-size:12px; color:var(--text-muted);">${v.asset_name} ${v.line_number > 0 ? ':L' + v.line_number : ''}</td>
                    <td><span class="badge ${sevClass}">${v.severity}</span></td>
                    <td>${statusBadge}</td>
                    <td>
                        <div style="display:flex; gap:8px;">
                            <button class="btn btn-neural" style="padding:6px 12px; font-size:11px;" onclick="NeuroRemediation.openModal(${v.internal_id})">
                                🤖 IA Patch
                            </button>
                            ${v.status !== 'remediated' ? `
                                <button class="btn btn-success" style="padding:6px 12px; font-size:11px;" onclick="NeuroRemediation.approveDirect(${v.internal_id})">
                                    ✓ Aprovar
                                </button>
                            ` : ''}
                        </div>
                    </td>
                </tr>
            `;
        }).join("");
    }
};
