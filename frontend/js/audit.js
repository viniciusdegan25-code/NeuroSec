// Audit Trail & Governance Management
const NeuroAudit = {
    async render() {
        try {
            const audits = await NeuroAPI.get("/audit?limit=50");
            const tbody = document.getElementById("auditTableBody");
            if (!tbody) return;

            if (!audits || audits.length === 0) {
                tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:30px; color:var(--text-muted);">Nenhum registro de auditoria disponível.</td></tr>`;
                return;
            }

            tbody.innerHTML = audits.map(a => {
                let badgeClass = "badge-low";
                if (a.action.includes("APPROVED")) badgeClass = "badge-safe";
                if (a.action.includes("GENERATED")) badgeClass = "badge-medium";
                if (a.action.includes("DELETED")) badgeClass = "badge-critical";

                return `
                    <tr>
                        <td style="font-family:var(--font-mono); font-size:12px; color:var(--cyan-neon);">${a.timestamp}</td>
                        <td><span class="badge ${badgeClass}">${a.action}</span></td>
                        <td style="font-weight:600; color:#ffffff;">${a.operator}</td>
                        <td style="color:var(--text-muted); font-size:13px;">${a.details}</td>
                        <td style="font-family:var(--font-mono); font-size:11px; color:var(--text-dim);">${a.vuln_key || '-'}</td>
                    </tr>
                `;
            }).join("");
        } catch (err) {
            console.error("Erro ao renderizar auditoria:", err);
        }
    }
};
