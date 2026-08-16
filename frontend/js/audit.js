// Audit Trail & Governance Management
const NeuroAudit = {
    async render() {
        try {
            const audits = await NeuroAPI.get("/audit?limit=50");
            const tbody = document.getElementById("auditTableBody");
            if (!tbody) return;

            if (!audits || audits.length === 0) {
                tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; padding:30px; color:var(--text-muted);">Nenhum registro de auditoria disponível ainda.</td></tr>`;
                return;
            }

            tbody.innerHTML = audits.map(a => {
                let badgeStyle = "background:rgba(99,102,241,0.15); color:#A5B4FC; border:1px solid rgba(99,102,241,0.3);";
                if (a.action.includes("APPROVED")) badgeStyle = "background:rgba(16,185,129,0.15); color:#10B981; border:1px solid rgba(16,185,129,0.3);";
                if (a.action.includes("GENERATED")) badgeStyle = "background:rgba(0,255,65,0.15); color:#00FF41; border:1px solid rgba(0,255,65,0.3);";
                if (a.action.includes("DELETED")) badgeStyle = "background:rgba(239,68,68,0.15); color:#EF4444; border:1px solid rgba(239,68,68,0.3);";

                return `
                    <tr style="border-bottom: 1px solid var(--border-subtle);">
                        <td style="padding:12px; font-family:var(--font-mono); font-size:12px; color:var(--matrix-green);">${a.timestamp}</td>
                        <td style="padding:12px;"><span style="font-size:11px; font-weight:700; padding:3px 8px; border-radius:4px; ${badgeStyle}">${a.action}</span></td>
                        <td style="padding:12px; font-weight:600; color:#ffffff;">${a.operator}</td>
                        <td style="padding:12px; color:var(--text-muted); font-size:13px;">${a.details}</td>
                        <td style="padding:12px; font-family:var(--font-mono); font-size:11px; color:var(--text-dim);">${a.vuln_key || '-'}</td>
                    </tr>
                `;
            }).join("");
        } catch (err) {
            console.error("Erro ao renderizar auditoria:", err);
        }
    }
};
