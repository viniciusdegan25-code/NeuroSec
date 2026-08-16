// Central de Varreduras (SAST, DAST, SCA, Cloud)
const NeuroScanners = {
    init() {
        // SAST Form
        const sastForm = document.getElementById("sastForm");
        if (sastForm) {
            sastForm.addEventListener("submit", async (e) => {
                e.preventDefault();
                const code = document.getElementById("sastCodeInput").value;
                const filename = document.getElementById("sastFilenameInput").value || "snippet.py";
                
                if (!code.trim()) {
                    NeuroUI.toast("Cole um trecho de código para análise.", "error");
                    return;
                }

                const btn = sastForm.querySelector("button[type='submit']");
                btn.disabled = true;
                btn.innerText = "Varrendo Código...";

                try {
                    const res = await NeuroAPI.post("/scan/sast/snippet", { code, filename });
                    NeuroUI.toast(`Scan SAST concluído: ${res.new_findings} nova(s) falha(s) identificada(s)!`, "success");
                    NeuroScanners.renderScanResults(res.findings, "sastResultsBox");
                    NeuroApp.refreshAll();
                } catch (err) {
                    NeuroUI.toast("Falha na varredura SAST.", "error");
                } finally {
                    btn.disabled = false;
                    btn.innerText = "Executar Scan SAST";
                }
            });
        }

        // DAST Form
        const dastForm = document.getElementById("dastForm");
        if (dastForm) {
            dastForm.addEventListener("submit", async (e) => {
                e.preventDefault();
                const url = document.getElementById("dastUrlInput").value;
                if (!url.trim()) {
                    NeuroUI.toast("Informe uma URL válida.", "error");
                    return;
                }

                const btn = dastForm.querySelector("button[type='submit']");
                btn.disabled = true;
                btn.innerText = "Inspecionando Alvo...";

                try {
                    const res = await NeuroAPI.post("/scan/dast/url", { url });
                    NeuroUI.toast(`Reconhecimento DAST concluído: ${res.new_findings} nova(s) brecha(s)!`, "success");
                    NeuroScanners.renderScanResults(res.findings, "dastResultsBox");
                    NeuroApp.refreshAll();
                } catch (err) {
                    NeuroUI.toast("Falha ao analisar a URL.", "error");
                } finally {
                    btn.disabled = false;
                    btn.innerText = "Disparar Scan DAST";
                }
            });
        }

        // SCA Form
        const scaForm = document.getElementById("scaForm");
        if (scaForm) {
            scaForm.addEventListener("submit", async (e) => {
                e.preventDefault();
                const content = document.getElementById("scaContentInput").value;
                const filename = document.getElementById("scaFilenameInput").value || "requirements.txt";

                const btn = scaForm.querySelector("button[type='submit']");
                btn.disabled = true;
                btn.innerText = "Auditando Dependências...";

                try {
                    const res = await NeuroAPI.post("/scan/sca/file", { content, filename });
                    NeuroUI.toast(`Scan SCA concluído: ${res.new_findings} pacote(s) vulnerável(is)!`, "success");
                    NeuroScanners.renderScanResults(res.findings, "scaResultsBox");
                    NeuroApp.refreshAll();
                } catch (err) {
                    NeuroUI.toast("Falha ao auditar dependências.", "error");
                } finally {
                    btn.disabled = false;
                    btn.innerText = "Auditar Dependências";
                }
            });
        }

        // Cloud Form
        const cloudForm = document.getElementById("cloudForm");
        if (cloudForm) {
            cloudForm.addEventListener("submit", async (e) => {
                e.preventDefault();
                const config_text = document.getElementById("cloudConfigInput").value;
                const provider = document.getElementById("cloudProviderSelect").value;

                const btn = cloudForm.querySelector("button[type='submit']");
                btn.disabled = true;
                btn.innerText = "Auditando Nuvem...";

                try {
                    const res = await NeuroAPI.post("/scan/cloud/audit", { config_text, provider });
                    NeuroUI.toast(`Auditoria Cloud finalizada: ${res.new_findings} desvios de postura!`, "success");
                    NeuroScanners.renderScanResults(res.findings, "cloudResultsBox");
                    NeuroApp.refreshAll();
                } catch (err) {
                    NeuroUI.toast("Falha na auditoria de nuvem.", "error");
                } finally {
                    btn.disabled = false;
                    btn.innerText = "Auditar Postura Cloud";
                }
            });
        }
    },

    renderScanResults(findings, targetContainerId) {
        const box = document.getElementById(targetContainerId);
        if (!box) return;

        if (!findings || findings.length === 0) {
            box.innerHTML = `<div style="padding: 16px; color: var(--emerald-safe); font-weight:600;">✨ Nenhuma vulnerabilidade encontrada. Ativo em conformidade!</div>`;
            return;
        }

        let html = `<div style="display:flex; flex-direction:column; gap:10px; margin-top:14px;">`;
        findings.forEach(f => {
            let sevClass = "badge-medium";
            if (f.severity === "CRITICAL") sevClass = "badge-critical";
            if (f.severity === "HIGH") sevClass = "badge-high";
            if (f.severity === "LOW") sevClass = "badge-low";

            html += `
                <div style="background:rgba(255,255,255,0.03); border:1px solid var(--border-subtle); padding:14px; border-radius:var(--radius-md);">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">
                        <span class="badge ${sevClass}">${f.severity}</span>
                        <span style="font-size:12px; color:var(--text-muted); font-family:var(--font-mono);">${f.asset} ${f.line > 0 ? ':L' + f.line : ''}</span>
                    </div>
                    <div style="font-weight:700; font-size:14px; color:#ffffff; margin-bottom:4px;">${f.type}</div>
                    <div style="font-size:12px; color:var(--text-muted);">${f.description}</div>
                </div>
            `;
        });
        html += `</div>`;
        box.innerHTML = html;
    }
};
