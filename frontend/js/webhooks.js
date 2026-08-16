// Webhooks & Real-time Alerts Manager
const NeuroWebhooks = {
    async testDispatch() {
        const urlInput = document.getElementById("webhookUrlInput");
        const platformSelect = document.getElementById("webhookPlatformSelect");
        const statusBox = document.getElementById("webhookStatusBox");

        if (!urlInput || !urlInput.value.trim()) {
            alert("Por favor, insira uma URL de Webhook válida (ex: Slack ou Discord).");
            return;
        }

        const url = urlInput.value.trim();
        const platform = platformSelect ? platformSelect.value : "discord";

        if (statusBox) {
            statusBox.style.display = "block";
            statusBox.style.background = "rgba(0,255,65,0.06)";
            statusBox.style.color = "var(--matrix-green)";
            statusBox.innerHTML = `⚡ Enviando alerta formatado pela NeuroSec IA para ${platform.toUpperCase()}...`;
        }

        try {
            const res = await NeuroAPI.post("/webhooks/test", {
                webhook_url: url,
                platform: platform
            });

            if (statusBox) {
                statusBox.style.background = "rgba(0,255,65,0.12)";
                statusBox.style.color = "#A7F3D0";
                statusBox.innerHTML = `<strong>✓ Sucesso!</strong> ${res.message}`;
            }
        } catch (err) {
            if (statusBox) {
                statusBox.style.background = "rgba(239,68,68,0.12)";
                statusBox.style.color = "#FCA5A5";
                statusBox.innerHTML = `<strong>✕ Erro ao disparar:</strong> ${err.message}`;
            }
        }
    }
};
