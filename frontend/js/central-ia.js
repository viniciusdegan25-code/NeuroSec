// NeuroSec Central de IA Dedicada Controller (Fullscreen AppSec Workspace)
const NeuroCentralAi = {
    history: [],

    init() {
        const input = document.getElementById("centralAiInput");
        if (input) {
            input.addEventListener("keydown", (e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                    e.preventDefault();
                    this.sendMessage();
                }
            });
        }
    },

    async sendMessage() {
        const input = document.getElementById("centralAiInput");
        const messagesContainer = document.getElementById("centralAiMessages");
        if (!input || !messagesContainer) return;

        const text = input.value.trim();
        if (!text) return;

        // Renderiza mensagem do usuário
        this.appendMessage("user", text);
        this.history.push({ role: "user", content: text });
        input.value = "";

        // Placeholder de resposta
        const botMsgId = `central_ai_res_${Date.now()}`;
        this.appendPlaceholder(botMsgId);

        try {
            const response = await NeuroAPI.post("/copilot/chat", {
                message: text,
                history: this.history.slice(-6)
            });

            const botElement = document.getElementById(botMsgId);
            if (botElement) {
                botElement.innerHTML = this.formatMarkdown(response.reply);
            }
            this.history.push({ role: "assistant", content: response.reply });
        } catch (err) {
            const botElement = document.getElementById(botMsgId);
            if (botElement) {
                botElement.innerHTML = `<span style="color:var(--crit-red);">Falha ao conectar com o motor NeuroSec IA: ${err.message}</span>`;
            }
        }

        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    },

    sendPreset(presetText) {
        const input = document.getElementById("centralAiInput");
        if (input) {
            input.value = presetText;
            this.sendMessage();
        }
    },

    appendMessage(sender, text) {
        const messagesContainer = document.getElementById("centralAiMessages");
        if (!messagesContainer) return;

        const msgDiv = document.createElement("div");
        msgDiv.className = `ai-msg ${sender}`;

        const avatarText = sender === "user" ? "VOCÊ" : "IA";
        msgDiv.innerHTML = `
            <div class="ai-msg-avatar">${avatarText}</div>
            <div class="ai-msg-content">${this.formatMarkdown(text)}</div>
        `;

        messagesContainer.appendChild(msgDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    },

    appendPlaceholder(id) {
        const messagesContainer = document.getElementById("centralAiMessages");
        if (!messagesContainer) return;

        const msgDiv = document.createElement("div");
        msgDiv.className = "ai-msg bot";
        msgDiv.innerHTML = `
            <div class="ai-msg-avatar">IA</div>
            <div class="ai-msg-content" id="${id}">
                <span style="color:var(--indigo-ai); font-style:italic;">Processando análise com NeuroSec IA...</span>
            </div>
        `;
        messagesContainer.appendChild(msgDiv);
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    },

    formatMarkdown(text) {
        if (!text) return "";
        let escaped = text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
        
        // Code blocks
        escaped = escaped.replace(/```([\s\S]*?)```/g, '<pre style="background:#040711; border:1px solid var(--border-matrix); padding:12px; border-radius:8px; font-family:var(--font-mono); font-size:13px; color:#00FF41; margin:10px 0; overflow-x:auto;"><code>$1</code></pre>');
        
        // Inline code
        escaped = escaped.replace(/`([^`]+)`/g, '<code style="background:rgba(255,255,255,0.08); padding:2px 6px; border-radius:4px; font-family:var(--font-mono); color:var(--cyan-neon); font-size:12px;">$1</code>');
        
        // Bold
        escaped = escaped.replace(/\*\*([^*]+)\*\*/g, '<strong style="color:#FFFFFF;">$1</strong>');
        
        // Newlines
        escaped = escaped.replace(/\n/g, '<br>');
        
        return escaped;
    }
};

document.addEventListener("DOMContentLoaded", () => {
    NeuroCentralAi.init();
});
