// Floating NeuroSec IA Chat Drawer
const NeuroCopilot = {
    isOpen: false,

    init() {
        const toggleBtn = document.getElementById("copilotToggleBtn");
        const closeBtn = document.getElementById("copilotCloseBtn");
        const form = document.getElementById("copilotForm");
        const input = document.getElementById("copilotInput");

        if (toggleBtn) {
            toggleBtn.addEventListener("click", () => this.toggle());
        }
        if (closeBtn) {
            closeBtn.addEventListener("click", () => this.close());
        }
        if (form && input) {
            form.addEventListener("submit", async (e) => {
                e.preventDefault();
                const text = input.value.trim();
                if (!text) return;

                this.addMessage(text, "user");
                input.value = "";

                const botMsgId = this.addMessage("Pensando e analisando com a NeuroSec IA...", "bot", true);

                try {
                    const res = await NeuroAPI.post("/copilot/chat", { message: text });
                    this.updateBotMessage(botMsgId, res.reply);
                } catch (err) {
                    this.updateBotMessage(botMsgId, `Erro ao contatar a NeuroSec IA: ${err.message}`);
                }
            });
        }
    },

    toggle() {
        const drawer = document.getElementById("copilotDrawer");
        if (!drawer) return;
        this.isOpen = !this.isOpen;
        if (this.isOpen) drawer.classList.add("open");
        else drawer.classList.remove("open");
    },

    open() {
        const drawer = document.getElementById("copilotDrawer");
        if (drawer) {
            this.isOpen = true;
            drawer.classList.add("open");
        }
    },

    close() {
        const drawer = document.getElementById("copilotDrawer");
        if (drawer) {
            this.isOpen = false;
            drawer.classList.remove("open");
        }
    },

    addMessage(text, sender = "bot", isTemp = false) {
        const container = document.getElementById("copilotMessages");
        if (!container) return null;

        const msgDiv = document.createElement("div");
        const msgId = "msg_" + Date.now();
        msgDiv.id = msgId;
        msgDiv.className = `chat-msg chat-${sender}`;
        
        if (sender === "bot") {
            msgDiv.innerHTML = this.formatMarkdown(text);
        } else {
            msgDiv.innerText = text;
        }

        container.appendChild(msgDiv);
        container.scrollTop = container.scrollHeight;
        return msgId;
    },

    updateBotMessage(msgId, text) {
        const el = document.getElementById(msgId);
        if (el) {
            el.innerHTML = this.formatMarkdown(text);
            const container = document.getElementById("copilotMessages");
            if (container) container.scrollTop = container.scrollHeight;
        }
    },

    formatMarkdown(text) {
        if (!text) return "";
        let escaped = text
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;");
        
        // Formata blocos de código ```
        escaped = escaped.replace(/```([\s\S]*?)```/g, '<pre style="background:rgba(0,0,0,0.5); padding:8px; border-radius:6px; font-family:monospace; margin:6px 0; overflow-x:auto;"><code>$1</code></pre>');
        // Formata código inline `
        escaped = escaped.replace(/`([^`]+)`/g, '<code style="background:rgba(0,0,0,0.4); padding:2px 5px; border-radius:4px; font-family:monospace; color:var(--cyan-neon);">$1</code>');
        // Formata negrito **
        escaped = escaped.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
        // Quebras de linha
        escaped = escaped.replace(/\n/g, '<br>');
        return escaped;
    },

    sendQuickPrompt(promptText) {
        this.open();
        const input = document.getElementById("copilotInput");
        if (input) {
            input.value = promptText;
            document.getElementById("copilotForm")?.dispatchEvent(new Event("submit"));
        }
    }
};
