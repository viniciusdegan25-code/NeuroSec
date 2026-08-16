// Interactive Cyber Terminal CLI
const NeuroTerminal = {
    history: [],
    historyIndex: -1,

    init() {
        const form = document.getElementById("terminalForm");
        const input = document.getElementById("terminalInput");
        const body = document.getElementById("terminalBody");

        if (!form || !input) return;

        // Auto focus
        input.focus();

        form.addEventListener("submit", async (e) => {
            e.preventDefault();
            const cmd = input.value.trim();
            if (!cmd) return;

            this.history.push(cmd);
            this.historyIndex = this.history.length;

            this.appendOutput(`neurosec@appsec:~$ ${cmd}`, "prompt");
            input.value = "";

            try {
                const res = await NeuroAPI.post("/terminal/execute", { command: cmd });
                if (res.type === "clear") {
                    body.innerHTML = "";
                } else if (res.output) {
                    this.appendOutput(res.output, res.type);
                }
            } catch (err) {
                this.appendOutput(`[ERRO] Falha de comunicação: ${err.message}`, "error");
            }

            body.scrollTop = body.scrollHeight;
        });

        // History Navigation (Up/Down)
        input.addEventListener("keydown", (e) => {
            if (e.key === "ArrowUp") {
                if (this.historyIndex > 0) {
                    this.historyIndex--;
                    input.value = this.history[this.historyIndex];
                }
            } else if (e.key === "ArrowDown") {
                if (this.historyIndex < this.history.length - 1) {
                    this.historyIndex++;
                    input.value = this.history[this.historyIndex];
                } else {
                    this.historyIndex = this.history.length;
                    input.value = "";
                }
            }
        });
    },

    appendOutput(text, type = "text") {
        const body = document.getElementById("terminalBody");
        if (!body) return;

        const el = document.createElement("div");
        el.className = "terminal-output";

        if (type === "prompt") el.style.color = "var(--cyan-neon)";
        else if (type === "error") el.style.color = "var(--crimson-crit)";
        else if (type === "success") el.style.color = "var(--emerald-safe)";
        else el.style.color = "#e2e8f0";

        el.innerText = text;
        body.appendChild(el);
    },

    runQuickCommand(cmd) {
        const input = document.getElementById("terminalInput");
        if (input) {
            input.value = cmd;
            document.getElementById("terminalForm")?.dispatchEvent(new Event("submit"));
        }
    }
};
