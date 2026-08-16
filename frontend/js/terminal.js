// Interactive Cyber Terminal CLI
const NeuroTerminal = {
    history: [],
    historyIndex: -1,

    async execute() {
        const input = document.getElementById("terminalCommandInput") || document.getElementById("terminalInput");
        const screen = document.getElementById("terminalScreen") || document.getElementById("terminalBody");
        if (!input || !screen) return;

        const cmd = input.value.trim();
        if (!cmd) return;

        this.history.push(cmd);
        this.historyIndex = this.history.length;

        this.appendOutput(`neurosec> ${cmd}`, "prompt");
        input.value = "";

        try {
            const res = await NeuroAPI.post("/terminal/execute", { command: cmd });
            if (res.type === "clear") {
                screen.innerHTML = `<div>NEUROSEC CYBER CLI v4.0.0 — Terminal Limpo.</div><br>`;
            } else if (res.output) {
                this.appendOutput(res.output, res.type);
            }
        } catch (err) {
            this.appendOutput(`[ERRO] Falha ao executar comando: ${err.message}`, "error");
        }

        screen.scrollTop = screen.scrollHeight;
    },

    clear() {
        const screen = document.getElementById("terminalScreen") || document.getElementById("terminalBody");
        if (screen) {
            screen.innerHTML = `<div>NEUROSEC CYBER CLI v4.0.0 — Terminal Limpo. Digite 'help' para comandos.</div><br>`;
        }
    },

    appendOutput(text, type = "text") {
        const screen = document.getElementById("terminalScreen") || document.getElementById("terminalBody");
        if (!screen) return;

        const el = document.createElement("div");
        el.style.margin = "4px 0";
        el.style.whiteSpace = "pre-wrap";

        if (type === "prompt") {
            el.style.color = "var(--matrix-green)";
            el.style.fontWeight = "700";
        } else if (type === "error") {
            el.style.color = "var(--crit-red)";
        } else if (type === "success") {
            el.style.color = "var(--matrix-green)";
        } else {
            el.style.color = "#E2E8F0";
        }

        el.innerText = text;
        screen.appendChild(el);
    }
};

document.addEventListener("DOMContentLoaded", () => {
    const input = document.getElementById("terminalCommandInput") || document.getElementById("terminalInput");
    if (input) {
        input.addEventListener("keydown", (e) => {
            if (e.key === "ArrowUp") {
                if (NeuroTerminal.historyIndex > 0) {
                    NeuroTerminal.historyIndex--;
                    input.value = NeuroTerminal.history[NeuroTerminal.historyIndex];
                }
            } else if (e.key === "ArrowDown") {
                if (NeuroTerminal.historyIndex < NeuroTerminal.history.length - 1) {
                    NeuroTerminal.historyIndex++;
                    input.value = NeuroTerminal.history[NeuroTerminal.historyIndex];
                } else {
                    NeuroTerminal.historyIndex = NeuroTerminal.history.length;
                    input.value = "";
                }
            }
        });
    }
});
