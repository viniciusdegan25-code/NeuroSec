// NeuroSec ASPM 4.0 — Security & Multi-Factor Authentication Controller
const NeuroAuth = {
    tempToken: null,
    pendingEmail: null,

    init() {
        this.bindDigitInputs();
        this.checkSessionOnDashboard();
    },

    bindDigitInputs() {
        const inputs = document.querySelectorAll(".mfa-digit-input");
        inputs.forEach((input, index) => {
            input.addEventListener("input", (e) => {
                const val = e.target.value;
                if (val.length === 1 && index < inputs.length - 1) {
                    inputs[index + 1].focus();
                }
                this.updateFullCode();
            });

            input.addEventListener("keydown", (e) => {
                if (e.key === "Backspace" && !e.target.value && index > 0) {
                    inputs[index - 1].focus();
                }
                if (e.key === "Enter") {
                    e.preventDefault();
                    this.handleStep2();
                }
            });

            input.addEventListener("paste", (e) => {
                e.preventDefault();
                const pasteData = (e.clipboardData || window.clipboardData).getData("text").trim();
                if (/^\d+$/.test(pasteData)) {
                    const digits = pasteData.slice(0, 6).split("");
                    digits.forEach((d, i) => {
                        if (inputs[i]) inputs[i].value = d;
                    });
                    if (inputs[Math.min(digits.length, 5)]) {
                        inputs[Math.min(digits.length, 5)].focus();
                    }
                    this.updateFullCode();
                    if (digits.length === 6) {
                        this.handleStep2();
                    }
                }
            });
        });
    },

    updateFullCode() {
        const inputs = document.querySelectorAll(".mfa-digit-input");
        let full = "";
        inputs.forEach(inp => full += inp.value);
        const hidden = document.getElementById("fullMfaCode");
        if (hidden) hidden.value = full;
        return full;
    },

    async handleStep1() {
        const email = document.getElementById("loginEmail")?.value.trim();
        const password = document.getElementById("loginPassword")?.value;
        const btn = document.getElementById("btnSubmitStep1");

        if (!email || !password) {
            NeuroUI.toast("Informe seu e-mail corporativo e senha.", "error");
            return;
        }

        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<span>Validando credenciais...</span>`;
        }

        try {
            const res = await NeuroAPI.post("/auth/login", { email, password });
            this.pendingEmail = email;

            if (res.mfa_required) {
                this.tempToken = res.temp_token;
                document.getElementById("mfaUserEmail").innerText = email;
                
                // Transição para o Passo 2 (MFA)
                document.getElementById("step1Form").classList.remove("active");
                document.getElementById("step2Form").classList.add("active");
                
                const firstDigit = document.querySelector('.mfa-digit-input[data-index="0"]');
                if (firstDigit) setTimeout(() => firstDigit.focus(), 150);
                
                NeuroUI.toast("Credenciais verificadas! Insira o código 2FA.", "info");
            } else if (res.access_token) {
                this.saveSession(res.access_token, res.user);
                NeuroUI.toast("Autenticado com sucesso! Redirecionando...", "success");
                setTimeout(() => window.location.href = "/dashboard", 600);
            }
        } catch (err) {
            NeuroUI.toast(err.message || "Credenciais inválidas.", "error");
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = `<span>Verificar Credenciais</span> <span>➔</span>`;
            }
        }
    },

    async handleStep2() {
        const code = this.updateFullCode();
        const btn = document.getElementById("btnSubmitStep2");

        if (code.length < 6) {
            NeuroUI.toast("Digite o código de 6 dígitos completo do autenticador.", "error");
            return;
        }

        if (btn) {
            btn.disabled = true;
            btn.innerHTML = `<span>Validando 2FA...</span>`;
        }

        try {
            const res = await NeuroAPI.post("/auth/verify-mfa", {
                email: this.pendingEmail || "admin@neurosec.ai",
                code: code,
                temp_token: this.tempToken
            });

            this.saveSession(res.access_token, res.user);
            NeuroUI.toast("MFA verificado com sucesso! Acesso concedido.", "success");
            setTimeout(() => window.location.href = "/dashboard", 600);
        } catch (err) {
            NeuroUI.toast(err.message || "Código MFA incorreto ou expirado.", "error");
        } finally {
            if (btn) {
                btn.disabled = false;
                btn.innerHTML = `<span>Validar 2FA & Acessar Cockpit</span> <span>✓</span>`;
            }
        }
    },

    async triggerDemoLogin() {
        try {
            NeuroUI.toast("Iniciando acesso rápido de demonstração (1-Click Pitch)...", "info");
            const res = await NeuroAPI.post("/auth/demo-login", {});
            this.saveSession(res.access_token, res.user);
            NeuroUI.toast("Demonstração carregada com perfil CISO Admin!", "success");
            setTimeout(() => window.location.href = "/dashboard", 500);
        } catch (err) {
            NeuroUI.toast("Falha no login demo: " + err.message, "error");
        }
    },

    backToStep1() {
        document.getElementById("step2Form").classList.remove("active");
        document.getElementById("step1Form").classList.add("active");
    },

    async openSetupMfaModal() {
        const email = this.pendingEmail || "admin@neurosec.ai";
        const modal = document.getElementById("setupMfaModal");
        if (!modal) return;
        
        modal.classList.add("open");
        try {
            const res = await NeuroAPI.post("/auth/setup-mfa", { email });
            document.getElementById("mfaQrImage").src = res.qr_code_base64;
            document.getElementById("mfaSecretDisplay").innerText = res.secret;
        } catch (err) {
            NeuroUI.toast("Erro ao gerar QR Code: " + err.message, "error");
        }
    },

    closeSetupMfaModal() {
        const modal = document.getElementById("setupMfaModal");
        if (modal) modal.classList.remove("open");
    },

    saveSession(token, user) {
        localStorage.setItem("neurosec_jwt_token", token);
        if (user) {
            localStorage.setItem("neurosec_user", JSON.stringify(user));
        }
    },

    getToken() {
        return localStorage.getItem("neurosec_jwt_token");
    },

    getUser() {
        try {
            return JSON.parse(localStorage.getItem("neurosec_user") || "null");
        } catch (e) {
            return null;
        }
    },

    async logout() {
        if (!confirm("Deseja realmente encerrar a sessão de segurança?")) return;
        try {
            await NeuroAPI.post("/auth/logout", {});
        } catch (e) {}
        localStorage.removeItem("neurosec_jwt_token");
        localStorage.removeItem("neurosec_user");
        window.location.href = "/login";
    },

    checkSessionOnDashboard() {
        // Atualiza elementos visuais do usuário no Dashboard se presentes
        const userBadge = document.getElementById("navUserBadge");
        const userName = document.getElementById("navUserName");
        const userRole = document.getElementById("navUserRole");

        const user = this.getUser() || {
            name: "SecOps Lead & CISO",
            email: "admin@neurosec.ai",
            role: "SECOPS_ADMIN",
            mfa_enabled: true
        };

        if (userName) userName.innerText = user.name || "SecOps Lead";
        if (userRole) userRole.innerText = (user.role || "SECOPS_ADMIN") + " // MFA ATIVO 🛡️";
    }
};

document.addEventListener("DOMContentLoaded", () => {
    NeuroAuth.init();
});
