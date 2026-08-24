// NeuroSec API Client Layer - Cloud & Local Hybrid Router with Auto-Failover (v4.5.1)
const isLocal = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1";
const isRender = window.location.hostname.includes("onrender.com");

const CLOUD_API_BASE = "https://neurosec-api.onrender.com/api/v1";

// Se está rodando no Render ou no backend local porta 8000, usa caminho relativo '/api/v1'
let activeApiBase = (isRender || (isLocal && window.location.port === "8000"))
    ? "/api/v1"
    : (isLocal ? "http://127.0.0.1:8000/api/v1" : CLOUD_API_BASE);

const NeuroAPI = {
    _getHeaders(extraHeaders = {}) {
        const headers = { "Content-Type": "application/json", ...extraHeaders };
        const token = localStorage.getItem("neurosec_jwt_token");
        if (token) {
            headers["Authorization"] = `Bearer ${token}`;
        }
        return headers;
    },

    async _fetchWithFailover(endpoint, options = {}) {
        try {
            const res = await fetch(`${activeApiBase}${endpoint}`, options);
            return res;
        } catch (err) {
            // Se falhou ao tentar o backend local ou relativo e não era a nuvem direta, tenta o Render Cloud automaticamente
            if (activeApiBase !== CLOUD_API_BASE) {
                console.warn(`[NeuroSec Auto-Failover] Falha ao conectar em ${activeApiBase}. Redirecionando para a Nuvem Render...`);
                activeApiBase = CLOUD_API_BASE;
                const cloudRes = await fetch(`${CLOUD_API_BASE}${endpoint}`, options);
                return cloudRes;
            }
            throw err;
        }
    },

    async get(endpoint) {
        try {
            const res = await this._fetchWithFailover(endpoint, {
                headers: this._getHeaders()
            });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                const errMsg = this._formatErrorMessage(errData) || `HTTP ${res.status}: ${res.statusText}`;
                throw new Error(errMsg);
            }
            return await res.json();
        } catch (err) {
            console.error(`Erro GET ${endpoint}:`, err);
            if (err.message && err.message.includes("Failed to fetch")) {
                NeuroUI.toast("⏳ Conectando ao cluster em nuvem...", "info");
            } else {
                NeuroUI.toast(`Erro na requisição: ${err.message}`, "error");
            }
            throw err;
        }
    },

    async post(endpoint, body = {}) {
        try {
            const res = await this._fetchWithFailover(endpoint, {
                method: "POST",
                headers: this._getHeaders(),
                body: JSON.stringify(body)
            });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                const errMsg = this._formatErrorMessage(errData) || `HTTP ${res.status}: ${res.statusText}`;
                throw new Error(errMsg);
            }
            return await res.json();
        } catch (err) {
            console.error(`Erro POST ${endpoint}:`, err);
            NeuroUI.toast(`Falha na operação: ${err.message}`, "error");
            throw err;
        }
    },

    async patch(endpoint, body = {}) {
        try {
            const res = await this._fetchWithFailover(endpoint, {
                method: "PATCH",
                headers: this._getHeaders(),
                body: JSON.stringify(body)
            });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                const errMsg = this._formatErrorMessage(errData) || `HTTP ${res.status}`;
                throw new Error(errMsg);
            }
            return await res.json();
        } catch (err) {
            console.error(`Erro PATCH ${endpoint}:`, err);
            NeuroUI.toast(`Falha ao atualizar: ${err.message}`, "error");
            throw err;
        }
    },

    async put(endpoint, body = {}) {
        try {
            const res = await this._fetchWithFailover(endpoint, {
                method: "PUT",
                headers: this._getHeaders(),
                body: JSON.stringify(body)
            });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                const errMsg = this._formatErrorMessage(errData) || `HTTP ${res.status}`;
                throw new Error(errMsg);
            }
            return await res.json();
        } catch (err) {
            console.error(`Erro PUT ${endpoint}:`, err);
            NeuroUI.toast(`Falha ao atualizar: ${err.message}`, "error");
            throw err;
        }
    },

    async delete(endpoint) {
        try {
            const res = await this._fetchWithFailover(endpoint, {
                method: "DELETE",
                headers: this._getHeaders()
            });
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                const errMsg = this._formatErrorMessage(errData) || `HTTP ${res.status}`;
                throw new Error(errMsg);
            }
            return await res.json();
        } catch (err) {
            console.error(`Erro DELETE ${endpoint}:`, err);
            NeuroUI.toast(`Falha ao excluir: ${err.message}`, "error");
            throw err;
        }
    },

    _formatErrorMessage(errData) {
        if (!errData) return null;
        if (typeof errData.detail === "string") return errData.detail;
        if (Array.isArray(errData.detail)) {
            return errData.detail.map(d => d.msg || d.message || JSON.stringify(d)).join(", ");
        }
        if (typeof errData.detail === "object") {
            return errData.detail.msg || JSON.stringify(errData.detail);
        }
        if (errData.message) return errData.message;
        return null;
    }
};

const NeuroUI = {
    toast(message, type = "info") {
        const container = document.getElementById("toastContainer");
        if (!container) return;

        const toast = document.createElement("div");
        toast.className = `toast toast-${type}`;
        
        let icon = "ℹ️";
        if (type === "success") icon = "✅";
        if (type === "error") icon = "⚠️";

        toast.innerHTML = `<span>${icon}</span> <span>${message}</span>`;
        container.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateX(100%)";
            toast.style.transition = "all 0.3s ease";
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }
};
