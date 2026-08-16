// NeuroSec API Client Layer - Cloud & Local Hybrid Router
const isLocal = window.location.hostname === "localhost" || window.location.hostname === "127.0.0.1";
const isRender = window.location.hostname.includes("onrender.com");

const API_BASE = isRender
    ? "/api/v1"
    : (isLocal 
        ? (window.location.port === "8000" ? "/api/v1" : "http://127.0.0.1:8000/api/v1")
        : "https://neurosec-api.onrender.com/api/v1");

const NeuroAPI = {
    async get(endpoint) {
        try {
            const res = await fetch(`${API_BASE}${endpoint}`);
            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                const errMsg = this._formatErrorMessage(errData) || `HTTP ${res.status}: ${res.statusText}`;
                throw new Error(errMsg);
            }
            return await res.json();
        } catch (err) {
            console.error(`Erro GET ${endpoint}:`, err);
            NeuroUI.toast(`Erro na requisição: ${err.message}`, "error");
            throw err;
        }
    },

    async post(endpoint, body = {}) {
        try {
            const res = await fetch(`${API_BASE}${endpoint}`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
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
            const res = await fetch(`${API_BASE}${endpoint}`, {
                method: "PATCH",
                headers: { "Content-Type": "application/json" },
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

    async delete(endpoint) {
        try {
            const res = await fetch(`${API_BASE}${endpoint}`, { method: "DELETE" });
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
