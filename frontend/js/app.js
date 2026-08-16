// NeuroSec Master Application Controller - Version 3.5
const NeuroApp = {
    init() {
        this.setupTabs();
        this.setupListeners();
        
        NeuroScanners.init();
        NeuroTerminal.init();
        NeuroCopilot.init();

        this.refreshAll();

        // Polling para sincronização a cada 30 segundos
        setInterval(() => {
            NeuroScorecard.render();
            NeuroInventory.render();
        }, 30000);
    },

    setupTabs() {
        const tabBtns = document.querySelectorAll(".tab-btn");
        tabBtns.forEach(btn => {
            btn.addEventListener("click", () => {
                const targetId = btn.getAttribute("data-tab");
                this.switchTab(targetId);
            });
        });
    },

    switchTab(targetId) {
        const tabBtns = document.querySelectorAll(".tab-btn");
        tabBtns.forEach(b => {
            if (b.getAttribute("data-tab") === targetId) {
                b.classList.add("active");
            } else {
                b.classList.remove("active");
            }
        });

        document.querySelectorAll(".tab-pane").forEach(pane => {
            if (pane.id === targetId) {
                pane.classList.add("active");
            } else {
                pane.classList.remove("active");
            }
        });

        // Render contextual
        if (targetId === "tab-inventory") NeuroInventory.render();
        if (targetId === "tab-audit") NeuroAudit.render();
        if (targetId === "tab-scorecard") NeuroScorecard.render();
    },

    scrollToSection(sectionId) {
        const target = document.getElementById(sectionId);
        if (target) {
            target.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    },

    scrollToCockpitTab(tabId) {
        this.switchTab(tabId);
        const cockpit = document.getElementById("section-cockpit");
        if (cockpit) {
            cockpit.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    },

    openLoginModal() {
        const modal = document.getElementById("loginModal");
        if (modal) modal.classList.add("open");
    },

    closeLoginModal() {
        const modal = document.getElementById("loginModal");
        if (modal) modal.classList.remove("open");
    },

    simulateLogin() {
        this.closeLoginModal();
        NeuroUI.toast("Autenticado com sucesso via SSO Enterprise!", "success");
        this.scrollToCockpitTab("tab-scorecard");
    },

    setupListeners() {
        // Filtros de inventário
        document.getElementById("invSearchInput")?.addEventListener("input", () => NeuroInventory.filterAndRenderTable());
        document.getElementById("invFilterSev")?.addEventListener("change", () => NeuroInventory.filterAndRenderTable());
        document.getElementById("invFilterStatus")?.addEventListener("change", () => NeuroInventory.filterAndRenderTable());
        document.getElementById("invFilterType")?.addEventListener("change", () => NeuroInventory.filterAndRenderTable());

        // Botão de Exportar PDF
        document.getElementById("btnExportPdf")?.addEventListener("click", () => {
            window.open(`${API_BASE}/reports/executive-pdf`, "_blank");
        });
    },

    async refreshAll() {
        await NeuroScorecard.render();
        await NeuroInventory.render();
        await NeuroAudit.render();
    }
};

// Inicia aplicação após carregamento do DOM
document.addEventListener("DOMContentLoaded", () => {
    NeuroApp.init();
});
