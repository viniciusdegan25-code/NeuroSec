// NeuroSec ASPM 4.0 — Dashboard SPA Orchestrator & Sidebar Controller
const NeuroDashboard = {
    currentTab: "tab-scorecard",

    tabTitles: {
        "tab-scorecard": "Security Scorecard & Métricas Executivas",
        "tab-inventory": "Inventário Dinâmico de Ameaças",
        "tab-sast": "SAST // Scanner de Código Estático",
        "tab-dast": "DAST // Scanner de Infraestrutura Web",
        "tab-sca": "SCA & SBOM // Cadeia de Suprimentos",
        "tab-cloud": "Cloud CSPM // Auditoria de Nuvem e IaC",
        "tab-remediation": "Studio de Remediação & Diff Viewer",
        "tab-central-ai": "Central de IA Dedicada // Workspace AppSec",
        "tab-terminal": "Cyber Terminal CLI Interativo",
        "tab-audit": "Trilha de Auditoria & Governança (SOC 2)",
        "tab-reports": "Exportação de Relatórios & Conformidade",
        "tab-cicd": "Automação CI/CD // GitHub Actions & GitLab",
        "tab-webhooks": "Webhooks & Alertas em Tempo Real (Slack/Discord)"
    },

    init() {
        this.bindSidebarEvents();
        this.bindTabButtons();
        this.refreshAll();
    },

    bindSidebarEvents() {
        const sidebar = document.getElementById("dashSidebar");
        const toggleBtn = document.getElementById("sidebarToggleBtn");
        const collapseIcon = document.getElementById("collapseIcon");

        if (toggleBtn && sidebar) {
            toggleBtn.addEventListener("click", () => {
                sidebar.classList.toggle("collapsed");
                if (sidebar.classList.contains("collapsed")) {
                    collapseIcon.innerText = "▶";
                } else {
                    collapseIcon.innerText = "◀";
                }
            });
        }
    },

    bindTabButtons() {
        const buttons = document.querySelectorAll(".sub-tab-btn");
        buttons.forEach(btn => {
            btn.addEventListener("click", () => {
                const targetTab = btn.getAttribute("data-tab");
                if (targetTab) {
                    this.switchTab(targetTab);
                }
            });
        });
    },

    switchTab(tabId) {
        this.currentTab = tabId;

        // Atualiza botões ativos no sidebar
        document.querySelectorAll(".sub-tab-btn").forEach(btn => {
            const matches = btn.getAttribute("data-tab") === tabId;
            if (tabId === "tab-central-ai") {
                btn.classList.toggle("active-ai", matches);
            } else {
                btn.classList.toggle("active", matches);
            }
        });

        // Alterna views no viewport
        document.querySelectorAll(".subtab-view").forEach(view => {
            view.classList.toggle("active", view.id === tabId);
        });

        // Atualiza Breadcrumb no topo
        const breadcrumbEl = document.getElementById("activeBreadcrumb");
        if (breadcrumbEl) {
            breadcrumbEl.innerText = this.tabTitles[tabId] || "Módulo de Segurança";
        }

        // Carrega dados específicos conforme a aba
        if (tabId === "tab-scorecard" && typeof NeuroScorecard !== "undefined") {
            NeuroScorecard.render();
        } else if (tabId === "tab-inventory" && typeof NeuroInventory !== "undefined") {
            NeuroInventory.render();
        } else if (tabId === "tab-audit" && typeof NeuroAudit !== "undefined") {
            NeuroAudit.render();
        }
    },

    async refreshAll() {
        try {
            if (typeof NeuroScorecard !== "undefined") await NeuroScorecard.render();
            if (typeof NeuroInventory !== "undefined") await NeuroInventory.render();
            if (typeof NeuroAudit !== "undefined") await NeuroAudit.render();
        } catch (e) {
            console.error("Erro ao sincronizar dashboard:", e);
        }
    },

    async seedDemoScenario() {
        if (!confirm("Deseja carregar o Cenário de Demonstração Enterprise (Fintech / Banking)? Isto populará 9 vulnerabilidades e métricas ricas para apresentação.")) {
            return;
        }

        try {
            const res = await NeuroAPI.post("/vulnerabilities/seed-demo", {});
            alert(`✓ ${res.message}\n${res.posture_summary}`);
            await this.refreshAll();
            this.switchTab("tab-scorecard");
        } catch (err) {
            alert(`Erro ao carregar cenário demo: ${err.message}`);
        }
    },

    downloadCSV() {
        window.open("/api/v1/reports/csv", "_blank");
    },

    downloadSBOM() {
        window.open("/api/v1/reports/cyclonedx-sbom", "_blank");
    },

    downloadPDF() {
        window.open("/api/v1/reports/executive-pdf", "_blank");
    }
};

// Aliases globais para compatibilidade
window.NeuroApp = NeuroDashboard;

document.addEventListener("DOMContentLoaded", () => {
    NeuroDashboard.init();
});
