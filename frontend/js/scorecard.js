// Scorecard & Posture Metrics Renderer with Neon Chart.js Visuals
const NeuroScorecard = {
    trendChart: null,
    layerChart: null,

    async render() {
        try {
            const data = await NeuroAPI.get("/scorecard");
            if (!data) return;

            // Score principal
            const scoreDisplay = document.getElementById("scoreDisplay") || document.getElementById("gaugeScoreNum");
            const gradeDisplay = document.getElementById("gradeDisplay") || document.getElementById("gaugeGrade");
            const postureText = document.getElementById("postureStatus") || document.getElementById("postureStatusText");

            if (scoreDisplay) {
                scoreDisplay.innerText = data.score;
                if (data.score >= 80) scoreDisplay.style.color = "var(--matrix-green)";
                else if (data.score >= 50) scoreDisplay.style.color = "var(--warn-orange)";
                else scoreDisplay.style.color = "var(--crit-red)";
            }

            if (gradeDisplay) gradeDisplay.innerText = `Classificação: ${data.grade}`;
            if (postureText) postureText.innerText = data.posture_status;

            // KPIs
            const kpiLoss = document.getElementById("kpiLossAvoided");
            if (kpiLoss) kpiLoss.innerText = `R$ ${data.loss_avoided_brl.toLocaleString('pt-BR')}`;

            const kpiMttr = document.getElementById("kpiMttr");
            if (kpiMttr) kpiMttr.innerText = `${data.mttr_days} dias`;

            const kpiOpen = document.getElementById("kpiOpenVulns");
            if (kpiOpen) kpiOpen.innerText = data.open_vulnerabilities;

            const kpiRemRate = document.getElementById("kpiRemediationRate") || document.getElementById("kpiRemRate");
            if (kpiRemRate) kpiRemRate.innerText = `${data.remediation_rate}%`;

            // Severidades
            const cCrit = document.getElementById("badgeCountCrit");
            if (cCrit) cCrit.innerText = data.severity_breakdown.critical;
            const cHigh = document.getElementById("badgeCountHigh");
            if (cHigh) cHigh.innerText = data.severity_breakdown.high;
            const cMed = document.getElementById("badgeCountMed");
            if (cMed) cMed.innerText = data.severity_breakdown.medium;
            const cLow = document.getElementById("badgeCountLow");
            if (cLow) cLow.innerText = data.severity_breakdown.low + data.severity_breakdown.info;

            // Renderiza os Gráficos Neon Chart.js
            await this.renderCharts();

        } catch (err) {
            console.error("Erro ao renderizar Scorecard:", err);
        }
    },

    async renderCharts() {
        if (typeof Chart === "undefined") return;

        try {
            const hist = await NeuroAPI.get("/scorecard/history");
            if (!hist) return;

            // 1. Gráfico de Tendência Histórica (Linha Neon)
            const trendCtx = document.getElementById("trendScoreChart");
            if (trendCtx) {
                if (this.trendChart) this.trendChart.destroy();

                const ctx2d = trendCtx.getContext("2d");
                const gradient = ctx2d.createLinearGradient(0, 0, 0, 250);
                gradient.addColorStop(0, "rgba(0, 255, 65, 0.35)");
                gradient.addColorStop(1, "rgba(0, 255, 65, 0.0)");

                this.trendChart = new Chart(trendCtx, {
                    type: "line",
                    data: {
                        labels: hist.timeline.labels,
                        datasets: [{
                            label: "Security Score (0-100)",
                            data: hist.timeline.scores,
                            borderColor: "#00FF41",
                            borderWidth: 3,
                            pointBackgroundColor: "#FFFFFF",
                            pointBorderColor: "#00FF41",
                            pointBorderWidth: 2,
                            pointRadius: 5,
                            pointHoverRadius: 7,
                            backgroundColor: gradient,
                            fill: true,
                            tension: 0.35
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { display: false },
                            tooltip: {
                                backgroundColor: "rgba(7, 9, 14, 0.95)",
                                titleColor: "#00FF41",
                                bodyColor: "#FFFFFF",
                                borderColor: "rgba(0, 255, 65, 0.3)",
                                borderWidth: 1,
                                padding: 10
                            }
                        },
                        scales: {
                            x: {
                                grid: { color: "rgba(255, 255, 255, 0.05)" },
                                ticks: { color: "#94A3B8", font: { family: "'JetBrains Mono', monospace", size: 11 } }
                            },
                            y: {
                                min: 0,
                                max: 100,
                                grid: { color: "rgba(255, 255, 255, 0.05)" },
                                ticks: { color: "#94A3B8", font: { family: "'JetBrains Mono', monospace", size: 11 } }
                            }
                        }
                    }
                });
            }

            // 2. Gráfico de Rosca (Distribuição por Camadas OSI/AppSec)
            const layerCtx = document.getElementById("layersDoughnutChart");
            if (layerCtx) {
                if (this.layerChart) this.layerChart.destroy();

                this.layerChart = new Chart(layerCtx, {
                    type: "doughnut",
                    data: {
                        labels: ["Código (SAST)", "Infra Web (DAST)", "Supply Chain (SCA)", "Nuvem (CSPM)"],
                        datasets: [{
                            data: [
                                hist.layers.sast || 1,
                                hist.layers.dast || 1,
                                hist.layers.sca || 1,
                                hist.layers.cloud || 1
                            ],
                            backgroundColor: [
                                "#00FF41", // Verde Matrix
                                "#00F0FF", // Ciano Neon
                                "#6366F1", // Índigo IA
                                "#F59E0B"  // Âmbar
                            ],
                            borderWidth: 2,
                            borderColor: "#0B111E"
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: "bottom",
                                labels: {
                                    color: "#E2E8F0",
                                    font: { family: "'Plus Jakarta Sans', sans-serif", size: 12 },
                                    padding: 14
                                }
                            }
                        },
                        cutout: "68%"
                    }
                });
            }

        } catch (e) {
            console.error("Erro ao renderizar gráficos Chart.js:", e);
        }
    }
};
