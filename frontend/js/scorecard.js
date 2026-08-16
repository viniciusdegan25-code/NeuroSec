// Scorecard & Posture Metrics Renderer
const NeuroScorecard = {
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

        } catch (err) {
            console.error("Erro ao renderizar Scorecard:", err);
        }
    }
};
