// Scorecard & Posture Metrics Renderer
const NeuroScorecard = {
    async render() {
        try {
            const data = await NeuroAPI.get("/scorecard");
            if (!data) return;

            // Atualiza o círculo SVG do Score
            const circle = document.getElementById("gaugeFillCircle");
            const scoreNum = document.getElementById("gaugeScoreNum");
            const scoreGrade = document.getElementById("gaugeGrade");
            const postureText = document.getElementById("postureStatusText");

            if (circle) {
                const radius = 70;
                const circumference = 2 * Math.PI * radius;
                const offset = circumference - (data.score / 100) * circumference;
                circle.style.strokeDasharray = `${circumference}`;
                circle.style.strokeDashoffset = `${offset}`;
                
                // Muda cor conforme gravidade do score
                if (data.score >= 80) circle.style.stroke = "var(--emerald-safe)";
                else if (data.score >= 50) circle.style.stroke = "var(--amber-warn)";
                else circle.style.stroke = "var(--crimson-crit)";
            }

            if (scoreNum) scoreNum.innerText = data.score;
            if (scoreGrade) scoreGrade.innerText = `Classificação: ${data.grade}`;
            if (postureText) postureText.innerText = data.posture_status;

            // Atualiza os cartões de KPI
            document.getElementById("kpiTotalVulns").innerText = data.total_vulnerabilities;
            document.getElementById("kpiOpenVulns").innerText = data.open_vulnerabilities;
            document.getElementById("kpiRemediatedVulns").innerText = data.remediated_vulnerabilities;
            document.getElementById("kpiLossAvoided").innerText = `R$ ${data.loss_avoided_brl.toLocaleString('pt-BR')}`;

            // Severidades
            document.getElementById("badgeCountCrit").innerText = data.severity_breakdown.critical;
            document.getElementById("badgeCountHigh").innerText = data.severity_breakdown.high;
            document.getElementById("badgeCountMed").innerText = data.severity_breakdown.medium;
            document.getElementById("badgeCountLow").innerText = data.severity_breakdown.low + data.severity_breakdown.info;

            // MTTR & Taxa
            document.getElementById("kpiMttr").innerText = `${data.mttr_days} dias`;
            document.getElementById("kpiRemRate").innerText = `${data.remediation_rate}%`;

        } catch (err) {
            console.error("Erro ao renderizar Scorecard:", err);
        }
    }
};
