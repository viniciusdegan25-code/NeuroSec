// NeuroSec Cobra Naja Cyber Shield Vector & Matrix Engine
const NeuroCobra = {
    getShieldSVG(size = 32, glowColor = "#00FF88") {
        return `
        <svg width="${size}" height="${size}" viewBox="0 0 120 120" fill="none" xmlns="http://www.w3.org/2000/svg" class="cobra-naja-svg">
            <defs>
                <filter id="najaNeonGlow" x="-30%" y="-30%" width="160%" height="160%">
                    <feGaussianBlur stdDeviation="2.5" result="blur" />
                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
                <linearGradient id="najaGreenGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stop-color="#00FF88"/>
                    <stop offset="50%" stop-color="#00FF41"/>
                    <stop offset="100%" stop-color="#10B981"/>
                </linearGradient>
            </defs>

            <!-- Outer Cobra Hood & Shield Silhouette -->
            <path d="M60 12 
                     C45 12 28 22 20 42 
                     C14 58 24 78 60 108 
                     C96 78 106 58 100 42 
                     C92 22 75 12 60 12 Z" 
                  stroke="url(#najaGreenGrad)" 
                  stroke-width="3.5" 
                  stroke-linejoin="round"
                  stroke-linecap="round"
                  fill="#0B111E" 
                  fill-opacity="0.9"
                  filter="url(#najaNeonGlow)"/>

            <!-- Inner Hood Boundary Wings -->
            <path d="M34 42 
                     C28 54 36 72 60 92 
                     C84 72 92 54 86 42" 
                  stroke="url(#najaGreenGrad)" 
                  stroke-width="2.5" 
                  stroke-linecap="round" 
                  fill="none" 
                  opacity="0.85"/>

            <!-- Cobra Head Crown & Brow -->
            <path d="M46 22 L60 16 L74 22 L68 34 L52 34 Z" 
                  stroke="url(#najaGreenGrad)" 
                  stroke-width="2.5" 
                  fill="#07090E" 
                  stroke-linejoin="round"/>

            <!-- Glowing Slanted Viper Eyes -->
            <path d="M48 26 L54 28" stroke="#00FF88" stroke-width="2.5" stroke-linecap="round" filter="url(#najaNeonGlow)"/>
            <path d="M72 26 L66 28" stroke="#00FF88" stroke-width="2.5" stroke-linecap="round" filter="url(#najaNeonGlow)"/>

            <!-- Viper Mouth & Fangs -->
            <path d="M52 38 L60 46 L68 38" stroke="url(#najaGreenGrad)" stroke-width="2" fill="#040711"/>
            <!-- Left Fang -->
            <path d="M54 38 L55 42" stroke="#FFFFFF" stroke-width="1.8" stroke-linecap="round"/>
            <!-- Right Fang -->
            <path d="M66 38 L65 42" stroke="#FFFFFF" stroke-width="1.8" stroke-linecap="round"/>

            <!-- Cobra Segmented Belly Plates / Horizontal Ribs -->
            <path d="M46 52 C52 50 68 50 74 52" stroke="url(#najaGreenGrad)" stroke-width="2.5" stroke-linecap="round"/>
            <path d="M48 60 C53 58 67 58 72 60" stroke="url(#najaGreenGrad)" stroke-width="2.5" stroke-linecap="round"/>
            <path d="M50 68 C54 66 66 66 70 68" stroke="url(#najaGreenGrad)" stroke-width="2.5" stroke-linecap="round"/>
            <path d="M52 76 C55 74 65 74 68 76" stroke="url(#najaGreenGrad)" stroke-width="2.5" stroke-linecap="round"/>
            <path d="M55 83 C57 82 63 82 65 83" stroke="url(#najaGreenGrad)" stroke-width="2" stroke-linecap="round"/>

            <!-- Central Spine Neural Line -->
            <path d="M60 46 L60 84" stroke="#00FF88" stroke-width="1.5" stroke-dasharray="2 3" opacity="0.6"/>
        </svg>
        `;
    },

    initMatrixRain() {
        const canvas = document.getElementById("matrixCanvas");
        if (!canvas) return;
        const ctx = canvas.getContext("2d");

        let width = canvas.width = window.innerWidth;
        let height = canvas.height = window.innerHeight;

        const chars = "010101NEUROSECOWASPEXPLOITPATCHDIFF0101PQC";
        const fontSize = 14;
        let columns = Math.floor(width / fontSize);
        let drops = [];

        for (let i = 0; i < columns; i++) {
            drops[i] = Math.random() * -100;
        }

        window.addEventListener("resize", () => {
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
            columns = Math.floor(width / fontSize);
            drops = [];
            for (let i = 0; i < columns; i++) {
                drops[i] = Math.random() * -100;
            }
        });

        function draw() {
            ctx.fillStyle = "rgba(7, 9, 14, 0.08)";
            ctx.fillRect(0, 0, width, height);

            ctx.fillStyle = "#00FF88";
            ctx.font = `${fontSize}px 'JetBrains Mono', monospace`;

            for (let i = 0; i < drops.length; i++) {
                const text = chars.charAt(Math.floor(Math.random() * chars.length));
                ctx.fillText(text, i * fontSize, drops[i] * fontSize);

                if (drops[i] * fontSize > height && Math.random() > 0.975) {
                    drops[i] = 0;
                }
                drops[i]++;
            }
        }

        setInterval(draw, 45);
    }
};

document.addEventListener("DOMContentLoaded", () => {
    // Insere SVGs em elementos marcados com data-cobra-shield
    document.querySelectorAll("[data-cobra-shield]").forEach(el => {
        const size = parseInt(el.getAttribute("data-cobra-shield") || "32", 10);
        el.innerHTML = NeuroCobra.getShieldSVG(size);
    });

    NeuroCobra.initMatrixRain();
});
