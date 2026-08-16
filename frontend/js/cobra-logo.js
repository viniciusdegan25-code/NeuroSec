// NeuroSec Cobra Naja Cyber Shield Vector & Matrix Engine
const NeuroCobra = {
    getShieldSVG(size = 32, glowColor = "#00FF41") {
        return `
        <svg width="${size}" height="${size}" viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" class="cobra-naja-svg">
            <defs>
                <filter id="matrixGlow" x="-20%" y="-20%" width="140%" height="140%">
                    <feGaussianBlur stdDeviation="2" result="blur" />
                    <feComposite in="SourceGraphic" in2="blur" operator="over" />
                </filter>
                <linearGradient id="shieldGrad" x1="0%" y1="0%" x2="100%" y2="100%">
                    <stop offset="0%" stop-color="#00FF41" stop-opacity="0.9"/>
                    <stop offset="50%" stop-color="#10B981" stop-opacity="0.7"/>
                    <stop offset="100%" stop-color="#07090E" stop-opacity="0.95"/>
                </linearGradient>
                <linearGradient id="najaGrad" x1="50%" y1="0%" x2="50%" y2="100%">
                    <stop offset="0%" stop-color="#00FF41"/>
                    <stop offset="100%" stop-color="#10B981"/>
                </linearGradient>
            </defs>

            <!-- Outer Shield Outline -->
            <path d="M50 8 L85 24 L85 58 Q85 82 50 94 Q15 82 15 58 L15 24 Z" 
                  stroke="url(#shieldGrad)" stroke-width="2.5" fill="#0B111E" fill-opacity="0.85" filter="url(#matrixGlow)"/>

            <!-- Lateral Cyber Circuit Traces -->
            <path d="M22 36 L32 36 L38 42" stroke="#00FF41" stroke-width="1.5" stroke-linecap="round" opacity="0.6"/>
            <circle cx="22" cy="36" r="1.5" fill="#00FF41"/>
            <path d="M78 36 L68 36 L62 42" stroke="#00FF41" stroke-width="1.5" stroke-linecap="round" opacity="0.6"/>
            <circle cx="78" cy="36" r="1.5" fill="#00FF41"/>

            <!-- Cobra Naja Expanded Hood (Capelo da Naja) -->
            <path d="M50 22 C36 22 28 32 26 48 C25 58 35 70 50 78 C65 70 75 58 74 48 C72 32 64 22 50 22 Z" 
                  fill="none" stroke="url(#najaGrad)" stroke-width="2" />

            <!-- Cobra Internal Hood Markings & Neural Scales -->
            <path d="M35 44 C38 36 44 32 50 32 C56 32 62 36 65 44" stroke="#00FF41" stroke-width="1.5" fill="none" opacity="0.8"/>
            <path d="M38 52 C42 46 46 44 50 44 C54 44 58 46 62 52" stroke="#10B981" stroke-width="1.5" fill="none" opacity="0.7"/>
            <path d="M42 60 L50 56 L58 60" stroke="#00FF41" stroke-width="1.5" fill="none"/>
            <path d="M45 67 L50 64 L55 67" stroke="#10B981" stroke-width="1.5" fill="none"/>

            <!-- Cobra Head Crown & Fangs Profile -->
            <path d="M50 26 L44 34 L50 40 L56 34 Z" fill="#00FF41" opacity="0.9"/>
            
            <!-- Glowing Eyes (Cyber Optics) -->
            <circle cx="46" cy="32" r="1.5" fill="#FFFFFF" />
            <circle cx="54" cy="32" r="1.5" fill="#FFFFFF" />
            <circle cx="46" cy="32" r="2.5" fill="#00FF41" opacity="0.7" filter="url(#matrixGlow)"/>
            <circle cx="54" cy="32" r="2.5" fill="#00FF41" opacity="0.7" filter="url(#matrixGlow)"/>

            <!-- Base Shield Node -->
            <circle cx="50" cy="88" r="2" fill="#00FF41" filter="url(#matrixGlow)"/>
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

            ctx.fillStyle = "#00FF41";
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
