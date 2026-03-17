document.addEventListener("DOMContentLoaded", () => {
    const BACKEND_URL = sessionStorage.getItem("backendUrl")
        || localStorage.getItem("backendUrl")
        || "http://127.0.0.1:8000";
    const API = `${BACKEND_URL}/predict`;
    const CHAT_API = `${BACKEND_URL}/chat`;
    const token = sessionStorage.getItem("accessToken");
    if (!token) {
        window.location.href = "index.html";
        return;
    }

    function normalizePrediction(value) {
        if (typeof value !== "string") return "unknown";
        const p = value.toLowerCase();
        if (p === "malicious" || p === "phish") return "phishing";
        if (p === "benign") return "safe";
        return p;
    }

    function getInitials(nameOrEmail) {
        if (!nameOrEmail) return "PG";
        const clean = String(nameOrEmail).trim();
        if (!clean) return "PG";
        const words = clean.split(/[\s._-]+/).filter(Boolean);
        if (words.length >= 2) return (words[0][0] + words[1][0]).toUpperCase();
        return words[0].slice(0, 2).toUpperCase();
    }

    function colorFromText(text) {
        let hash = 0;
        for (let i = 0; i < text.length; i++) hash = text.charCodeAt(i) + ((hash << 5) - hash);
        const hue = Math.abs(hash) % 360;
        return `linear-gradient(145deg, hsl(${hue}, 78%, 62%), hsl(${(hue + 36) % 360}, 78%, 56%))`;
    }

    function toDisplayName(email, storedName) {
        if (storedName && storedName.trim()) return storedName.trim();
        if (!email || !email.includes("@")) return "Security Analyst";
        const local = email.split("@")[0].replace(/[._-]+/g, " ").trim();
        return local ? local.replace(/\b\w/g, (m) => m.toUpperCase()) : "Security Analyst";
    }

    function authHeaders() {
        return {
            "Content-Type": "application/json",
            Authorization: `Bearer ${sessionStorage.getItem("accessToken") || ""}`,
        };
    }

    function logout() {
        sessionStorage.removeItem("accessToken");
        sessionStorage.removeItem("userEmail");
        sessionStorage.removeItem("userName");
        window.location.href = "index.html";
    }

    const menuToggle = document.getElementById("menuToggle");
    const sidebar = document.getElementById("sidebar");
    const scanBtn = document.getElementById("scanBtn");
    const urlInput = document.getElementById("urlInput");
    const homeBtn = document.getElementById("homeBtn");
    const chartsBtn = document.getElementById("chartsBtn");
    const historyBtn = document.getElementById("historyBtn");
    const homeSection = document.getElementById("homeSection");
    const chartsSection = document.getElementById("chartsSection");
    const historySection = document.getElementById("historySection");
    const topProfileAvatar = document.getElementById("topProfileAvatar");
    const topProfileName = document.getElementById("topProfileName");
    const profileAvatar = document.getElementById("profileAvatar");
    const profileName = document.getElementById("profileName");
    const profileEmail = document.getElementById("profileEmail");
    const logoutBtn = document.getElementById("logoutBtn");
    const chatbotToggle = document.getElementById("chatbotToggle");
    const chatbotPanel = document.getElementById("chatbotPanel");
    const chatbotClose = document.getElementById("chatbotClose");
    const chatbotMessages = document.getElementById("chatbotMessages");
    const chatbotInput = document.getElementById("chatbotInput");
    const chatbotSend = document.getElementById("chatbotSend");
    const chatbotClear = document.getElementById("chatbotClear");

    const CHAT_HISTORY_KEY = "chatHistory";
    const CHAT_OPEN_KEY = "chatbotAutoOpened";

    function saveChatHistory() {
        if (!chatbotMessages) return;
        const messages = Array.from(chatbotMessages.querySelectorAll(".chatbot-msg")).map((node) => ({
            role: node.classList.contains("user") ? "user" : "bot",
            text: node.textContent || "",
        }));
        localStorage.setItem(CHAT_HISTORY_KEY, JSON.stringify(messages));
    }

    function loadChatHistory() {
        if (!chatbotMessages) return;
        try {
            const raw = JSON.parse(localStorage.getItem(CHAT_HISTORY_KEY));
            if (!Array.isArray(raw)) return;
            raw.forEach((item) => {
                if (!item || typeof item.text !== "string") return;
                appendChatMessage(item.role === "user" ? "user" : "bot", item.text);
            });
        } catch {
            // ignore parse errors
        }
    }

    if (menuToggle && sidebar) {
        menuToggle.addEventListener("click", () => {
            sidebar.classList.toggle("hide");
            document.body.classList.toggle("sidebar-collapsed", sidebar.classList.contains("hide"));
        });
    }

    function setNavActive(section) {
        homeBtn.classList.remove("active");
        chartsBtn.classList.remove("active");
        historyBtn.classList.remove("active");
        if (section === "home") homeBtn.classList.add("active");
        if (section === "charts") chartsBtn.classList.add("active");
        if (section === "history") historyBtn.classList.add("active");
    }

    function showSection(section) {
        setNavActive(section);
        [homeSection, chartsSection, historySection].forEach((sec) => {
            sec.style.opacity = "0";
            sec.style.transform = "translateY(10px)";
            setTimeout(() => {
                sec.style.display = "none";
            }, 300);
        });
        let active = homeSection;
        if (section === "charts") active = chartsSection;
        if (section === "history") active = historySection;
        setTimeout(() => {
            active.style.display = "block";
            setTimeout(() => {
                active.style.opacity = "1";
                active.style.transform = "translateY(0)";
            }, 50);
        }, 300);
    }

    homeBtn.onclick = (e) => {
        e.preventDefault();
        showSection("home");
    };
    chartsBtn.onclick = (e) => {
        e.preventDefault();
        showSection("charts");
        initCharts();
    };
    historyBtn.onclick = (e) => {
        e.preventDefault();
        showSection("history");
    };

    function initProfile() {
        const email = sessionStorage.getItem("userEmail") || "analyst@local";
        const name = toDisplayName(email, sessionStorage.getItem("userName"));
        const initials = getInitials(name);
        const gradient = colorFromText(email.toLowerCase());
        if (topProfileAvatar) {
            topProfileAvatar.innerText = initials;
            topProfileAvatar.style.background = gradient;
        }
        if (profileAvatar) {
            profileAvatar.innerText = initials;
            profileAvatar.style.background = gradient;
        }
        if (topProfileName) topProfileName.innerText = name;
        if (profileName) profileName.innerText = name;
        if (profileEmail) profileEmail.innerText = email;
    }

    let liveChart;
    let pieChart;
    let barChart;
    let chartsInitialized = false;
    const CHART_WINDOW = 30;

    function getHistory() {
        try {
            const raw = JSON.parse(localStorage.getItem("scanHistory")) || [];
            return Array.isArray(raw) ? raw : [];
        } catch {
            return [];
        }
    }

    function initCharts() {
        if (chartsInitialized) return;
        const lineCanvas = document.getElementById("liveChart");
        const pieCanvas = document.getElementById("pieChart");
        const barCanvas = document.getElementById("barChart");

        if (lineCanvas) {
            liveChart = new Chart(lineCanvas, {
                type: "line",
                data: {
                    labels: [],
                    datasets: [{
                        label: "Risk Score",
                        data: [],
                        borderColor: "#00f2ff",
                        fill: true,
                        tension: 0.4,
                        backgroundColor: "rgba(0,242,255,0.05)",
                    }],
                },
                options: {
                    plugins: { legend: { display: false } },
                    scales: { y: { beginAtZero: true, max: 100 }, x: { display: false } },
                },
            });
        }

        if (pieCanvas) {
            pieChart = new Chart(pieCanvas, {
                type: "doughnut",
                data: {
                    labels: ["Phishing", "Safe"],
                    datasets: [{ data: [0, 0], backgroundColor: ["#ff0055", "#10b981"], borderWidth: 0 }],
                },
                options: { cutout: "70%" },
            });
        }

        if (barCanvas) {
            barChart = new Chart(barCanvas, {
                type: "bar",
                data: {
                    labels: ["Phishing", "Safe"],
                    datasets: [{ label: "Scans", data: [0, 0], backgroundColor: ["#ff0055", "#10b981"] }],
                },
            });
        }

        chartsInitialized = true;
        updateCharts();
    }

    function typeWriter(element, text, speed = 30) {
        element.innerText = "";
        let i = 0;
        const interval = setInterval(() => {
            element.innerText += text.charAt(i);
            i++;
            if (i >= text.length) clearInterval(interval);
        }, speed);
    }

    function animateRisk(target) {
        let count = 0;
        const riskFill = document.getElementById("riskFill");
        const confidenceText = document.getElementById("confidenceText");
        const interval = setInterval(() => {
            if (count >= target) {
                clearInterval(interval);
            } else {
                count++;
                riskFill.style.width = `${count}%`;
                confidenceText.innerText = `Confidence: ${count}%`;
            }
        }, 15);
    }

    async function scanURL() {
        const url = urlInput.value.trim();
        if (!url) {
            alert("Enter URL");
            return;
        }

        const card = document.getElementById("scanResultCard");
        const title = document.getElementById("resultTitle");
        const urlText = document.getElementById("resultURL");
        card.classList.remove("safe", "phishing", "show");
        card.classList.remove("hidden");
        typeWriter(title, "Scanning URL...");
        urlText.innerText = url;
        scanBtn.classList.add("scan-loading");

        try {
            const res = await fetch(API, {
                method: "POST",
                headers: authHeaders(),
                body: JSON.stringify({ url }),
            });
            const data = await res.json();
            scanBtn.classList.remove("scan-loading");

            if (res.status === 401) {
                logout();
                return;
            }
            if (!res.ok || !data || typeof data.prediction !== "string") {
                throw new Error(data?.detail || data?.message || "Prediction failed");
            }

            const prediction = normalizePrediction(data.prediction);
            const rawProbability = Number(data.probability);
            const probability = Number.isFinite(rawProbability)
                ? Math.round(rawProbability <= 1 ? rawProbability * 100 : rawProbability)
                : 0;

            if (prediction === "safe") {
                card.classList.add("safe");
                typeWriter(title, "Safe Website");
            } else {
                card.classList.add("phishing");
                typeWriter(title, "Phishing Detected");
            }

            animateRisk(probability);
            setTimeout(() => card.classList.add("show"), 200);
            saveHistory(url, prediction, probability);
            updateStats();
            updateRecent();
            updateCharts();
            urlInput.value = "";
        } catch (err) {
            scanBtn.classList.remove("scan-loading");
            alert(err.message || "Backend error.");
        }
    }

    if (scanBtn) scanBtn.addEventListener("click", scanURL);

    function saveHistory(url, prediction, prob) {
        const history = getHistory();
        history.push({
            url,
            prediction: normalizePrediction(prediction),
            probability: prob,
            time: new Date().toLocaleString(),
        });
        localStorage.setItem("scanHistory", JSON.stringify(history));
    }

    function updateStats() {
        const history = getHistory();
        const total = history.length;
        const safe = history.filter((x) => x.prediction === "safe").length;
        const phishing = history.filter((x) => x.prediction === "phishing").length;
        const accuracy = total ? Math.round((safe / total) * 100) : 0;
        document.getElementById("total").innerText = total;
        document.getElementById("safe").innerText = safe;
        document.getElementById("phishing").innerText = phishing;
        document.getElementById("accuracy").innerText = `${accuracy}%`;
    }

    function appendHistoryRows(table, rows) {
        table.innerHTML = "";
        rows.forEach((item) => {
            const tr = document.createElement("tr");
            const urlTd = document.createElement("td");
            const resultTd = document.createElement("td");
            const probTd = document.createElement("td");
            const timeTd = document.createElement("td");
            urlTd.textContent = String(item.url || "");
            resultTd.textContent = String(item.prediction || "");
            probTd.textContent = String(item.probability ?? "");
            timeTd.textContent = String(item.time || "");
            tr.appendChild(urlTd);
            tr.appendChild(resultTd);
            tr.appendChild(probTd);
            tr.appendChild(timeTd);
            table.appendChild(tr);
        });
    }

    function updateRecent() {
        const history = getHistory();
        const lastFive = history.slice(-5).reverse();
        appendHistoryRows(document.getElementById("recentTable"), lastFive);
    }

    function updateHistory() {
        appendHistoryRows(document.getElementById("historyTable"), getHistory());
    }

    function updateCharts() {
        const history = getHistory();
        let safeCount = 0;
        let phishingCount = 0;

        history.forEach((item) => {
            if (item.prediction === "safe") safeCount++;
            else if (item.prediction === "phishing") phishingCount++;
        });

        if (liveChart) {
            const recent = history.slice(-CHART_WINDOW);
            liveChart.data.labels = recent.map((_, idx) => String(idx + 1));
            liveChart.data.datasets[0].data = recent.map((item) => {
                const p = Number(item.probability);
                if (!Number.isFinite(p)) return 0;
                return Math.max(0, Math.min(100, p));
            });
            liveChart.update();
        }
        if (pieChart) {
            pieChart.data.datasets[0].data = [phishingCount, safeCount];
            pieChart.update();
        }
        if (barChart) {
            barChart.data.datasets[0].data = [phishingCount, safeCount];
            barChart.update();
        }
        updateHistory();
    }

    function appendChatMessage(role, text) {
        if (!chatbotMessages) return;
        const msg = document.createElement("div");
        msg.className = `chatbot-msg ${role}`;
        msg.textContent = text;
        chatbotMessages.appendChild(msg);
        chatbotMessages.scrollTop = chatbotMessages.scrollHeight;
        saveChatHistory();
    }

    function ensureTypingIndicator() {
        if (!chatbotMessages) return null;
        let typing = chatbotMessages.querySelector(".chatbot-typing");
        if (!typing) {
            typing = document.createElement("div");
            typing.className = "chatbot-typing";
            typing.innerHTML = `Assistant is typing <span class="typing-dots"><span></span><span></span><span></span></span>`;
            chatbotMessages.appendChild(typing);
        }
        return typing;
    }

    function setTyping(isTyping) {
        const typing = ensureTypingIndicator();
        if (!typing) return;
        if (isTyping) {
            typing.classList.add("show");
            chatbotMessages.scrollTop = chatbotMessages.scrollHeight;
        } else {
            typing.classList.remove("show");
        }
    }

    async function sendChatMessage() {
        if (!chatbotInput) return;
        const message = chatbotInput.value.trim();
        if (!message) return;

        appendChatMessage("user", message);
        chatbotInput.value = "";
        setTyping(true);

        try {
            const res = await fetch(CHAT_API, {
                method: "POST",
                headers: authHeaders(),
                body: JSON.stringify({ message }),
            });
            const data = await res.json();

            if (res.status === 401) {
                setTyping(false);
                logout();
                return;
            }
            if (!res.ok || typeof data?.reply !== "string") {
                throw new Error(data?.detail || "Chat request failed");
            }

            setTyping(false);
            appendChatMessage("bot", data.reply);
        } catch (err) {
            setTyping(false);
            appendChatMessage("bot", err.message || "Chat service is unavailable right now.");
        }
    }

    initProfile();
    updateStats();
    updateRecent();
    updateCharts();
    if (chatbotToggle && chatbotPanel) {
        const chatAnimations = ["chat-anim-fade", "chat-anim-slide", "chat-anim-pop"];
        const pickAnimation = () => chatAnimations[Math.floor(Math.random() * chatAnimations.length)];
        chatbotToggle.addEventListener("click", () => {
            if (!chatbotPanel.classList.contains("open")) {
                chatbotPanel.classList.remove(...chatAnimations);
                chatbotPanel.classList.add(pickAnimation());
                chatbotPanel.classList.add("open");
                localStorage.setItem(CHAT_OPEN_KEY, "true");
            } else {
                chatbotPanel.classList.remove("open");
            }
        });
    }
    if (chatbotClose && chatbotPanel) {
        chatbotClose.addEventListener("click", () => chatbotPanel.classList.remove("open"));
    }
    if (chatbotSend) chatbotSend.addEventListener("click", sendChatMessage);
    if (chatbotInput) {
        chatbotInput.addEventListener("keydown", (e) => {
            if (e.key === "Enter") {
                e.preventDefault();
                sendChatMessage();
            }
        });
    }

    if (logoutBtn) logoutBtn.addEventListener("click", logout);

    if (chatbotClear && chatbotMessages) {
        chatbotClear.addEventListener("click", () => {
            chatbotMessages.innerHTML = "";
            localStorage.removeItem(CHAT_HISTORY_KEY);
        });
    }

    loadChatHistory();
    if (chatbotPanel && !localStorage.getItem(CHAT_OPEN_KEY)) {
        chatbotPanel.classList.add("open");
        localStorage.setItem(CHAT_OPEN_KEY, "true");
    }
});

const cyberCanvas = document.getElementById("cyberCanvas");
if (cyberCanvas) {
    const ctx = cyberCanvas.getContext("2d");
    function resizeCanvas() {
        cyberCanvas.width = window.innerWidth;
        cyberCanvas.height = window.innerHeight;
    }
    resizeCanvas();
    window.addEventListener("resize", resizeCanvas);

    let particles = [];
    class Particle {
        constructor() {
            this.x = Math.random() * cyberCanvas.width;
            this.y = Math.random() * cyberCanvas.height;
            this.size = Math.random() * 2 + 0.5;
            this.speedX = (Math.random() - 0.5) * 0.4;
            this.speedY = (Math.random() - 0.5) * 0.4;
        }
        update() {
            this.x += this.speedX;
            this.y += this.speedY;
            if (this.x > cyberCanvas.width) this.x = 0;
            if (this.x < 0) this.x = cyberCanvas.width;
            if (this.y > cyberCanvas.height) this.y = 0;
            if (this.y < 0) this.y = cyberCanvas.height;
        }
        draw() {
            ctx.fillStyle = "rgba(0, 242, 255, 0.8)";
            ctx.shadowColor = "#00f2ff";
            ctx.shadowBlur = 8;
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
            ctx.fill();
            ctx.shadowBlur = 0;
        }
    }
    function initParticles() {
        particles = [];
        for (let i = 0; i < 120; i++) particles.push(new Particle());
    }
    function connectParticles() {
        for (let a = 0; a < particles.length; a++) {
            for (let b = a; b < particles.length; b++) {
                const dx = particles[a].x - particles[b].x;
                const dy = particles[a].y - particles[b].y;
                const distance = dx * dx + dy * dy;
                if (distance < 12000) {
                    ctx.strokeStyle = "rgba(0, 242, 255, 0.05)";
                    ctx.lineWidth = 0.5;
                    ctx.beginPath();
                    ctx.moveTo(particles[a].x, particles[a].y);
                    ctx.lineTo(particles[b].x, particles[b].y);
                    ctx.stroke();
                }
            }
        }
    }
    function animate() {
        ctx.clearRect(0, 0, cyberCanvas.width, cyberCanvas.height);
        particles.forEach((p) => {
            p.update();
            p.draw();
        });
        connectParticles();
        requestAnimationFrame(animate);
    }
    initParticles();
    animate();
}
