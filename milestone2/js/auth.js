const BACKEND_URL = sessionStorage.getItem("backendUrl")
    || localStorage.getItem("backendUrl")
    || "http://127.0.0.1:8000";
let popupTimer = null;

function ensurePopup() {
    let backdrop = document.getElementById("authPopupBackdrop");
    if (backdrop) return backdrop;

    backdrop = document.createElement("div");
    backdrop.id = "authPopupBackdrop";
    backdrop.className = "auth-popup-backdrop";
    backdrop.innerHTML = `
      <div class="auth-popup" role="alertdialog" aria-live="polite" aria-modal="true">
        <div id="authPopupIcon" class="auth-popup-icon"></div>
        <p id="authPopupText" class="auth-popup-text"></p>
        <button id="authPopupClose" type="button" class="auth-popup-close">Close</button>
      </div>
    `;
    document.body.appendChild(backdrop);

    const closeBtn = document.getElementById("authPopupClose");
    if (closeBtn) closeBtn.addEventListener("click", hidePopup);
    backdrop.addEventListener("click", (e) => {
        if (e.target === backdrop) hidePopup();
    });
    return backdrop;
}

function hidePopup() {
    const backdrop = document.getElementById("authPopupBackdrop");
    if (!backdrop) return;
    backdrop.classList.remove("show");
}

function showMessage(msg, isSuccess = true, autoHideMs = 2200) {
    const messageEl = document.getElementById("message");
    if (messageEl) {
        messageEl.innerText = msg;
        messageEl.classList.remove("msg-success", "msg-error", "show");
        messageEl.classList.add(isSuccess ? "msg-success" : "msg-error");
        messageEl.classList.add("show");
    }

    const backdrop = ensurePopup();
    const textEl = document.getElementById("authPopupText");
    const iconEl = document.getElementById("authPopupIcon");
    if (textEl) textEl.innerText = msg;
    if (iconEl) {
        iconEl.classList.remove("success", "error");
        iconEl.classList.add(isSuccess ? "success" : "error");
        iconEl.innerText = isSuccess ? "Success" : "Error";
    }

    backdrop.classList.add("show");
    if (popupTimer) clearTimeout(popupTimer);
    if (autoHideMs > 0) popupTimer = setTimeout(hidePopup, autoHideMs);
}

function saveSession(data, fallbackEmail) {
    sessionStorage.setItem("accessToken", data.access_token);
    sessionStorage.setItem("userEmail", data.user_email || fallbackEmail || "");
    sessionStorage.setItem("userName", data.user_name || "");
}

function clearSession() {
    sessionStorage.removeItem("accessToken");
    sessionStorage.removeItem("userEmail");
    sessionStorage.removeItem("userName");
}

const loginForm = document.getElementById("loginForm");
if (loginForm) {
    loginForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const email = document.getElementById("email").value.trim().toLowerCase();
        const password = document.getElementById("password").value.trim();
        if (!email || !password) {
            showMessage("Please enter email and password", false);
            return;
        }

        try {
            const response = await fetch(`${BACKEND_URL}/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email, password }),
            });
            const data = await response.json();

            if (response.ok && data?.access_token) {
                saveSession(data, email);
                showMessage("Login successful. Redirecting...", true, 800);
                setTimeout(() => {
                    window.location.href = "dashboard.html";
                }, 900);
                return;
            }

            clearSession();
            showMessage(data.detail || data.message || "Invalid credentials", false);
        } catch (err) {
            clearSession();
            showMessage(`Cannot connect to backend (${BACKEND_URL})`, false);
            console.error(err);
        }
    });
}

const signupForm = document.getElementById("signupForm");
if (signupForm) {
    signupForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const name = document.getElementById("name").value.trim();
        const email = document.getElementById("email").value.trim().toLowerCase();
        const password = document.getElementById("password").value.trim();

        if (!name || !email || !password) {
            showMessage("Please fill all fields", false);
            return;
        }

        try {
            const response = await fetch(`${BACKEND_URL}/signup`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ name, email, password }),
            });
            const data = await response.json();
            if (response.ok && data?.message === "Signup successful") {
                showMessage("Account created. Redirecting to login...", true, 1050);
                setTimeout(() => {
                    window.location.href = "index.html";
                }, 1200);
            } else {
                showMessage(data.detail || data.message || "Signup failed", false);
            }
        } catch (err) {
            showMessage(`Cannot connect to backend (${BACKEND_URL})`, false);
            console.error(err);
        }
    });
}
