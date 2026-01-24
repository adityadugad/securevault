// ======================================================
// SecureVault Authentication Logic (FINAL & STABLE)
// ======================================================

// ---------------- UTIL ----------------
function qs(id) {
  return document.getElementById(id);
}

function setMsg(id, text, type = "") {
  const el = document.getElementById(id);
  if (!el) return;
  el.innerText = text;
  el.className = "msg " + type;
}

// ---------------- SIGNUP ----------------
async function signup() {
  try {
    const email = qs("email")?.value?.trim();
    const password = qs("password")?.value;

    if (!email || !password) {
      setMsg("msg", "Email and password required", "err");
      return;
    }

    setMsg("msg", "Sending OTP...");

    const res = await fetch("/auth/signup", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (!res.ok) {
      setMsg("msg", data.detail || "Signup failed", "err");
      return;
    }

    localStorage.setItem("otp_mode", "signup");
    localStorage.setItem("signup_email", email);

    window.location.href = "/static/otp.html";
  } catch (e) {
    setMsg("msg", "Network error", "err");
  }
}

// ---------------- LOGIN (PASSWORD) ----------------
async function login() {
  try {
    const email = qs("email")?.value?.trim();
    const password = qs("password")?.value;

    if (!email || !password) {
      setMsg("msg", "Email and password required", "err");
      return;
    }

    setMsg("msg", "Checking credentials...");

    const res = await fetch("/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password })
    });

    const data = await res.json();

    if (!res.ok) {
      setMsg("msg", data.detail || "Login failed", "err");
      return;
    }

    localStorage.setItem("otp_mode", "login");
    localStorage.setItem("login_email", email);

    window.location.href = "/static/otp.html";
  } catch (e) {
    setMsg("msg", "Network error", "err");
  }
}

// ---------------- VERIFY OTP (UNIFIED) ----------------
async function verifyOtp() {
  try {
    const otp = qs("otp")?.value?.trim();
    const mode = localStorage.getItem("otp_mode");

    if (!otp || !mode) {
      setMsg("msg", "OTP session expired", "err");
      return;
    }

    setMsg("msg", "Verifying OTP...");

    // ---------- SIGNUP OTP ----------
    if (mode === "signup") {
      const email = localStorage.getItem("signup_email");

      const res = await fetch(
        `/auth/verify-signup-otp?email=${encodeURIComponent(email)}&otp=${encodeURIComponent(otp)}`,
        { method: "POST" }
      );

      const data = await res.json();

      if (!res.ok) {
        setMsg("msg", data.detail || "Invalid OTP", "err");
        return;
      }

      setMsg("msg", "Account verified ✅ Redirecting to login...", "ok");

      localStorage.removeItem("otp_mode");
      localStorage.removeItem("signup_email");

      setTimeout(() => {
        window.location.href = "/";
      }, 1200);
    }

    // ---------- LOGIN OTP ----------
    if (mode === "login") {
      const email = localStorage.getItem("login_email");

      const res = await fetch(
        `/auth/login-otp?email=${encodeURIComponent(email)}&otp=${encodeURIComponent(otp)}`,
        { method: "POST" }
      );

      const data = await res.json();

      if (!res.ok) {
        setMsg("msg", data.detail || "Invalid OTP", "err");
        return;
      }

      localStorage.setItem("token", data.access_token);

      localStorage.removeItem("otp_mode");
      localStorage.removeItem("login_email");

      window.location.href = "/static/dashboard.html";
    }
  } catch (e) {
    setMsg("msg", "Network error", "err");
  }
}

// ---------------- AUTH HELPERS ----------------
function requireAuth() {
  const token = localStorage.getItem("token");
  if (!token) {
    window.location.href = "/";
  }
}

function logout() {
  localStorage.clear();
  window.location.href = "/";
}

// ---------------- NAV HELPERS ----------------
function goSignup() {
  window.location.href = "/static/signup.html";
}

function goLogin() {
  window.location.href = "/";
}

// ---------------- DASHBOARD NAV ----------------
function goNotes() {
  requireAuth();
  window.location.href = "/static/notes.html";
}

function goTodos() {
  requireAuth();
  window.location.href = "/static/todos.html";
}

function goPasswords() {
  requireAuth();
  window.location.href = "/static/passwords.html";
}

function goPqc() {
  requireAuth();
  window.location.href = "/static/pqc.html";
}
